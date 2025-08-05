// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import "../interfaces/IFluxSwapTypes.sol";

/// @title FXRateOracle
/// @notice Real-time foreign exchange rate provider with built-in safety mechanisms
/// @dev Aggregates FX rates from multiple sources with fallback mechanisms
contract FXRateOracle is AccessControl, Pausable, IFluxSwapTypes {
    
    // Role definitions
    bytes32 public constant RATE_UPDATER_ROLE = keccak256("RATE_UPDATER_ROLE");
    bytes32 public constant EMERGENCY_ADMIN_ROLE = keccak256("EMERGENCY_ADMIN_ROLE");

    /// @notice Rate information for each token pair
    struct RateData {
        uint256 rate;              // Latest rate (18 decimals)
        uint256 timestamp;         // Last update timestamp
        uint256 deviation;         // Price deviation from TWAP
        bool isValid;              // Whether rate is currently valid
        AggregatorV3Interface chainlinkFeed; // Chainlink price feed
    }

    /// @notice Supported token pairs: tokenA => tokenB => RateData
    mapping(address => mapping(address => RateData)) public rates;
    
    /// @notice Rate history for TWAP calculations: pair => history array
    mapping(bytes32 => RateHistory[]) public rateHistory;
    
    /// @notice Maximum allowed price deviation from TWAP (basis points)
    uint256 public maxPriceDeviation = 500; // 5%
    
    /// @notice Minimum number of data points for TWAP
    uint256 public constant MIN_TWAP_POINTS = 3;
    
    /// @notice Maximum rate age before considered stale
    uint256 public maxRateAge = FluxSwapConstants.MAX_PRICE_AGE;
    
    /// @notice Emergency rate override (admin controlled)
    mapping(address => mapping(address => uint256)) public emergencyRates;
    mapping(address => mapping(address => bool)) public emergencyRateActive;
    
    /// @notice Circuit breaker - disable all rates
    bool public circuitBreakerTriggered = false;
    
    // Events
    event RateUpdated(
        address indexed tokenA,
        address indexed tokenB,
        uint256 newRate,
        uint256 timestamp,
        string source
    );
    
    event TWAPUpdated(
        address indexed tokenA,
        address indexed tokenB,
        uint256 twapRate,
        uint256 dataPoints
    );
    
    event PriceDeviationAlert(
        address indexed tokenA,
        address indexed tokenB,
        uint256 currentRate,
        uint256 twapRate,
        uint256 deviation
    );
    
    event EmergencyRateSet(
        address indexed tokenA,
        address indexed tokenB,
        uint256 rate,
        address indexed admin
    );
    
    event CircuitBreakerToggled(bool enabled, address indexed admin);
    
    event ChainlinkFeedUpdated(
        address indexed tokenA,
        address indexed tokenB,
        address indexed feedAddress
    );

    /// @notice Constructor initializes oracle settings
    /// @param _admin Address to grant admin role
    constructor(address _admin) {
        require(_admin != address(0), "FXRateOracle: Invalid admin");
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(RATE_UPDATER_ROLE, _admin);
        _grantRole(EMERGENCY_ADMIN_ROLE, _admin);
        
        // Initialize default USDC/EURC rate (placeholder)
        // In production, this would be set to actual Chainlink feeds
    }

    /// @notice Get latest rate for a token pair
    /// @param baseToken Base token address (e.g., USDC)
    /// @param quoteToken Quote token address (e.g., EURC)
    /// @return rate Latest exchange rate (18 decimals)
    /// @return timestamp Last update timestamp
    function getLatestRate(
        address baseToken,
        address quoteToken
    ) external view returns (uint256 rate, uint256 timestamp) {
        require(!circuitBreakerTriggered, "FXRateOracle: Circuit breaker active");
        
        RateData memory rateData = rates[baseToken][quoteToken];
        
        // Check if emergency rate is active
        if (emergencyRateActive[baseToken][quoteToken]) {
            return (emergencyRates[baseToken][quoteToken], block.timestamp);
        }
        
        // Check if we have a direct rate
        if (rateData.isValid && _isRateFresh(rateData.timestamp)) {
            return (rateData.rate, rateData.timestamp);
        }
        
        // Try inverse rate
        RateData memory inverseRate = rates[quoteToken][baseToken];
        if (inverseRate.isValid && _isRateFresh(inverseRate.timestamp)) {
            // Return 1/inverseRate scaled to 18 decimals
            uint256 inversedRate = (1e36) / inverseRate.rate;
            return (inversedRate, inverseRate.timestamp);
        }
        
        // Try Chainlink feed
        if (address(rateData.chainlinkFeed) != address(0)) {
            try rateData.chainlinkFeed.latestRoundData() returns (
                uint80 roundId,
                int256 price,
                uint256 startedAt,
                uint256 updatedAt,
                uint80 answeredInRound
            ) {
                if (price > 0 && _isRateFresh(updatedAt)) {
                    // Convert Chainlink price to 18 decimals
                    uint256 chainlinkRate = _scaleChainlinkPrice(uint256(price), rateData.chainlinkFeed);
                    return (chainlinkRate, updatedAt);
                }
            } catch {
                // Chainlink feed failed, continue to fallback
            }
        }
        
        // Fallback to TWAP if available
        uint256 twapRate = _calculateTWAP(baseToken, quoteToken, FluxSwapConstants.TWAP_WINDOW);
        if (twapRate > 0) {
            return (twapRate, block.timestamp);
        }
        
        revert("FXRateOracle: No valid rate available");
    }

    /// @notice Validate rate with slippage protection
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param expectedRate Expected rate from user
    /// @param maxSlippage Maximum slippage tolerance (basis points)
    /// @return valid Whether rate is within acceptable range
    function validateRateWithSlippage(
        address baseToken,
        address quoteToken,
        uint256 expectedRate,
        uint256 maxSlippage
    ) external view returns (bool valid) {
        (uint256 currentRate, ) = this.getLatestRate(baseToken, quoteToken);
        
        // Calculate acceptable range
        uint256 minAcceptableRate = (expectedRate * (FluxSwapConstants.BASIS_POINTS - maxSlippage)) / FluxSwapConstants.BASIS_POINTS;
        uint256 maxAcceptableRate = (expectedRate * (FluxSwapConstants.BASIS_POINTS + maxSlippage)) / FluxSwapConstants.BASIS_POINTS;
        
        return currentRate >= minAcceptableRate && currentRate <= maxAcceptableRate;
    }

    /// @notice Get time-weighted average price (TWAP)
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param duration Duration for TWAP calculation (seconds)
    /// @return twapRate TWAP rate (18 decimals)
    function getTWAPRate(
        address baseToken,
        address quoteToken,
        uint256 duration
    ) external view returns (uint256 twapRate) {
        return _calculateTWAP(baseToken, quoteToken, duration);
    }

    /// @notice Update rate from external source
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param newRate New rate (18 decimals)
    /// @param source Rate source identifier
    function updateRate(
        address baseToken,
        address quoteToken,
        uint256 newRate,
        string calldata source
    ) external onlyRole(RATE_UPDATER_ROLE) whenNotPaused {
        require(newRate > 0, "FXRateOracle: Invalid rate");
        require(baseToken != quoteToken, "FXRateOracle: Same token pair");
        
        // Validate against TWAP if available
        uint256 twapRate = _calculateTWAP(baseToken, quoteToken, FluxSwapConstants.TWAP_WINDOW);
        if (twapRate > 0) {
            uint256 deviation = _calculateDeviation(newRate, twapRate);
            
            if (deviation > maxPriceDeviation) {
                emit PriceDeviationAlert(baseToken, quoteToken, newRate, twapRate, deviation);
                
                // Don't update if deviation is too high, unless it's an emergency admin
                if (!hasRole(EMERGENCY_ADMIN_ROLE, msg.sender)) {
                    revert("FXRateOracle: Price deviation too high");
                }
            }
        }
        
        // Update rate data
        rates[baseToken][quoteToken] = RateData({
            rate: newRate,
            timestamp: block.timestamp,
            deviation: twapRate > 0 ? _calculateDeviation(newRate, twapRate) : 0,
            isValid: true,
            chainlinkFeed: rates[baseToken][quoteToken].chainlinkFeed
        });
        
        // Add to history for TWAP
        _addToHistory(baseToken, quoteToken, newRate);
        
        emit RateUpdated(baseToken, quoteToken, newRate, block.timestamp, source);
        
        // Update TWAP
        uint256 newTwapRate = _calculateTWAP(baseToken, quoteToken, FluxSwapConstants.TWAP_WINDOW);
        if (newTwapRate > 0) {
            bytes32 pairKey = _getPairKey(baseToken, quoteToken);
            emit TWAPUpdated(baseToken, quoteToken, newTwapRate, rateHistory[pairKey].length);
        }
    }

    /// @notice Set Chainlink price feed for a token pair
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param feedAddress Chainlink aggregator address
    function setChainlinkFeed(
        address baseToken,
        address quoteToken,
        address feedAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(feedAddress != address(0), "FXRateOracle: Invalid feed address");
        
        rates[baseToken][quoteToken].chainlinkFeed = AggregatorV3Interface(feedAddress);
        
        emit ChainlinkFeedUpdated(baseToken, quoteToken, feedAddress);
    }

    /// @notice Set emergency rate override
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param emergencyRate Emergency rate (18 decimals)
    function setEmergencyRate(
        address baseToken,
        address quoteToken,
        uint256 emergencyRate
    ) external onlyRole(EMERGENCY_ADMIN_ROLE) {
        require(emergencyRate > 0, "FXRateOracle: Invalid emergency rate");
        
        emergencyRates[baseToken][quoteToken] = emergencyRate;
        emergencyRateActive[baseToken][quoteToken] = true;
        
        emit EmergencyRateSet(baseToken, quoteToken, emergencyRate, msg.sender);
    }

    /// @notice Disable emergency rate override
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    function clearEmergencyRate(
        address baseToken,
        address quoteToken
    ) external onlyRole(EMERGENCY_ADMIN_ROLE) {
        emergencyRateActive[baseToken][quoteToken] = false;
    }

    /// @notice Toggle circuit breaker
    /// @param enabled Whether to enable circuit breaker
    function toggleCircuitBreaker(bool enabled) external onlyRole(EMERGENCY_ADMIN_ROLE) {
        circuitBreakerTriggered = enabled;
        emit CircuitBreakerToggled(enabled, msg.sender);
    }

    /// @notice Update maximum price deviation
    /// @param newMaxDeviation New maximum deviation (basis points)
    function updateMaxPriceDeviation(uint256 newMaxDeviation) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMaxDeviation <= 2000, "FXRateOracle: Deviation too high"); // Max 20%
        maxPriceDeviation = newMaxDeviation;
    }

    /// @notice Update maximum rate age
    /// @param newMaxAge New maximum age (seconds)
    function updateMaxRateAge(uint256 newMaxAge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMaxAge >= 60, "FXRateOracle: Age too low"); // Min 1 minute
        maxRateAge = newMaxAge;
    }

    /// @notice Get rate history for a pair
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @return history Array of rate history entries
    function getRateHistory(
        address baseToken,
        address quoteToken
    ) external view returns (RateHistory[] memory history) {
        bytes32 pairKey = _getPairKey(baseToken, quoteToken);
        return rateHistory[pairKey];
    }

    /// @notice Check if rate is fresh
    /// @param timestamp Rate timestamp
    /// @return fresh Whether rate is within acceptable age
    function _isRateFresh(uint256 timestamp) internal view returns (bool fresh) {
        return block.timestamp <= timestamp + maxRateAge;
    }

    /// @notice Calculate TWAP for a token pair
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param duration Duration for calculation
    /// @return twapRate TWAP rate
    function _calculateTWAP(
        address baseToken,
        address quoteToken,
        uint256 duration
    ) internal view returns (uint256 twapRate) {
        bytes32 pairKey = _getPairKey(baseToken, quoteToken);
        RateHistory[] memory history = rateHistory[pairKey];
        
        if (history.length < MIN_TWAP_POINTS) {
            return 0;
        }
        
        uint256 cutoffTime = block.timestamp - duration;
        uint256 weightedSum = 0;
        uint256 totalWeight = 0;
        
        for (uint256 i = 0; i < history.length; i++) {
            if (history[i].timestamp < cutoffTime) {
                continue;
            }
            
            uint256 weight = block.timestamp - history[i].timestamp + 1;
            weightedSum += history[i].rate * weight;
            totalWeight += weight;
        }
        
        return totalWeight > 0 ? weightedSum / totalWeight : 0;
    }

    /// @notice Add rate to history
    /// @param baseToken Base token address
    /// @param quoteToken Quote token address
    /// @param rate Rate to add
    function _addToHistory(address baseToken, address quoteToken, uint256 rate) internal {
        bytes32 pairKey = _getPairKey(baseToken, quoteToken);
        
        rateHistory[pairKey].push(RateHistory({
            rate: rate,
            timestamp: block.timestamp
        }));
        
        // Limit history size to prevent excessive gas costs
        if (rateHistory[pairKey].length > 100) {
            // Remove oldest entry
            for (uint256 i = 0; i < rateHistory[pairKey].length - 1; i++) {
                rateHistory[pairKey][i] = rateHistory[pairKey][i + 1];
            }
            rateHistory[pairKey].pop();
        }
    }

    /// @notice Calculate price deviation between two rates
    /// @param rate1 First rate
    /// @param rate2 Second rate
    /// @return deviation Deviation in basis points
    function _calculateDeviation(uint256 rate1, uint256 rate2) internal pure returns (uint256 deviation) {
        if (rate1 == rate2) return 0;
        
        uint256 diff = rate1 > rate2 ? rate1 - rate2 : rate2 - rate1;
        uint256 baseRate = rate1 > rate2 ? rate2 : rate1;
        
        return (diff * FluxSwapConstants.BASIS_POINTS) / baseRate;
    }

    /// @notice Get unique key for token pair
    /// @param tokenA First token
    /// @param tokenB Second token
    /// @return pairKey Unique pair identifier
    function _getPairKey(address tokenA, address tokenB) internal pure returns (bytes32 pairKey) {
        return tokenA < tokenB ? 
            keccak256(abi.encodePacked(tokenA, tokenB)) : 
            keccak256(abi.encodePacked(tokenB, tokenA));
    }

    /// @notice Scale Chainlink price to 18 decimals
    /// @param price Chainlink price
    /// @param feed Chainlink feed interface
    /// @return scaledPrice Price scaled to 18 decimals
    function _scaleChainlinkPrice(
        uint256 price,
        AggregatorV3Interface feed
    ) internal view returns (uint256 scaledPrice) {
        try feed.decimals() returns (uint8 decimals) {
            if (decimals < 18) {
                return price * (10 ** (18 - decimals));
            } else if (decimals > 18) {
                return price / (10 ** (decimals - 18));
            } else {
                return price;
            }
        } catch {
            // Assume 8 decimals if call fails (standard for Chainlink)
            return price * 1e10;
        }
    }

    /// @notice Emergency pause
    function pause() external onlyRole(EMERGENCY_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}