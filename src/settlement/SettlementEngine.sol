// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IFluxSwapTypes.sol";
import "../config/FluxSwapNetworkConfig.sol";

/// @title SettlementEngine
/// @notice Intelligent routing and settlement optimization engine
/// @dev Calculates optimal settlement paths and manages execution strategies
contract SettlementEngine is AccessControl, Pausable, ReentrancyGuard, IFluxSwapTypes {
    using FluxSwapNetworkConfig for uint256;

    // Role definitions
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ROUTE_OPTIMIZER_ROLE = keccak256("ROUTE_OPTIMIZER_ROLE");

    /// @notice Network performance metrics for each chain
    mapping(uint32 => NetworkMetrics) public networkMetrics;
    
    /// @notice Gas price tracking for different chains
    mapping(uint32 => uint256) public chainGasPrices;
    
    /// @notice Liquidity tracking for routes
    mapping(bytes32 => uint256) public routeLiquidity;
    
    /// @notice Route success rates (basis points)
    mapping(bytes32 => uint256) public routeSuccessRates;
    
    /// @notice Pending settlements
    mapping(bytes32 => RouteInfo) public pendingSettlements;
    
    /// @notice Settlement history for analytics
    mapping(address => RouteInfo[]) public userSettlementHistory;
    
    /// @notice MEV protection settings
    bool public mevProtectionEnabled = true;
    uint256 public maxMEVTolerance = 100; // 1% in basis points
    
    /// @notice Route scoring weights
    uint256 public constant COST_WEIGHT = 40; // 40%
    uint256 public constant SPEED_WEIGHT = 30; // 30%
    uint256 public constant LIQUIDITY_WEIGHT = 20; // 20%
    uint256 public constant RELIABILITY_WEIGHT = 10; // 10%
    
    /// @notice Batch processing settings
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public batchSettlementThreshold = 10; // Auto-batch when 10+ pending
    
    // Events
    event RouteCalculated(
        address indexed user,
        address sourceToken,
        address targetToken,
        uint256 amount,
        RouteInfo route
    );
    
    event SettlementExecuted(
        bytes32 indexed settlementId,
        RouteInfo route,
        bool success,
        uint256 gasUsed
    );
    
    event BatchSettlementExecuted(
        bytes32[] settlementIds,
        uint256 totalGasSaved,
        uint256 successCount
    );
    
    event NetworkMetricsUpdated(
        uint32 indexed chainId,
        uint256 avgConfirmationTime,
        uint256 successRate,
        uint256 congestionLevel
    );
    
    event MEVProtectionTriggered(
        bytes32 indexed settlementId,
        uint256 detectedMEV,
        uint256 tolerance
    );
    
    event RouteOptimized(
        bytes32 indexed routeId,
        uint256 oldScore,
        uint256 newScore,
        string optimization
    );

    /// @notice Constructor initializes settlement engine
    /// @param _admin Address to grant admin role
    constructor(address _admin) {
        require(_admin != address(0), "SettlementEngine: Invalid admin");
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(ROUTE_OPTIMIZER_ROLE, _admin);
        
        // Initialize default network metrics
        _initializeNetworkMetrics();
    }

    /// @notice Calculate optimal route for a swap
    /// @param sourceToken Source token address
    /// @param targetToken Target token address
    /// @param amount Amount to swap
    /// @param availableChains Array of available chain IDs
    /// @return optimalRoute Best route based on current conditions
    function calculateOptimalRoute(
        address sourceToken,
        address targetToken,
        uint256 amount,
        uint32[] calldata availableChains
    ) external view returns (RouteInfo memory optimalRoute) {
        require(sourceToken != address(0), "SettlementEngine: Invalid source token");
        require(targetToken != address(0), "SettlementEngine: Invalid target token");
        require(amount > 0, "SettlementEngine: Invalid amount");
        require(availableChains.length > 0, "SettlementEngine: No chains available");

        uint256 bestScore = 0;
        RouteInfo memory bestRoute;

        // Evaluate each possible route
        for (uint256 i = 0; i < availableChains.length; i++) {
            uint32 chainId = availableChains[i];
            
            // Skip if chain not supported
            if (!FluxSwapNetworkConfig.isChainSupported(chainId)) {
                continue;
            }

            RouteInfo memory route = _calculateRouteForChain(
                sourceToken,
                targetToken,
                amount,
                chainId
            );

            uint256 routeScore = _calculateRouteScore(route, chainId);
            
            if (routeScore > bestScore) {
                bestScore = routeScore;
                bestRoute = route;
            }
        }

        require(bestScore > 0, "SettlementEngine: No viable route found");
        return bestRoute;
    }

    /// @notice Execute settlement for a given route
    /// @param swapId Swap identifier
    /// @param route Route information to execute
    /// @return success Whether settlement was successful
    function executeSettlement(
        bytes32 swapId,
        RouteInfo calldata route
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused returns (bool success) {
        require(swapId != bytes32(0), "SettlementEngine: Invalid swap ID");
        require(route.chainPath.length > 0, "SettlementEngine: Invalid route");

        // Store pending settlement
        pendingSettlements[swapId] = route;

        // MEV protection check
        if (mevProtectionEnabled) {
            uint256 detectedMEV = _detectMEV(route);
            if (detectedMEV > maxMEVTolerance) {
                emit MEVProtectionTriggered(swapId, detectedMEV, maxMEVTolerance);
                return false;
            }
        }

        // Execute the route
        uint256 gasStart = gasleft();
        
        try this._executeRoute(swapId, route) returns (bool executed) {
            uint256 gasUsed = gasStart - gasleft();
            
            if (executed) {
                // Update success metrics
                _updateRouteSuccessRate(route, true);
                
                // Record in user history
                userSettlementHistory[msg.sender].push(route);
                
                emit SettlementExecuted(swapId, route, true, gasUsed);
                return true;
            } else {
                _updateRouteSuccessRate(route, false);
                emit SettlementExecuted(swapId, route, false, gasUsed);
                return false;
            }
        } catch Error(string memory reason) {
            uint256 gasUsed = gasStart - gasleft();
            _updateRouteSuccessRate(route, false);
            emit SettlementExecuted(swapId, route, false, gasUsed);
            return false;
        }
    }

    /// @notice Batch multiple settlements for gas efficiency
    /// @param swapIds Array of swap IDs to settle
    /// @return successCount Number of successful settlements
    function batchSettlements(
        bytes32[] calldata swapIds
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused returns (uint256 successCount) {
        require(swapIds.length <= MAX_BATCH_SIZE, "SettlementEngine: Batch too large");
        require(swapIds.length > 1, "SettlementEngine: Use single settlement");

        uint256 totalGasStart = gasleft();
        uint256 successful = 0;

        for (uint256 i = 0; i < swapIds.length; i++) {
            RouteInfo memory route = pendingSettlements[swapIds[i]];
            
            if (route.chainPath.length == 0) {
                continue; // Skip invalid routes
            }

            try this._executeRoute(swapIds[i], route) returns (bool executed) {
                if (executed) {
                    successful++;
                    _updateRouteSuccessRate(route, true);
                } else {
                    _updateRouteSuccessRate(route, false);
                }
            } catch {
                _updateRouteSuccessRate(route, false);
            }
        }

        uint256 totalGasUsed = totalGasStart - gasleft();
        uint256 estimatedSingleGas = totalGasUsed / swapIds.length;
        uint256 gasSaved = (estimatedSingleGas * swapIds.length) - totalGasUsed;

        emit BatchSettlementExecuted(swapIds, gasSaved, successful);
        return successful;
    }

    /// @notice Update network metrics for a chain
    /// @param chainId Chain identifier
    /// @param avgConfirmationTime Average confirmation time (seconds)
    /// @param successRate Success rate (basis points)
    /// @param congestionLevel Congestion level (0-100)
    function updateNetworkMetrics(
        uint32 chainId,
        uint256 avgConfirmationTime,
        uint256 successRate,
        uint256 congestionLevel
    ) external onlyRole(ROUTE_OPTIMIZER_ROLE) {
        require(FluxSwapNetworkConfig.isChainSupported(chainId), "SettlementEngine: Unsupported chain");
        require(successRate <= FluxSwapConstants.BASIS_POINTS, "SettlementEngine: Invalid success rate");
        require(congestionLevel <= 100, "SettlementEngine: Invalid congestion level");

        networkMetrics[chainId] = NetworkMetrics({
            avgConfirmationTime: avgConfirmationTime,
            successRate: successRate,
            congestionLevel: congestionLevel,
            lastUpdate: block.timestamp
        });

        emit NetworkMetricsUpdated(chainId, avgConfirmationTime, successRate, congestionLevel);
    }

    /// @notice Update gas price for a chain
    /// @param chainId Chain identifier
    /// @param gasPrice New gas price (in wei)
    function updateGasPrice(uint32 chainId, uint256 gasPrice) external onlyRole(ROUTE_OPTIMIZER_ROLE) {
        chainGasPrices[chainId] = gasPrice;
    }

    /// @notice Update route liquidity
    /// @param routeId Route identifier
    /// @param liquidity Available liquidity amount
    function updateRouteLiquidity(bytes32 routeId, uint256 liquidity) external onlyRole(OPERATOR_ROLE) {
        routeLiquidity[routeId] = liquidity;
    }

    /// @notice Set MEV protection settings
    /// @param enabled Whether MEV protection is enabled
    /// @param tolerance MEV tolerance in basis points
    function setMEVProtection(bool enabled, uint256 tolerance) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(tolerance <= 1000, "SettlementEngine: MEV tolerance too high"); // Max 10%
        
        mevProtectionEnabled = enabled;
        maxMEVTolerance = tolerance;
    }

    /// @notice Get route statistics
    /// @param routeId Route identifier
    /// @return successRate Success rate in basis points
    /// @return liquidity Available liquidity
    function getRouteStats(bytes32 routeId) external view returns (uint256 successRate, uint256 liquidity) {
        return (routeSuccessRates[routeId], routeLiquidity[routeId]);
    }

    /// @notice Get user settlement history
    /// @param user User address
    /// @return routes Array of route information
    function getUserSettlementHistory(address user) external view returns (RouteInfo[] memory routes) {
        return userSettlementHistory[user];
    }

    /// @notice Internal function to execute a route
    /// @param swapId Swap identifier
    /// @param route Route to execute
    /// @return success Whether execution was successful
    function _executeRoute(bytes32 swapId, RouteInfo memory route) external returns (bool success) {
        require(msg.sender == address(this), "SettlementEngine: Internal function");
        
        // This is a simplified implementation
        // In production, this would:
        // 1. Execute cross-chain transfers via CCTP
        // 2. Perform swaps on destination chains
        // 3. Handle multi-hop routes
        // 4. Manage gas optimization
        
        // For now, simulate successful execution based on route score
        return route.score > 5000; // 50% threshold
    }

    /// @notice Calculate route for a specific chain
    /// @param sourceToken Source token
    /// @param targetToken Target token
    /// @param amount Swap amount
    /// @param chainId Target chain
    /// @return route Route information
    function _calculateRouteForChain(
        address sourceToken,
        address targetToken,
        uint256 amount,
        uint32 chainId
    ) internal view returns (RouteInfo memory route) {
        // Simplified route calculation
        uint32[] memory chainPath = new uint32[](1);
        chainPath[0] = chainId;
        
        address[] memory tokenPath = new address[](2);
        tokenPath[0] = sourceToken;
        tokenPath[1] = targetToken;
        
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount;
        amounts[1] = amount; // Simplified 1:1 conversion
        
        uint256 gasPrice = chainGasPrices[chainId];
        uint256 estimatedGas = 200000; // Estimated gas for cross-chain swap
        uint256 totalGasCost = gasPrice * estimatedGas;
        
        NetworkMetrics memory metrics = networkMetrics[chainId];
        
        return RouteInfo({
            chainPath: chainPath,
            tokenPath: tokenPath,
            amounts: amounts,
            totalGasCost: totalGasCost,
            estimatedTime: metrics.avgConfirmationTime,
            slippage: 50, // 0.5% default slippage
            score: 0 // Will be calculated separately
        });
    }

    /// @notice Calculate route score based on multiple factors
    /// @param route Route information
    /// @param chainId Primary chain for the route
    /// @return score Route score (higher is better)
    function _calculateRouteScore(RouteInfo memory route, uint32 chainId) internal view returns (uint256 score) {
        NetworkMetrics memory metrics = networkMetrics[chainId];
        
        // Cost score (lower cost = higher score)
        uint256 costScore = route.totalGasCost > 0 ? 
            (1e18 / route.totalGasCost) * COST_WEIGHT / 100 : 0;
        
        // Speed score (faster = higher score)
        uint256 speedScore = route.estimatedTime > 0 ? 
            (3600 / route.estimatedTime) * SPEED_WEIGHT / 100 : 0; // 1 hour baseline
        
        // Liquidity score
        bytes32 routeId = _getRouteId(route);
        uint256 liquidityScore = routeLiquidity[routeId] > 0 ? 
            (routeLiquidity[routeId] / 1e6) * LIQUIDITY_WEIGHT / 100 : 0; // Scale by USDC
        
        // Reliability score
        uint256 reliabilityScore = (metrics.successRate * RELIABILITY_WEIGHT) / 100;
        
        // Apply congestion penalty
        uint256 congestionPenalty = (metrics.congestionLevel * 100); // Max 10% penalty
        
        uint256 totalScore = costScore + speedScore + liquidityScore + reliabilityScore;
        
        return totalScore > congestionPenalty ? totalScore - congestionPenalty : 0;
    }

    /// @notice Detect potential MEV in a route
    /// @param route Route to analyze
    /// @return mevLevel MEV risk level in basis points
    function _detectMEV(RouteInfo memory route) internal view returns (uint256 mevLevel) {
        // Simplified MEV detection
        // In production, this would analyze:
        // - Price impact across DEXs
        // - Arbitrage opportunities
        // - Sandwich attack potential
        // - Front-running risks
        
        if (route.slippage > 200) { // >2% slippage indicates high MEV risk
            return 150; // 1.5% MEV risk
        }
        
        return 25; // 0.25% baseline MEV risk
    }

    /// @notice Update route success rate based on execution result
    /// @param route Route that was executed
    /// @param success Whether execution was successful
    function _updateRouteSuccessRate(RouteInfo memory route, bool success) internal {
        bytes32 routeId = _getRouteId(route);
        uint256 currentRate = routeSuccessRates[routeId];
        
        // Simple exponential moving average
        if (success) {
            routeSuccessRates[routeId] = (currentRate * 9 + FluxSwapConstants.BASIS_POINTS) / 10;
        } else {
            routeSuccessRates[routeId] = (currentRate * 9) / 10;
        }
    }

    /// @notice Generate unique route identifier
    /// @param route Route information
    /// @return routeId Unique identifier
    function _getRouteId(RouteInfo memory route) internal pure returns (bytes32 routeId) {
        return keccak256(abi.encode(route.chainPath, route.tokenPath));
    }

    /// @notice Initialize default network metrics
    function _initializeNetworkMetrics() internal {
        // Foundry Test Chain (for testing)
        networkMetrics[FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN] = NetworkMetrics({
            avgConfirmationTime: 1, // 1 second (instant in test)
            successRate: 10000, // 100% (test environment)
            congestionLevel: 0,
            lastUpdate: block.timestamp
        });
        
        // Ethereum Sepolia
        networkMetrics[FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN] = NetworkMetrics({
            avgConfirmationTime: 12, // 12 seconds
            successRate: 9800, // 98%
            congestionLevel: 30,
            lastUpdate: block.timestamp
        });
        
        // Arbitrum Sepolia
        networkMetrics[FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_DOMAIN] = NetworkMetrics({
            avgConfirmationTime: 2, // 2 seconds
            successRate: 9900, // 99%
            congestionLevel: 15,
            lastUpdate: block.timestamp
        });
        
        // Base Sepolia
        networkMetrics[FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN] = NetworkMetrics({
            avgConfirmationTime: 2, // 2 seconds
            successRate: 9850, // 98.5%
            congestionLevel: 20,
            lastUpdate: block.timestamp
        });
        
        // Optimism Sepolia
        networkMetrics[FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_DOMAIN] = NetworkMetrics({
            avgConfirmationTime: 2, // 2 seconds
            successRate: 9750, // 97.5%
            congestionLevel: 25,
            lastUpdate: block.timestamp
        });
    }

    /// @notice Emergency pause
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}