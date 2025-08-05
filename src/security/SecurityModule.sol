// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IFluxSwapTypes.sol";

/// @title SecurityModule
/// @notice Comprehensive security and risk management system for FluxSwap
/// @dev Implements transaction limits, circuit breakers, and emergency controls
contract SecurityModule is AccessControl, Pausable, ReentrancyGuard, IFluxSwapTypes {
    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ADMIN_ROLE = keccak256("EMERGENCY_ADMIN_ROLE");
    bytes32 public constant RISK_MANAGER_ROLE = keccak256("RISK_MANAGER_ROLE");
    
    /// @notice Current risk parameters
    RiskParams public riskParams;
    
    /// @notice User transaction tracking: user -> day -> volume
    mapping(address => mapping(uint256 => uint256)) public userDailyVolume;
    
    /// @notice Blacklisted addresses
    mapping(address => bool) public blacklistedAddresses;
    
    /// @notice Whitelisted addresses (bypass limits)
    mapping(address => bool) public whitelistedAddresses;
    
    /// @notice Total daily volume for the system
    uint256 public totalDailyVolume;
    
    /// @notice System health score (100% = 10000 basis points)
    uint256 public systemHealthScore = FluxSwapConstants.BASIS_POINTS;
    
    /// @notice Last system health update timestamp
    uint256 public lastHealthUpdate;
    
    /// @notice Emergency pause state
    bool public emergencyPause = false;
    
    /// @notice Emergency start time
    uint256 public emergencyStartTime;
    
    /// @notice Circuit breaker states
    mapping(bytes32 => bool) public circuitBreakers;
    
    // Events
    event EmergencyPauseTriggered(address indexed admin, string reason, uint256 timestamp);
    event RiskParametersUpdated(RiskParams newParams, address indexed admin);
    event AddressBlacklisted(address indexed addr, string reason, address indexed admin);
    event AddressWhitelisted(address indexed addr, address indexed admin);
    event CircuitBreakerTriggered(bytes32 indexed breakerType, address indexed trigger, string reason);
    event SystemHealthUpdated(uint256 newScore, uint256 timestamp);
    event TransactionRecorded(address indexed user, uint256 amount, uint256 dailyTotal);

    /// @notice Constructor initializes roles and default risk parameters
    /// @param _admin Address to grant admin role
    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(EMERGENCY_ADMIN_ROLE, _admin);
        
        // Initialize default risk parameters
        riskParams = RiskParams({
            dailyUserLimit: 100_000 * 1e6,        // $100K USDC (6 decimals)
            maxSingleTransaction: 1_000_000 * 1e6, // $1M USDC
            maxPriceDeviation: 1000,               // 10% = 1000 basis points
            minLiquidityBuffer: 2000,              // 20% = 2000 basis points
            emergencyThreshold: 5000,              // 50% = 5000 basis points
            globalPauseEnabled: true
        });
        
        lastHealthUpdate = block.timestamp;
    }

    /// @notice Check if transaction is within risk limits
    /// @param user Address of the user
    /// @param amount Transaction amount
    /// @param timeWindow Time window for rate limiting (not used in daily limit)
    /// @return withinLimits True if transaction is allowed
    function checkTransactionLimits(
        address user,
        uint256 amount,
        uint256 timeWindow
    ) external view returns (bool withinLimits) {
        // Check global pause states
        if (emergencyPause || paused()) {
            return false;
        }
        
        // Check blacklist
        if (blacklistedAddresses[user]) {
            return false;
        }
        
        // Whitelist bypass
        if (whitelistedAddresses[user]) {
            return true;
        }
        
        // Check single transaction limit
        if (amount > riskParams.maxSingleTransaction) {
            return false;
        }
        
        // Check daily limit
        uint256 today = block.timestamp / 1 days;
        uint256 currentDailyVolume = userDailyVolume[user][today];
        
        if (currentDailyVolume + amount > riskParams.dailyUserLimit) {
            return false;
        }
        
        return true;
    }

    /// @notice Trigger emergency pause
    /// @param reason Reason for the emergency pause
    function triggerEmergencyPause(
        string calldata reason
    ) external onlyRole(EMERGENCY_ADMIN_ROLE) {
        require(!emergencyPause, "SecurityModule: Already paused");
        
        emergencyPause = true;
        emergencyStartTime = block.timestamp;
        
        // Pause all contract operations
        _pause();
        
        emit EmergencyPauseTriggered(msg.sender, reason, block.timestamp);
    }

    /// @notice Update risk parameters
    /// @param newParams New risk parameters
    function updateRiskParameters(
        RiskParams calldata newParams
    ) external onlyRole(ADMIN_ROLE) {
        // Validate parameters
        require(newParams.dailyUserLimit > 0, "SecurityModule: Invalid daily limit");
        require(newParams.maxSingleTransaction > 0, "SecurityModule: Invalid transaction limit");
        require(newParams.maxPriceDeviation <= 5000, "SecurityModule: Price deviation too high"); // Max 50%
        
        riskParams = newParams;
        emit RiskParametersUpdated(newParams, msg.sender);
    }

    /// @notice Blacklist an address
    /// @param maliciousAddress Address to blacklist
    /// @param reason Reason for blacklisting
    function blacklistAddress(
        address maliciousAddress,
        string calldata reason
    ) external onlyRole(ADMIN_ROLE) {
        require(maliciousAddress != address(0), "SecurityModule: Invalid address");
        require(!whitelistedAddresses[maliciousAddress], "SecurityModule: Cannot blacklist whitelisted address");
        
        blacklistedAddresses[maliciousAddress] = true;
        emit AddressBlacklisted(maliciousAddress, reason, msg.sender);
    }

    /// @notice Whitelist an address (bypass limits)
    /// @param trustedAddress Address to whitelist
    function whitelistAddress(address trustedAddress) external onlyRole(ADMIN_ROLE) {
        require(trustedAddress != address(0), "SecurityModule: Invalid address");
        
        whitelistedAddresses[trustedAddress] = true;
        
        // Remove from blacklist if present
        if (blacklistedAddresses[trustedAddress]) {
            blacklistedAddresses[trustedAddress] = false;
        }
        
        emit AddressWhitelisted(trustedAddress, msg.sender);
    }

    /// @notice Trigger a circuit breaker
    /// @param breakerType Type of circuit breaker
    /// @param reason Reason for triggering
    function triggerCircuitBreaker(
        bytes32 breakerType,
        string calldata reason
    ) external {
        require(
            hasRole(RISK_MANAGER_ROLE, msg.sender) || 
            hasRole(EMERGENCY_ADMIN_ROLE, msg.sender),
            "SecurityModule: Insufficient permissions"
        );
        
        circuitBreakers[breakerType] = true;
        
        // Auto-pause if critical breaker triggered
        if (breakerType == keccak256("CRITICAL_FAILURE") || 
            breakerType == keccak256("PRICE_ORACLE_FAILURE")) {
            
            if (riskParams.globalPauseEnabled && !emergencyPause) {
                emergencyPause = true;
                emergencyStartTime = block.timestamp;
                _pause();
                emit EmergencyPauseTriggered(msg.sender, reason, block.timestamp);
            }
        }
        
        emit CircuitBreakerTriggered(breakerType, msg.sender, reason);
    }

    /// @notice Update system health score
    /// @dev Should be called by external monitoring systems
    function updateSystemHealth() external {
        require(
            block.timestamp >= lastHealthUpdate + 300, // 5 minute cooldown
            "SecurityModule: Health update too frequent"
        );
        
        uint256 newScore = _calculateSystemHealth();
        systemHealthScore = newScore;
        lastHealthUpdate = block.timestamp;
        
        // Trigger emergency measures if health is critically low
        if (newScore < riskParams.emergencyThreshold) {
            circuitBreakers[keccak256("LOW_SYSTEM_HEALTH")] = true;
            
            if (riskParams.globalPauseEnabled && !emergencyPause) {
                emergencyPause = true;
                emergencyStartTime = block.timestamp;
                _pause();
                emit EmergencyPauseTriggered(msg.sender, "System health below emergency threshold", block.timestamp);
            }
            
            emit CircuitBreakerTriggered(keccak256("LOW_SYSTEM_HEALTH"), msg.sender, "System health below emergency threshold");
        }
        
        emit SystemHealthUpdated(newScore, block.timestamp);
    }

    /// @notice Record a completed transaction for tracking
    /// @param user User address
    /// @param amount Transaction amount
    function recordTransaction(address user, uint256 amount) external onlyRole(ADMIN_ROLE) {
        uint256 today = block.timestamp / 1 days;
        uint256 newDailyVolume = userDailyVolume[user][today] + amount;
        userDailyVolume[user][today] = newDailyVolume;
        totalDailyVolume += amount;
        
        emit TransactionRecorded(user, amount, newDailyVolume);
    }

    /// @notice Check if system is healthy
    /// @return healthy True if system is operating normally
    function isSystemHealthy() external view returns (bool healthy) {
        return systemHealthScore >= riskParams.emergencyThreshold && !emergencyPause;
    }

    /// @notice Get user's daily volume
    /// @param user User address
    /// @return volume Current daily volume
    function getUserDailyVolume(address user) external view returns (uint256 volume) {
        uint256 today = block.timestamp / 1 days;
        return userDailyVolume[user][today];
    }

    /// @notice Get remaining user limit
    /// @param user User address  
    /// @return remaining Remaining daily limit
    function getRemainingUserLimit(address user) external view returns (uint256 remaining) {
        if (whitelistedAddresses[user]) {
            return type(uint256).max;
        }
        
        uint256 today = block.timestamp / 1 days;
        uint256 used = userDailyVolume[user][today];
        
        return used >= riskParams.dailyUserLimit ? 0 : riskParams.dailyUserLimit - used;
    }

    /// @notice Resume operations after emergency pause
    /// @dev Only callable by default admin role
    function resumeOperations() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(emergencyPause, "SecurityModule: Not currently paused");
        require(systemHealthScore >= riskParams.emergencyThreshold, "SecurityModule: System health insufficient");
        
        emergencyPause = false;
        _unpause();
        
        // Clear circuit breakers
        circuitBreakers[keccak256("CRITICAL_FAILURE")] = false;
        circuitBreakers[keccak256("PRICE_ORACLE_FAILURE")] = false;
        circuitBreakers[keccak256("LIQUIDITY_SHORTAGE")] = false;
        circuitBreakers[keccak256("HIGH_SLIPPAGE")] = false;
        circuitBreakers[keccak256("LOW_SYSTEM_HEALTH")] = false;
    }

    /// @notice Calculate system health score based on various factors
    /// @return score Health score (10000 = 100%)
    function _calculateSystemHealth() private view returns (uint256 score) {
        uint256 baseScore = FluxSwapConstants.BASIS_POINTS; // 100%
        
        // Deduct points for active circuit breakers
        if (circuitBreakers[keccak256("PRICE_ORACLE_FAILURE")]) {
            baseScore = baseScore - 3000; // -30%
        }
        
        if (circuitBreakers[keccak256("LIQUIDITY_SHORTAGE")]) {
            baseScore = baseScore - 2000; // -20%
        }
        
        if (circuitBreakers[keccak256("HIGH_SLIPPAGE")]) {
            baseScore = baseScore - 1000; // -10%
        }
        
        if (circuitBreakers[keccak256("CRITICAL_FAILURE")]) {
            baseScore = baseScore - 5000; // -50%
        }
        
        // Ensure score doesn't go below 0
        return baseScore > FluxSwapConstants.BASIS_POINTS ? 0 : baseScore;
    }
}