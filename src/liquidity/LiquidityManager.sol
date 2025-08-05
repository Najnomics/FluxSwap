// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../interfaces/IFluxSwapTypes.sol";
import "../config/FluxSwapNetworkConfig.sol";

/// @title LiquidityManager
/// @notice Cross-chain liquidity optimization and rebalancing system
/// @dev Manages liquidity pools and automated rebalancing across chains
contract LiquidityManager is AccessControl, Pausable, ReentrancyGuard, ERC20, IFluxSwapTypes {
    using SafeERC20 for IERC20;
    using FluxSwapNetworkConfig for uint256;

    // Role definitions
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant REBALANCER_ROLE = keccak256("REBALANCER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /// @notice Pool information for each chain and token
    mapping(uint32 => mapping(address => PoolInfo)) public pools;
    
    /// @notice Liquidity provider information
    mapping(address => mapping(uint32 => uint256)) public lpBalances;
    
    /// @notice Total liquidity provided by each user
    mapping(address => uint256) public totalLPTokens;
    
    /// @notice Fee collection per chain and token
    mapping(uint32 => mapping(address => uint256)) public collectedFees;
    
    /// @notice Rebalancing history
    RebalanceAction[] public rebalanceHistory;
    
    /// @notice Last rebalancing timestamp per chain pair
    mapping(bytes32 => uint256) public lastRebalanceTime;
    
    /// @notice JIT liquidity providers
    mapping(address => bool) public jitProviders;
    
    /// @notice Emergency evacuation status
    bool public emergencyEvacuation = false;
    
    /// @notice Minimum liquidity threshold per pool
    uint256 public constant MIN_LIQUIDITY_THRESHOLD = 10000e6; // $10,000 USDC
    
    /// @notice Maximum single deposit
    uint256 public constant MAX_SINGLE_DEPOSIT = 10_000_000e6; // $10M USDC
    
    /// @notice Fee rate for liquidity providers (basis points)
    uint256 public lpFeeRate = 50; // 0.5%

    // Events
    event LiquidityAdded(
        address indexed provider,
        address indexed token,
        uint256 amount,
        uint32 targetChain,
        uint256 lpTokens
    );
    
    event LiquidityRemoved(
        address indexed provider,
        uint256 lpTokens,
        uint32 chainId,
        uint256 amount
    );
    
    event RebalanceExecuted(
        uint32 indexed sourceChain,
        uint32 indexed destinationChain,
        address indexed token,
        uint256 amount,
        address executor
    );
    
    event FeesDistributed(
        uint32 indexed chainId,
        address indexed token,
        uint256 totalFees,
        uint256 lpCount
    );
    
    event JITLiquidityProvided(
        address indexed provider,
        address indexed token,
        uint256 amount,
        uint32 chainId
    );
    
    event EmergencyEvacuationTriggered(address indexed admin, uint256 timestamp);
    
    event UtilizationAlert(
        uint32 indexed chainId,
        address indexed token,
        uint256 utilizationRate,
        uint256 threshold
    );

    /// @notice Constructor initializes liquidity manager
    /// @param _admin Address to grant admin role
    /// @param _name LP token name
    /// @param _symbol LP token symbol
    constructor(
        address _admin,
        string memory _name,
        string memory _symbol
    ) ERC20(_name, _symbol) {
        require(_admin != address(0), "LiquidityManager: Invalid admin");
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(REBALANCER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
    }

    /// @notice Add liquidity to a specific chain and token
    /// @param token Token address to provide liquidity for
    /// @param amount Amount of tokens to provide
    /// @param targetChain Target chain ID for liquidity
    /// @return lpTokens Amount of LP tokens minted
    function addLiquidity(
        address token,
        uint256 amount,
        uint32 targetChain
    ) external nonReentrant whenNotPaused returns (uint256 lpTokens) {
        require(amount > 0, "LiquidityManager: Invalid amount");
        require(amount <= MAX_SINGLE_DEPOSIT, "LiquidityManager: Amount too large");
        require(FluxSwapNetworkConfig.isChainSupported(targetChain), "LiquidityManager: Unsupported chain");
        require(!emergencyEvacuation, "LiquidityManager: Emergency evacuation active");

        // Transfer tokens from user
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Calculate LP tokens to mint
        PoolInfo storage pool = pools[targetChain][token];
        
        if (pool.totalLiquidity == 0) {
            // First liquidity provision
            lpTokens = amount;
            pool.active = true;
        } else {
            // Proportional to existing pool
            lpTokens = (amount * totalSupply()) / pool.totalLiquidity;
        }

        // Update pool state
        pool.usdcReserves += amount; // Assuming USDC for simplicity
        pool.totalLiquidity += amount;
        pool.utilizationRate = _calculateUtilizationRate(pool);

        // Mint LP tokens to user
        _mint(msg.sender, lpTokens);
        
        // Update user balances
        lpBalances[msg.sender][targetChain] += lpTokens;
        totalLPTokens[msg.sender] += lpTokens;

        emit LiquidityAdded(msg.sender, token, amount, targetChain, lpTokens);

        // Check if rebalancing is needed
        _checkRebalancingNeeds(targetChain, token);

        return lpTokens;
    }

    /// @notice Remove liquidity from pools
    /// @param lpTokens Amount of LP tokens to burn
    /// @param chainId Chain to remove liquidity from
    /// @return amount Amount of underlying tokens returned
    function removeLiquidity(
        uint256 lpTokens,
        uint32 chainId
    ) external nonReentrant returns (uint256 amount) {
        require(lpTokens > 0, "LiquidityManager: Invalid LP amount");
        require(lpBalances[msg.sender][chainId] >= lpTokens, "LiquidityManager: Insufficient LP balance");

        // Get USDC address for the chain
        address usdcToken = FluxSwapNetworkConfig.getUSDCAddress(chainId);
        PoolInfo storage pool = pools[chainId][usdcToken];
        
        require(pool.totalLiquidity > 0, "LiquidityManager: No liquidity in pool");

        // Calculate proportional amount
        amount = (lpTokens * pool.totalLiquidity) / totalSupply();
        
        // Ensure we don't go below minimum threshold
        require(
            pool.totalLiquidity - amount >= MIN_LIQUIDITY_THRESHOLD ||
            pool.totalLiquidity - amount == 0,
            "LiquidityManager: Would go below minimum threshold"
        );

        // Update pool state
        pool.totalLiquidity -= amount;
        pool.usdcReserves -= amount;
        pool.utilizationRate = _calculateUtilizationRate(pool);

        // Burn LP tokens
        _burn(msg.sender, lpTokens);
        
        // Update user balances
        lpBalances[msg.sender][chainId] -= lpTokens;
        totalLPTokens[msg.sender] -= lpTokens;

        // Transfer tokens back to user
        IERC20(usdcToken).safeTransfer(msg.sender, amount);

        emit LiquidityRemoved(msg.sender, lpTokens, chainId, amount);

        return amount;
    }

    /// @notice Execute liquidity rebalancing between chains
    /// @param sourceChain Source chain to move liquidity from
    /// @param destinationChain Destination chain to move liquidity to
    /// @param token Token to rebalance
    /// @param amount Amount to rebalance
    function rebalanceLiquidity(
        uint32 sourceChain,
        uint32 destinationChain,
        address token,
        uint256 amount
    ) external onlyRole(REBALANCER_ROLE) nonReentrant {
        require(sourceChain != destinationChain, "LiquidityManager: Same chain");
        require(amount > 0, "LiquidityManager: Invalid amount");
        
        bytes32 rebalanceKey = keccak256(abi.encodePacked(sourceChain, destinationChain));
        require(
            block.timestamp >= lastRebalanceTime[rebalanceKey] + FluxSwapConstants.REBALANCE_COOLDOWN,
            "LiquidityManager: Rebalancing too frequent"
        );

        PoolInfo storage sourcePool = pools[sourceChain][token];
        PoolInfo storage destPool = pools[destinationChain][token];
        
        require(sourcePool.totalLiquidity >= amount, "LiquidityManager: Insufficient source liquidity");
        require(sourcePool.active && destPool.active, "LiquidityManager: Inactive pools");

        // Update pool states
        sourcePool.totalLiquidity -= amount;
        sourcePool.usdcReserves -= amount;
        sourcePool.utilizationRate = _calculateUtilizationRate(sourcePool);
        sourcePool.lastRebalanceTime = block.timestamp;

        destPool.totalLiquidity += amount;
        destPool.usdcReserves += amount;
        destPool.utilizationRate = _calculateUtilizationRate(destPool);

        // Record rebalancing action
        rebalanceHistory.push(RebalanceAction({
            sourceChain: sourceChain,
            destinationChain: destinationChain,
            token: token,
            amount: amount,
            priority: _calculateRebalancePriority(sourcePool, destPool)
        }));

        // Update timestamp
        lastRebalanceTime[rebalanceKey] = block.timestamp;

        emit RebalanceExecuted(sourceChain, destinationChain, token, amount, msg.sender);
    }

    /// @notice Calculate optimal rebalancing actions
    /// @return actions Array of recommended rebalancing actions
    function calculateOptimalRebalancing() external view returns (RebalanceAction[] memory actions) {
        // This is a simplified implementation
        // In production, this would use complex algorithms to optimize across all chains
        
        uint32[] memory supportedChains = _getSupportedChains();
        address usdcToken = FluxSwapNetworkConfig.getUSDCAddress(block.chainid);
        
        uint256 actionCount = 0;
        RebalanceAction[] memory tempActions = new RebalanceAction[](10); // Max 10 actions
        
        for (uint256 i = 0; i < supportedChains.length; i++) {
            for (uint256 j = 0; j < supportedChains.length; j++) {
                if (i == j) continue;
                
                uint32 sourceChain = supportedChains[i];
                uint32 destChain = supportedChains[j];
                
                PoolInfo memory sourcePool = pools[sourceChain][usdcToken];
                PoolInfo memory destPool = pools[destChain][usdcToken];
                
                // Check if rebalancing is needed
                if (sourcePool.utilizationRate < FluxSwapConstants.OPTIMAL_UTILIZATION &&
                    destPool.utilizationRate > FluxSwapConstants.REBALANCE_THRESHOLD) {
                    
                    uint256 rebalanceAmount = _calculateRebalanceAmount(sourcePool, destPool);
                    
                    if (rebalanceAmount > 0 && actionCount < 10) {
                        tempActions[actionCount] = RebalanceAction({
                            sourceChain: sourceChain,
                            destinationChain: destChain,
                            token: usdcToken,
                            amount: rebalanceAmount,
                            priority: _calculateRebalancePriority(sourcePool, destPool)
                        });
                        actionCount++;
                    }
                }
            }
        }
        
        // Return only the filled actions
        actions = new RebalanceAction[](actionCount);
        for (uint256 k = 0; k < actionCount; k++) {
            actions[k] = tempActions[k];
        }
        
        return actions;
    }

    /// @notice Provide just-in-time liquidity
    /// @param token Token to provide JIT liquidity for
    /// @param amount Amount of liquidity to provide
    /// @param chainId Target chain
    function provideJITLiquidity(
        address token,
        uint256 amount,
        uint32 chainId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        require(jitProviders[msg.sender], "LiquidityManager: Not authorized JIT provider");
        require(amount > 0, "LiquidityManager: Invalid amount");

        // Transfer tokens
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Update pool (temporary increase)
        PoolInfo storage pool = pools[chainId][token];
        pool.totalLiquidity += amount;
        pool.usdcReserves += amount;

        emit JITLiquidityProvided(msg.sender, token, amount, chainId);
    }

    /// @notice Distribute fees to liquidity providers
    /// @param chainId Chain to distribute fees for
    /// @param token Token fees to distribute
    function distributeFees(uint32 chainId, address token) external onlyRole(OPERATOR_ROLE) {
        uint256 totalFees = collectedFees[chainId][token];
        require(totalFees > 0, "LiquidityManager: No fees to distribute");

        uint256 totalLP = totalSupply();
        require(totalLP > 0, "LiquidityManager: No LP tokens");

        // Reset collected fees
        collectedFees[chainId][token] = 0;

        // In a real implementation, we would iterate through all LP holders
        // For now, we just emit the event
        emit FeesDistributed(chainId, token, totalFees, totalLP);
    }

    /// @notice Add JIT liquidity provider
    /// @param provider Address to authorize as JIT provider
    function addJITProvider(address provider) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(provider != address(0), "LiquidityManager: Invalid provider");
        jitProviders[provider] = true;
    }

    /// @notice Remove JIT liquidity provider
    /// @param provider Address to remove JIT authorization
    function removeJITProvider(address provider) external onlyRole(DEFAULT_ADMIN_ROLE) {
        jitProviders[provider] = false;
    }

    /// @notice Trigger emergency evacuation
    function triggerEmergencyEvacuation() external onlyRole(EMERGENCY_ROLE) {
        emergencyEvacuation = true;
        _pause();
        emit EmergencyEvacuationTriggered(msg.sender, block.timestamp);
    }

    /// @notice Get pool information
    /// @param chainId Chain ID
    /// @param token Token address
    /// @return poolInfo Pool information
    function getPoolInfo(uint32 chainId, address token) external view returns (PoolInfo memory poolInfo) {
        return pools[chainId][token];
    }

    /// @notice Get user LP balance
    /// @param user User address
    /// @param chainId Chain ID
    /// @return balance LP token balance
    function getUserLPBalance(address user, uint32 chainId) external view returns (uint256 balance) {
        return lpBalances[user][chainId];
    }

    /// @notice Calculate utilization rate for a pool
    /// @param pool Pool information
    /// @return utilizationRate Utilization rate in basis points
    function _calculateUtilizationRate(PoolInfo memory pool) internal pure returns (uint256 utilizationRate) {
        if (pool.totalLiquidity == 0) return 0;
        
        // Simplified calculation - in production would consider active swaps
        uint256 availableLiquidity = pool.usdcReserves;
        uint256 utilizedLiquidity = pool.totalLiquidity - availableLiquidity;
        
        return (utilizedLiquidity * FluxSwapConstants.BASIS_POINTS) / pool.totalLiquidity;
    }

    /// @notice Check if rebalancing is needed
    /// @param chainId Chain to check
    /// @param token Token to check
    function _checkRebalancingNeeds(uint32 chainId, address token) internal {
        PoolInfo memory pool = pools[chainId][token];
        
        if (pool.utilizationRate > FluxSwapConstants.REBALANCE_THRESHOLD) {
            emit UtilizationAlert(chainId, token, pool.utilizationRate, FluxSwapConstants.REBALANCE_THRESHOLD);
        }
    }

    /// @notice Calculate rebalance amount between pools
    /// @param sourcePool Source pool information
    /// @param destPool Destination pool information
    /// @return amount Amount to rebalance
    function _calculateRebalanceAmount(
        PoolInfo memory sourcePool,
        PoolInfo memory destPool
    ) internal pure returns (uint256 amount) {
        // Simplified calculation - move 25% of excess liquidity
        if (sourcePool.utilizationRate < FluxSwapConstants.OPTIMAL_UTILIZATION) {
            uint256 excess = sourcePool.totalLiquidity * 
                (FluxSwapConstants.OPTIMAL_UTILIZATION - sourcePool.utilizationRate) / 
                FluxSwapConstants.BASIS_POINTS;
            return excess / 4; // 25% of excess
        }
        return 0;
    }

    /// @notice Calculate rebalancing priority
    /// @param sourcePool Source pool information
    /// @param destPool Destination pool information
    /// @return priority Priority score (higher = more urgent)
    function _calculateRebalancePriority(
        PoolInfo memory sourcePool,
        PoolInfo memory destPool
    ) internal pure returns (uint256 priority) {
        // Higher priority if destination has very high utilization
        if (destPool.utilizationRate > 9000) { // >90%
            return 100;
        } else if (destPool.utilizationRate > 8000) { // >80%
            return 75;
        } else if (destPool.utilizationRate > 7000) { // >70%
            return 50;
        }
        return 25;
    }

    /// @notice Get supported chains
    /// @return chains Array of supported chain IDs
    function _getSupportedChains() internal pure returns (uint32[] memory chains) {
        chains = new uint32[](4);
        chains[0] = FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN;
        chains[1] = FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_DOMAIN;
        chains[2] = FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_DOMAIN;
        chains[3] = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        return chains;
    }

    /// @notice Emergency pause
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Resume operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!emergencyEvacuation, "LiquidityManager: Emergency evacuation active");
        _unpause();
    }
}