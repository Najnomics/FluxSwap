// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title FluxSwap Types and Interfaces
/// @notice Common types and constants used across FluxSwap contracts
interface IFluxSwapTypes {
    /// @notice Swap status enumeration
    enum SwapStatus {
        Initiated,
        CCTPTransferring,
        DestinationProcessing,
        Completed,
        Failed
    }

    /// @notice Swap information structure
    struct SwapInfo {
        address user;
        address sourceToken;
        address targetToken;
        uint256 amount;
        uint32 destinationChain;
        SwapStatus status;
        uint256 timestamp;
        uint256 executionRate;
        uint64 cctpNonce;
    }

    /// @notice Route information for settlement optimization
    struct RouteInfo {
        uint32[] chainPath;
        address[] tokenPath;
        uint256[] amounts;
        uint256 totalGasCost;
        uint256 estimatedTime;
        uint256 slippage;
        uint256 score; // Higher = better route
    }

    /// @notice Transfer information for CCTP integration
    struct TransferInfo {
        address sender;
        uint256 amount;
        uint32 destinationDomain;
        bytes hookData;
        uint256 timestamp;
        bool completed;
    }

    /// @notice Risk parameters for security module
    struct RiskParams {
        uint256 dailyUserLimit;      // $100K default
        uint256 maxSingleTransaction; // $1M default  
        uint256 maxPriceDeviation;   // 10% default
        uint256 minLiquidityBuffer;  // 20% default
        uint256 emergencyThreshold;  // 50% default
        bool globalPauseEnabled;
    }

    /// @notice Network performance metrics
    struct NetworkMetrics {
        uint256 avgConfirmationTime;
        uint256 successRate; // Basis points
        uint256 congestionLevel;
        uint256 lastUpdate;
    }

    /// @notice Pool information for liquidity management
    struct PoolInfo {
        uint256 usdcReserves;
        uint256 eurcReserves;
        uint256 totalLiquidity;
        uint256 utilizationRate; // Basis points
        uint256 lastRebalanceTime;
        bool active;
    }

    /// @notice Rebalancing action structure
    struct RebalanceAction {
        uint32 sourceChain;
        uint32 destinationChain;
        address token;
        uint256 amount;
        uint256 priority; // Higher number = higher priority
    }

    /// @notice Rate history for TWAP calculations
    struct RateHistory {
        uint256 rate;
        uint256 timestamp;
    }
}

/// @title FluxSwap Constants
/// @notice Common constants used across FluxSwap contracts
library FluxSwapConstants {
    /// @notice Basis points denominator (100% = 10000)
    uint256 internal constant BASIS_POINTS = 10000;
    
    /// @notice Maximum slippage allowed (10%)
    uint256 internal constant MAX_SLIPPAGE = 1000;
    
    /// @notice TWAP calculation window (1 hour)
    uint256 internal constant TWAP_WINDOW = 3600;
    
    /// @notice Maximum price age for rate validation (5 minutes)
    uint256 internal constant MAX_PRICE_AGE = 300;
    
    /// @notice Rebalancing threshold (80% utilization)
    uint256 internal constant REBALANCE_THRESHOLD = 8000;
    
    /// @notice Optimal utilization target (60%)
    uint256 internal constant OPTIMAL_UTILIZATION = 6000;
    
    /// @notice Rebalancing cooldown period (1 hour)
    uint256 internal constant REBALANCE_COOLDOWN = 1 hours;
    
    /// @notice Default platform fee rate (0.08% = 8 basis points)
    uint256 internal constant DEFAULT_FEE_RATE = 8;
    
    /// @notice Hook expiry time (5 minutes)
    uint256 internal constant HOOK_EXPIRY = 300;
    
    /// @notice CCTP Fast Transfer timeout (60 seconds)
    uint256 internal constant CCTP_TIMEOUT = 60;

    // Token addresses (will be set per network)
    /// @notice USDC token address (to be configured per chain)
    address internal constant USDC_ADDRESS = 0xa0b86A33e6417c5e00Fb7FCE7daccFe14B4E8a9E; // Placeholder
    
    /// @notice EURC token address (to be configured per chain)  
    address internal constant EURC_ADDRESS = 0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c; // Placeholder
}