// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../interfaces/IFluxSwapTypes.sol";
import "../security/SecurityModule.sol";
import "../cctp/CCTPv2Integration.sol";
import "../oracles/FXRateOracle.sol";
import "../liquidity/LiquidityManager.sol";
import "../settlement/SettlementEngine.sol";
import "../config/FluxSwapNetworkConfig.sol";

/// @title FluxSwapManager
/// @notice Main orchestrator contract and entry point for all cross-chain FX operations
/// @dev Coordinates between all other contracts in the system
contract FluxSwapManager is AccessControl, Pausable, ReentrancyGuard, IFluxSwapTypes {
    using SafeERC20 for IERC20;
    using FluxSwapNetworkConfig for uint256;

    // Role definitions
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");

    /// @notice Contract instances
    SecurityModule public immutable securityModule;
    CCTPv2Integration public immutable cctpIntegration;
    FXRateOracle public immutable fxRateOracle;
    LiquidityManager public immutable liquidityManager;
    SettlementEngine public immutable settlementEngine;

    /// @notice Current fee rate (basis points)
    uint256 public feeRate = FluxSwapConstants.DEFAULT_FEE_RATE;

    /// @notice Protocol fee collector address
    address public feeCollector;

    /// @notice Swap information mapping: swapId => SwapInfo
    mapping(bytes32 => SwapInfo) public swaps;

    /// @notice User swap history: user => swapId[]
    mapping(address => bytes32[]) public userSwapHistory;

    /// @notice Total volume metrics
    uint256 public totalVolumeUSD;
    uint256 public totalSwapsCount;

    /// @notice Supported trading pairs: tokenA => tokenB => supported
    mapping(address => mapping(address => bool)) public supportedPairs;

    // Events
    event CrossChainSwapInitiated(
        bytes32 indexed swapId,
        address indexed user,
        address sourceToken,
        address targetToken,
        uint256 amount,
        uint32 destinationDomain,
        address recipient
    );

    event CrossChainSwapCompleted(
        bytes32 indexed swapId,
        address indexed user,
        uint256 finalAmount,
        uint256 executionRate,
        uint256 totalFees
    );

    event CrossChainSwapFailed(
        bytes32 indexed swapId,
        address indexed user,
        string reason
    );

    event FeeRateUpdated(uint256 oldRate, uint256 newRate, address indexed admin);
    event SupportedPairUpdated(address tokenA, address tokenB, bool supported);
    event FeeCollectorUpdated(address oldCollector, address newCollector);

    /// @notice Constructor initializes all contract dependencies
    /// @param _admin Address to grant admin role
    /// @param _securityModule Security module contract address
    /// @param _cctpIntegration CCTP integration contract address
    /// @param _fxRateOracle FX rate oracle contract address
    /// @param _liquidityManager Liquidity manager contract address
    /// @param _settlementEngine Settlement engine contract address
    /// @param _feeCollector Fee collector address
    constructor(
        address _admin,
        address _securityModule,
        address _cctpIntegration,
        address _fxRateOracle,
        address _liquidityManager,
        address _settlementEngine,
        address _feeCollector
    ) {
        require(_admin != address(0), "FluxSwapManager: Invalid admin address");
        require(_securityModule != address(0), "FluxSwapManager: Invalid security module");
        require(_cctpIntegration != address(0), "FluxSwapManager: Invalid CCTP integration");
        require(_fxRateOracle != address(0), "FluxSwapManager: Invalid FX oracle");
        require(_liquidityManager != address(0), "FluxSwapManager: Invalid liquidity manager");
        require(_settlementEngine != address(0), "FluxSwapManager: Invalid settlement engine");
        require(_feeCollector != address(0), "FluxSwapManager: Invalid fee collector");

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(FEE_MANAGER_ROLE, _admin);

        securityModule = SecurityModule(_securityModule);
        cctpIntegration = CCTPv2Integration(_cctpIntegration);
        fxRateOracle = FXRateOracle(_fxRateOracle);
        liquidityManager = LiquidityManager(_liquidityManager);
        settlementEngine = SettlementEngine(_settlementEngine);
        feeCollector = _feeCollector;

        // Initialize default supported pairs (USDC <-> EURC)
        _setSupportedPairInternal(
            FluxSwapNetworkConfig.getUSDCAddress(block.chainid),
            FluxSwapConstants.EURC_ADDRESS,
            true
        );
    }

    /// @notice Initiate a cross-chain FX swap
    /// @param sourceToken Source token address (e.g., USDC)
    /// @param targetToken Target token address (e.g., EURC)
    /// @param amount Amount to swap
    /// @param destinationDomain CCTP destination domain ID
    /// @param recipient Recipient address on destination chain
    /// @param maxSlippage Maximum acceptable slippage (basis points)
    /// @return swapId Unique swap identifier
    function initiateCrossChainFXSwap(
        address sourceToken,
        address targetToken,
        uint256 amount,
        uint32 destinationDomain,
        address recipient,
        uint256 maxSlippage
    ) external nonReentrant whenNotPaused returns (bytes32 swapId) {
        require(amount > 0, "FluxSwapManager: Invalid amount");
        require(recipient != address(0), "FluxSwapManager: Invalid recipient");
        require(maxSlippage <= FluxSwapConstants.MAX_SLIPPAGE, "FluxSwapManager: Slippage too high");
        require(supportedPairs[sourceToken][targetToken], "FluxSwapManager: Unsupported pair");

        // Security checks
        require(
            securityModule.checkTransactionLimits(msg.sender, amount, 3600),
            "FluxSwapManager: Transaction exceeds limits"
        );

        // Validate FX rate
        (uint256 currentRate, uint256 timestamp) = fxRateOracle.getLatestRate(sourceToken, targetToken);
        require(
            fxRateOracle.validateRateWithSlippage(sourceToken, targetToken, currentRate, maxSlippage),
            "FluxSwapManager: Rate validation failed"
        );

        // Generate unique swap ID
        swapId = keccak256(abi.encodePacked(
            msg.sender,
            sourceToken,
            targetToken,
            amount,
            destinationDomain,
            block.timestamp,
            block.number
        ));

        // Transfer source tokens from user
        IERC20(sourceToken).safeTransferFrom(msg.sender, address(this), amount);

        // Calculate optimal route
        RouteInfo memory optimalRoute = settlementEngine.calculateOptimalRoute(
            sourceToken,
            targetToken,
            amount,
            _getSupportedDomains()
        );

        // Create swap record
        swaps[swapId] = SwapInfo({
            user: msg.sender,
            sourceToken: sourceToken,
            targetToken: targetToken,
            amount: amount,
            destinationChain: destinationDomain,
            status: SwapStatus.Initiated,
            timestamp: block.timestamp,
            executionRate: currentRate,
            cctpNonce: 0
        });

        // Add to user history
        userSwapHistory[msg.sender].push(swapId);

        // Approve CCTP integration to spend tokens
        IERC20(sourceToken).approve(address(cctpIntegration), amount);

        // Initiate fast transfer with hooks
        bytes memory hookData = abi.encode(swapId, targetToken, recipient, currentRate, maxSlippage);
        
        uint64 cctpNonce = cctpIntegration.initiateFastTransfer(
            amount,
            destinationDomain,
            bytes32(uint256(uint160(recipient))),
            hookData
        );

        // Update swap with CCTP nonce
        swaps[swapId].cctpNonce = cctpNonce;
        swaps[swapId].status = SwapStatus.CCTPTransferring;

        // Record transaction for security tracking
        securityModule.recordTransaction(msg.sender, amount);

        emit CrossChainSwapInitiated(
            swapId,
            msg.sender,
            sourceToken,
            targetToken,
            amount,
            destinationDomain,
            recipient
        );

        return swapId;
    }

    /// @notice Get swap status and details
    /// @param swapId Swap identifier
    /// @return swapInfo Complete swap information
    function getSwapStatus(bytes32 swapId) external view returns (SwapInfo memory swapInfo) {
        return swaps[swapId];
    }

    /// @notice Get user swap history
    /// @param user User address
    /// @return swapIds Array of swap IDs
    function getUserSwapHistory(address user) external view returns (bytes32[] memory swapIds) {
        return userSwapHistory[user];
    }

    /// @notice Handle completed swap callback from CCTP integration
    /// @dev Only callable by CCTP integration contract
    /// @param swapId Swap identifier
    /// @param finalAmount Final amount received
    /// @param totalFees Total fees paid
    function handleSwapCompletion(
        bytes32 swapId,
        uint256 finalAmount,
        uint256 totalFees
    ) external {
        require(msg.sender == address(cctpIntegration), "FluxSwapManager: Unauthorized callback");
        require(swaps[swapId].status == SwapStatus.CCTPTransferring, "FluxSwapManager: Invalid status");

        SwapInfo storage swap = swaps[swapId];
        swap.status = SwapStatus.Completed;

        // Update metrics
        totalVolumeUSD += swap.amount;
        totalSwapsCount++;

        emit CrossChainSwapCompleted(swapId, swap.user, finalAmount, swap.executionRate, totalFees);
    }

    /// @notice Handle failed swap callback from CCTP integration
    /// @dev Only callable by CCTP integration contract
    /// @param swapId Swap identifier
    /// @param reason Failure reason
    function handleSwapFailure(bytes32 swapId, string calldata reason) external {
        require(msg.sender == address(cctpIntegration), "FluxSwapManager: Unauthorized callback");
        require(swaps[swapId].status != SwapStatus.Completed, "FluxSwapManager: Already completed");

        SwapInfo storage swap = swaps[swapId];
        swap.status = SwapStatus.Failed;

        // Refund user (tokens are held by CCTP integration)
        cctpIntegration.refundFailedSwap(swapId, swap.user, swap.amount);

        emit CrossChainSwapFailed(swapId, swap.user, reason);
    }

    /// @notice Update fee rate
    /// @param newFeeRate New fee rate in basis points
    function updateFeeStructure(uint256 newFeeRate) external onlyRole(FEE_MANAGER_ROLE) {
        require(newFeeRate <= 100, "FluxSwapManager: Fee rate too high"); // Max 1%
        
        uint256 oldRate = feeRate;
        feeRate = newFeeRate;
        
        emit FeeRateUpdated(oldRate, newFeeRate, msg.sender);
    }

    /// @notice Update fee collector address
    /// @param newFeeCollector New fee collector address
    function updateFeeCollector(address newFeeCollector) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newFeeCollector != address(0), "FluxSwapManager: Invalid fee collector");
        
        address oldCollector = feeCollector;
        feeCollector = newFeeCollector;
        
        emit FeeCollectorUpdated(oldCollector, newFeeCollector);
    }

    /// @notice Set supported trading pair
    /// @param tokenA First token address
    /// @param tokenB Second token address
    /// @param supported Whether pair is supported
    function setSupportedPair(
        address tokenA,
        address tokenB,
        bool supported
    ) external onlyRole(OPERATOR_ROLE) {
        _setSupportedPairInternal(tokenA, tokenB, supported);
    }

    /// @notice Emergency pause
    /// @dev Triggers security module emergency pause
    function emergencyPause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        securityModule.triggerEmergencyPause("FluxSwapManager emergency pause");
        _pause();
    }

    /// @notice Resume operations
    /// @dev Can only resume if security module allows
    function resumeOperations() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(securityModule.isSystemHealthy(), "FluxSwapManager: System not healthy");
        _unpause();
    }

    /// @notice Get platform statistics
    /// @return totalVolume Total volume in USD
    /// @return totalSwaps Total number of swaps
    /// @return currentFeeRate Current fee rate in basis points
    /// @return currentFeeCollector Current fee collector address
    function getPlatformStats() external view returns (
        uint256 totalVolume,
        uint256 totalSwaps,
        uint256 currentFeeRate,
        address currentFeeCollector
    ) {
        return (totalVolumeUSD, totalSwapsCount, feeRate, feeCollector);
    }

    /// @notice Internal function to set supported pairs
    /// @param tokenA First token address
    /// @param tokenB Second token address
    /// @param supported Whether pair is supported
    function _setSupportedPairInternal(address tokenA, address tokenB, bool supported) internal {
        require(tokenA != address(0) && tokenB != address(0), "FluxSwapManager: Invalid token addresses");
        
        supportedPairs[tokenA][tokenB] = supported;
        supportedPairs[tokenB][tokenA] = supported; // Bidirectional support
        
        emit SupportedPairUpdated(tokenA, tokenB, supported);
    }

    /// @notice Get supported CCTP domains
    /// @return domains Array of supported domain IDs
    function _getSupportedDomains() internal pure returns (uint32[] memory domains) {
        domains = new uint32[](4);
        domains[0] = FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN;
        domains[1] = FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_DOMAIN;
        domains[2] = FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_DOMAIN;
        domains[3] = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        return domains;
    }
}