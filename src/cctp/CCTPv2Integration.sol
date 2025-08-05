// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../interfaces/ICCTPInterfaces.sol";
import "../interfaces/IFluxSwapTypes.sol";
import "../config/FluxSwapNetworkConfig.sol";

/// @title CCTPv2Integration
/// @notice Direct interface with Circle's Cross-Chain Transfer Protocol v2
/// @dev Manages CCTP v2 Fast Transfer operations and hooks
contract CCTPv2Integration is AccessControl, Pausable, ReentrancyGuard, IFluxSwapTypes {
    using SafeERC20 for IERC20;
    using FluxSwapNetworkConfig for uint256;

    // Role definitions
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant HOOK_EXECUTOR_ROLE = keccak256("HOOK_EXECUTOR_ROLE");

    /// @notice Circle CCTP contracts
    ITokenMessenger public immutable tokenMessenger;
    IMessageTransmitter public immutable messageTransmitter;

    /// @notice FluxSwap Manager contract (callback target)
    address public fluxSwapManager;

    /// @notice Transfer tracking: nonce => TransferInfo
    mapping(uint64 => TransferInfo) public transfers;

    /// @notice Nonce to swap ID mapping
    mapping(uint64 => bytes32) public nonceToSwapId;

    /// @notice Failed transfers awaiting refund
    mapping(bytes32 => bool) public failedTransfers;

    /// @notice Maximum time to wait for attestation (in seconds)
    uint256 public constant ATTESTATION_TIMEOUT = FluxSwapConstants.CCTP_TIMEOUT;

    /// @notice Retry attempts for failed attestations
    uint256 public constant MAX_RETRY_ATTEMPTS = 3;

    /// @notice Retry tracking: nonce => attempt count
    mapping(uint64 => uint256) public retryAttempts;

    // Events
    event FastTransferInitiated(
        uint64 indexed nonce,
        bytes32 indexed swapId,
        address indexed sender,
        uint256 amount,
        uint32 destinationDomain,
        bytes32 recipient
    );

    event FastTransferCompleted(
        uint64 indexed nonce,
        bytes32 indexed swapId,
        address indexed recipient,
        uint256 amount
    );

    event FastTransferFailed(
        uint64 indexed nonce,
        bytes32 indexed swapId,
        string reason
    );

    event HookActionExecuted(
        uint32 sourceDomain,
        bytes32 sender,
        bytes32 indexed swapId,
        address targetToken,
        uint256 finalAmount
    );

    event AttestationRetry(
        uint64 indexed nonce,
        uint256 attempt,
        string reason
    );

    event RefundProcessed(
        bytes32 indexed swapId,
        address indexed user,
        uint256 amount
    );

    /// @notice Constructor initializes CCTP contracts
    /// @param _admin Address to grant admin role
    /// @param _fluxSwapManager FluxSwap manager contract address
    constructor(address _admin, address _fluxSwapManager) {
        require(_admin != address(0), "CCTPv2Integration: Invalid admin");
        require(_fluxSwapManager != address(0), "CCTPv2Integration: Invalid manager");

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(MANAGER_ROLE, _fluxSwapManager);
        _grantRole(HOOK_EXECUTOR_ROLE, _admin);

        // Initialize CCTP contracts using network config
        tokenMessenger = ITokenMessenger(FluxSwapNetworkConfig.TOKEN_MESSENGER);
        messageTransmitter = IMessageTransmitter(FluxSwapNetworkConfig.MESSAGE_TRANSMITTER);
        
        fluxSwapManager = _fluxSwapManager;
    }

    /// @notice Initiate a CCTP v2 Fast Transfer
    /// @param amount Amount to transfer
    /// @param destinationDomain CCTP destination domain ID
    /// @param recipient Recipient address (as bytes32)
    /// @param hookData Data to pass to destination hook
    /// @return nonce CCTP transfer nonce
    function initiateFastTransfer(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 recipient,
        bytes calldata hookData
    ) external nonReentrant whenNotPaused onlyRole(MANAGER_ROLE) returns (uint64 nonce) {
        require(amount > 0, "CCTPv2Integration: Invalid amount");
        require(recipient != bytes32(0), "CCTPv2Integration: Invalid recipient");

        // Decode hook data to get swap ID
        (bytes32 swapId, , , , ) = abi.decode(hookData, (bytes32, address, address, uint256, uint256));

        // Get USDC token address for current chain
        address usdcToken = FluxSwapNetworkConfig.getUSDCAddress(block.chainid);
        
        // Transfer USDC from FluxSwapManager
        IERC20(usdcToken).safeTransferFrom(msg.sender, address(this), amount);
        
        // Approve TokenMessenger to spend USDC
        IERC20(usdcToken).approve(address(tokenMessenger), amount);

        // Burn and send via CCTP
        nonce = tokenMessenger.depositForBurnWithCaller(
            amount,
            destinationDomain,
            recipient,
            usdcToken,
            bytes32(uint256(uint160(address(this)))) // This contract as destination caller
        );

        // Store transfer information
        transfers[nonce] = TransferInfo({
            sender: msg.sender,
            amount: amount,
            destinationDomain: destinationDomain,
            hookData: hookData,
            timestamp: block.timestamp,
            completed: false
        });

        // Map nonce to swap ID
        nonceToSwapId[nonce] = swapId;

        emit FastTransferInitiated(nonce, swapId, msg.sender, amount, destinationDomain, recipient);

        return nonce;
    }

    /// @notice Receive and process CCTP message with attestation
    /// @param message CCTP message bytes
    /// @param attestation Circle attestation signature
    /// @return success Whether message was processed successfully
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external nonReentrant whenNotPaused returns (bool success) {
        try messageTransmitter.receiveMessage(message, attestation) returns (bool received) {
            if (received) {
                // Decode message to get transfer details
                // Note: Actual message parsing would depend on CCTP message format
                // This is a simplified version
                emit FastTransferCompleted(0, bytes32(0), address(0), 0);
                return true;
            }
        } catch Error(string memory reason) {
            emit FastTransferFailed(0, bytes32(0), reason);
            return false;
        }
        
        return false;
    }

    /// @notice Execute hook action on destination chain
    /// @param sourceDomain Source CCTP domain
    /// @param sender Original sender (as bytes32)
    /// @param messageBody Message payload
    function executeHookAction(
        uint32 sourceDomain,
        bytes32 sender,
        bytes calldata messageBody
    ) external onlyRole(HOOK_EXECUTOR_ROLE) nonReentrant {
        // Decode message body to extract swap details
        (
            bytes32 swapId,
            address targetToken,
            address recipient,
            uint256 expectedRate,
            uint256 maxSlippage
        ) = abi.decode(messageBody, (bytes32, address, address, uint256, uint256));

        require(swapId != bytes32(0), "CCTPv2Integration: Invalid swap ID");
        require(targetToken != address(0), "CCTPv2Integration: Invalid target token");
        require(recipient != address(0), "CCTPv2Integration: Invalid recipient");

        // Get USDC amount from original transfer
        // In a real implementation, this would come from the CCTP message
        uint256 usdcAmount = 1000e6; // Placeholder - should parse from message

        try this._executeFXConversion(targetToken, recipient, usdcAmount, expectedRate, maxSlippage) returns (
            uint256 finalAmount
        ) {
            // Notify FluxSwapManager of successful completion
            IFluxSwapManager(fluxSwapManager).handleSwapCompletion(swapId, finalAmount, 0);
            
            emit HookActionExecuted(sourceDomain, sender, swapId, targetToken, finalAmount);
        } catch Error(string memory reason) {
            // Mark as failed and initiate refund process
            failedTransfers[swapId] = true;
            IFluxSwapManager(fluxSwapManager).handleSwapFailure(swapId, reason);
            
            emit FastTransferFailed(0, swapId, reason);
        }
    }

    /// @notice Execute FX conversion on destination chain
    /// @dev This is a placeholder - actual implementation would integrate with DEX
    /// @param targetToken Target token to convert to
    /// @param recipient Final recipient
    /// @param usdcAmount USDC amount to convert
    /// @param expectedRate Expected conversion rate
    /// @param maxSlippage Maximum slippage tolerance
    /// @return finalAmount Final amount after conversion
    function _executeFXConversion(
        address targetToken,
        address recipient,
        uint256 usdcAmount,
        uint256 expectedRate,
        uint256 maxSlippage
    ) external returns (uint256 finalAmount) {
        require(msg.sender == address(this), "CCTPv2Integration: Internal function");
        
        // Placeholder implementation
        // In production, this would:
        // 1. Check available liquidity
        // 2. Execute swap on Uniswap v4 or other DEX
        // 3. Apply slippage protection
        // 4. Transfer final tokens to recipient
        
        // For now, simulate 1:1 conversion minus fees
        uint256 platformFee = (usdcAmount * 8) / 10000; // 0.08% fee
        finalAmount = usdcAmount - platformFee;
        
        // In real implementation: transfer targetToken to recipient
        // IERC20(targetToken).safeTransfer(recipient, finalAmount);
        
        return finalAmount;
    }

    /// @notice Process refund for failed swap
    /// @param swapId Swap identifier
    /// @param user User to refund
    /// @param amount Amount to refund
    function refundFailedSwap(
        bytes32 swapId,
        address user,
        uint256 amount
    ) external onlyRole(MANAGER_ROLE) nonReentrant {
        require(failedTransfers[swapId], "CCTPv2Integration: Not a failed transfer");
        require(user != address(0), "CCTPv2Integration: Invalid user");
        require(amount > 0, "CCTPv2Integration: Invalid amount");

        // Clear failed status
        failedTransfers[swapId] = false;

        // Get USDC token and transfer back to user
        address usdcToken = FluxSwapNetworkConfig.getUSDCAddress(block.chainid);
        IERC20(usdcToken).safeTransfer(user, amount);

        emit RefundProcessed(swapId, user, amount);
    }

    /// @notice Retry failed attestation
    /// @param nonce CCTP transfer nonce
    /// @param message CCTP message
    /// @param attestation Updated attestation
    function retryAttestation(
        uint64 nonce,
        bytes calldata message,
        bytes calldata attestation
    ) external onlyRole(HOOK_EXECUTOR_ROLE) {
        require(retryAttempts[nonce] < MAX_RETRY_ATTEMPTS, "CCTPv2Integration: Max retries exceeded");
        require(transfers[nonce].timestamp != 0, "CCTPv2Integration: Invalid nonce");
        require(!transfers[nonce].completed, "CCTPv2Integration: Already completed");

        retryAttempts[nonce]++;
        
        bool success = this.receiveMessage(message, attestation);
        
        emit AttestationRetry(nonce, retryAttempts[nonce], success ? "Success" : "Failed");
        
        if (success) {
            transfers[nonce].completed = true;
        } else if (retryAttempts[nonce] >= MAX_RETRY_ATTEMPTS) {
            // Mark as permanently failed
            bytes32 swapId = nonceToSwapId[nonce];
            failedTransfers[swapId] = true;
        }
    }

    /// @notice Get transfer information
    /// @param nonce CCTP transfer nonce
    /// @return transferInfo Transfer details
    function getTransferInfo(uint64 nonce) external view returns (TransferInfo memory transferInfo) {
        return transfers[nonce];
    }

    /// @notice Check if transfer has timed out
    /// @param nonce CCTP transfer nonce
    /// @return timedOut Whether transfer has exceeded timeout
    function isTransferTimedOut(uint64 nonce) external view returns (bool timedOut) {
        TransferInfo memory transfer = transfers[nonce];
        return transfer.timestamp != 0 && 
               !transfer.completed && 
               block.timestamp > transfer.timestamp + ATTESTATION_TIMEOUT;
    }

    /// @notice Set FluxSwap manager address
    /// @param _fluxSwapManager New manager address
    function setFluxSwapManager(address _fluxSwapManager) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_fluxSwapManager != address(0), "CCTPv2Integration: Invalid manager");
        
        // Revoke old manager role
        _revokeRole(MANAGER_ROLE, fluxSwapManager);
        
        // Grant role to new manager
        fluxSwapManager = _fluxSwapManager;
        _grantRole(MANAGER_ROLE, _fluxSwapManager);
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

/// @notice Interface for FluxSwapManager callbacks
interface IFluxSwapManager {
    function handleSwapCompletion(bytes32 swapId, uint256 finalAmount, uint256 totalFees) external;
    function handleSwapFailure(bytes32 swapId, string calldata reason) external;
}