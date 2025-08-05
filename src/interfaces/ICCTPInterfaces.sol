// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title CCTP Interface Compatibility Layer
/// @notice Compatible interfaces for CCTP v2 contracts
/// @dev These interfaces are compatible with Solidity 0.8.26

/// @notice Interface for CCTP TokenMessenger
interface ITokenMessenger {
    /// @notice Deposits and burns tokens to be minted on destination domain
    /// @param amount Amount of tokens to burn
    /// @param destinationDomain Destination domain ID
    /// @param mintRecipient Recipient address on destination domain (as bytes32)
    /// @param burnToken Token address to burn
    /// @return nonce Unique nonce for the transfer
    function depositForBurn(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient,
        address burnToken
    ) external returns (uint64 nonce);

    /// @notice Deposits and burns tokens with caller specification
    /// @param amount Amount of tokens to burn
    /// @param destinationDomain Destination domain ID
    /// @param mintRecipient Recipient address on destination domain (as bytes32)
    /// @param burnToken Token address to burn
    /// @param destinationCaller Authorized caller on destination domain (as bytes32)
    /// @return nonce Unique nonce for the transfer
    function depositForBurnWithCaller(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient,
        address burnToken,
        bytes32 destinationCaller
    ) external returns (uint64 nonce);

    /// @notice Get the local message transmitter
    /// @return messageTransmitter Address of the local message transmitter
    function localMessageTransmitter() external view returns (address messageTransmitter);
}

/// @notice Interface for CCTP v2 TokenMessenger with hooks support
interface ITokenMessengerV2 {
    /// @notice Deposits and burns tokens with hook data
    /// @param amount Amount of tokens to burn
    /// @param destinationDomain Destination domain ID
    /// @param mintRecipient Recipient address on destination domain (as bytes32)
    /// @param burnToken Token address to burn
    /// @param destinationCaller Authorized caller on destination domain (as bytes32)
    /// @param maxFee Maximum fee to pay on destination domain
    /// @param minFinalityThreshold Minimum finality threshold
    /// @param hookData Hook data for destination execution
    function depositForBurnWithHook(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient,
        address burnToken,
        bytes32 destinationCaller,
        uint256 maxFee,
        uint32 minFinalityThreshold,
        bytes calldata hookData
    ) external;

    /// @notice Handle finalized message reception
    /// @param remoteDomain Source domain
    /// @param sender Message sender (as bytes32)
    /// @param finalityThreshold Finality threshold used
    /// @param messageBody Message body bytes
    /// @return success Whether handling was successful
    function handleReceiveFinalizedMessage(
        uint32 remoteDomain,
        bytes32 sender,
        uint32 finalityThreshold,
        bytes calldata messageBody
    ) external returns (bool success);

    /// @notice Handle unfinalized message reception
    /// @param remoteDomain Source domain
    /// @param sender Message sender (as bytes32)
    /// @param finalityThresholdExecuted Finality threshold executed
    /// @param messageBody Message body bytes
    /// @return success Whether handling was successful
    function handleReceiveUnfinalizedMessage(
        uint32 remoteDomain,
        bytes32 sender,
        uint32 finalityThresholdExecuted,
        bytes calldata messageBody
    ) external returns (bool success);
}

/// @notice Interface for CCTP MessageTransmitter
interface IMessageTransmitter {
    /// @notice Send a message to a destination domain
    /// @param destinationDomain Destination domain ID
    /// @param recipient Recipient address on destination domain (as bytes32)
    /// @param messageBody Message body to send
    /// @return nonce Unique nonce for the message
    function sendMessage(
        uint32 destinationDomain,
        bytes32 recipient,
        bytes calldata messageBody
    ) external returns (uint64 nonce);

    /// @notice Send a message with specific caller
    /// @param destinationDomain Destination domain ID
    /// @param recipient Recipient address on destination domain (as bytes32)
    /// @param destinationCaller Authorized caller on destination domain (as bytes32)
    /// @param messageBody Message body to send
    /// @return nonce Unique nonce for the message
    function sendMessageWithCaller(
        uint32 destinationDomain,
        bytes32 recipient,
        bytes32 destinationCaller,
        bytes calldata messageBody
    ) external returns (uint64 nonce);

    /// @notice Receive and process a message
    /// @param message Message bytes
    /// @param attestation Attestation signature
    /// @return success Whether message was processed successfully
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external returns (bool success);

    /// @notice Replace a message
    /// @param originalMessage Original message bytes
    /// @param originalAttestation Original attestation
    /// @param newMessageBody New message body
    /// @param newDestinationCaller New destination caller
    function replaceMessage(
        bytes calldata originalMessage,
        bytes calldata originalAttestation,
        bytes calldata newMessageBody,
        bytes32 newDestinationCaller
    ) external;
}

/// @notice Interface for CCTP v2 MessageTransmitter with Fast Transfer support
interface IMessageTransmitterV2 {
    /// @notice Send message with finality threshold
    /// @param destinationDomain Destination domain ID
    /// @param recipient Recipient address (as bytes32)
    /// @param destinationCaller Authorized caller (as bytes32)
    /// @param minFinalityThreshold Minimum finality threshold
    /// @param messageBody Message body bytes
    /// @return nonce Message nonce
    function sendMessage(
        uint32 destinationDomain,
        bytes32 recipient,
        bytes32 destinationCaller,
        uint32 minFinalityThreshold,
        bytes calldata messageBody
    ) external returns (uint64 nonce);

    /// @notice Receive finalized message
    /// @param message Message bytes
    /// @param attestation Attestation signature
    /// @return success Whether processing was successful
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external returns (bool success);
}

/// @notice Interface for CCTP TokenMinter
interface ITokenMinter {
    /// @notice Mint tokens on local domain
    /// @param remoteDomain Source domain where tokens were burned
    /// @param burnToken Token that was burned (as bytes32)
    /// @param to Recipient address
    /// @param amount Amount to mint
    /// @return mintToken Address of minted token
    function mint(
        uint32 remoteDomain,
        bytes32 burnToken,
        address to,
        uint256 amount
    ) external returns (address mintToken);

    /// @notice Burn tokens on local domain
    /// @param burnToken Token to burn
    /// @param amount Amount to burn
    function burn(address burnToken, uint256 amount) external;
}

/// @notice Interface for CCTP v2 TokenMinter
interface ITokenMinterV2 {
    /// @notice Mint tokens with fee handling
    /// @param remoteDomain Source domain
    /// @param burnToken Burned token (as bytes32)
    /// @param to Recipient address
    /// @param amount Amount to mint (after fees)
    /// @param fee Fee amount to mint to fee recipient
    /// @return mintToken Address of minted token
    function mint(
        uint32 remoteDomain,
        bytes32 burnToken,
        address to,
        uint256 amount,
        uint256 fee
    ) external returns (address mintToken);

    /// @notice Burn tokens
    /// @param burnToken Token to burn
    /// @param amount Amount to burn
    function burn(address burnToken, uint256 amount) external;
}

/// @notice Interface for message handling
interface IMessageHandler {
    /// @notice Handle received message
    /// @param remoteDomain Source domain
    /// @param sender Message sender (as bytes32)
    /// @param messageBody Message body bytes
    /// @return success Whether handling was successful
    function handleReceiveMessage(
        uint32 remoteDomain,
        bytes32 sender,
        bytes calldata messageBody
    ) external returns (bool success);
}

/// @notice Interface for v2 message handling with finality support
interface IMessageHandlerV2 {
    /// @notice Handle finalized message
    /// @param remoteDomain Source domain
    /// @param sender Message sender (as bytes32)
    /// @param finalityThreshold Finality threshold
    /// @param messageBody Message body bytes
    /// @return success Whether handling was successful
    function handleReceiveFinalizedMessage(
        uint32 remoteDomain,
        bytes32 sender,
        uint32 finalityThreshold,
        bytes calldata messageBody
    ) external returns (bool success);

    /// @notice Handle unfinalized message
    /// @param remoteDomain Source domain
    /// @param sender Message sender (as bytes32)
    /// @param finalityThresholdExecuted Executed finality threshold
    /// @param messageBody Message body bytes
    /// @return success Whether handling was successful
    function handleReceiveUnfinalizedMessage(
        uint32 remoteDomain,
        bytes32 sender,
        uint32 finalityThresholdExecuted,
        bytes calldata messageBody
    ) external returns (bool success);
}