// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title FluxSwap Network Configuration  
/// @notice Testnet configurations for CCTP v2 and supported networks
library FluxSwapNetworkConfig {
    
    /// @notice CCTP Domain IDs (testnet)
    uint32 internal constant ETHEREUM_SEPOLIA_DOMAIN = 0;
    uint32 internal constant OPTIMISM_SEPOLIA_DOMAIN = 2; 
    uint32 internal constant ARBITRUM_SEPOLIA_DOMAIN = 3;
    uint32 internal constant BASE_SEPOLIA_DOMAIN = 6;
    
    // Foundry Test Domain (mock)
    uint32 internal constant FOUNDRY_ANVIL_DOMAIN = 999;
    
    // Foundry Test Chain
    uint256 internal constant FOUNDRY_ANVIL_CHAIN_ID = 1;
    
    /// @notice Chain IDs (testnet)
    uint256 internal constant ETHEREUM_SEPOLIA_CHAIN_ID = 11155111;
    uint256 internal constant OPTIMISM_SEPOLIA_CHAIN_ID = 11155420;
    uint256 internal constant ARBITRUM_SEPOLIA_CHAIN_ID = 421614;
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant POLYGON_AMOY_CHAIN_ID = 80002;
    uint256 internal constant UNICHAIN_SEPOLIA_CHAIN_ID = 1301;
    
    /// @notice CCTP TokenMessenger addresses (same across all testnets)
    address internal constant TOKEN_MESSENGER = 0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5;
    
    /// @notice CCTP MessageTransmitter addresses (same across all testnets)
    address internal constant MESSAGE_TRANSMITTER = 0x2703483B1a5a7c577e8680de9Df8Be03c6f30e3c;
    
    /// @notice USDC token addresses on testnets
    address internal constant USDC_SEPOLIA = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    address internal constant USDC_ARBITRUM_SEPOLIA = 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d;
    address internal constant USDC_BASE_SEPOLIA = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;
    address internal constant USDC_OPTIMISM_SEPOLIA = 0x5fd84259d66Cd46123540766Be93DFE6D43130D7;
    
    /// @notice Circle Attestation Service API (testnet)
    string internal constant ATTESTATION_API_BASE = "https://iris-api-sandbox.circle.com";
    
    /// @notice Get CCTP domain ID for a given chain ID
    /// @param chainId The chain ID to look up
    /// @return domainId The corresponding CCTP domain ID
    function getCCTPDomain(uint256 chainId) internal pure returns (uint32 domainId) {
        if (chainId == FOUNDRY_ANVIL_CHAIN_ID) return FOUNDRY_ANVIL_DOMAIN;
        if (chainId == ETHEREUM_SEPOLIA_CHAIN_ID) return ETHEREUM_SEPOLIA_DOMAIN;
        if (chainId == OPTIMISM_SEPOLIA_CHAIN_ID) return OPTIMISM_SEPOLIA_DOMAIN;
        if (chainId == ARBITRUM_SEPOLIA_CHAIN_ID) return ARBITRUM_SEPOLIA_DOMAIN;
        if (chainId == BASE_SEPOLIA_CHAIN_ID) return BASE_SEPOLIA_DOMAIN;
        
        // Default to Foundry Anvil domain for testing
        return FOUNDRY_ANVIL_DOMAIN;
    }
    
    /// @notice Get USDC address for a given chain ID
    /// @param chainId The chain ID to look up
    /// @return usdcAddress The USDC token address on that chain
    function getUSDCAddress(uint256 chainId) internal pure returns (address usdcAddress) {
        if (chainId == ETHEREUM_SEPOLIA_CHAIN_ID) return USDC_SEPOLIA;
        if (chainId == OPTIMISM_SEPOLIA_CHAIN_ID) return USDC_OPTIMISM_SEPOLIA;
        if (chainId == ARBITRUM_SEPOLIA_CHAIN_ID) return USDC_ARBITRUM_SEPOLIA;
        if (chainId == BASE_SEPOLIA_CHAIN_ID) return USDC_BASE_SEPOLIA;
        
        // Default to Sepolia USDC for testing
        return USDC_SEPOLIA;
    }
    
    /// @notice Check if chain is supported for CCTP
    /// @param chainId The chain ID to check
    /// @return supported True if chain is supported
    function isChainSupported(uint256 chainId) internal pure returns (bool supported) {
        return chainId == FOUNDRY_ANVIL_CHAIN_ID ||
               chainId == ETHEREUM_SEPOLIA_CHAIN_ID ||
               chainId == OPTIMISM_SEPOLIA_CHAIN_ID ||
               chainId == ARBITRUM_SEPOLIA_CHAIN_ID ||
               chainId == BASE_SEPOLIA_CHAIN_ID;
    }
    
    /// @notice Get chain name for display purposes
    /// @param chainId The chain ID to look up
    /// @return name The human-readable chain name
    function getChainName(uint256 chainId) internal pure returns (string memory name) {
        if (chainId == ETHEREUM_SEPOLIA_CHAIN_ID) return "Ethereum Sepolia";
        if (chainId == OPTIMISM_SEPOLIA_CHAIN_ID) return "Optimism Sepolia";
        if (chainId == ARBITRUM_SEPOLIA_CHAIN_ID) return "Arbitrum Sepolia";
        if (chainId == BASE_SEPOLIA_CHAIN_ID) return "Base Sepolia";
        return "Unknown Chain";
    }
}