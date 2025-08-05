// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../src/FluxSwapMainHook.sol";
import "../src/core/FluxSwapManager.sol";
import "../src/security/SecurityModule.sol";
import "../src/cctp/CCTPv2Integration.sol";
import "../src/oracles/FXRateOracle.sol";
import "../src/liquidity/LiquidityManager.sol";
import "../src/settlement/SettlementEngine.sol";
import "../src/config/FluxSwapNetworkConfig.sol";
import "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import "@uniswap/v4-core/src/libraries/Hooks.sol";

/// @title FluxSwap Deployment Script
/// @notice Deploys the complete FluxSwap ecosystem
contract Deploy is Script {
    
    // Deployment addresses
    FluxSwapMainHook public hook;
    FluxSwapManager public manager;
    SecurityModule public security;
    FXRateOracle public oracle;
    LiquidityManager public liquidity;
    SettlementEngine public settlement;
    CCTPv2Integration public cctp;
    
    // Configuration
    address public admin;
    address public feeCollector;
    address public hookFeeCollector;
    address public poolManager;
    
    function run() external {
        // Get configuration from environment or use defaults
        admin = vm.envOr("ADMIN_ADDRESS", address(0x1001));
        feeCollector = vm.envOr("FEE_COLLECTOR", address(0x1002));
        hookFeeCollector = vm.envOr("HOOK_FEE_COLLECTOR", address(0x1003));
        poolManager = vm.envOr("POOL_MANAGER", address(0x4000));
        
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("🚀 Starting FluxSwap Deployment...");
        console.log("Admin:", admin);
        console.log("Fee Collector:", feeCollector);
        console.log("Hook Fee Collector:", hookFeeCollector);
        console.log("Pool Manager:", poolManager);
        
        // Deploy core contracts
        deployCore();
        
        // Deploy main hook
        deployHook();
        
        // Configure integrations
        configureIntegrations();
        
        // Set initial parameters
        setInitialParameters();
        
        // Verify deployment
        verifyDeployment();
        
        vm.stopBroadcast();
        
        console.log("✅ FluxSwap Deployment Complete!");
        logDeploymentSummary();
    }
    
    function deployCore() internal {
        console.log("📦 Deploying Core Contracts...");
        
        // Deploy security module
        security = new SecurityModule(admin);
        console.log("SecurityModule deployed at:", address(security));
        
        // Deploy FX rate oracle
        oracle = new FXRateOracle(admin);
        console.log("FXRateOracle deployed at:", address(oracle));
        
        // Deploy liquidity manager
        liquidity = new LiquidityManager(admin, "FluxSwap LP", "FLUX-LP");
        console.log("LiquidityManager deployed at:", address(liquidity));
        
        // Deploy settlement engine
        settlement = new SettlementEngine(admin);
        console.log("SettlementEngine deployed at:", address(settlement));
        
        // Deploy CCTP integration
        cctp = new CCTPv2Integration(admin, admin);
        console.log("CCTPv2Integration deployed at:", address(cctp));
        
        // Deploy main manager
        manager = new FluxSwapManager(
            admin,
            address(security),
            address(cctp),
            address(oracle),
            address(liquidity),
            address(settlement),
            feeCollector
        );
        console.log("FluxSwapManager deployed at:", address(manager));
    }
    
    function deployHook() internal {
        console.log("🎣 Deploying FluxSwap Hook...");
        
        // Calculate proper hook address with flags
        uint160 flags = uint160(
            Hooks.BEFORE_SWAP_FLAG |
            Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
        );
        
        // For deterministic deployment, we'll use CREATE2
        bytes32 salt = keccak256(abi.encode("FluxSwapMainHook", block.chainid));
        
        hook = new FluxSwapMainHook{salt: salt}(
            IPoolManager(poolManager),
            address(manager),
            address(oracle),
            admin,
            hookFeeCollector
        );
        
        console.log("FluxSwapMainHook deployed at:", address(hook));
        
        // Verify hook address has correct flags
        uint160 hookFlags = uint160(address(hook)) & uint160(0x3FF << 144);
        require(hookFlags & uint160(Hooks.BEFORE_SWAP_FLAG) != 0, "Hook missing beforeSwap flag");
        require(hookFlags & uint160(Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG) != 0, "Hook missing beforeSwapReturnDelta flag");
    }
    
    function configureIntegrations() internal {
        console.log("🔗 Configuring Integrations...");
        
        // Set CCTP manager
        cctp.setFluxSwapManager(address(manager));
        console.log("CCTP integration configured");
        
        // Grant necessary roles
        security.grantRole(security.EMERGENCY_ROLE(), admin);
        hook.grantRole(hook.MANAGER_ROLE(), address(manager));
        hook.grantRole(hook.HOOK_ADMIN_ROLE(), admin);
        hook.grantRole(hook.EMERGENCY_ROLE(), admin);
        console.log("Roles configured");
    }
    
    function setInitialParameters() internal {
        console.log("⚙️ Setting Initial Parameters...");
        
        // Set initial FX rates
        oracle.updateRate(
            FluxSwapNetworkConfig.getUSDCAddress(block.chainid),
            FluxSwapConstants.EURC_ADDRESS,
            920000000000000000, // 0.92 EUR/USD
            "Initial deployment rate"
        );
        
        oracle.updateRate(
            FluxSwapConstants.EURC_ADDRESS,
            FluxSwapNetworkConfig.getUSDCAddress(block.chainid),
            1086956521739130435, // ~1.087 USD/EUR
            "Initial deployment rate reverse"
        );
        console.log("Initial FX rates set");
        
        // Update system health
        security.updateSystemHealth();
        console.log("System health initialized");
        
        // Set default hook fee rate (0.05%)
        hook.updateHookFeeRate(5);
        console.log("Hook fee rate set to 0.05%");
    }
    
    function verifyDeployment() internal view {
        console.log("🔍 Verifying Deployment...");
        
        // Verify all contracts are deployed
        require(address(security) != address(0), "SecurityModule not deployed");
        require(address(oracle) != address(0), "FXRateOracle not deployed");
        require(address(liquidity) != address(0), "LiquidityManager not deployed");
        require(address(settlement) != address(0), "SettlementEngine not deployed");
        require(address(cctp) != address(0), "CCTPv2Integration not deployed");
        require(address(manager) != address(0), "FluxSwapManager not deployed");
        require(address(hook) != address(0), "FluxSwapMainHook not deployed");
        
        // Verify integrations
        require(address(cctp.fluxSwapManager()) == address(manager), "CCTP integration not configured");
        require(address(hook.fluxSwapManager()) == address(manager), "Hook-Manager integration not configured");
        require(address(hook.fxRateOracle()) == address(oracle), "Hook-Oracle integration not configured");
        
        // Verify permissions
        require(security.hasRole(security.DEFAULT_ADMIN_ROLE(), admin), "Security admin role not set");
        require(hook.hasRole(hook.DEFAULT_ADMIN_ROLE(), admin), "Hook admin role not set");
        require(hook.hasRole(hook.MANAGER_ROLE(), address(manager)), "Hook manager role not set");
        
        // Verify system health
        require(security.isSystemHealthy(), "System not healthy");
        
        console.log("✅ Deployment verification passed");
    }
    
    function logDeploymentSummary() internal view {
        console.log("\n📋 DEPLOYMENT SUMMARY");
        console.log("====================");
        console.log("Network:", getNetworkName());
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", msg.sender);
        console.log("Admin:", admin);
        console.log("");
        console.log("Contract Addresses:");
        console.log("------------------");
        console.log("SecurityModule:      ", address(security));
        console.log("FXRateOracle:        ", address(oracle));
        console.log("LiquidityManager:    ", address(liquidity));
        console.log("SettlementEngine:    ", address(settlement));
        console.log("CCTPv2Integration:   ", address(cctp));
        console.log("FluxSwapManager:     ", address(manager));
        console.log("FluxSwapMainHook:    ", address(hook));
        console.log("");
        console.log("Configuration:");
        console.log("-------------");
        console.log("Pool Manager:        ", poolManager);
        console.log("Fee Collector:       ", feeCollector);
        console.log("Hook Fee Collector:  ", hookFeeCollector);
        console.log("Hook Fee Rate:       ", hook.hookFeeRate(), "bp (", hook.hookFeeRate() / 100, ".", hook.hookFeeRate() % 100, "%)");
        console.log("");
        console.log("CCTP Configuration:");
        console.log("------------------");
        console.log("Domain ID:           ", FluxSwapNetworkConfig.getCCTPDomain(block.chainid));
        console.log("USDC Address:        ", FluxSwapNetworkConfig.getUSDCAddress(block.chainid));
        console.log("Token Messenger:     ", FluxSwapNetworkConfig.TOKEN_MESSENGER);
        console.log("Message Transmitter: ", FluxSwapNetworkConfig.MESSAGE_TRANSMITTER);
        console.log("");
        console.log("🎉 FluxSwap is ready for cross-chain FX swaps!");
    }
    
    function getNetworkName() internal view returns (string memory) {
        if (block.chainid == 1) return "Ethereum Mainnet";
        if (block.chainid == 11155111) return "Ethereum Sepolia";
        if (block.chainid == 10) return "Optimism";
        if (block.chainid == 11155420) return "Optimism Sepolia";
        if (block.chainid == 42161) return "Arbitrum One";
        if (block.chainid == 421614) return "Arbitrum Sepolia";
        if (block.chainid == 8453) return "Base";
        if (block.chainid == 84532) return "Base Sepolia";
        if (block.chainid == 31337) return "Anvil Local";
        return "Unknown Network";
    }
}