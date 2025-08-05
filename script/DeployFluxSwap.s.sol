// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import "../src/core/FluxSwapManager.sol";
import "../src/security/SecurityModule.sol";
import "../src/cctp/CCTPv2Integration.sol";
import "../src/oracles/FXRateOracle.sol";
import "../src/liquidity/LiquidityManager.sol";
import "../src/settlement/SettlementEngine.sol";
import "../src/FluxSwapMainHook.sol";

/// @title FluxSwap Deployment Script
/// @notice Deploys all FluxSwap contracts in the correct order
contract DeployFluxSwap is Script {
    
    // Deployment addresses
    address public securityModule;
    address public fxRateOracle;
    address public liquidityManager;
    address public settlementEngine;
    address public cctpIntegration;
    address public fluxSwapManager;
    address public fluxSwapHook;
    
    // Configuration
    address public constant ADMIN = 0x1000000000000000000000000000000000000001;
    address public constant FEE_COLLECTOR = 0x2000000000000000000000000000000000000002;
    address public constant HOOK_FEE_COLLECTOR = 0x3000000000000000000000000000000000000003;
    
    // Mock Pool Manager for testing (replace with actual in production)
    address public constant MOCK_POOL_MANAGER = 0x4000000000000000000000000000000000000004;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("Deploying FluxSwap contracts to testnet...");
        
        // 1. Deploy SecurityModule
        console.log("1. Deploying SecurityModule...");
        securityModule = address(new SecurityModule(ADMIN));
        console.log("   SecurityModule deployed at:", securityModule);
        
        // 2. Deploy FXRateOracle
        console.log("2. Deploying FXRateOracle...");
        fxRateOracle = address(new FXRateOracle(ADMIN));
        console.log("   FXRateOracle deployed at:", fxRateOracle);
        
        // 3. Deploy LiquidityManager
        console.log("3. Deploying LiquidityManager...");
        liquidityManager = address(new LiquidityManager(
            ADMIN,
            "FluxSwap LP Token",
            "FLUX-LP"
        ));
        console.log("   LiquidityManager deployed at:", liquidityManager);
        
        // 4. Deploy SettlementEngine
        console.log("4. Deploying SettlementEngine...");
        settlementEngine = address(new SettlementEngine(ADMIN));
        console.log("   SettlementEngine deployed at:", settlementEngine);
        
        // 5. Deploy CCTPv2Integration
        console.log("5. Deploying CCTPv2Integration...");
        cctpIntegration = address(new CCTPv2Integration(
            ADMIN,
            address(0) // Will be set after FluxSwapManager deployment
        ));
        console.log("   CCTPv2Integration deployed at:", cctpIntegration);
        
        // 6. Deploy FluxSwapManager
        console.log("6. Deploying FluxSwapManager...");
        fluxSwapManager = address(new FluxSwapManager(
            ADMIN,
            securityModule,
            cctpIntegration,
            fxRateOracle,
            liquidityManager,
            settlementEngine,
            FEE_COLLECTOR
        ));
        console.log("   FluxSwapManager deployed at:", fluxSwapManager);
        
        // 7. Deploy FluxSwapMainHook (THE REVOLUTIONARY HOOK!)
        console.log("7. Deploying FluxSwapMainHook (THE REVOLUTIONARY HOOK!)...");
        fluxSwapHook = address(new FluxSwapMainHook(
            IPoolManager(MOCK_POOL_MANAGER),
            fluxSwapManager,
            fxRateOracle,
            ADMIN,
            HOOK_FEE_COLLECTOR
        ));
        console.log("   FluxSwapMainHook deployed at:", fluxSwapHook);
        
        // 8. Configure contracts
        console.log("8. Configuring contracts...");
        
        // Set FluxSwapManager in CCTPv2Integration
        CCTPv2Integration(cctpIntegration).setFluxSwapManager(fluxSwapManager);
        console.log("   CCTPv2Integration configured with FluxSwapManager");
        
        // Initialize default USDC/EURC rate in oracle (mock rate for testnet)
        FXRateOracle(fxRateOracle).updateRate(
            0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238, // USDC Sepolia
            0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c,  // EURC (placeholder)
            920000000000000000, // 0.92 EUR/USD (18 decimals)
            "Initial Rate"
        );
        console.log("   Initial USDC/EURC rate set in FXRateOracle");
        
        vm.stopBroadcast();
        
        console.log("\n=== FluxSwap Deployment Complete ===");
        console.log("SecurityModule:     ", securityModule);
        console.log("FXRateOracle:       ", fxRateOracle);
        console.log("LiquidityManager:   ", liquidityManager);
        console.log("SettlementEngine:   ", settlementEngine);
        console.log("CCTPv2Integration:  ", cctpIntegration);
        console.log("FluxSwapManager:    ", fluxSwapManager);
        console.log("FluxSwapHook:       ", fluxSwapHook);
        console.log("\n=== Next Steps ===");
        console.log("1. Verify contracts on Etherscan");
        console.log("2. Set up Chainlink price feeds");
        console.log("3. Configure supported pools in FluxSwapHook");
        console.log("4. Add initial liquidity to LiquidityManager");
        console.log("5. Test cross-chain swaps on testnet");
    }
}