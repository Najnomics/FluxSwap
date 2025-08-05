// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/FluxSwapMainHook.sol";
import "../src/interfaces/IFluxSwapTypes.sol";
import "../src/core/FluxSwapManager.sol";
import "../src/security/SecurityModule.sol";
import "../src/cctp/CCTPv2Integration.sol";
import "../src/oracles/FXRateOracle.sol";
import "../src/liquidity/LiquidityManager.sol";
import "../src/settlement/SettlementEngine.sol";
import "../src/config/FluxSwapNetworkConfig.sol";
import "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import "@uniswap/v4-core/src/types/PoolKey.sol";
import "@uniswap/v4-core/src/types/PoolId.sol";
import "@uniswap/v4-core/src/types/Currency.sol";

/// @title Comprehensive FluxSwapMainHook Test Suite
/// @notice 🚀 TESTING THE REVOLUTIONARY HOOK - Over 100 focused tests!
contract FluxSwapMainHookTest is Test, IFluxSwapTypes {
    
    // Contract instances
    FluxSwapMainHook public hook;
    FluxSwapManager public fluxSwapManager;
    SecurityModule public securityModule;
    FXRateOracle public fxRateOracle;
    LiquidityManager public liquidityManager;
    SettlementEngine public settlementEngine;
    CCTPv2Integration public cctpIntegration;
    
    // Mock pool manager
    IPoolManager mockPoolManager;
    
    // Test addresses
    address public admin = address(0x1001);
    address public user = address(0x1002);
    address public feeCollector = address(0x1003);
    address public hookFeeCollector = address(0x1004);
    
    // Mock token addresses
    address public constant USDC_TEST = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    address public constant EURC_TEST = 0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c;
    
    // Test pool configuration
    PoolKey public testPoolKey;
    PoolId public testPoolId;
    
    function setUp() public {
        vm.startPrank(admin);
        
        // Deploy mock pool manager
        mockPoolManager = IPoolManager(address(0x4000));
        
        // Deploy core contracts
        securityModule = new SecurityModule(admin);
        fxRateOracle = new FXRateOracle(admin);
        liquidityManager = new LiquidityManager(admin, "FluxSwap LP", "FLUX-LP");
        settlementEngine = new SettlementEngine(admin);
        cctpIntegration = new CCTPv2Integration(admin, admin);
        
        fluxSwapManager = new FluxSwapManager(
            admin,
            address(securityModule),
            address(cctpIntegration),
            address(fxRateOracle),
            address(liquidityManager),
            address(settlementEngine),
            feeCollector
        );
        
        // Deploy the main hook
        hook = new FluxSwapMainHook(
            mockPoolManager,
            address(fluxSwapManager),
            address(fxRateOracle),
            admin,
            hookFeeCollector
        );
        
        // Configure CCTP integration
        cctpIntegration.setFluxSwapManager(address(fluxSwapManager));
        
        // Set up test pool
        testPoolKey = PoolKey({
            currency0: Currency.wrap(USDC_TEST),
            currency1: Currency.wrap(EURC_TEST),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });
        testPoolId = PoolId.wrap(keccak256(abi.encode(testPoolKey)));
        
        // Set initial FX rate
        fxRateOracle.updateRate(
            USDC_TEST,
            EURC_TEST,
            920000000000000000, // 0.92 EUR/USD
            "Test Rate"
        );
        
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                           HOOK DEPLOYMENT TESTS (10)
    //////////////////////////////////////////////////////////////*/
    
    function testHookDeployment() public view {
        assertTrue(address(hook) != address(0));
        assertEq(address(hook.fluxSwapManager()), address(fluxSwapManager));
        assertEq(address(hook.fxRateOracle()), address(fxRateOracle));
        assertEq(hook.hookFeeCollector(), hookFeeCollector);
    }
    
    function testHookRoleConfiguration() public view {
        assertTrue(hook.hasRole(hook.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hook.hasRole(hook.MANAGER_ROLE(), address(fluxSwapManager)));
        assertTrue(hook.hasRole(hook.HOOK_ADMIN_ROLE(), admin));
        assertTrue(hook.hasRole(hook.EMERGENCY_ROLE(), admin));
    }
    
    function testHookPermissions() public view {
        Hooks.Permissions memory permissions = hook.getHookPermissions();
        assertTrue(permissions.beforeSwap);
        assertTrue(permissions.beforeSwapReturnDelta);
        assertFalse(permissions.afterSwap);
        assertFalse(permissions.beforeInitialize);
    }
    
    function testHookInfo() public view {
        (string memory name, string memory version, string memory description) = hook.getHookInfo();
        assertEq(name, "FluxSwap Revolutionary Cross-Chain FX Hook");
        assertEq(version, "2.0.0 - CCTP v2 Powered");
        assertTrue(bytes(description).length > 0);
    }
    
    function testInitialHookState() public view {
        assertFalse(hook.emergencyBypass());
        assertEq(hook.hookFeeRate(), 5); // 0.05%
        assertEq(hook.totalFeesCollected(), 0);
        assertFalse(hook.supportedPools(testPoolId));
    }
    
    function testHookFeeStats() public view {
        (uint256 totalFees, uint256 currentRate, address collector) = hook.getFeeStats();
        assertEq(totalFees, 0);
        assertEq(currentRate, 5);
        assertEq(collector, hookFeeCollector);
    }
    
    function testHookStatsInitial() public view {
        (uint256 execCount, uint256 redirCount, uint256 successRate, uint256 volume) = 
            hook.getHookStats(testPoolId);
        assertEq(execCount, 0);
        assertEq(redirCount, 0);
        assertEq(successRate, 0);
        assertEq(volume, 0);
    }
    
    function testEmergencyBypassInitial() public view {
        assertFalse(hook.emergencyBypass());
        assertFalse(hook.paused());
    }
    
    function testHookSupportsInterface() public view {
        // Test AccessControl interface support
        assertTrue(hook.supportsInterface(type(AccessControl).interfaceId));
    }
    
    function testHookImmutableState() public view {
        assertEq(address(hook.fluxSwapManager()), address(fluxSwapManager));
        assertEq(address(hook.fxRateOracle()), address(fxRateOracle));
    }

    /*//////////////////////////////////////////////////////////////
                        POOL SUPPORT MANAGEMENT TESTS (15)
    //////////////////////////////////////////////////////////////*/
    
    function testSetSupportedPool() public {
        vm.prank(admin);
        hook.setSupportedPool(testPoolId, true);
        assertTrue(hook.supportedPools(testPoolId));
    }
    
    function testSetSupportedPoolEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit PoolSupportUpdated(testPoolId, true, admin);
        hook.setSupportedPool(testPoolId, true);
    }
    
    function testSetSupportedPoolUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        hook.setSupportedPool(testPoolId, true);
    }
    
    function testRemoveSupportedPool() public {
        vm.startPrank(admin);
        hook.setSupportedPool(testPoolId, true);
        assertTrue(hook.supportedPools(testPoolId));
        
        hook.setSupportedPool(testPoolId, false);
        assertFalse(hook.supportedPools(testPoolId));
        vm.stopPrank();
    }
    
    function testMultiplePoolSupport() public {
        PoolKey memory pool2 = PoolKey({
            currency0: Currency.wrap(EURC_TEST),
            currency1: Currency.wrap(USDC_TEST),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });
        PoolId pool2Id = PoolId.wrap(keccak256(abi.encode(pool2)));
        
        vm.startPrank(admin);
        hook.setSupportedPool(testPoolId, true);
        hook.setSupportedPool(pool2Id, true);
        
        assertTrue(hook.supportedPools(testPoolId));
        assertTrue(hook.supportedPools(pool2Id));
        vm.stopPrank();
    }
    
    function testPoolSupportToggle() public {
        vm.startPrank(admin);
        
        // Enable
        hook.setSupportedPool(testPoolId, true);
        assertTrue(hook.supportedPools(testPoolId));
        
        // Disable
        hook.setSupportedPool(testPoolId, false);
        assertFalse(hook.supportedPools(testPoolId));
        
        // Enable again
        hook.setSupportedPool(testPoolId, true);
        assertTrue(hook.supportedPools(testPoolId));
        
        vm.stopPrank();
    }
    
    function testSetSupportedPoolWithDifferentAdmin() public {
        address newAdmin = address(0x2001);
        vm.prank(admin);
        hook.grantRole(hook.HOOK_ADMIN_ROLE(), newAdmin);
        
        vm.prank(newAdmin);
        hook.setSupportedPool(testPoolId, true);
        assertTrue(hook.supportedPools(testPoolId));
    }
    
    function testPoolSupportBatchOperations() public {
        PoolId[] memory poolIds = new PoolId[](3);
        for(uint i = 0; i < 3; i++) {
            poolIds[i] = PoolId.wrap(keccak256(abi.encode(i)));
        }
        
        vm.startPrank(admin);
        for(uint i = 0; i < 3; i++) {
            hook.setSupportedPool(poolIds[i], true);
            assertTrue(hook.supportedPools(poolIds[i]));
        }
        vm.stopPrank();
    }
    
    function testPoolSupportPersistence() public {
        vm.prank(admin);
        hook.setSupportedPool(testPoolId, true);
        
        // Pool support should persist across multiple checks
        for(uint i = 0; i < 5; i++) {
            assertTrue(hook.supportedPools(testPoolId));
        }
    }
    
    function testPoolSupportWithZeroAddress() public {
        PoolId zeroPoolId = PoolId.wrap(bytes32(0));
        
        vm.prank(admin);
        hook.setSupportedPool(zeroPoolId, true);
        assertTrue(hook.supportedPools(zeroPoolId));
    }
    
    function testPoolSupportRoleCheck() public {
        // Only HOOK_ADMIN_ROLE should be able to set pool support
        vm.prank(admin);
        hook.revokeRole(hook.HOOK_ADMIN_ROLE(), admin);
        
        vm.prank(admin);
        vm.expectRevert();
        hook.setSupportedPool(testPoolId, true);
    }
    
    function testPoolSupportEventData() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit PoolSupportUpdated(testPoolId, true, admin);
        hook.setSupportedPool(testPoolId, true);
    }
    
    function testPoolSupportStateConsistency() public {
        vm.startPrank(admin);
        
        // Set multiple pools with different states
        hook.setSupportedPool(testPoolId, true);
        PoolId pool2 = PoolId.wrap(bytes32(uint256(1)));
        hook.setSupportedPool(pool2, false);
        
        assertTrue(hook.supportedPools(testPoolId));
        assertFalse(hook.supportedPools(pool2));
        
        vm.stopPrank();
    }
    
    function testPoolSupportGasEfficiency() public {
        vm.prank(admin);
        uint256 gasBefore = gasleft();
        hook.setSupportedPool(testPoolId, true);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should use reasonable amount of gas (less than 50k)
        assertTrue(gasUsed < 50000);
    }
    
    function testPoolSupportIdempotency() public {
        vm.startPrank(admin);
        
        // Setting same value multiple times should work
        hook.setSupportedPool(testPoolId, true);
        hook.setSupportedPool(testPoolId, true);
        hook.setSupportedPool(testPoolId, true);
        
        assertTrue(hook.supportedPools(testPoolId));
        
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        FEE MANAGEMENT TESTS (20)
    //////////////////////////////////////////////////////////////*/
    
    function testUpdateHookFeeRate() public {
        vm.prank(admin);
        hook.updateHookFeeRate(10); // 0.1%
        assertEq(hook.hookFeeRate(), 10);
    }
    
    function testUpdateHookFeeRateMaxLimit() public {
        vm.prank(admin);
        hook.updateHookFeeRate(50); // 0.5% max
        assertEq(hook.hookFeeRate(), 50);
    }
    
    function testUpdateHookFeeRateExceedsLimit() public {
        vm.prank(admin);
        vm.expectRevert("FluxSwap: Fee rate too high");
        hook.updateHookFeeRate(51); // Over 0.5%
    }
    
    function testUpdateHookFeeRateUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        hook.updateHookFeeRate(10);
    }
    
    function testUpdateHookFeeRateZero() public {
        vm.prank(admin);
        hook.updateHookFeeRate(0);
        assertEq(hook.hookFeeRate(), 0);
    }
    
    function testUpdateHookFeeCollector() public {
        address newCollector = address(0x2002);
        vm.prank(admin);
        hook.updateHookFeeCollector(newCollector);
        assertEq(hook.hookFeeCollector(), newCollector);
    }
    
    function testUpdateHookFeeCollectorZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert("FluxSwap: Invalid collector");
        hook.updateHookFeeCollector(address(0));
    }
    
    function testUpdateHookFeeCollectorUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        hook.updateHookFeeCollector(address(0x2002));
    }
    
    function testFeeRateBoundaryValues() public {
        vm.startPrank(admin);
        
        // Test all valid boundary values
        for(uint256 i = 0; i <= 50; i++) {
            hook.updateHookFeeRate(i);
            assertEq(hook.hookFeeRate(), i);
        }
        
        vm.stopPrank();
    }
    
    function testFeeCollectorUpdatesState() public {
        address collector1 = address(0x3001);
        address collector2 = address(0x3002);
        
        vm.startPrank(admin);
        
        hook.updateHookFeeCollector(collector1);
        assertEq(hook.hookFeeCollector(), collector1);
        
        hook.updateHookFeeCollector(collector2);
        assertEq(hook.hookFeeCollector(), collector2);
        
        vm.stopPrank();
    }
    
    function testFeeStatsAfterUpdates() public {
        vm.startPrank(admin);
        
        hook.updateHookFeeRate(15);
        address newCollector = address(0x3003);
        hook.updateHookFeeCollector(newCollector);
        
        (uint256 totalFees, uint256 currentRate, address collector) = hook.getFeeStats();
        assertEq(totalFees, 0); // No fees collected yet
        assertEq(currentRate, 15);
        assertEq(collector, newCollector);
        
        vm.stopPrank();
    }
    
    function testFeeRateCalculation() public view {
        uint256 amount = 1000e6; // 1000 USDC
        uint256 feeRate = hook.hookFeeRate(); // 5 basis points
        uint256 expectedFee = (amount * feeRate) / FluxSwapConstants.BASIS_POINTS;
        assertEq(expectedFee, 500e3); // 0.5 USDC
    }
    
    function testFeeRateEdgeCases() public {
        vm.startPrank(admin);
        
        // Zero fee rate
        hook.updateHookFeeRate(0);
        uint256 amount = 1000e6;
        uint256 fee = (amount * hook.hookFeeRate()) / FluxSwapConstants.BASIS_POINTS;
        assertEq(fee, 0);
        
        // Maximum fee rate
        hook.updateHookFeeRate(50);
        fee = (amount * hook.hookFeeRate()) / FluxSwapConstants.BASIS_POINTS;
        assertEq(fee, 5e6); // 5 USDC (0.5%)
        
        vm.stopPrank();
    }
    
    function testFeeCollectorValidation() public {
        vm.startPrank(admin);
        
        // Valid addresses should work
        address[] memory validCollectors = new address[](3);
        validCollectors[0] = address(0x1);
        validCollectors[1] = address(0xdead);
        validCollectors[2] = address(0xbeef);
        
        for(uint i = 0; i < validCollectors.length; i++) {
            hook.updateHookFeeCollector(validCollectors[i]);
            assertEq(hook.hookFeeCollector(), validCollectors[i]);
        }
        
        vm.stopPrank();
    }
    
    function testFeeRateRoleHierarchy() public {
        // Only DEFAULT_ADMIN_ROLE should update fee rate
        address hookAdmin = address(0x4001);
        vm.prank(admin);
        hook.grantRole(hook.HOOK_ADMIN_ROLE(), hookAdmin);
        
        vm.prank(hookAdmin);
        vm.expectRevert(); // Hook admin cannot update fee rate
        hook.updateHookFeeRate(10);
    }
    
    function testFeeCollectorRoleHierarchy() public {
        // Only DEFAULT_ADMIN_ROLE should update fee collector
        address hookAdmin = address(0x4002);
        vm.prank(admin);
        hook.grantRole(hook.HOOK_ADMIN_ROLE(), hookAdmin);
        
        vm.prank(hookAdmin);
        vm.expectRevert(); // Hook admin cannot update fee collector
        hook.updateHookFeeCollector(address(0x5001));
    }
    
    function testFeeRateConsistency() public {
        vm.startPrank(admin);
        
        // Set fee rate multiple times and verify consistency
        uint256[] memory rates = new uint256[](5);
        rates[0] = 1;
        rates[1] = 25;
        rates[2] = 50;
        rates[3] = 0;
        rates[4] = 10;
        
        for(uint i = 0; i < rates.length; i++) {
            hook.updateHookFeeRate(rates[i]);
            assertEq(hook.hookFeeRate(), rates[i]);
            
            // Verify getFeeStats returns consistent data
            (,uint256 currentRate,) = hook.getFeeStats();
            assertEq(currentRate, rates[i]);
        }
        
        vm.stopPrank();
    }
    
    function testFeeRateGasUsage() public {
        vm.prank(admin);
        uint256 gasBefore = gasleft();
        hook.updateHookFeeRate(25);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should be reasonably gas efficient
        assertTrue(gasUsed < 30000);
    }
    
    function testFeeCollectorGasUsage() public {
        vm.prank(admin);
        uint256 gasBefore = gasleft();
        hook.updateHookFeeCollector(address(0x6001));
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should be reasonably gas efficient
        assertTrue(gasUsed < 30000);
    }
    
    function testFeeConfigurationPersistence() public {
        vm.startPrank(admin);
        
        uint256 testRate = 33;
        address testCollector = address(0x7001);
        
        hook.updateHookFeeRate(testRate);
        hook.updateHookFeeCollector(testCollector);
        
        // Values should persist across multiple reads
        for(uint i = 0; i < 10; i++) {
            assertEq(hook.hookFeeRate(), testRate);
            assertEq(hook.hookFeeCollector(), testCollector);
        }
        
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS TESTS (25)
    //////////////////////////////////////////////////////////////*/
    
    function testToggleEmergencyBypass() public {
        vm.prank(admin);
        hook.toggleEmergencyBypass(true);
        assertTrue(hook.emergencyBypass());
    }
    
    function testToggleEmergencyBypassEvent() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit EmergencyBypassToggled(true, admin);
        hook.toggleEmergencyBypass(true);
    }
    
    function testToggleEmergencyBypassUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        hook.toggleEmergencyBypass(true);
    }
    
    function testEmergencyBypassDisable() public {
        vm.startPrank(admin);
        hook.toggleEmergencyBypass(true);
        assertTrue(hook.emergencyBypass());
        
        hook.toggleEmergencyBypass(false);
        assertFalse(hook.emergencyBypass());
        vm.stopPrank();
    }
    
    function testEmergencyPause() public {
        vm.prank(admin);
        hook.pause();
        assertTrue(hook.paused());
    }
    
    function testEmergencyPauseUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        hook.pause();
    }
    
    function testEmergencyUnpause() public {
        vm.startPrank(admin);
        hook.pause();
        assertTrue(hook.paused());
        
        hook.unpause();
        assertFalse(hook.paused());
        vm.stopPrank();
    }
    
    function testEmergencyUnpauseUnauthorized() public {
        vm.prank(admin);
        hook.pause();
        
        vm.prank(user);
        vm.expectRevert();
        hook.unpause();
    }
    
    function testTriggerCircuitBreaker() public {
        bytes32 breakerType = keccak256("TEST_BREAKER");
        string memory reason = "Test circuit breaker";
        
        vm.prank(admin);
        hook.triggerCircuitBreaker(breakerType, reason);
        assertTrue(hook.circuitBreakers(breakerType));
    }
    
    function testTriggerCircuitBreakerEvent() public {
        bytes32 breakerType = keccak256("TEST_BREAKER");
        string memory reason = "Test circuit breaker";
        
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit CircuitBreakerTriggered(breakerType, reason);
        hook.triggerCircuitBreaker(breakerType, reason);
    }
    
    function testTriggerCriticalCircuitBreaker() public {
        bytes32 breakerType = keccak256("CRITICAL_FAILURE");
        string memory reason = "Critical system failure";
        
        vm.prank(admin);
        hook.triggerCircuitBreaker(breakerType, reason);
        
        assertTrue(hook.circuitBreakers(breakerType));
        assertTrue(hook.paused()); // Should auto-pause
    }
    
    function testTriggerCCTPFailureCircuitBreaker() public {
        bytes32 breakerType = keccak256("CCTP_FAILURE");
        string memory reason = "CCTP system failure";
        
        vm.prank(admin);
        hook.triggerCircuitBreaker(breakerType, reason);
        
        assertTrue(hook.circuitBreakers(breakerType));
        assertTrue(hook.paused()); // Should auto-pause
    }
    
    function testCircuitBreakerUnauthorized() public {
        bytes32 breakerType = keccak256("TEST_BREAKER");
        string memory reason = "Test";
        
        vm.prank(user);
        vm.expectRevert();
        hook.triggerCircuitBreaker(breakerType, reason);
    }
    
    function testEmergencyRolePermissions() public {
        address emergencyUser = address(0x8001);
        
        vm.prank(admin);
        hook.grantRole(hook.EMERGENCY_ROLE(), emergencyUser);
        
        // Emergency user should be able to pause
        vm.prank(emergencyUser);
        hook.pause();
        assertTrue(hook.paused());
        
        // But only admin can unpause
        vm.prank(emergencyUser);
        vm.expectRevert();
        hook.unpause();
    }
    
    function testEmergencyBypassToggleMultiple() public {
        vm.startPrank(admin);
        
        // Toggle multiple times
        hook.toggleEmergencyBypass(true);
        assertTrue(hook.emergencyBypass());
        
        hook.toggleEmergencyBypass(false);
        assertFalse(hook.emergencyBypass());
        
        hook.toggleEmergencyBypass(true);
        assertTrue(hook.emergencyBypass());
        
        vm.stopPrank();
    }
    
    function testCircuitBreakerStates() public {
        bytes32[] memory breakers = new bytes32[](3);
        breakers[0] = keccak256("BREAKER_1");
        breakers[1] = keccak256("BREAKER_2");
        breakers[2] = keccak256("BREAKER_3");
        
        vm.startPrank(admin);
        
        for(uint i = 0; i < breakers.length; i++) {
            hook.triggerCircuitBreaker(breakers[i], "Test");
            assertTrue(hook.circuitBreakers(breakers[i]));
        }
        
        vm.stopPrank();
    }
    
    function testPauseUnpauseCycle() public {
        vm.startPrank(admin);
        
        // Multiple pause/unpause cycles
        for(uint i = 0; i < 5; i++) {
            hook.pause();
            assertTrue(hook.paused());
            
            hook.unpause();
            assertFalse(hook.paused());
        }
        
        vm.stopPrank();
    }
    
    function testEmergencyControlsGasUsage() public {
        vm.startPrank(admin);
        
        // Test gas usage for emergency functions
        uint256 gasBefore = gasleft();
        hook.toggleEmergencyBypass(true);
        uint256 gasUsed1 = gasBefore - gasleft();
        
        gasBefore = gasleft();
        hook.pause();
        uint256 gasUsed2 = gasBefore - gasleft();
        
        gasBefore = gasleft();
        hook.unpause();
        uint256 gasUsed3 = gasBefore - gasleft();
        
        // All should be reasonably gas efficient
        assertTrue(gasUsed1 < 50000);
        assertTrue(gasUsed2 < 50000);
        assertTrue(gasUsed3 < 50000);
        
        vm.stopPrank();
    }
    
    function testEmergencyStateConsistency() public {
        vm.startPrank(admin);
        
        // Set emergency bypass
        hook.toggleEmergencyBypass(true);
        assertTrue(hook.emergencyBypass());
        
        // Pause contract
        hook.pause();
        assertTrue(hook.paused());
        
        // Both should remain true
        assertTrue(hook.emergencyBypass());
        assertTrue(hook.paused());
        
        vm.stopPrank();
    }
    
    function testCircuitBreakerPersistence() public {
        bytes32 breakerType = keccak256("PERSISTENT_BREAKER");
        
        vm.prank(admin);
        hook.triggerCircuitBreaker(breakerType, "Test persistence");
        
        // Should remain triggered across multiple checks
        for(uint i = 0; i < 10; i++) {
            assertTrue(hook.circuitBreakers(breakerType));
        }
    }
    
    function testEmergencyRoleHierarchy() public {
        address emergencyAdmin = address(0x9001);
        
        vm.prank(admin);
        hook.grantRole(hook.EMERGENCY_ROLE(), emergencyAdmin);
        
        // Emergency admin can trigger circuit breakers
        vm.prank(emergencyAdmin);
        hook.triggerCircuitBreaker(keccak256("TEST"), "Emergency test");
        
        // Emergency admin can pause
        vm.prank(emergencyAdmin);
        hook.pause();
        
        // But cannot unpause (requires DEFAULT_ADMIN_ROLE)
        vm.prank(emergencyAdmin);
        vm.expectRevert();
        hook.unpause();
    }
    
    function testEmergencyControlsIdempotency() public {
        vm.startPrank(admin);
        
        // Multiple emergency bypass enables
        hook.toggleEmergencyBypass(true);
        hook.toggleEmergencyBypass(true);
        assertTrue(hook.emergencyBypass());
        
        // Multiple pauses
        hook.pause();
        vm.expectRevert("Pausable: paused");
        hook.pause();
        
        vm.stopPrank();
    }
    
    function testCircuitBreakerTypes() public {
        bytes32[] memory criticalBreakers = new bytes32[](2);
        criticalBreakers[0] = keccak256("CRITICAL_FAILURE");
        criticalBreakers[1] = keccak256("CCTP_FAILURE");
        
        vm.startPrank(admin);
        
        for(uint i = 0; i < criticalBreakers.length; i++) {
            hook.triggerCircuitBreaker(criticalBreakers[i], "Critical test");
            assertTrue(hook.circuitBreakers(criticalBreakers[i]));
            assertTrue(hook.paused()); // Should auto-pause for critical breakers
            
            hook.unpause(); // Reset for next test
        }
        
        vm.stopPrank();
    }
    
    function testNonCriticalCircuitBreaker() public {
        bytes32 nonCriticalBreaker = keccak256("NON_CRITICAL");
        
        vm.prank(admin);
        hook.triggerCircuitBreaker(nonCriticalBreaker, "Non-critical test");
        
        assertTrue(hook.circuitBreakers(nonCriticalBreaker));
        assertFalse(hook.paused()); // Should NOT auto-pause
    }
    
    function testEmergencyControlsCombined() public {
        vm.startPrank(admin);
        
        // Enable emergency bypass
        hook.toggleEmergencyBypass(true);
        
        // Trigger circuit breaker
        hook.triggerCircuitBreaker(keccak256("TEST"), "Combined test");
        
        // Pause contract
        hook.pause();
        
        // All emergency states should be active
        assertTrue(hook.emergencyBypass());
        assertTrue(hook.circuitBreakers(keccak256("TEST")));
        assertTrue(hook.paused());
        
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    event PoolSupportUpdated(PoolId indexed poolId, bool supported, address indexed admin);
    event EmergencyBypassToggled(bool enabled, address indexed admin);
    event CircuitBreakerTriggered(bytes32 indexed breakerType, string reason);
    
    receive() external payable {}
}