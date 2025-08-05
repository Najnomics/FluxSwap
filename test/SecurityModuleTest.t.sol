// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./FoundationTest.t.sol";

/// @title Security Module Test Suite (Tests 126-150)
/// @notice 🛡️ COMPREHENSIVE SECURITY TESTING
contract SecurityModuleTest is FoundationTest {

    /*//////////////////////////////////////////////////////////////
                        SECURITY MODULE TESTS (25)
    //////////////////////////////////////////////////////////////*/
    
    function test_126_TransactionLimitsValidation() public {
        bool withinLimits = security.checkTransactionLimits(
            user1,
            50000e6, // $50K
            24 hours
        );
        
        assertTrue(withinLimits, "50K should be within daily limits");
    }
    
    function test_127_TransactionLimitsExceed() public {
        bool withinLimits = security.checkTransactionLimits(
            user1,
            2_000_000e6, // $2M - exceeds $1M limit
            24 hours
        );
        
        assertFalse(withinLimits, "2M should exceed transaction limits");
    }
    
    function test_128_EmergencyPauseTrigger() public {
        vm.prank(emergency);
        security.triggerEmergencyPause("Test emergency");
        
        assertTrue(security.emergencyPause(), "Emergency pause should be active");
        assertTrue(security.paused(), "Contract should be paused");
    }
    
    function test_129_SystemHealthUpdate() public {
        vm.prank(admin);
        security.updateSystemHealth();
        
        assertTrue(security.isSystemHealthy(), "System should be healthy");
    }
    
    function test_130_DailyLimitTracking() public {
        // Record transaction
        vm.prank(admin);
        security.recordTransaction(user1, 30000e6);
        
        uint256 dailyVolume = security.getUserDailyVolume(user1);
        assertEq(dailyVolume, 30000e6, "Daily volume should be tracked");
    }
    
    function test_131_DailyLimitReset() public {
        // Record transaction
        vm.prank(admin);
        security.recordTransaction(user1, 30000e6);
        
        // Move to next day
        vm.warp(block.timestamp + 25 hours);
        
        uint256 dailyVolume = security.getUserDailyVolume(user1);
        assertEq(dailyVolume, 0, "Daily volume should reset");
    }
    
    function test_132_BlacklistFunctionality() public {
        vm.prank(admin);
        security.blacklistAddress(user1, "Test blacklist");
        
        bool withinLimits = security.checkTransactionLimits(user1, 1000e6, 24 hours);
        assertFalse(withinLimits, "Blacklisted address should be blocked");
    }
    
    function test_133_WhitelistBypass() public {
        vm.prank(admin);
        security.whitelistAddress(user1);
        
        bool withinLimits = security.checkTransactionLimits(user1, 2_000_000e6, 24 hours);
        assertTrue(withinLimits, "Whitelisted address should bypass limits");
    }
    
    function test_134_RiskParametersUpdate() public {
        RiskParams memory newParams = RiskParams({
            dailyUserLimit: 200_000e6,
            maxSingleTransaction: 2_000_000e6,
            maxPriceDeviation: 2000,
            minLiquidityBuffer: 3000,
            emergencyThreshold: 6000,
            globalPauseEnabled: false
        });
        
        vm.prank(admin);
        security.updateRiskParameters(newParams);
        
        RiskParams memory stored = security.riskParams();
        assertEq(stored.dailyUserLimit, 200_000e6, "Risk params should be updated");
    }
    
    function test_135_CircuitBreakerTrigger() public {
        bytes32 breakerType = keccak256("PRICE_ORACLE_FAILURE");
        
        vm.prank(admin);
        security.triggerCircuitBreaker(breakerType, "Oracle failure test");
        
        assertTrue(security.circuitBreakers(breakerType), "Circuit breaker should be triggered");
    }
    
    function test_136_SystemHealthCalculation() public {
        vm.prank(admin);
        security.updateSystemHealth();
        
        uint256 healthScore = security.systemHealthScore();
        assertEq(healthScore, 10000, "Healthy system should have max score");
    }
    
    function test_137_SystemHealthWithCircuitBreaker() public {
        // Trigger circuit breaker
        vm.prank(admin);
        security.triggerCircuitBreaker(keccak256("PRICE_ORACLE_FAILURE"), "Test");
        
        vm.prank(admin);
        security.updateSystemHealth();
        
        uint256 healthScore = security.systemHealthScore();
        assertTrue(healthScore < 10000, "Health score should decrease with circuit breaker");
    }
    
    function test_138_EmergencyPauseUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        security.triggerEmergencyPause("Unauthorized");
    }
    
    function test_139_RiskParametersInvalidValues() public {
        RiskParams memory invalidParams = RiskParams({
            dailyUserLimit: 0, // Invalid
            maxSingleTransaction: 1000e6,
            maxPriceDeviation: 1000,
            minLiquidityBuffer: 2000,
            emergencyThreshold: 5000,
            globalPauseEnabled: true
        });
        
        vm.prank(admin);
        vm.expectRevert("Invalid daily limit");
        security.updateRiskParameters(invalidParams);
    }
    
    function test_140_RemainingUserLimit() public {
        // Record partial transaction
        vm.prank(admin);
        security.recordTransaction(user1, 30000e6);
        
        uint256 remaining = security.getRemainingUserLimit(user1);
        assertEq(remaining, 70000e6, "Remaining limit should be calculated correctly");
    }
    
    function test_141_WhitelistRemainingLimit() public {
        vm.prank(admin);
        security.whitelistAddress(user1);
        
        uint256 remaining = security.getRemainingUserLimit(user1);
        assertEq(remaining, type(uint256).max, "Whitelisted should have unlimited");
    }
    
    function test_142_SystemRecovery() public {
        // Trigger emergency pause
        vm.prank(emergency);
        security.triggerEmergencyPause("Test recovery");
        
        // Recover system
        vm.prank(admin);
        security.resumeOperations();
        
        assertFalse(security.emergencyPause(), "Emergency pause should be cleared");
        assertFalse(security.paused(), "Contract should be unpaused");
    }
    
    function test_143_RecoveryRequiresHealthySystem() public {
        // Trigger circuit breaker to lower health
        vm.prank(admin);
        security.triggerCircuitBreaker(keccak256("CRITICAL_FAILURE"), "Test");
        
        vm.prank(emergency);
        security.triggerEmergencyPause("Test");
        
        // Try to recover with unhealthy system
        vm.prank(admin);
        vm.expectRevert("System health insufficient");
        security.resumeOperations();
    }
    
    function test_144_HealthUpdateCooldown() public {
        vm.prank(admin);
        security.updateSystemHealth();
        
        // Try to update again immediately
        vm.prank(admin);
        vm.expectRevert("Health update too frequent");
        security.updateSystemHealth();
    }
    
    function test_145_MultipleDailyTransactions() public {
        vm.startPrank(admin);
        
        // Record multiple transactions within limit
        security.recordTransaction(user1, 20000e6);
        security.recordTransaction(user1, 30000e6);
        security.recordTransaction(user1, 25000e6);
        
        vm.stopPrank();
        
        uint256 dailyVolume = security.getUserDailyVolume(user1);
        assertEq(dailyVolume, 75000e6, "Multiple transactions should accumulate");
    }
    
    function test_146_PausedStateChecks() public {
        vm.prank(admin);
        security.pause();
        
        bool withinLimits = security.checkTransactionLimits(user1, 1000e6, 24 hours);
        assertFalse(withinLimits, "Paused state should block transactions");
    }
    
    function test_147_SecurityRoleHierarchy() public {
        address securityAdmin = address(0x3001);
        
        vm.prank(admin);
        security.grantRole(security.RISK_MANAGER_ROLE(), securityAdmin);
        
        vm.prank(securityAdmin);
        security.triggerCircuitBreaker(keccak256("LIQUIDITY_SHORTAGE"), "Risk manager test");
        
        assertTrue(security.circuitBreakers(keccak256("LIQUIDITY_SHORTAGE")));
    }
    
    function test_148_TimeWindowValidation() public view {
        // Test different time windows
        bool result1 = security.checkTransactionLimits(user1, 50000e6, 1 hours);
        bool result2 = security.checkTransactionLimits(user1, 50000e6, 24 hours);
        bool result3 = security.checkTransactionLimits(user1, 50000e6, 48 hours);
        
        assertTrue(result1, "1 hour window should work");
        assertTrue(result2, "24 hour window should work");
        assertTrue(result3, "48 hour window should work");
    }
    
    function test_149_GlobalPauseConfiguration() public {
        RiskParams memory params = security.riskParams();
        assertTrue(params.globalPauseEnabled, "Global pause should be enabled by default");
        
        // Disable global pause
        params.globalPauseEnabled = false;
        vm.prank(admin);
        security.updateRiskParameters(params);
        
        RiskParams memory updated = security.riskParams();
        assertFalse(updated.globalPauseEnabled, "Global pause should be disabled");
    }
    
    function test_150_SecurityModuleGasOptimization() public {
        uint256 gasBefore = gasleft();
        security.checkTransactionLimits(user1, 1000e6, 24 hours);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 50000, "Security checks should be gas efficient");
    }
}