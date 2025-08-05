// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./FoundationTest.t.sol";

/// @title Oracle Test Suite (Tests 101-125)
/// @notice 📊 COMPREHENSIVE ORACLE TESTING
contract OracleTest is FoundationTest {

    /*//////////////////////////////////////////////////////////////
                         ORACLE TESTS (25)
    //////////////////////////////////////////////////////////////*/
    
    function test_101_OracleRateUpdate() public {
        vm.prank(admin);
        oracle.updateRate(
            address(usdc),
            address(eurc),
            950000000000000000, // 0.95 EUR/USD
            "Rate update test"
        );
        
        (uint256 rate, uint256 timestamp) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(rate, 950000000000000000, "Rate should be updated");
        assertTrue(timestamp > 0, "Timestamp should be set");
    }
    
    function test_102_OracleSlippageValidation() public {
        (uint256 currentRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        bool valid = oracle.validateRateWithSlippage(
            address(usdc),
            address(eurc),
            currentRate,
            100 // 1% slippage
        );
        
        assertTrue(valid, "Current rate should be valid");
    }
    
    function test_103_OracleStaleRateDetection() public {
        // Warp time to make rate stale
        vm.warp(block.timestamp + 400); // > 5 minutes
        
        (uint256 rate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        bool valid = oracle.validateRateWithSlippage(
            address(usdc),
            address(eurc),
            rate,
            100
        );
        
        assertFalse(valid, "Stale rate should be invalid");
    }
    
    function test_104_OracleSlippageCalculation() public {
        (uint256 currentRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        // Test rate outside slippage tolerance
        uint256 deviatedRate = currentRate * 11 / 10; // 10% higher
        
        bool valid = oracle.validateRateWithSlippage(
            address(usdc),
            address(eurc),
            deviatedRate,
            500 // 5% max slippage
        );
        
        assertFalse(valid, "Rate outside slippage should be invalid");
    }
    
    function test_105_OracleRateHistory() public {
        vm.startPrank(admin);
        
        // Update rate multiple times
        oracle.updateRate(address(usdc), address(eurc), 920000000000000000, "Rate 1");
        vm.warp(block.timestamp + 60);
        oracle.updateRate(address(usdc), address(eurc), 930000000000000000, "Rate 2");
        vm.warp(block.timestamp + 60);
        oracle.updateRate(address(usdc), address(eurc), 940000000000000000, "Rate 3");
        
        vm.stopPrank();
        
        (uint256 latestRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(latestRate, 940000000000000000, "Latest rate should be correct");
    }
    
    function test_106_OracleUnauthorizedUpdate() public {
        vm.prank(user1);
        vm.expectRevert();
        oracle.updateRate(address(usdc), address(eurc), 950000000000000000, "Unauthorized");
    }
    
    function test_107_OracleZeroRateValidation() public {
        vm.prank(admin);
        vm.expectRevert("Invalid rate");
        oracle.updateRate(address(usdc), address(eurc), 0, "Zero rate test");
    }
    
    function test_108_OracleReverseRateConsistency() public {
        (uint256 usdcToEurc,) = oracle.getLatestRate(address(usdc), address(eurc));
        (uint256 eurcToUsdc,) = oracle.getLatestRate(address(eurc), address(usdc));
        
        // Rates should be inverse of each other (within precision)
        uint256 product = (usdcToEurc * eurcToUsdc) / 1e18;
        assertTrue(product > 0.99e18 && product < 1.01e18, "Reverse rates should be consistent");
    }
    
    function test_109_OracleMaxSlippageValidation() public {
        (uint256 currentRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        // Test maximum allowed slippage
        vm.expectRevert("Slippage too high");
        oracle.validateRateWithSlippage(
            address(usdc),
            address(eurc),
            currentRate,
            1500 // 15% - exceeds 10% max
        );
    }
    
    function test_110_OracleRatePersistence() public {
        vm.prank(admin);
        oracle.updateRate(address(usdc), address(eurc), 980000000000000000, "Persistence test");
        
        // Rate should persist across multiple reads
        for (uint i = 0; i < 5; i++) {
            (uint256 rate,) = oracle.getLatestRate(address(usdc), address(eurc));
            assertEq(rate, 980000000000000000, "Rate should persist");
        }
    }
    
    function test_111_OracleTimestampAccuracy() public {
        uint256 beforeTime = block.timestamp;
        
        vm.prank(admin);
        oracle.updateRate(address(usdc), address(eurc), 960000000000000000, "Timestamp test");
        
        (, uint256 timestamp) = oracle.getLatestRate(address(usdc), address(eurc));
        assertTrue(timestamp >= beforeTime, "Timestamp should be accurate");
    }
    
    function test_112_OracleRateUpdateEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit RateUpdated(address(usdc), address(eurc), 975000000000000000, block.timestamp);
        oracle.updateRate(address(usdc), address(eurc), 975000000000000000, "Event test");
    }
    
    function test_113_OracleMultiplePairSupport() public {
        // Test support for multiple token pairs
        MockERC20 gbp = new MockERC20("British Pound", "GBP", 6);
        
        vm.startPrank(admin);
        oracle.updateRate(address(usdc), address(gbp), 800000000000000000, "USDC/GBP");
        oracle.updateRate(address(eurc), address(gbp), 870000000000000000, "EURC/GBP");
        vm.stopPrank();
        
        (uint256 usdcGbpRate,) = oracle.getLatestRate(address(usdc), address(gbp));
        (uint256 eurcGbpRate,) = oracle.getLatestRate(address(eurc), address(gbp));
        
        assertEq(usdcGbpRate, 800000000000000000, "USDC/GBP rate should be set");
        assertEq(eurcGbpRate, 870000000000000000, "EURC/GBP rate should be set");
    }
    
    function test_114_OracleRateBoundaryValues() public {
        vm.startPrank(admin);
        
        // Test minimum valid rate
        oracle.updateRate(address(usdc), address(eurc), 1, "Min rate");
        (uint256 minRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(minRate, 1, "Minimum rate should be accepted");
        
        // Test maximum rate
        oracle.updateRate(address(usdc), address(eurc), type(uint256).max, "Max rate");
        (uint256 maxRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(maxRate, type(uint256).max, "Maximum rate should be accepted");
        
        vm.stopPrank();
    }
    
    function test_115_OracleSlippageEdgeCases() public {
        (uint256 currentRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        // Test zero slippage
        bool valid1 = oracle.validateRateWithSlippage(address(usdc), address(eurc), currentRate, 0);
        assertTrue(valid1, "Zero slippage with exact rate should be valid");
        
        // Test with slightly different rate
        bool valid2 = oracle.validateRateWithSlippage(address(usdc), address(eurc), currentRate + 1, 0);
        assertFalse(valid2, "Zero slippage with different rate should be invalid");
    }
    
    function test_116_OracleRateSourceValidation() public {
        vm.prank(admin);
        oracle.updateRate(address(usdc), address(eurc), 985000000000000000, "Valid source");
        
        (uint256 rate, uint256 timestamp) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(rate, 985000000000000000, "Rate from valid source should be accepted");
        assertTrue(timestamp > 0, "Timestamp should be set");
    }
    
    function test_117_OracleGasOptimization() public {
        uint256 gasBefore = gasleft();
        oracle.getLatestRate(address(usdc), address(eurc));
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 20000, "Rate retrieval should be gas efficient");
    }
    
    function test_118_OracleRateUpdateGas() public {
        vm.prank(admin);
        uint256 gasBefore = gasleft();
        oracle.updateRate(address(usdc), address(eurc), 990000000000000000, "Gas test");
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 100000, "Rate update should be gas efficient");
    }
    
    function test_119_OracleSlippageValidationGas() public {
        (uint256 currentRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        uint256 gasBefore = gasleft();
        oracle.validateRateWithSlippage(address(usdc), address(eurc), currentRate, 100);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 30000, "Slippage validation should be gas efficient");
    }
    
    function test_120_OracleFailureHandling() public {
        // Test behavior with non-existent token pair
        MockERC20 unknownToken = new MockERC20("Unknown", "UNK", 18);
        
        vm.expectRevert("No rate available");
        oracle.getLatestRate(address(usdc), address(unknownToken));
    }
    
    function test_121_OracleRateUpdateDescription() public {
        string memory description = "Comprehensive rate test with long description";
        
        vm.prank(admin);
        oracle.updateRate(address(usdc), address(eurc), 995000000000000000, description);
        
        (uint256 rate,) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(rate, 995000000000000000, "Rate should be updated with description");
    }
    
    function test_122_OracleRateConsistencyAcrossReads() public {
        vm.prank(admin);
        oracle.updateRate(address(usdc), address(eurc), 977000000000000000, "Consistency test");
        
        // Multiple reads should return consistent values
        (uint256 rate1, uint256 timestamp1) = oracle.getLatestRate(address(usdc), address(eurc));
        (uint256 rate2, uint256 timestamp2) = oracle.getLatestRate(address(usdc), address(eurc));
        (uint256 rate3, uint256 timestamp3) = oracle.getLatestRate(address(usdc), address(eurc));
        
        assertEq(rate1, rate2, "Rates should be consistent");
        assertEq(rate2, rate3, "Rates should be consistent");
        assertEq(timestamp1, timestamp2, "Timestamps should be consistent");
        assertEq(timestamp2, timestamp3, "Timestamps should be consistent");
    }
    
    function test_123_OracleRoleBasedAccess() public {
        address oracleAdmin = address(0x4001);
        
        vm.prank(admin);
        oracle.grantRole(oracle.DEFAULT_ADMIN_ROLE(), oracleAdmin);
        
        vm.prank(oracleAdmin);
        oracle.updateRate(address(usdc), address(eurc), 988000000000000000, "Oracle admin test");
        
        (uint256 rate,) = oracle.getLatestRate(address(usdc), address(eurc));
        assertEq(rate, 988000000000000000, "Oracle admin should be able to update rates");
    }
    
    function test_124_OracleTimePrecision() public {
        uint256 preciseBefore = block.timestamp;
        
        vm.prank(admin);
        oracle.updateRate(address(usdc), address(eurc), 982000000000000000, "Precision test");
        
        (, uint256 timestamp) = oracle.getLatestRate(address(usdc), address(eurc));
        
        // Timestamp should be within reasonable bounds
        assertTrue(timestamp >= preciseBefore, "Timestamp should be at least the time before update");
        assertTrue(timestamp <= block.timestamp, "Timestamp should not be in the future");
    }
    
    function test_125_OracleRateValidationEdgeCases() public {
        (uint256 currentRate,) = oracle.getLatestRate(address(usdc), address(eurc));
        
        // Test rate exactly at slippage boundary
        uint256 boundaryRate = currentRate * 1050 / 1000; // Exactly 5% higher
        
        bool validWithin = oracle.validateRateWithSlippage(address(usdc), address(eurc), boundaryRate, 500);
        bool validOutside = oracle.validateRateWithSlippage(address(usdc), address(eurc), boundaryRate, 499);
        
        assertTrue(validWithin, "Rate at boundary should be valid with sufficient slippage");
        assertFalse(validOutside, "Rate at boundary should be invalid with insufficient slippage");
    }
    
    // Events for testing
    event RateUpdated(
        address indexed baseToken,
        address indexed quoteToken,
        uint256 rate,
        uint256 timestamp
    );
}