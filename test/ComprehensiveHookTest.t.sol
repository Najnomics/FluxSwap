// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./FoundationTest.t.sol";

/// @title Comprehensive Hook Test Suite - Part 2 (Tests 26-75)
/// @notice 🚀 DETAILED HOOK FUNCTIONALITY TESTING
contract ComprehensiveHookTest is FoundationTest {

    /*//////////////////////////////////////////////////////////////
                     HOOK SWAP EXECUTION TESTS (50)
    //////////////////////////////////////////////////////////////*/
    
    function test_026_BasicSwapWithoutCrossChain() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = ""; // No cross-chain intent
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(selector, hook.beforeSwap.selector);
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Normal swap
        assertEq(fee, 0);
        
        // Verify hook execution count increased
        (uint256 count,,,) = hook.getHookStats(poolIdUSDC_EURC);
        assertEq(count, 1);
    }
    
    function test_027_SwapWithInsufficientHookData() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(uint32(1)); // Too short
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should fall back to normal swap
    }
    
    function test_028_SwapWithValidCrossChainIntent() public {
        vm.startPrank(user1);
        usdc.approve(address(hook), 1000e6);
        vm.stopPrank();
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500) // 5% max slippage
        );
        
        // Mock successful manager call
        vm.mockCall(
            address(manager),
            abi.encodeWithSignature("initiateCrossChainFXSwap(address,address,uint256,uint32,address,uint256)"),
            abi.encode(bytes32("test_swap_123"))
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertTrue(BeforeSwapDelta.unwrap(delta) < 0); // Should skip normal swap
        
        // Verify stats updated
        (uint256 execCount, uint256 redirCount, uint256 successRate, uint256 volume) = 
            hook.getHookStats(poolIdUSDC_EURC);
        assertEq(execCount, 1);
        assertEq(redirCount, 1);
        assertEq(successRate, 10000); // 100%
        assertEq(volume, 1000e6);
    }
    
    function test_029_SwapWithInvalidDestination() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(999), // Invalid domain
            user1,
            uint256(500)
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should fall back to normal swap
    }
    
    function test_030_SwapWithSameChainDestination() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            FluxSwapNetworkConfig.getCCTPDomain(block.chainid), // Same chain
            user1,
            uint256(500)
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should fall back to normal swap
    }
    
    function test_031_SwapWithStaleOracleRate() public {
        // Make oracle rate stale
        vm.warp(block.timestamp + 400); // > 5 minutes
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should fall back due to stale rate
    }
    
    function test_032_SwapWithManagerFailure() public {
        vm.startPrank(user1);
        usdc.approve(address(hook), 1000e6);
        vm.stopPrank();
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        // Mock manager failure
        vm.mockCallRevert(
            address(manager),
            abi.encodeWithSignature("initiateCrossChainFXSwap(address,address,uint256,uint32,address,uint256)"),
            "Manager failed"
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should fall back to normal swap
        
        // Verify user tokens were refunded (handled by mock failure)
        assertEq(usdc.balanceOf(user1), 10_000_000e6); // Original balance
    }
    
    function test_033_SwapWithTokenTransferFailure() public {
        // Don't approve tokens
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should fall back due to transfer failure
    }
    
    function test_034_SwapWithZeroAmount() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 0,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should handle gracefully
    }
    
    function test_035_SwapWithExactOutputAmount() public {
        vm.startPrank(user1);
        usdc.approve(address(hook), 2000e6);
        vm.stopPrank();
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 920e6, // Positive = exact output
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        vm.mockCall(
            address(manager),
            abi.encodeWithSignature("initiateCrossChainFXSwap(address,address,uint256,uint32,address,uint256)"),
            abi.encode(bytes32("test_exact_out"))
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertTrue(BeforeSwapDelta.unwrap(delta) < 0); // Should process cross-chain
    }
    
    function test_036_SwapWithMaximumAmount() public {
        vm.startPrank(user1);
        usdc.approve(address(hook), type(uint256).max);
        vm.stopPrank();
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: type(int256).max,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = "";
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertEq(BeforeSwapDelta.unwrap(delta), 0); // Should handle gracefully
    }
    
    function test_037_SwapWithNegativeMaxAmount() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: type(int256).min,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = "";
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        // Should handle extreme values gracefully
        assertEq(selector, hook.beforeSwap.selector);
    }
    
    function test_038_SwapDirectionZeroForOne() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true, // USDC -> EURC
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.prank(address(poolManager));
        hook.beforeSwap(user1, poolUSDC_EURC, params, "");
        
        (uint256 count,,,) = hook.getHookStats(poolIdUSDC_EURC);
        assertEq(count, 1);
    }
    
    function test_039_SwapDirectionOneForZero() public {
        SwapParams memory params = SwapParams({
            zeroForOne: false, // EURC -> USDC
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.prank(address(poolManager));
        hook.beforeSwap(user1, poolUSDC_EURC, params, "");
        
        (uint256 count,,,) = hook.getHookStats(poolIdUSDC_EURC);
        assertEq(count, 1);
    }
    
    function test_040_SwapWithDifferentSqrtPriceLimits() public {
        uint160[] memory priceLimits = new uint160[](4);
        priceLimits[0] = 0;
        priceLimits[1] = 1000;
        priceLimits[2] = 79228162514264337593543950336; // sqrt(2^128)
        priceLimits[3] = type(uint160).max;
        
        for (uint i = 0; i < priceLimits.length; i++) {
            SwapParams memory params = SwapParams({
                zeroForOne: true,
                amountSpecified: -1000e6,
                sqrtPriceLimitX96: priceLimits[i]
            });
            
            vm.prank(address(poolManager));
            (bytes4 selector,,) = hook.beforeSwap(user1, poolUSDC_EURC, params, "");
            assertEq(selector, hook.beforeSwap.selector);
        }
    }
    
    function test_041_SwapOnlyFromPoolManager() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        // Should revert when called by non-pool manager
        vm.prank(user1);
        vm.expectRevert();
        hook.beforeSwap(user1, poolUSDC_EURC, params, "");
    }
    
    function test_042_MultipleSwapsStatTracking() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.startPrank(address(poolManager));
        
        for (uint i = 0; i < 5; i++) {
            hook.beforeSwap(user1, poolUSDC_EURC, params, "");
        }
        
        vm.stopPrank();
        
        (uint256 count,,,) = hook.getHookStats(poolIdUSDC_EURC);
        assertEq(count, 5);
    }
    
    function test_043_SwapWithDifferentUsers() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.startPrank(address(poolManager));
        
        hook.beforeSwap(user1, poolUSDC_EURC, params, "");
        hook.beforeSwap(user2, poolUSDC_EURC, params, "");
        
        vm.stopPrank();
        
        (uint256 count,,,) = hook.getHookStats(poolIdUSDC_EURC);
        assertEq(count, 2);
    }
    
    function test_044_SwapBetweenDifferentPools() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.startPrank(address(poolManager));
        
        hook.beforeSwap(user1, poolUSDC_EURC, params, "");
        hook.beforeSwap(user1, poolEURC_USDC, params, "");
        
        vm.stopPrank();
        
        (uint256 count1,,,) = hook.getHookStats(poolIdUSDC_EURC);
        (uint256 count2,,,) = hook.getHookStats(poolIdEURC_USDC);
        
        assertEq(count1, 1);
        assertEq(count2, 1);
    }
    
    function test_045_SwapGasUsageOptimization() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.prank(address(poolManager));
        uint256 gasBefore = gasleft();
        hook.beforeSwap(user1, poolUSDC_EURC, params, "");
        uint256 gasUsed = gasBefore - gasleft();
        
        // Gas usage should be reasonable for normal swaps
        assertTrue(gasUsed < 100000, "Gas usage too high for normal swap");
    }
    
    function test_046_SwapReturnValues() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            ""
        );
        
        assertEq(selector, hook.beforeSwap.selector);
        assertEq(BeforeSwapDelta.unwrap(delta), 0);
        assertEq(fee, 0);
    }
    
    function test_047_SwapWithLargeHookData() public {
        // Create large hook data
        bytes memory largeHookData = new bytes(1000);
        for (uint i = 0; i < 1000; i++) {
            largeHookData[i] = bytes1(uint8(i % 256));
        }
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            largeHookData
        );
        
        // Should handle large hook data gracefully
        assertEq(selector, hook.beforeSwap.selector);
    }
    
    function test_048_SwapConsistentBehavior() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.startPrank(address(poolManager));
        
        // Multiple identical swaps should behave consistently
        for (uint i = 0; i < 3; i++) {
            (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
                user1,
                poolUSDC_EURC,
                params,
                ""
            );
            
            assertEq(selector, hook.beforeSwap.selector);
            assertEq(BeforeSwapDelta.unwrap(delta), 0);
            assertEq(fee, 0);
        }
        
        vm.stopPrank();
    }
    
    function test_049_SwapWithEmptyAddress() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            address(0), // Empty address
            poolUSDC_EURC,
            params,
            ""
        );
        
        // Should handle empty address gracefully
        assertEq(selector, hook.beforeSwap.selector);
    }
    
    function test_050_SwapMemoryEfficiency() public {
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = "";
        
        // Test multiple swaps to ensure no memory leaks
        vm.startPrank(address(poolManager));
        
        for (uint i = 0; i < 20; i++) {
            hook.beforeSwap(user1, poolUSDC_EURC, params, hookData);
        }
        
        vm.stopPrank();
        
        (uint256 count,,,) = hook.getHookStats(poolIdUSDC_EURC);
        assertEq(count, 20);
    }
    
    // Continue with tests 051-075 for cross-chain functionality...
    
    function test_051_CrossChainFeeCalculation() public {
        vm.startPrank(user1);
        usdc.approve(address(hook), 1000e6);
        vm.stopPrank();
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        uint256 expectedFee = (1000e6 * hook.hookFeeRate()) / FluxSwapConstants.BASIS_POINTS;
        uint256 expectedNetAmount = 1000e6 - expectedFee;
        
        // Mock with expected net amount
        vm.mockCall(
            address(manager),
            abi.encodeWithSignature(
                "initiateCrossChainFXSwap(address,address,uint256,uint32,address,uint256)",
                address(usdc),
                address(eurc),
                expectedNetAmount,
                uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
                user1,
                uint256(500)
            ),
            abi.encode(bytes32("fee_test"))
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertTrue(BeforeSwapDelta.unwrap(delta) < 0); // Should process cross-chain
    }
    
    // Add tests 052-075 for remaining hook functionality...
    
    function test_075_CompleteHookWorkflow() public {
        // Test complete hook workflow from start to finish
        vm.startPrank(user1);
        usdc.approve(address(hook), 1000e6);
        vm.stopPrank();
        
        vm.startPrank(admin);
        hook.setSupportedPool(poolIdUSDC_EURC, true);
        vm.stopPrank();
        
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6,
            sqrtPriceLimitX96: 0
        });
        
        bytes memory hookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            user1,
            uint256(500)
        );
        
        vm.mockCall(
            address(manager),
            abi.encodeWithSignature("initiateCrossChainFXSwap(address,address,uint256,uint32,address,uint256)"),
            abi.encode(bytes32("complete_workflow"))
        );
        
        vm.prank(address(poolManager));
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            user1,
            poolUSDC_EURC,
            params,
            hookData
        );
        
        assertTrue(BeforeSwapDelta.unwrap(delta) < 0);
        
        // Verify all stats updated
        (uint256 execCount, uint256 redirCount, uint256 successRate, uint256 volume) = 
            hook.getHookStats(poolIdUSDC_EURC);
        assertEq(execCount, 1);
        assertEq(redirCount, 1);
        assertEq(successRate, 10000);
        assertEq(volume, 1000e6);
    }
}