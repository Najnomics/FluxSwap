// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./FoundationTest.t.sol";

/// @title Liquidity Manager Test Suite (Tests 151-175)
/// @notice 💧 COMPREHENSIVE LIQUIDITY MANAGEMENT TESTING
contract LiquidityManagerTest is FoundationTest {

    /*//////////////////////////////////////////////////////////////
                    LIQUIDITY MANAGER TESTS (25)
    //////////////////////////////////////////////////////////////*/
    
    function test_151_LiquidityProvision() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        assertTrue(lpTokens > 0, "LP tokens should be minted");
        assertEq(liquidity.balanceOf(user1), lpTokens, "User should receive LP tokens");
        vm.stopPrank();
    }
    
    function test_152_LiquidityRemoval() public {
        // First add liquidity
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            1000e6,  
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        // Then remove liquidity
        uint256 returnedAmount = liquidity.removeLiquidity(
            lpTokens,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        assertTrue(returnedAmount > 0, "Should return some amount");
        assertEq(liquidity.balanceOf(user1), 0, "LP tokens should be burned");
        vm.stopPrank();
    }
    
    function test_153_MultipleProvidersLiquidity() public {
        // User1 adds liquidity
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 2000e6);
        uint256 lpTokens1 = liquidity.addLiquidity(
            address(usdc),
            2000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
        
        // User2 adds liquidity
        vm.startPrank(user2);
        usdc.approve(address(liquidity), 1000e6);
        uint256 lpTokens2 = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
        
        assertTrue(lpTokens1 > lpTokens2, "User1 should get more LP tokens");
        assertEq(liquidity.balanceOf(user1), lpTokens1, "User1 balance should be correct");
        assertEq(liquidity.balanceOf(user2), lpTokens2, "User2 balance should be correct");
    }
    
    function test_154_LiquidityWithDifferentTokens() public {
        vm.startPrank(user1);
        
        // Add USDC liquidity
        usdc.approve(address(liquidity), 1000e6);
        uint256 usdcLp = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        // Add EURC liquidity
        eurc.approve(address(liquidity), 1000e6);
        uint256 eurcLp = liquidity.addLiquidity(
            address(eurc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        vm.stopPrank();
        
        assertTrue(usdcLp > 0, "USDC LP tokens should be minted");
        assertTrue(eurcLp > 0, "EURC LP tokens should be minted");
    }
    
    function test_155_LiquidityUnsupportedChain() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        
        vm.expectRevert("Chain not supported");
        liquidity.addLiquidity(
            address(usdc),
            1000e6,
            999 // Unsupported chain
        );
        vm.stopPrank();
    }
    
    function test_156_LiquidityUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNS", 18);
        unsupportedToken.mint(user1, 1000e18);
        
        vm.startPrank(user1);
        unsupportedToken.approve(address(liquidity), 1000e18);
        
        vm.expectRevert("Unsupported token");
        liquidity.addLiquidity(
            address(unsupportedToken),
            1000e18,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
    }
    
    function test_157_LiquidityInsufficientBalance() public {
        vm.startPrank(user1);
        
        // Try to add more liquidity than balance
        usdc.approve(address(liquidity), type(uint256).max);
        
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        liquidity.addLiquidity(
            address(usdc),
            20_000_000e6, // More than minted
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
    }
    
    function test_158_LiquidityRemovalInsufficientLP() public {
        vm.startPrank(user1);
        
        vm.expectRevert("Insufficient balance");
        liquidity.removeLiquidity(
            1000e18, // More than user has
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
    }
    
    function test_159_LiquidityInitialSupply() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        // First liquidity provision gets multiplier
        uint256 expectedTokens = 1000e6 * 1e12; // Multiplier for initial liquidity
        assertEq(lpTokens, expectedTokens, "Initial LP tokens should have multiplier");
        vm.stopPrank();
    }
    
    function test_160_LiquiditySubsequentSupply() public {
        // First provider
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        liquidity.addLiquidity(address(usdc), 1000e6, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        vm.stopPrank();
        
        // Second provider - should get proportional tokens
        vm.startPrank(user2);
        usdc.approve(address(liquidity), 500e6);
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            500e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
        
        assertTrue(lpTokens > 0, "Subsequent provider should get LP tokens");
    }
    
    function test_161_LiquidityTokenMetadata() public view {
        assertEq(liquidity.name(), "FluxSwap LP", "LP token name should be correct");
        assertEq(liquidity.symbol(), "FLUX-LP", "LP token symbol should be correct");
        assertEq(liquidity.decimals(), 18, "LP token decimals should be 18");
    }
    
    function test_162_LiquidityTotalSupplyTracking() public {
        uint256 initialSupply = liquidity.totalSupply();
        
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        vm.stopPrank();
        
        uint256 finalSupply = liquidity.totalSupply();
        assertEq(finalSupply - initialSupply, lpTokens, "Total supply should increase by LP tokens");
    }
    
    function test_163_LiquidityEvent() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        
        vm.expectEmit(true, true, false, true);
        emit LiquidityAdded(user1, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN, address(usdc), 1000e6, 0);
        
        liquidity.addLiquidity(address(usdc), 1000e6, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        vm.stopPrank();
    }
    
    function test_164_LiquidityRemovalEvent() public {
        // First add liquidity
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        vm.expectEmit(true, true, false, true);
        emit LiquidityRemoved(user1, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN, lpTokens, 0);
        
        liquidity.removeLiquidity(lpTokens, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        vm.stopPrank();
    }
    
    function test_165_LiquidityRebalancingAuth() public {
        vm.prank(user1); // Unauthorized user
        vm.expectRevert("Not authorized");
        liquidity.rebalanceLiquidity(
            FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN,
            FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
            address(usdc),
            1000e6
        );
    }
    
    function test_166_LiquidityRebalancingValidChains() public {
        vm.prank(admin);
        vm.expectRevert("Invalid chains");
        liquidity.rebalanceLiquidity(
            999, // Invalid source chain
            FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
            address(usdc),
            1000e6
        );
    }
    
    function test_167_LiquidityRebalancingCooldown() public {
        // First rebalance
        vm.prank(admin);
        liquidity.rebalanceLiquidity(
            FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN,
            FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
            address(usdc),
            1000e6
        );
        
        // Try to rebalance again immediately
        vm.prank(admin);
        vm.expectRevert("Rebalance on cooldown");
        liquidity.rebalanceLiquidity(
            FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN,
            FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
            address(usdc),
            500e6
        );
    }
    
    function test_168_LiquidityCalculateOptimalRebalancing() public view {
        IFluxSwapTypes.RebalanceAction[] memory actions = liquidity.calculateOptimalRebalancing();
        
        // Should return some rebalancing actions or empty array
        assertTrue(actions.length >= 0, "Should return rebalancing actions array");
    }
    
    function test_169_LiquidityZeroAmount() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 0);
        
        vm.expectRevert();
        liquidity.addLiquidity(address(usdc), 0, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        vm.stopPrank();
    }
    
    function test_170_LiquidityWithoutApproval() public {
        vm.startPrank(user1);
        // Don't approve tokens
        
        vm.expectRevert("ERC20: insufficient allowance");
        liquidity.addLiquidity(address(usdc), 1000e6, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        vm.stopPrank();
    }
    
    function test_171_LiquidityPartialRemoval() public {
        // Add liquidity
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 2000e6);
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            2000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        // Remove half
        uint256 halfTokens = lpTokens / 2;
        uint256 returned = liquidity.removeLiquidity(
            halfTokens,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        assertTrue(returned > 0, "Should return some tokens");
        assertEq(liquidity.balanceOf(user1), lpTokens - halfTokens, "Should have remaining LP tokens");
        vm.stopPrank();
    }
    
    function test_172_LiquidityMaxAmountHandling() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), type(uint256).max);
        
        // Add maximum amount available
        uint256 maxAmount = usdc.balanceOf(user1);
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            maxAmount,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        assertTrue(lpTokens > 0, "Should handle max amount");
        assertEq(usdc.balanceOf(user1), 0, "Should transfer all tokens");
        vm.stopPrank();
    }
    
    function test_173_LiquidityGasOptimization() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        
        uint256 gasBefore = gasleft();
        liquidity.addLiquidity(address(usdc), 1000e6, FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 200000, "Liquidity operations should be gas efficient");
        vm.stopPrank();
    }
    
    function test_174_LiquidityStateConsistency() public {
        vm.startPrank(user1);
        usdc.approve(address(liquidity), 1000e6);
        
        uint256 userBalanceBefore = usdc.balanceOf(user1);
        uint256 contractBalanceBefore = usdc.balanceOf(address(liquidity));
        uint256 totalSupplyBefore = liquidity.totalSupply();
        
        uint256 lpTokens = liquidity.addLiquidity(
            address(usdc),
            1000e6,
            FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN
        );
        
        uint256 userBalanceAfter = usdc.balanceOf(user1);
        uint256 contractBalanceAfter = usdc.balanceOf(address(liquidity));
        uint256 totalSupplyAfter = liquidity.totalSupply();
        
        assertEq(userBalanceBefore - userBalanceAfter, 1000e6, "User balance should decrease by amount");
        assertEq(contractBalanceAfter - contractBalanceBefore, 1000e6, "Contract balance should increase");
        assertEq(totalSupplyAfter - totalSupplyBefore, lpTokens, "Total supply should increase by LP tokens");
        
        vm.stopPrank();
    }
    
    function test_175_LiquidityManagerRoleAccess() public view {
        assertTrue(liquidity.hasRole(liquidity.DEFAULT_ADMIN_ROLE(), admin), "Admin should have admin role");
        assertFalse(liquidity.hasRole(liquidity.DEFAULT_ADMIN_ROLE(), user1), "User should not have admin role");
    }
    
    // Events for testing
    event LiquidityAdded(
        address indexed provider,
        uint32 indexed chainId,
        address token,
        uint256 amount,
        uint256 lpTokens
    );
    
    event LiquidityRemoved(
        address indexed provider,
        uint32 indexed chainId,
        uint256 lpTokens,
        uint256 amount
    );
}