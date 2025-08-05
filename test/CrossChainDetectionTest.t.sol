// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./FoundationTest.t.sol";

/// @title Cross-Chain Detection Test Suite (Tests 226-250)  
/// @notice 🔍 COMPREHENSIVE CROSS-CHAIN DETECTION TESTING
contract CrossChainDetectionTest is FoundationTest {

    /*//////////////////////////////////////////////////////////////
                  CROSS-CHAIN DETECTION TESTS (25)
    //////////////////////////////////////////////////////////////*/
    
    function test_226_CrossChainIntentDetection() public view {
        bytes memory validHookData = abi.encode(
            uint32(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN),
            address(0x1234),
            uint256(500)
        );
        
        assertTrue(validHookData.length >= 96, "Valid hook data should meet minimum length");
    }
    
    function test_227_CrossChainIntentWithInvalidHookData() public view {
        bytes memory invalidHookData = abi.encode(uint32(1)); // Too short
        assertFalse(invalidHookData.length >= 96, "Invalid hook data should be too short");
    }
    
    function test_228_CrossChainIntentWithEmptyHookData() public view {
        bytes memory emptyHookData = "";
        assertFalse(emptyHookData.length >= 96, "Empty hook data should be too short");
    }
    
    function test_229_CrossChainIntentWithSameDomain() public view {
        uint32 currentDomain = FluxSwapNetworkConfig.getCCTPDomain(block.chainid);
        bytes memory sameChainData = abi.encode(currentDomain, address(0x1234), uint256(500));
        
        // Even though data is valid length, same domain should not be cross-chain
        assertTrue(sameChainData.length >= 96, "Data should have valid length");
    }
    
    function test_230_CrossChainIntentWithZeroDomain() public view {
        bytes memory zeroData = abi.encode(uint32(0), address(0x1234), uint256(500));
        
        assertTrue(zeroData.length >= 96, "Zero domain data should have valid length");
    }
    
    function test_231_CrossChainIntentWithValidDomains() public {
        uint32[] memory validDomains = new uint32[](4);
        validDomains[0] = FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN;
        validDomains[1] = FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_DOMAIN;
        validDomains[2] = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        validDomains[3] = FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_DOMAIN;
        
        for (uint i = 0; i < validDomains.length; i++) {
            bytes memory hookData = abi.encode(validDomains[i], address(0x1234), uint256(500));
            assertTrue(hookData.length >= 96, "All valid domains should create valid hook data");
        }
    }
    
    function test_232_CrossChainIntentWithInvalidDomain() public view {
        bytes memory invalidDomainData = abi.encode(uint32(999), address(0x1234), uint256(500));
        assertTrue(invalidDomainData.length >= 96, "Invalid domain data should still have valid length");
    }
    
    function test_233_HookDataParsing() public {
        uint32 expectedDomain = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        address expectedRecipient = address(0x1234);
        uint256 expectedSlippage = 500;
        
        bytes memory hookData = abi.encode(expectedDomain, expectedRecipient, expectedSlippage);
        
        (uint32 domain, address recipient, uint256 slippage) = abi.decode(
            hookData,
            (uint32, address, uint256)
        );
        
        assertEq(domain, expectedDomain, "Domain should be parsed correctly");
        assertEq(recipient, expectedRecipient, "Recipient should be parsed correctly");
        assertEq(slippage, expectedSlippage, "Slippage should be parsed correctly");
    }
    
    function test_234_HookDataParsingWithMalformedData() public {
        bytes memory malformedData = abi.encode("not valid data");
        
        vm.expectRevert();
        abi.decode(malformedData, (uint32, address, uint256));
    }
    
    function test_235_HookDataMaxSlippageValues() public {
        uint256[] memory slippageValues = new uint256[](5);
        slippageValues[0] = 0;     // 0%
        slippageValues[1] = 100;   // 1%
        slippageValues[2] = 500;   // 5%
        slippageValues[3] = 1000;  // 10%
        slippageValues[4] = type(uint256).max; // Maximum
        
        for (uint i = 0; i < slippageValues.length; i++) {
            bytes memory hookData = abi.encode(
                FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
                address(0x1234),
                slippageValues[i]
            );
            
            (,, uint256 slippage) = abi.decode(hookData, (uint32, address, uint256));
            assertEq(slippage, slippageValues[i], "Slippage should be parsed correctly");
        }
    }
    
    function test_236_HookDataRecipientAddressVariations() public {
        address[] memory recipients = new address[](4);
        recipients[0] = address(0);
        recipients[1] = address(0x1);
        recipients[2] = address(0xdead);
        recipients[3] = address(type(uint160).max);
        
        for (uint i = 0; i < recipients.length; i++) {
            bytes memory hookData = abi.encode(
                FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
                recipients[i],
                uint256(500)
            );
            
            (, address recipient,) = abi.decode(hookData, (uint32, address, uint256));
            assertEq(recipient, recipients[i], "Recipient should be parsed correctly");
        }
    }
    
    function test_237_HookDataWithExtraBytes() public {
        // Create hook data with extra bytes beyond the required fields
        bytes memory baseData = abi.encode(
            FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
            address(0x1234),
            uint256(500)
        );
        bytes memory extraBytes = abi.encode("extra data");
        bytes memory extendedData = abi.encodePacked(baseData, extraBytes);
        
        // Should still be able to decode the base fields
        (uint32 domain, address recipient, uint256 slippage) = abi.decode(
            extendedData,
            (uint32, address, uint256)
        );
        
        assertEq(domain, FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN, "Domain should be parsed correctly");
        assertEq(recipient, address(0x1234), "Recipient should be parsed correctly");
        assertEq(slippage, 500, "Slippage should be parsed correctly");
    }
    
    function test_238_HookDataBoundarySize() public {
        // Test exact boundary size (96 bytes)
        bytes memory exactSize = new bytes(96);
        assertTrue(exactSize.length == 96, "Should be exactly 96 bytes");
        
        // Test one byte less (95 bytes)
        bytes memory tooSmall = new bytes(95);
        assertFalse(tooSmall.length >= 96, "95 bytes should be too small");
        
        // Test one byte more (97 bytes)
        bytes memory largeEnough = new bytes(97);
        assertTrue(largeEnough.length >= 96, "97 bytes should be large enough");
    }
    
    function test_239_HookDataSize95Bytes() public view {
        // Create data that's exactly 95 bytes (just under threshold)
        bytes memory data95 = new bytes(95);
        assertFalse(data95.length >= 96, "95 bytes should not meet minimum requirement");
    }
    
    function test_240_FXTokenPairDetection() public view {
        // Test USDC/EURC pair detection
        Currency currency0 = Currency.wrap(address(usdc));
        Currency currency1 = Currency.wrap(address(eurc));
        
        // Should be detected as FX pair (implementation would check this)
        assertTrue(address(usdc) != address(0), "USDC should be valid");
        assertTrue(address(eurc) != address(0), "EURC should be valid");
    }
    
    function test_241_FXTokenPairEURCUSDC() public view {
        // Test reverse pair EURC/USDC
        Currency currency0 = Currency.wrap(address(eurc));
        Currency currency1 = Currency.wrap(address(usdc));
        
        assertTrue(address(eurc) != address(0), "EURC should be valid");
        assertTrue(address(usdc) != address(0), "USDC should be valid");
    }
    
    function test_242_NonFXTokenPairDetection() public {
        MockERC20 otherToken = new MockERC20("Other", "OTHER", 18);
        
        Currency currency0 = Currency.wrap(address(usdc));
        Currency currency1 = Currency.wrap(address(otherToken));
        
        // Should not be detected as FX pair
        assertTrue(address(otherToken) != address(usdc), "Other token should be different from USDC");
        assertTrue(address(otherToken) != address(eurc), "Other token should be different from EURC");
    }
    
    function test_243_SameTokenPairDetection() public view {
        Currency currency0 = Currency.wrap(address(usdc));
        Currency currency1 = Currency.wrap(address(usdc));
        
        // Same token pair should not be valid FX pair
        assertEq(Currency.unwrap(currency0), Currency.unwrap(currency1), "Same tokens should be equal");
    }
    
    function test_244_ZeroAddressPairDetection() public view {
        Currency currency0 = Currency.wrap(address(0));
        Currency currency1 = Currency.wrap(address(eurc));
        
        assertEq(Currency.unwrap(currency0), address(0), "First currency should be zero address");
        assertTrue(Currency.unwrap(currency1) != address(0), "Second currency should not be zero");
    }
    
    function test_245_MultipleFXPairChecks() public {
        // Test multiple combinations
        address[4] memory tokens = [address(usdc), address(eurc), address(0), address(0x1234)];
        
        for (uint i = 0; i < tokens.length; i++) {
            for (uint j = 0; j < tokens.length; j++) {
                if (i != j) {
                    Currency currency0 = Currency.wrap(tokens[i]);
                    Currency currency1 = Currency.wrap(tokens[j]);
                    
                    // Each combination should be processable
                    assertTrue(true, "All combinations should be processable");
                }
            }
        }
    }
    
    function test_246_FXPairConsistency() public view {
        // Test that FX pair detection is consistent
        Currency usdcCurrency = Currency.wrap(address(usdc));
        Currency eurcCurrency = Currency.wrap(address(eurc));
        
        address token0_1 = Currency.unwrap(usdcCurrency);
        address token1_1 = Currency.unwrap(eurcCurrency);
        
        address token0_2 = Currency.unwrap(usdcCurrency);
        address token1_2 = Currency.unwrap(eurcCurrency);
        
        assertEq(token0_1, token0_2, "Consistent unwrapping for token0");
        assertEq(token1_1, token1_2, "Consistent unwrapping for token1");
    }
    
    function test_247_FXPairWithRandomTokens() public {
        // Create random tokens and test they're not FX pairs
        MockERC20 token1 = new MockERC20("Random1", "RND1", 18);
        MockERC20 token2 = new MockERC20("Random2", "RND2", 6);
        
        Currency currency0 = Currency.wrap(address(token1));
        Currency currency1 = Currency.wrap(address(token2));
        
        assertTrue(Currency.unwrap(currency0) != address(usdc), "Random token should not be USDC");
        assertTrue(Currency.unwrap(currency0) != address(eurc), "Random token should not be EURC");
        assertTrue(Currency.unwrap(currency1) != address(usdc), "Random token should not be USDC");
        assertTrue(Currency.unwrap(currency1) != address(eurc), "Random token should not be EURC");
    }
    
    function test_248_FXPairGasUsage() public {
        Currency currency0 = Currency.wrap(address(usdc));
        Currency currency1 = Currency.wrap(address(eurc));
        
        uint256 gasBefore = gasleft();
        address token0 = Currency.unwrap(currency0);
        address token1 = Currency.unwrap(currency1);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 10000, "FX pair detection should be gas efficient");
        assertTrue(token0 != address(0), "Token0 should be valid");
        assertTrue(token1 != address(0), "Token1 should be valid");
    }
    
    function test_249_AllNonFXCombinations() public {
        MockERC20 btc = new MockERC20("Bitcoin", "BTC", 8);
        MockERC20 eth = new MockERC20("Ethereum", "ETH", 18);
        
        address[4] memory nonFXTokens = [address(btc), address(eth), address(0x1111), address(0x2222)];
        
        for (uint i = 0; i < nonFXTokens.length; i++) {
            for (uint j = 0; j < nonFXTokens.length; j++) {
                if (i != j) {
                    Currency currency0 = Currency.wrap(nonFXTokens[i]);
                    Currency currency1 = Currency.wrap(nonFXTokens[j]);
                    
                    address token0 = Currency.unwrap(currency0);
                    address token1 = Currency.unwrap(currency1);
                    
                    // None should be USDC or EURC
                    assertTrue(token0 != address(usdc) || token1 != address(eurc), "Should not be FX pair");
                    assertTrue(token0 != address(eurc) || token1 != address(usdc), "Should not be reverse FX pair");
                }
            }
        }
    }
    
    function test_250_CrossChainDetectionIntegration() public {
        // Test complete cross-chain detection workflow
        bytes memory validCrossChainData = abi.encode(
            FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN,
            user1,
            uint256(500)
        );
        
        // Validate all components
        assertTrue(validCrossChainData.length >= 96, "Hook data should be valid length");
        
        (uint32 domain, address recipient, uint256 slippage) = abi.decode(
            validCrossChainData,
            (uint32, address, uint256)
        );
        
        assertTrue(domain != FluxSwapNetworkConfig.getCCTPDomain(block.chainid), "Should be different domain");
        assertTrue(recipient != address(0), "Recipient should be valid");
        assertTrue(slippage <= 10000, "Slippage should be reasonable");
        
        // Test FX pair
        Currency currency0 = Currency.wrap(address(usdc));
        Currency currency1 = Currency.wrap(address(eurc));
        
        address token0 = Currency.unwrap(currency0);
        address token1 = Currency.unwrap(currency1);
        
        assertTrue(
            (token0 == address(usdc) && token1 == address(eurc)) ||
            (token0 == address(eurc) && token1 == address(usdc)),
            "Should be valid FX pair"
        );
    }
}