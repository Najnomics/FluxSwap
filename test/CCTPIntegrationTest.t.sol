// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./FoundationTest.t.sol";

/// @title CCTP Integration Test Suite (Tests 201-225)
/// @notice 🌐 COMPREHENSIVE CCTP INTEGRATION TESTING
contract CCTPIntegrationTest is FoundationTest {

    /*//////////////////////////////////////////////////////////////
                      CCTP INTEGRATION TESTS (25)
    //////////////////////////////////////////////////////////////*/
    
    function test_201_CCTPManagerSetup() public view {
        assertEq(address(cctp.fluxSwapManager()), address(manager), "FluxSwap manager should be set");
        assertTrue(cctp.hasRole(cctp.MANAGER_ROLE(), address(manager)), "Manager should have MANAGER_ROLE");
    }
    
    function test_202_CCTPDomainConfiguration() public view {
        // Test that CCTP domain mappings are configured
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(1), FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN);
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(11155111), FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN);
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(84532), FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN);
    }
    
    function test_203_CCTPSupportedChains() public view {
        assertTrue(FluxSwapNetworkConfig.isChainSupported(1), "Foundry chain should be supported");
        assertTrue(FluxSwapNetworkConfig.isChainSupported(11155111), "Ethereum Sepolia should be supported");
        assertTrue(FluxSwapNetworkConfig.isChainSupported(84532), "Base Sepolia should be supported");
        assertFalse(FluxSwapNetworkConfig.isChainSupported(999999), "Random chain should not be supported");
    }
    
    function test_204_CCTPTokenMessengerAddress() public view {
        assertEq(cctp.tokenMessenger(), FluxSwapNetworkConfig.TOKEN_MESSENGER, "Token messenger should be configured");
    }
    
    function test_205_CCTPMessageTransmitterAddress() public view {
        assertEq(cctp.messageTransmitter(), FluxSwapNetworkConfig.MESSAGE_TRANSMITTER, "Message transmitter should be configured");
    }
    
    function test_206_CCTPManagerRoleValidation() public view {
        assertTrue(cctp.hasRole(cctp.MANAGER_ROLE(), address(manager)), "Manager should have MANAGER_ROLE");
        assertFalse(cctp.hasRole(cctp.MANAGER_ROLE(), user1), "User should not have MANAGER_ROLE");
    }
    
    function test_207_CCTPAdminRoleValidation() public view {
        assertTrue(cctp.hasRole(cctp.DEFAULT_ADMIN_ROLE(), admin), "Admin should have DEFAULT_ADMIN_ROLE");
        assertFalse(cctp.hasRole(cctp.DEFAULT_ADMIN_ROLE(), user1), "User should not have DEFAULT_ADMIN_ROLE");
    }
    
    function test_208_CCTPManagerUpdate() public {
        address newManager = address(0x5001);
        
        vm.prank(admin);
        cctp.setFluxSwapManager(newManager);
        
        assertEq(address(cctp.fluxSwapManager()), newManager, "Manager should be updated");
        assertTrue(cctp.hasRole(cctp.MANAGER_ROLE(), newManager), "New manager should have role");
    }
    
    function test_209_CCTPManagerUpdateUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        cctp.setFluxSwapManager(address(0x5002));
    }
    
    function test_210_CCTPManagerUpdateZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert("Invalid manager address");
        cctp.setFluxSwapManager(address(0));
    }
    
    function test_211_CCTPFastTransferInitiation() public {
        uint256 amount = 1000e6;
        uint32 destinationDomain = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        bytes32 recipient = bytes32(uint256(uint160(user1)));
        bytes memory hookData = abi.encode("test hook data");
        
        // Mock the token messenger call
        vm.mockCall(
            cctp.tokenMessenger(),
            abi.encodeWithSignature("depositForBurnWithCaller(uint256,uint32,bytes32,address,bytes32)"),
            abi.encode(uint64(12345))
        );
        
        vm.prank(address(manager));
        uint64 nonce = cctp.initiateFastTransfer(amount, destinationDomain, recipient, hookData);
        
        assertEq(nonce, 12345, "Should return mocked nonce");
    }
    
    function test_212_CCTPFastTransferUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        cctp.initiateFastTransfer(1000e6, FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN, bytes32(0), "");
    }
    
    function test_213_CCTPMessageReceiving() public {
        bytes memory message = abi.encode("test message");
        bytes memory attestation = abi.encode("test attestation");
        
        // Mock the message transmitter call
        vm.mockCall(
            cctp.messageTransmitter(),
            abi.encodeWithSignature("receiveMessage(bytes,bytes)"),
            abi.encode(true)
        );
        
        bool success = cctp.receiveMessage(message, attestation);
        assertTrue(success, "Message receiving should succeed");
    }
    
    function test_214_CCTPHookExecution() public {
        uint32 sourceDomain = FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN;
        bytes32 sender = bytes32(uint256(uint160(address(manager))));
        bytes memory messageBody = abi.encode(
            address(eurc),     // target token
            user1,             // recipient
            920000000000000000, // expected rate
            block.timestamp + 300 // expiry
        );
        
        // Should not revert
        cctp.executeHookAction(sourceDomain, sender, messageBody);
    }
    
    function test_215_CCTPDomainMapping() public view {
        // Test all supported domain mappings
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN);
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_DOMAIN);
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(FluxSwapNetworkConfig.BASE_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN);
        assertEq(FluxSwapNetworkConfig.getCCTPDomain(FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_DOMAIN);
    }
    
    function test_216_CCTPUSDCAddressMapping() public view {
        // Test USDC address mappings for different chains
        assertEq(FluxSwapNetworkConfig.getUSDCAddress(FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.USDC_SEPOLIA);
        assertEq(FluxSwapNetworkConfig.getUSDCAddress(FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.USDC_ARBITRUM_SEPOLIA);
        assertEq(FluxSwapNetworkConfig.getUSDCAddress(FluxSwapNetworkConfig.BASE_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.USDC_BASE_SEPOLIA);
        assertEq(FluxSwapNetworkConfig.getUSDCAddress(FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_CHAIN_ID), 
                FluxSwapNetworkConfig.USDC_OPTIMISM_SEPOLIA);
    }
    
    function test_217_CCTPChainNameMapping() public view {
        assertEq(FluxSwapNetworkConfig.getChainName(FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_CHAIN_ID), "Ethereum Sepolia");
        assertEq(FluxSwapNetworkConfig.getChainName(FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_CHAIN_ID), "Arbitrum Sepolia");
        assertEq(FluxSwapNetworkConfig.getChainName(FluxSwapNetworkConfig.BASE_SEPOLIA_CHAIN_ID), "Base Sepolia");
        assertEq(FluxSwapNetworkConfig.getChainName(FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_CHAIN_ID), "Optimism Sepolia");
        assertEq(FluxSwapNetworkConfig.getChainName(999999), "Unknown Chain");
    }
    
    function test_218_CCTPTransferTracking() public {
        uint256 amount = 1000e6;
        uint32 destinationDomain = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        bytes32 recipient = bytes32(uint256(uint160(user1)));
        bytes memory hookData = abi.encode("tracking test");
        
        vm.mockCall(
            cctp.tokenMessenger(),
            abi.encodeWithSignature("depositForBurnWithCaller(uint256,uint32,bytes32,address,bytes32)"),
            abi.encode(uint64(54321))
        );
        
        vm.prank(address(manager));
        uint64 nonce = cctp.initiateFastTransfer(amount, destinationDomain, recipient, hookData);
        
        // Verify transfer is tracked
        (address sender, uint256 trackedAmount, uint32 trackedDomain, bytes memory trackedHookData, uint256 timestamp, bool completed) = 
            cctp.transfers(nonce);
        
        assertEq(sender, address(manager), "Sender should be tracked");
        assertEq(trackedAmount, amount, "Amount should be tracked");
        assertEq(trackedDomain, destinationDomain, "Domain should be tracked");
        assertTrue(timestamp > 0, "Timestamp should be set");
        assertFalse(completed, "Should not be completed yet");
    }
    
    function test_219_CCTPFastTransferEvent() public {
        uint256 amount = 2000e6;
        uint32 destinationDomain = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        bytes32 recipient = bytes32(uint256(uint160(user2)));
        bytes memory hookData = abi.encode("event test");
        
        vm.mockCall(
            cctp.tokenMessenger(),
            abi.encodeWithSignature("depositForBurnWithCaller(uint256,uint32,bytes32,address,bytes32)"),
            abi.encode(uint64(98765))
        );
        
        vm.expectEmit(true, true, false, true);
        emit FastTransferInitiated(98765, address(manager), amount, destinationDomain);
        
        vm.prank(address(manager));
        cctp.initiateFastTransfer(amount, destinationDomain, recipient, hookData);
    }
    
    function test_220_CCTPMessageCompletionEvent() public {
        bytes memory message = abi.encode("completion test");
        bytes memory attestation = abi.encode("completion attestation");
        
        vm.mockCall(
            cctp.messageTransmitter(),
            abi.encodeWithSignature("receiveMessage(bytes,bytes)"),
            abi.encode(true)
        );
        
        vm.expectEmit(true, false, false, true);
        emit FastTransferCompleted(0, true);
        
        cctp.receiveMessage(message, attestation);
    }
    
    function test_221_CCTPUnsupportedDestination() public {
        vm.mockCall(
            cctp.tokenMessenger(),
            abi.encodeWithSignature("depositForBurnWithCaller(uint256,uint32,bytes32,address,bytes32)"),
            abi.encode(uint64(11111))
        );
        
        vm.prank(address(manager));
        vm.expectRevert("Unsupported destination");
        cctp.initiateFastTransfer(1000e6, 999, bytes32(0), "");
    }
    
    function test_222_CCTPHookDataValidation() public {
        uint32 sourceDomain = FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN;
        bytes32 sender = bytes32(uint256(uint160(address(manager))));
        
        // Hook data with expired timestamp
        bytes memory expiredMessageBody = abi.encode(
            address(eurc),
            user1,
            920000000000000000,
            block.timestamp - 100 // Expired
        );
        
        vm.expectRevert("Hook action expired");
        cctp.executeHookAction(sourceDomain, sender, expiredMessageBody);
    }
    
    function test_223_CCTPConstants() public view {
        // Verify CCTP constants are properly set
        assertEq(FluxSwapNetworkConfig.TOKEN_MESSENGER, 0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5);
        assertEq(FluxSwapNetworkConfig.MESSAGE_TRANSMITTER, 0x2703483B1a5a7c577e8680de9Df8Be03c6f30e3c);
        assertTrue(bytes(FluxSwapNetworkConfig.ATTESTATION_API_BASE).length > 0);
    }
    
    function test_224_CCTPNetworkConfiguration() public view {
        // Test all network constants
        assertEq(FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_DOMAIN, 0);
        assertEq(FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_DOMAIN, 2);
        assertEq(FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_DOMAIN, 3);
        assertEq(FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN, 6);
        assertEq(FluxSwapNetworkConfig.FOUNDRY_ANVIL_DOMAIN, 999);
        
        assertEq(FluxSwapNetworkConfig.ETHEREUM_SEPOLIA_CHAIN_ID, 11155111);
        assertEq(FluxSwapNetworkConfig.OPTIMISM_SEPOLIA_CHAIN_ID, 11155420);
        assertEq(FluxSwapNetworkConfig.ARBITRUM_SEPOLIA_CHAIN_ID, 421614);
        assertEq(FluxSwapNetworkConfig.BASE_SEPOLIA_CHAIN_ID, 84532);
        assertEq(FluxSwapNetworkConfig.FOUNDRY_ANVIL_CHAIN_ID, 1);
    }
    
    function test_225_CCTPIntegrationGasOptimization() public {
        uint256 amount = 1000e6;
        uint32 destinationDomain = FluxSwapNetworkConfig.BASE_SEPOLIA_DOMAIN;
        bytes32 recipient = bytes32(uint256(uint160(user1)));
        bytes memory hookData = abi.encode("gas test");
        
        vm.mockCall(
            cctp.tokenMessenger(),
            abi.encodeWithSignature("depositForBurnWithCaller(uint256,uint32,bytes32,address,bytes32)"),
            abi.encode(uint64(77777))
        );
        
        vm.prank(address(manager));
        uint256 gasBefore = gasleft();
        cctp.initiateFastTransfer(amount, destinationDomain, recipient, hookData);
        uint256 gasUsed = gasBefore - gasleft();
        
        assertTrue(gasUsed < 150000, "CCTP operations should be gas efficient");
    }
    
    // Events for testing
    event FastTransferInitiated(
        uint64 indexed nonce,
        address indexed sender,
        uint256 amount,
        uint32 destinationDomain
    );
    
    event FastTransferCompleted(
        uint64 indexed nonce,
        bool success
    );
}