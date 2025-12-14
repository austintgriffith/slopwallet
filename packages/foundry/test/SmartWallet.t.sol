// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../contracts/SmartWallet.sol";
import "../contracts/Clones.sol";

contract SmartWalletTest is Test {
    SmartWallet public wallet;
    SmartWallet public implementation;
    address public owner;
    uint256 public ownerPrivateKey;
    address public unauthorized;
    uint256 public unauthorizedPrivateKey;

    // ERC-1271 magic value
    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant INVALID_SIGNATURE = 0xffffffff;

    function setUp() public {
        // Create test accounts
        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);
        
        unauthorizedPrivateKey = 0xBAD;
        unauthorized = vm.addr(unauthorizedPrivateKey);

        // Deploy implementation (constructor disables initializers)
        implementation = new SmartWallet();
        
        // Deploy a clone (like the Factory does) and initialize it
        address clone = Clones.cloneDeterministic(address(implementation), bytes32(0));
        wallet = SmartWallet(payable(clone));
        wallet.initialize(owner);
    }

    function testIsValidSignature_WithOwnerSignature() public {
        // Create a message hash
        bytes32 messageHash = keccak256("Hello, ERC-1271!");

        // Sign with owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature through smart wallet
        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, ERC1271_MAGIC_VALUE, "Owner signature should be valid");
    }

    function testIsValidSignature_WithUnauthorizedSignature() public {
        // Create a message hash
        bytes32 messageHash = keccak256("Unauthorized message");

        // Sign with unauthorized private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(unauthorizedPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature through smart wallet
        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, INVALID_SIGNATURE, "Unauthorized signature should be invalid");
    }

    function testIsValidSignature_WithInvalidSignature() public {
        // Create a message hash
        bytes32 messageHash = keccak256("Test message");

        // Create invalid signature (wrong format)
        bytes memory invalidSignature = hex"1234";

        // Should revert with ECDSA error
        vm.expectRevert();
        wallet.isValidSignature(messageHash, invalidSignature);
    }

    function testIsValidSignature_PersonalSign() public {
        // Simulate personal_sign message format
        // personal_sign prepends "\x19Ethereum Signed Message:\n" + message length
        string memory message = "Sign this message";
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n",
                "17", // length of "Sign this message"
                message
            )
        );

        // Sign with owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature through smart wallet
        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, ERC1271_MAGIC_VALUE, "Personal sign format should be valid");
    }

    function testIsValidSignature_WrongMessageHash() public {
        // Sign one message but verify with different hash
        bytes32 signedHash = keccak256("Signed message");
        bytes32 differentHash = keccak256("Different message");

        // Sign with owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, signedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify with different hash should fail
        bytes4 result = wallet.isValidSignature(differentHash, signature);

        assertEq(result, INVALID_SIGNATURE, "Signature for different hash should be invalid");
    }

    function testIsValidSignature_EmptySignature() public {
        bytes32 messageHash = keccak256("Test message");
        bytes memory emptySignature = "";

        // Should revert with ECDSA error
        vm.expectRevert();
        wallet.isValidSignature(messageHash, emptySignature);
    }

    function testFuzz_IsValidSignature_OwnerAlwaysValid(bytes32 messageHash) public {
        // Fuzz test: owner signature should always be valid for any message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, ERC1271_MAGIC_VALUE, "Owner signature should always be valid");
    }

    function testFuzz_IsValidSignature_UnauthorizedAlwaysInvalid(bytes32 messageHash) public {
        // Fuzz test: unauthorized signature should always be invalid
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(unauthorizedPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, INVALID_SIGNATURE, "Unauthorized signature should always be invalid");
    }

    // Test passkey registration
    function testAddPasskey() public {
        bytes32 qx = bytes32(uint256(1));
        bytes32 qy = bytes32(uint256(2));
        bytes32 credentialIdHash = keccak256("test-credential");

        vm.prank(owner);
        wallet.addPasskey(qx, qy, credentialIdHash);

        address passkeyAddr = wallet.getPasskeyAddress(qx, qy);
        assertTrue(wallet.isPasskey(passkeyAddr), "Passkey should be registered");
        assertTrue(wallet.passkeyCreated(), "passkeyCreated flag should be true");
    }

    function testAddPasskey_OnlyOwner() public {
        bytes32 qx = bytes32(uint256(1));
        bytes32 qy = bytes32(uint256(2));
        bytes32 credentialIdHash = keccak256("test-credential");

        vm.prank(unauthorized);
        vm.expectRevert();
        wallet.addPasskey(qx, qy, credentialIdHash);
    }

    function testAddPasskey_AlreadyRegistered() public {
        bytes32 qx = bytes32(uint256(1));
        bytes32 qy = bytes32(uint256(2));
        bytes32 credentialIdHash = keccak256("test-credential");

        vm.startPrank(owner);
        wallet.addPasskey(qx, qy, credentialIdHash);
        
        // Try to add same passkey again
        vm.expectRevert(SmartWallet.PasskeyAlreadyRegistered.selector);
        wallet.addPasskey(qx, qy, credentialIdHash);
        vm.stopPrank();
    }

    function testRemovePasskey() public {
        bytes32 qx = bytes32(uint256(1));
        bytes32 qy = bytes32(uint256(2));
        bytes32 credentialIdHash = keccak256("test-credential");

        vm.startPrank(owner);
        wallet.addPasskey(qx, qy, credentialIdHash);
        
        address passkeyAddr = wallet.getPasskeyAddress(qx, qy);
        assertTrue(wallet.isPasskey(passkeyAddr), "Passkey should be registered");
        
        wallet.removePasskey(qx, qy);
        assertFalse(wallet.isPasskey(passkeyAddr), "Passkey should be removed");
        vm.stopPrank();
    }

    function testRemovePasskey_NotRegistered() public {
        bytes32 qx = bytes32(uint256(1));
        bytes32 qy = bytes32(uint256(2));

        vm.prank(owner);
        vm.expectRevert(SmartWallet.PasskeyNotRegistered.selector);
        wallet.removePasskey(qx, qy);
    }

    function testExec_OnlyOwner() public {
        // Fund the wallet
        vm.deal(address(wallet), 1 ether);

        // Owner can exec
        vm.prank(owner);
        wallet.exec(unauthorized, 0.1 ether, "");

        assertEq(unauthorized.balance, 0.1 ether, "Transfer should succeed");
    }

    function testExec_UnauthorizedFails() public {
        vm.deal(address(wallet), 1 ether);

        vm.prank(unauthorized);
        vm.expectRevert();
        wallet.exec(unauthorized, 0.1 ether, "");
    }

    function testBatchExec_OnlyOwner() public {
        vm.deal(address(wallet), 1 ether);

        SmartWallet.Call[] memory calls = new SmartWallet.Call[](2);
        calls[0] = SmartWallet.Call({target: unauthorized, value: 0.1 ether, data: ""});
        calls[1] = SmartWallet.Call({target: owner, value: 0.2 ether, data: ""});

        uint256 ownerBalanceBefore = owner.balance;

        vm.prank(owner);
        wallet.batchExec(calls);

        assertEq(unauthorized.balance, 0.1 ether, "First transfer should succeed");
        assertEq(owner.balance, ownerBalanceBefore + 0.2 ether, "Second transfer should succeed");
    }
}
