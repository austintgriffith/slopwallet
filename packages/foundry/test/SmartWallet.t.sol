// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../contracts/SmartWallet.sol";

contract SmartWalletTest is Test {
    SmartWallet public wallet;
    address public owner;
    uint256 public ownerPrivateKey;
    address public operator;
    uint256 public operatorPrivateKey;
    address public unauthorized;
    uint256 public unauthorizedPrivateKey;

    // ERC-1271 magic value
    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant INVALID_SIGNATURE = 0xffffffff;

    function setUp() public {
        // Create test accounts
        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);
        
        operatorPrivateKey = 0xB0B;
        operator = vm.addr(operatorPrivateKey);
        
        unauthorizedPrivateKey = 0xBAD;
        unauthorized = vm.addr(unauthorizedPrivateKey);

        // Deploy smart wallet
        wallet = new SmartWallet(owner);

        // Add operator
        vm.prank(owner);
        wallet.addOperator(operator);
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

    function testIsValidSignature_WithOperatorSignature() public {
        // Create a message hash
        bytes32 messageHash = keccak256("Hello from operator!");

        // Sign with operator's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature through smart wallet
        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, ERC1271_MAGIC_VALUE, "Operator signature should be valid");
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

    function testIsValidSignature_AfterOperatorRemoved() public {
        // Create a message hash
        bytes32 messageHash = keccak256("Test after removal");

        // Remove operator
        vm.prank(owner);
        wallet.removeOperator(operator);

        // Sign with operator's private key (who is no longer an operator)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature should fail
        bytes4 result = wallet.isValidSignature(messageHash, signature);

        assertEq(result, INVALID_SIGNATURE, "Removed operator signature should be invalid");
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

    function testIsValidSignature_MultipleValidSigners() public {
        // Test that both owner and operator can sign different messages
        bytes32 ownerMessage = keccak256("Owner's message");
        bytes32 operatorMessage = keccak256("Operator's message");

        // Owner signs their message
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPrivateKey, ownerMessage);
        bytes memory ownerSignature = abi.encodePacked(r1, s1, v1);

        // Operator signs their message
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(operatorPrivateKey, operatorMessage);
        bytes memory operatorSignature = abi.encodePacked(r2, s2, v2);

        // Both should be valid
        assertEq(
            wallet.isValidSignature(ownerMessage, ownerSignature),
            ERC1271_MAGIC_VALUE,
            "Owner signature should be valid"
        );
        assertEq(
            wallet.isValidSignature(operatorMessage, operatorSignature),
            ERC1271_MAGIC_VALUE,
            "Operator signature should be valid"
        );
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
}
