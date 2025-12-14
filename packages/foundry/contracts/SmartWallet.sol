//SPDX-License-Identifier: MIT
pragma solidity >=0.8.24 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol"; // Only needed for EOA metaExec
import "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @title SmartWallet
 * @notice A minimal smart contract wallet that allows an owner to execute arbitrary calls
 * @notice Supports ERC-1271 signature validation for off-chain signing
 * @author BuidlGuidl
 */
contract SmartWallet is Ownable, IERC1271, Initializable {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    // Nonce for replay protection (keyed by passkey address)
    mapping(address => uint256) public nonces;

    // Passkey public key storage (keyed by derived address)
    // If passkeyQx[addr] != 0, then addr is a registered passkey
    mapping(address => bytes32) public passkeyQx;
    mapping(address => bytes32) public passkeyQy;

    // Track if any passkey has been created (controls frontend CTA)
    bool public passkeyCreated;

    // Map credentialId hash to passkey address for login lookup
    mapping(bytes32 => address) public credentialIdToAddress;

    event Executed(address indexed target, uint256 value, bytes data);
    event PasskeyAdded(address indexed passkeyAddress, bytes32 qx, bytes32 qy);
    event PasskeyRemoved(address indexed passkeyAddress);
    event MetaExecuted(address indexed passkey, address indexed target, uint256 value, bytes data);

    error NotAuthorized();
    error ExecutionFailed();
    error InvalidSignature();
    error ExpiredSignature();
    error PasskeyAlreadyRegistered();
    error PasskeyNotRegistered();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(address(1)) {
        _disableInitializers();
    }

    /**
     * @notice Initialize the wallet with an owner (called by Factory on clone deployment)
     * @param _owner The address of the wallet owner
     */
    function initialize(address _owner) external initializer {
        _transferOwnership(_owner);
    }

    /**
     * @notice Derive a deterministic address from passkey public key coordinates
     * @param qx The x-coordinate of the passkey public key
     * @param qy The y-coordinate of the passkey public key
     * @return The derived address
     */
    function getPasskeyAddress(bytes32 qx, bytes32 qy) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(qx, qy)))));
    }

    /**
     * @notice Add a passkey
     * @param qx The x-coordinate of the passkey public key
     * @param qy The y-coordinate of the passkey public key
     * @param credentialIdHash The keccak256 hash of the WebAuthn credentialId for login lookup
     */
    function addPasskey(bytes32 qx, bytes32 qy, bytes32 credentialIdHash) external onlyOwner {
        address passkeyAddr = getPasskeyAddress(qx, qy);
        if (passkeyQx[passkeyAddr] != bytes32(0)) revert PasskeyAlreadyRegistered();

        passkeyQx[passkeyAddr] = qx;
        passkeyQy[passkeyAddr] = qy;
        credentialIdToAddress[credentialIdHash] = passkeyAddr;

        // Set flag on first passkey
        if (!passkeyCreated) {
            passkeyCreated = true;
        }

        emit PasskeyAdded(passkeyAddr, qx, qy);
    }

    /**
     * @notice Remove a passkey
     * @param qx The x-coordinate of the passkey public key
     * @param qy The y-coordinate of the passkey public key
     */
    function removePasskey(bytes32 qx, bytes32 qy) external onlyOwner {
        address passkeyAddr = getPasskeyAddress(qx, qy);
        if (passkeyQx[passkeyAddr] == bytes32(0)) revert PasskeyNotRegistered();

        delete passkeyQx[passkeyAddr];
        delete passkeyQy[passkeyAddr];

        emit PasskeyRemoved(passkeyAddr);
    }

    /**
     * @notice Check if an address is a registered passkey
     * @param addr The address to check
     * @return True if the address is a registered passkey
     */
    function isPasskey(address addr) public view returns (bool) {
        return passkeyQx[addr] != bytes32(0);
    }

    /**
     * @notice Get passkey info by credentialId hash (for login flow)
     * @param credentialIdHash The keccak256 hash of the WebAuthn credentialId
     * @return passkeyAddr The derived passkey address (address(0) if not registered)
     * @return qx The x-coordinate of the passkey public key
     * @return qy The y-coordinate of the passkey public key
     */
    function getPasskeyByCredentialId(bytes32 credentialIdHash) external view returns (
        address passkeyAddr,
        bytes32 qx,
        bytes32 qy
    ) {
        passkeyAddr = credentialIdToAddress[credentialIdHash];
        if (passkeyAddr != address(0)) {
            qx = passkeyQx[passkeyAddr];
            qy = passkeyQy[passkeyAddr];
        }
        // If passkeyAddr == address(0), passkey not registered
    }

    /**
     * @notice Execute a call to any contract 
     * @param target The address to call
     * @param value The ETH value to send
     * @param data The calldata to send
     * @return result The return data from the call
     */
    function exec(address target, uint256 value, bytes calldata data) 
        external 
        onlyOwner 
        returns (bytes memory result) 
    {
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();
        
        emit Executed(target, value, data);
        return returnData;
    }

    /**
     * @notice Execute multiple calls atomically (for wallet_sendCalls / EIP-5792)
     * @param calls Array of calls to execute
     * @return results Array of return data from each call
     */
    function batchExec(Call[] calldata calls) 
        external 
        onlyOwner 
        returns (bytes[] memory results) 
    {
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory returnData) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert ExecutionFailed();
            emit Executed(calls[i].target, calls[i].value, calls[i].data);
            results[i] = returnData;
        }
    }

    // /**
    //  * @notice Execute a call via meta transaction (K1/ECDSA signature from EOA operator)
    //  * @dev Anyone can relay this transaction on behalf of an operator
    //  * @param target The address to call
    //  * @param value The ETH value to send
    //  * @param data The calldata to send
    //  * @param signer The address of the operator who signed
    //  * @param deadline The timestamp after which the signature expires
    //  * @param signature The ECDSA signature from the operator
    //  * @return result The return data from the call
    //  */
    // function metaExec(
    //     address target,
    //     uint256 value,
    //     bytes calldata data,
    //     address signer,
    //     uint256 deadline,
    //     bytes calldata signature
    // ) external returns (bytes memory result) {
    //     // Check signature hasn't expired
    //     if (block.timestamp > deadline) revert ExpiredSignature();

    //     // Verify signer is a valid EOA operator (not a passkey)
    //     if (!operators[signer]) revert NotOperator();
    //     if (isPasskey(signer)) revert UseMetaExecPasskey();

    //     // Build and verify the signed hash (includes chainId for cross-chain replay protection)
    //     bytes32 hash = keccak256(abi.encodePacked(
    //         block.chainid,
    //         address(this),
    //         target,
    //         value,
    //         data,
    //         nonces[signer],
    //         deadline
    //     ));
    //     bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);

    //     if (ECDSA.recover(ethHash, signature) != signer) revert InvalidSignature();

    //     // Increment nonce
    //     nonces[signer]++;

    //     // Execute the call
    //     (bool success, bytes memory returnData) = target.call{value: value}(data);
    //     if (!success) revert ExecutionFailed();

    //     emit MetaExecuted(signer, target, value, data);
    //     return returnData;
    // }

    // /**
    //  * @notice Execute multiple calls via meta transaction (K1/ECDSA signature from EOA operator)
    //  * @dev Anyone can relay this transaction on behalf of an operator
    //  * @param calls Array of calls to execute
    //  * @param signer The address of the operator who signed
    //  * @param deadline The timestamp after which the signature expires
    //  * @param signature The ECDSA signature from the operator
    //  * @return results Array of return data from each call
    //  */
    // function metaBatchExec(
    //     Call[] calldata calls,
    //     address signer,
    //     uint256 deadline,
    //     bytes calldata signature
    // ) external returns (bytes[] memory results) {
    //     // Check signature hasn't expired
    //     if (block.timestamp > deadline) revert ExpiredSignature();

    //     // Verify signer is a valid EOA operator (not a passkey)
    //     if (!operators[signer]) revert NotOperator();
    //     if (isPasskey(signer)) revert UseMetaExecPasskey();

    //     // Build and verify the signed hash (includes chainId for cross-chain replay protection)
    //     bytes32 hash = keccak256(abi.encodePacked(
    //         block.chainid,
    //         address(this),
    //         keccak256(abi.encode(calls)),
    //         nonces[signer],
    //         deadline
    //     ));
    //     bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);

    //     if (ECDSA.recover(ethHash, signature) != signer) revert InvalidSignature();

    //     // Increment nonce
    //     nonces[signer]++;

    //     // Execute all calls
    //     results = new bytes[](calls.length);
    //     for (uint256 i = 0; i < calls.length; i++) {
    //         (bool success, bytes memory returnData) = calls[i].target.call{value: calls[i].value}(calls[i].data);
    //         if (!success) revert ExecutionFailed();
    //         emit MetaExecuted(signer, calls[i].target, calls[i].value, calls[i].data);
    //         results[i] = returnData;
    //     }
    // }

    /**
     * @notice Execute a call via passkey meta transaction (R1/WebAuthn signature)
     * @dev Anyone can relay this transaction on behalf of a registered passkey
     * @param target The address to call
     * @param value The ETH value to send
     * @param data The calldata to send
     * @param qx The x-coordinate of the passkey public key
     * @param qy The y-coordinate of the passkey public key
     * @param deadline The timestamp after which the signature expires
     * @param auth The WebAuthn authentication assertion data
     * @return result The return data from the call
     */
    function metaExecPasskey(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 qx,
        bytes32 qy,
        uint256 deadline,
        WebAuthn.WebAuthnAuth calldata auth
    ) external returns (bytes memory result) {
        // Check signature hasn't expired
        if (block.timestamp > deadline) revert ExpiredSignature();

        // Derive the passkey address and verify it's registered
        address passkeyAddr = getPasskeyAddress(qx, qy);
        if (passkeyQx[passkeyAddr] != qx || passkeyQy[passkeyAddr] != qy) revert PasskeyNotRegistered();

        // Build the challenge that was signed (includes chainId for cross-chain replay protection)
        bytes memory challenge = abi.encodePacked(keccak256(abi.encodePacked(
            block.chainid,
            address(this),
            target,
            value,
            data,
            nonces[passkeyAddr],
            deadline
        )));

        // Verify the WebAuthn signature
        if (!WebAuthn.verify(challenge, auth, qx, qy)) revert InvalidSignature();

        // Increment nonce
        nonces[passkeyAddr]++;

        // Execute the call
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();

        emit MetaExecuted(passkeyAddr, target, value, data);
        return returnData;
    }

    /**
     * @notice Execute multiple calls via passkey meta transaction (R1/WebAuthn signature)
     * @dev Anyone can relay this transaction on behalf of a registered passkey
     * @param calls Array of calls to execute
     * @param qx The x-coordinate of the passkey public key
     * @param qy The y-coordinate of the passkey public key
     * @param deadline The timestamp after which the signature expires
     * @param auth The WebAuthn authentication assertion data
     * @return results Array of return data from each call
     */
    function metaBatchExecPasskey(
        Call[] calldata calls,
        bytes32 qx,
        bytes32 qy,
        uint256 deadline,
        WebAuthn.WebAuthnAuth calldata auth
    ) external returns (bytes[] memory results) {
        // Check signature hasn't expired
        if (block.timestamp > deadline) revert ExpiredSignature();

        // Derive the passkey address and verify it's registered
        address passkeyAddr = getPasskeyAddress(qx, qy);
        if (passkeyQx[passkeyAddr] != qx || passkeyQy[passkeyAddr] != qy) revert PasskeyNotRegistered();

        // Build the challenge that was signed (includes chainId for cross-chain replay protection)
        bytes memory challenge = abi.encodePacked(keccak256(abi.encodePacked(
            block.chainid,
            address(this),
            keccak256(abi.encode(calls)),
            nonces[passkeyAddr],
            deadline
        )));

        // Verify the WebAuthn signature
        if (!WebAuthn.verify(challenge, auth, qx, qy)) revert InvalidSignature();

        // Increment nonce
        nonces[passkeyAddr]++;

        // Execute all calls
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory returnData) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert ExecutionFailed();
            emit MetaExecuted(passkeyAddr, calls[i].target, calls[i].value, calls[i].data);
            results[i] = returnData;
        }
    }

    /**
     * @notice ERC-1271 signature validation (ECDSA only)
     * @dev Validates that the signature was created by the owner.
     *      Passkeys use WebAuthn signatures and should use metaExecPasskey instead.
     * @param hash The hash of the data that was signed
     * @param signature The signature bytes (ECDSA signature)
     * @return magicValue The magic value 0x1626ba7e if valid, 0xffffffff otherwise
     */
    function isValidSignature(bytes32 hash, bytes memory signature) 
        external 
        view 
        returns (bytes4 magicValue) 
    {
        // Recover the signer from the signature
        address signer = ECDSA.recover(hash, signature);
        
        // Check if signer is owner
        if (signer == owner()) {
            return IERC1271.isValidSignature.selector; // 0x1626ba7e
        }
        
        return 0xffffffff; // Invalid signature
    }

    /**
     * @notice Allow the wallet to receive ETH
     */
    receive() external payable {}

    /**
     * @notice ERC-721 receiver hook to allow receiving NFTs via safeTransferFrom
     */
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /**
     * @notice ERC-1155 receiver hook to allow receiving tokens via safeTransferFrom
     */
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    /**
     * @notice ERC-1155 batch receiver hook to allow receiving tokens via safeBatchTransferFrom
     */
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }
}

