//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./SmartWallet.sol";

/**
 * @title Factory
 * @notice A factory contract that deploys SmartWallet contracts using CREATE2 for deterministic addresses
 * @author BuidlGuidl
 */
contract Factory {
    event WalletCreated(address indexed owner, address indexed wallet, bytes32 salt);

    /**
     * @notice Deploy a new SmartWallet for a given owner using CREATE2
     * @param owner The owner of the new SmartWallet
     * @param salt A salt value for CREATE2 (allows multiple wallets per owner)
     * @return wallet The address of the deployed SmartWallet
     */
    function createWallet(address owner, bytes32 salt) external returns (address wallet) {
        // Combine owner and salt for unique CREATE2 salt
        bytes32 finalSalt = keccak256(abi.encodePacked(owner, salt));
        
        // Deploy SmartWallet using CREATE2
        wallet = address(new SmartWallet{salt: finalSalt}(owner));
        
        emit WalletCreated(owner, wallet, salt);
    }

    /**
     * @notice Compute the address of a SmartWallet before deployment
     * @param owner The owner of the SmartWallet
     * @param salt The salt value that will be used for CREATE2
     * @return The predicted address of the SmartWallet
     */
    function getWalletAddress(address owner, bytes32 salt) external view returns (address) {
        bytes32 finalSalt = keccak256(abi.encodePacked(owner, salt));
        
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                finalSalt,
                keccak256(abi.encodePacked(type(SmartWallet).creationCode, abi.encode(owner)))
            )
        );
        
        return address(uint160(uint256(hash)));
    }
}

