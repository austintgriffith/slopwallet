//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./SmartWallet.sol";
import "./Clones.sol";

/**
 * @title Factory
 * @notice A factory contract that deploys SmartWallet clones using EIP-1167 minimal proxies
 * @dev Uses CREATE2 for deterministic addresses with minimal gas costs per deployment
 * @author BuidlGuidl
 */
contract Factory {
    /// @notice The SmartWallet implementation contract that all clones delegate to
    address public immutable implementation;

    event WalletCreated(address indexed owner, address indexed wallet, bytes32 salt);

    /**
     * @notice Initialize the factory with a SmartWallet implementation address
     * @param _implementation The address of the deployed SmartWallet implementation
     */
    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice Deploy a new SmartWallet clone for a given owner using CREATE2
     * @param owner The owner of the new SmartWallet
     * @param salt A salt value for CREATE2 (allows multiple wallets per owner)
     * @return wallet The address of the deployed SmartWallet clone
     */
    function createWallet(address owner, bytes32 salt) external returns (address wallet) {
        // Combine owner and salt for unique CREATE2 salt
        bytes32 finalSalt = keccak256(abi.encodePacked(owner, salt));
        
        // Deploy minimal proxy clone using CREATE2
        wallet = Clones.cloneDeterministic(implementation, finalSalt);
        
        // Initialize the clone with the owner
        SmartWallet(payable(wallet)).initialize(owner);
        
        emit WalletCreated(owner, wallet, salt);
    }

    /**
     * @notice Compute the address of a SmartWallet clone before deployment
     * @param owner The owner of the SmartWallet
     * @param salt The salt value that will be used for CREATE2
     * @return The predicted address of the SmartWallet clone
     */
    function getWalletAddress(address owner, bytes32 salt) external view returns (address) {
        bytes32 finalSalt = keccak256(abi.encodePacked(owner, salt));
        return Clones.predictDeterministicAddress(implementation, finalSalt, address(this));
    }
}
