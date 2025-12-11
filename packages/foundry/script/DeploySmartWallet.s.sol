// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./DeployHelpers.s.sol";
import "../contracts/Factory.sol";

/**
 * @notice Deploy a SmartWallet for a specific owner using the Factory
 * @dev This script deploys a smart wallet on Base for the owner who needs WalletConnect functionality
 */
contract DeploySmartWallet is ScaffoldETHDeploy {
    // Factory address on Base (from deployedContracts.ts)
    address constant FACTORY = 0x7E8530E2AC3FEf0DaE3C7B48983a6F34D1576b72;
    
    // Owner address (determined from on-chain activity)
    address constant OWNER = 0x34aA3F359A9D614239015126635CE7732c18fDF3;
    
    // Salt to use for CREATE2 (try 0 first)
    bytes32 constant SALT = bytes32(uint256(0));
    
    function run() external ScaffoldEthDeployerRunner {
        Factory factory = Factory(FACTORY);
        
        // Predict the address first
        address predicted = factory.getWalletAddress(OWNER, SALT);
        console.log("Predicted wallet address:", predicted);
        console.log("Target address:          0x687A579ac262F1Ca3092fF8D6726EEA24e8836E2");
        
        // Deploy the smart wallet
        address wallet = factory.createWallet(OWNER, SALT);
        console.log("Deployed wallet address:", wallet);
        
        // Verify it matches
        if (wallet == 0x687A579ac262F1Ca3092fF8D6726EEA24e8836E2) {
            console.log("SUCCESS: Wallet deployed at expected address!");
        } else {
            console.log("WARNING: Wallet address does not match expected address");
            console.log("You may need to use a different salt value");
        }
    }
}


