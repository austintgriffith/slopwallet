//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title Clones
 * @notice EIP-1167 Minimal Proxy (Clone) library
 * @dev Deploys minimal proxy contracts that delegate all calls to an implementation
 * @author BuidlGuidl (based on OpenZeppelin Clones)
 */
library Clones {
    /**
     * @dev A clone instance deployment failed.
     */
    error CloneCreationFailed();

    /**
     * @notice Deploys a clone of `implementation` using CREATE2 with `salt`
     * @param implementation The address of the implementation contract
     * @param salt The salt for CREATE2
     * @return instance The address of the deployed clone
     */
    function cloneDeterministic(address implementation, bytes32 salt) internal returns (address instance) {
        // EIP-1167 minimal proxy bytecode
        // 3d602d80600a3d3981f3363d3d373d3d3d363d73<implementation>5af43d82803e903d91602b57fd5bf3
        assembly {
            // Store the bytecode in memory
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            
            // Deploy using CREATE2
            instance := create2(0, ptr, 0x37, salt)
        }
        if (instance == address(0)) {
            revert CloneCreationFailed();
        }
    }

    /**
     * @notice Predicts the address of a clone deployed with `cloneDeterministic`
     * @param implementation The address of the implementation contract
     * @param salt The salt for CREATE2
     * @param deployer The address that will deploy the clone (usually address(this))
     * @return predicted The predicted address of the clone
     */
    function predictDeterministicAddress(
        address implementation,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        // First compute the init code hash
        bytes32 initCodeHash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            initCodeHash := keccak256(ptr, 0x37)
        }
        
        // CREATE2 address = keccak256(0xff ++ deployer ++ salt ++ initCodeHash)[12:]
        predicted = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            deployer,
            salt,
            initCodeHash
        )))));
    }
}
