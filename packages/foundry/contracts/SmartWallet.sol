//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SmartWallet
 * @notice A minimal smart contract wallet that allows an owner to execute arbitrary calls
 * @author BuidlGuidl
 */
contract SmartWallet is Ownable {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    mapping(address => bool) public operators;

    event Executed(address indexed target, uint256 value, bytes data);
    event OperatorAdded(address indexed operator);
    event OperatorRemoved(address indexed operator);

    error NotAuthorized();
    error ExecutionFailed();

    constructor(address _owner) Ownable(_owner) {}

    modifier onlyOwnerOrOperator() {
        if (msg.sender != owner() && !operators[msg.sender]) revert NotAuthorized();
        _;
    }

    /**
     * @notice Add an operator who can execute calls
     * @param operator The address to add as operator
     */
    function addOperator(address operator) external onlyOwner {
        operators[operator] = true;
        emit OperatorAdded(operator);
    }

    /**
     * @notice Remove an operator
     * @param operator The address to remove as operator
     */
    function removeOperator(address operator) external onlyOwner {
        operators[operator] = false;
        emit OperatorRemoved(operator);
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
        onlyOwnerOrOperator 
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
        onlyOwnerOrOperator 
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

    /**
     * @notice Allow the wallet to receive ETH
     */
    receive() external payable {}
}

