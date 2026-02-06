// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockPlasmaOperatorOracle
 * @notice Mock Plasma operator oracle for testing the Plasma bridge adapter
 * @dev Simulates operator verification for block commitments and confirmations
 *
 * In production, this would verify operator signatures against the root chain
 * contract and track the operator's block commitment history.
 *
 * Plasma uses a single operator (or small operator set) rather than a large
 * validator/mediator set. Security comes from fraud proofs and the exit game,
 * not from consensus among many nodes.
 */
contract MockPlasmaOperatorOracle is Ownable {
    /// @notice Set of registered operators
    mapping(address => bool) public operators;

    /// @notice List of active operator addresses
    address[] public operatorList;

    /// @notice Mapping of block commitments to L1 tx hashes
    mapping(bytes32 => bytes32) public commitmentToL1Tx;

    /// @notice Whether a block has been committed to L1
    mapping(uint256 => bool) public committedBlocks;

    event OperatorAdded(address indexed operator);
    event OperatorRemoved(address indexed operator);
    event BlockCommitted(uint256 indexed blockNumber, bytes32 blockHash, bytes32 l1TxHash);

    constructor() Ownable(msg.sender) {}

    /// @notice Add a Plasma operator
    function addOperator(address operator) external onlyOwner {
        require(operator != address(0), "Zero address");
        require(!operators[operator], "Already operator");

        operators[operator] = true;
        operatorList.push(operator);

        emit OperatorAdded(operator);
    }

    /// @notice Remove a Plasma operator
    function removeOperator(address operator) external onlyOwner {
        require(operators[operator], "Not operator");

        operators[operator] = false;

        for (uint256 i = 0; i < operatorList.length; i++) {
            if (operatorList[i] == operator) {
                operatorList[i] = operatorList[operatorList.length - 1];
                operatorList.pop();
                break;
            }
        }

        emit OperatorRemoved(operator);
    }

    /// @notice Verify an operator confirmation (mock: always returns true for registered operators)
    function verifyConfirmation(
        bytes32 blockHash,
        address operator,
        bytes calldata /* signature */
    ) external view returns (bool) {
        return operators[operator];
    }

    /// @notice Batch verify multiple operator confirmations
    function batchVerifyConfirmations(
        bytes32 blockHash,
        address[] calldata operatorAddrs,
        bytes[] calldata signatures
    ) external view returns (bool) {
        require(operatorAddrs.length == signatures.length, "Length mismatch");
        for (uint256 i = 0; i < operatorAddrs.length; i++) {
            if (!operators[operatorAddrs[i]]) return false;
        }
        return true;
    }

    /// @notice Record a block commitment to L1
    function recordCommitment(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 l1TxHash
    ) external onlyOwner {
        commitmentToL1Tx[blockHash] = l1TxHash;
        committedBlocks[blockNumber] = true;

        emit BlockCommitted(blockNumber, blockHash, l1TxHash);
    }

    /// @notice Check if a block has been committed to L1
    function isBlockCommitted(uint256 blockNumber) external view returns (bool) {
        return committedBlocks[blockNumber];
    }

    /// @notice Get all active operators
    function getActiveOperators() external view returns (address[] memory) {
        return operatorList;
    }

    /// @notice Check if an address is a registered operator
    function isOperator(address addr) external view returns (bool) {
        return operators[addr];
    }

    /// @notice Get the number of active operators
    function getOperatorCount() external view returns (uint256) {
        return operatorList.length;
    }

    /// @notice Get the minimum required confirmations (for Plasma, typically just the operator)
    function getMinRequiredConfirmations() external view returns (uint256) {
        // Plasma typically needs just 1 operator confirmation
        // Security comes from fraud proofs, not consensus
        return operatorList.length > 0 ? 1 : 0;
    }
}
