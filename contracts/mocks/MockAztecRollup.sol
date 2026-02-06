// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockAztecRollup
 * @notice Mock Aztec rollup contract for testing AztecBridgeAdapter
 * @dev Simulates note commitments and cross-domain verification
 */
contract MockAztecRollup {
    mapping(bytes32 => bool) public noteCommitments;
    mapping(bytes32 => bool) public nullifiers;
    uint256 public rollupBlockNumber;
    bytes32 public stateRoot;

    event NoteCommitted(bytes32 indexed commitment);
    event NullifierConsumed(bytes32 indexed nullifier);

    function addNoteCommitment(bytes32 commitment) external {
        noteCommitments[commitment] = true;
        emit NoteCommitted(commitment);
    }

    function consumeNullifier(bytes32 nullifier) external {
        require(!nullifiers[nullifier], "Nullifier already consumed");
        nullifiers[nullifier] = true;
        emit NullifierConsumed(nullifier);
    }

    function verifyProof(
        bytes calldata,
        bytes32[] calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function setRollupBlockNumber(uint256 blockNum) external {
        rollupBlockNumber = blockNum;
    }

    function setStateRoot(bytes32 root) external {
        stateRoot = root;
    }

    function isNoteCommitted(bytes32 commitment) external view returns (bool) {
        return noteCommitments[commitment];
    }

    function isNullifierConsumed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }
}

/**
 * @title MockAztecPortal
 * @notice Mock Aztec outbox/portal for cross-chain message passing
 */
contract MockAztecPortal {
    mapping(bytes32 => bool) public messages;

    event MessageSent(bytes32 indexed messageHash, address indexed sender);

    function sendMessage(
        bytes32 recipient,
        bytes calldata content,
        uint32
    ) external payable returns (bytes32) {
        bytes32 msgHash = keccak256(abi.encode(msg.sender, recipient, content));
        messages[msgHash] = true;
        emit MessageSent(msgHash, msg.sender);
        return msgHash;
    }

    function consumeMessage(bytes32 msgHash) external {
        require(messages[msgHash], "Message not found");
        delete messages[msgHash];
    }

    function hasMessage(bytes32 msgHash) external view returns (bool) {
        return messages[msgHash];
    }
}
