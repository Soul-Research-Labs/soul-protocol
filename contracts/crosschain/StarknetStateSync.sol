// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract StarknetStateSync is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    struct BlockHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 txRoot;
        bytes32 receiptsRoot;
        uint256 sequencer;
        uint256 timestamp;
        uint256 gasUsed;
        bool isProven;
    }

    struct Checkpoint {
        uint256 index;
        uint256 blockNumber;
        bytes32 stateRoot;
        uint256 timestamp;
    }

    // Storage
    mapping(uint256 => BlockHeader) public blockHeaders;
    mapping(uint256 => Checkpoint) public checkpoints;
    
    uint256 public latestBlockNumber;
    uint256 public latestCheckpointIndex;
    address public starknetCore;

    event BlockHeaderCached(uint256 indexed blockNumber, bytes32 blockHash);
    event BlockProven(uint256 indexed blockNumber);
    event CheckpointCreated(uint256 indexed index, uint256 blockNumber, bytes32 stateRoot);
    event StarknetCoreUpdated(address indexed newCore);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    function setStarknetCore(address _core) external onlyRole(OPERATOR_ROLE) {
        starknetCore = _core;
        emit StarknetCoreUpdated(_core);
    }

    function cacheBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 txRoot,
        bytes32 receiptsRoot,
        uint256 sequencer,
        uint256 timestamp,
        uint256 gasUsed
    ) external onlyRole(SEQUENCER_ROLE) {
        // Simple validation
        if (blockNumber <= latestBlockNumber && latestBlockNumber != 0) {
            // In a real implementation we might check checks for forks or reorgs
            // For now we allow overwriting or out-of-order for simplicity/testing or require strictly increasing
        }

        blockHeaders[blockNumber] = BlockHeader({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            stateRoot: stateRoot,
            txRoot: txRoot,
            receiptsRoot: receiptsRoot,
            sequencer: sequencer,
            timestamp: timestamp,
            gasUsed: gasUsed,
            isProven: false
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
        }

        emit BlockHeaderCached(blockNumber, blockHash);
    }

    function markBlockProven(
        uint256 blockNumber,
        bytes calldata /* proof */
    ) external onlyRole(VERIFIER_ROLE) {
        require(blockHeaders[blockNumber].timestamp != 0, "Block not found");
        // Verify proof logic would go here
        
        blockHeaders[blockNumber].isProven = true;
        emit BlockProven(blockNumber);
    }

    function createCheckpoint(uint256 blockNumber) external onlyRole(OPERATOR_ROLE) {
        require(blockHeaders[blockNumber].isProven, "Block not proven");
        
        latestCheckpointIndex++;
        checkpoints[latestCheckpointIndex] = Checkpoint({
            index: latestCheckpointIndex,
            blockNumber: blockNumber,
            stateRoot: blockHeaders[blockNumber].stateRoot,
            timestamp: block.timestamp
        });

        emit CheckpointCreated(latestCheckpointIndex, blockNumber, blockHeaders[blockNumber].stateRoot);
    }
}
