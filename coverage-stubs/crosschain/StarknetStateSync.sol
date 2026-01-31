// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
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

    mapping(uint256 => BlockHeader) public blockHeaders;
    mapping(uint256 => Checkpoint) public checkpoints;
    uint256 public latestBlockNumber;
    uint256 public latestCheckpointIndex;
    address public starknetCore;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function setStarknetCore(address) external {}
    function cacheBlockHeader(uint256, bytes32, bytes32, bytes32, bytes32, bytes32, uint256, uint256, uint256) external {}
    function markBlockProven(uint256, bytes calldata) external {}
    function createCheckpoint(uint256) external {}
}
