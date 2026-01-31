// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract LinearStateManager is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant STATE_ADMIN_ROLE = 0xf7054b28837a3e0f0fcdf0631d7a1f2c54f272601d37d24ed1fa836bd1c2ae94;
    bytes32 public constant KERNEL_ROLE = 0x6461d7edb0de6153faa1dbe72f8286821dd20b9e202b6351eb86ef5e04eaec51;
    bytes32 public constant BRIDGE_ROLE = 0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;

    enum StateLifecycle { NonExistent, Active, Consumed, Invalidated }

    struct LinearState {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 predecessor;
        bytes32 successor;
        bytes32 transitionPredicate;
        bytes32 policyHash;
        uint256 sourceChainId;
        uint256 currentChainId;
        StateLifecycle lifecycle;
        uint64 createdAt;
        uint64 consumedAt;
    }

    struct StateTransition {
        bytes32 fromCommitment;
        bytes32 toCommitment;
        bytes32 nullifier;
        bytes32 transitionPredicate;
        bytes32 kernelProofId;
        uint256 fromChainId;
        uint256 toChainId;
        uint64 timestamp;
    }
    
    uint256 public immutable CHAIN_ID;
    mapping(bytes32 => LinearState) public linearStates;
    mapping(bytes32 => bool) public nullifierRegistry;
    mapping(uint256 => uint256) public stateCountByChain;

    event StateCreated(bytes32 indexed commitment, bytes32 indexed predecessor, bytes32 transitionPredicate, uint256 chainId);
    event StateConsumed(bytes32 indexed oldCommitment, bytes32 indexed newCommitment, bytes32 indexed nullifier, uint256 fromChainId, uint256 toChainId);

    constructor() {
        CHAIN_ID = block.chainid;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function createGenesisState(bytes32 c, bytes32 tp, bytes32 ph) external returns (bool) {
        linearStates[c] = LinearState(c, bytes32(0), bytes32(0), bytes32(0), tp, ph, CHAIN_ID, CHAIN_ID, StateLifecycle.Active, uint64(block.timestamp), 0);
        return true;
    }
    
    function consumeAndProduce(bytes32 old, bytes32 newC, bytes32 n, bytes32 tp, bytes32 kp, uint256 destChain) external returns (bool) {
        return true;
    }
    
    function registerCrossDomainNullifier(bytes32, bytes32, bytes32, uint256) external {}
    function registerPredicate(bytes32) external {}
    function revokePredicate(bytes32) external {}
    
    function getStateLifecycle(bytes32 c) external view returns (StateLifecycle) { return linearStates[c].lifecycle; }
    function isStateActive(bytes32 c) external view returns (bool) { return linearStates[c].lifecycle == StateLifecycle.Active; }
    function isStateConsumed(bytes32 c) external view returns (bool) { return linearStates[c].lifecycle == StateLifecycle.Consumed; }
    function isNullifierUsed(bytes32 n) external view returns (bool) { return nullifierRegistry[n]; }
    
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
}
