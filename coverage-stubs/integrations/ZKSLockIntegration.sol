// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../primitives/ZKBoundStateLocks.sol";

// STUB for coverage only
contract ZKSLockIntegration {
    error InvalidLockId();
    error InvalidContainerId();
    error InvalidNullifier();
    error LockNotActive();
    error ContainerAlreadyLocked();
    error NullifierAlreadyConsumed();
    error DomainMismatch();
    error UnauthorizedCaller();
    error IntegrationDisabled();
    error UserEntropyRequired();

    struct AtomicLockParams {
        bytes32 stateCommitment;
        bytes32 transitionPredicateHash;
        bytes32 policyBinding;
        bytes32 domainSeparator;
        bytes32 commitmentHash;
        uint64 unlockDeadline;
        bytes32 userEntropy;
        bytes encryptedPayload;
    }

    address public zkSlocks;
    address public pc3;
    address public cdna;
    bool public integrationEnabled;
    bytes32 public defaultDomainSeparator;

    mapping(bytes32 => bytes32) public containerToLock;
    mapping(bytes32 => bytes32) public lockToContainer;
    mapping(bytes32 => bytes32) public lockToNullifier;
    mapping(bytes32 => bytes32) public nullifierToLock;

    constructor(address, address, address) {
        integrationEnabled = true;
    }

    function lockContainer(bytes32, bytes32, bytes32, bytes32, uint64) external returns (bytes32) { return bytes32(0); }
    function unlockContainer(bytes32, ZKBoundStateLocks.UnlockProof calldata) external {}
    function createCrossDomainLock(bytes32, bytes32, bytes32, bytes32, bytes32, bytes32) external returns (bytes32, bytes32) { return (bytes32(0), bytes32(0)); }
    function createAtomicLock(AtomicLockParams calldata) external returns (bytes32, bytes32, bytes32) { return (bytes32(0), bytes32(0), bytes32(0)); }
    function batchCreateLocks(bytes32[] calldata, bytes32[] calldata, bytes32[] calldata, bytes32, uint64[] calldata) external returns (bytes32[] memory) { return new bytes32[](0); }
    function getLockInfo(bytes32) external view returns (bytes32, bytes32, bytes32, bool) { return (bytes32(0), bytes32(0), bytes32(0), false); }
    function isContainerLocked(bytes32) external view returns (bool) { return false; }
    function getLockForNullifier(bytes32) external view returns (bytes32) { return bytes32(0); }
    function setIntegrationEnabled(bool) external {}
    function setDefaultDomainSeparator(bytes32) external {}
}
