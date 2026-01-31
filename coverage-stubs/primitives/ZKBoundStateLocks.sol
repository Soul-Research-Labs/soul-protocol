// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract ZKBoundStateLocks is AccessControl, ReentrancyGuard, Pausable {
    error LockAlreadyExists(bytes32 lockId);
    error LockDoesNotExist(bytes32 lockId);
    error LockAlreadyUnlocked(bytes32 lockId);
    error LockExpired(bytes32 lockId, uint256 deadline);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error VerifierNotRegistered(bytes32 verifierKeyHash);
    error InvalidProof(bytes32 lockId);
    error InvalidDisputeWindow();
    error InsufficientBond(uint256 required, uint256 provided);
    error InvalidDomainSeparator(bytes32 domain);
    error TransitionPredicateMismatch(bytes32 expected, bytes32 provided);
    error StateCommitmentMismatch(bytes32 expected, bytes32 provided);
    error ChallengeWindowClosed(bytes32 lockId);
    error NoOptimisticUnlock(bytes32 lockId);
    error AlreadyDisputed(bytes32 lockId);
    error InvalidConflictProof(bytes32 lockId);
    error ETHTransferFailed();
    error VerifierAlreadyRegistered(bytes32 verifierKeyHash);
    error InvalidVerifierAddress();
    error DomainAlreadyExists(bytes32 domainSeparator);
    error InvalidLock(bytes32 lockId);

    bytes32 public constant LOCK_ADMIN_ROLE = keccak256("LOCK_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant DOMAIN_ADMIN_ROLE = keccak256("DOMAIN_ADMIN_ROLE");
    bytes32 public constant DISPUTE_RESOLVER_ROLE = keccak256("DISPUTE_RESOLVER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");

    struct ZKSLock {
        bytes32 lockId;
        bytes32 oldStateCommitment;
        bytes32 transitionPredicateHash;
        bytes32 policyHash;
        bytes32 domainSeparator;
        address lockedBy;
        uint64 createdAt;
        uint64 unlockDeadline;
        bool isUnlocked;
    }

    struct UnlockProof {
        bytes32 lockId;
        bytes zkProof;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 verifierKeyHash;
        bytes auxiliaryData;
    }

    struct OptimisticUnlock {
        address unlocker;
        uint64 unlockTime;
        uint128 bondAmount;
        bytes32 proofHash;
        uint64 finalizeAfter;
        bool disputed;
        bytes32 newStateCommitment;
        bytes32 nullifier;
    }

    struct Domain {
        uint16 chainId;
        uint16 appId;
        uint32 epoch;
        string name;
        bool isActive;
        uint64 registeredAt;
    }

    struct UnlockReceipt {
        bytes32 lockId;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 domainSeparator;
        address unlockedBy;
        uint64 unlockedAt;
    }

    mapping(bytes32 => ZKSLock) public locks;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(bytes32 => address) public verifiers;
    mapping(bytes32 => OptimisticUnlock) public optimisticUnlocks;
    mapping(bytes32 => bytes32) public commitmentSuccessor;
    mapping(bytes32 => bytes32) public commitmentPredecessor;
    mapping(bytes32 => Domain) public domains;
    mapping(address => uint256) public userLockCount;
    mapping(bytes32 => UnlockReceipt) public unlockReceipts;
    address public proofVerifier;

    constructor(address _proofVerifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        proofVerifier = _proofVerifier;
    }

    function createLock(bytes32, bytes32, bytes32, bytes32, uint64) external returns (bytes32) {
        return bytes32(0);
    }

    function unlock(UnlockProof calldata) external {}
    function optimisticUnlock(UnlockProof calldata) external payable {}
    function finalizeOptimisticUnlock(bytes32) external {}
    function challengeOptimisticUnlock(bytes32, UnlockProof calldata) external {}
    function registerVerifier(bytes32, address) external {}
    function registerDomain(uint16, uint16, uint32, string calldata) external returns (bytes32) {
        return bytes32(0);
    }
    function recoverLock(bytes32, address) external {}

    function totalLocksCreated() external pure returns (uint256) { return 0; }
    function totalLocksUnlocked() external pure returns (uint256) { return 0; }
    function totalOptimisticUnlocks() external pure returns (uint256) { return 0; }
    function totalDisputes() external pure returns (uint256) { return 0; }

    function generateDomainSeparator(uint16 chainId, uint16 appId, uint32 epoch) public pure returns (bytes32) {
        return keccak256(abi.encode(chainId, appId, epoch));
    }

    function generateNullifier(bytes32 secret, bytes32 lockId, bytes32 domainSeparator) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(secret, lockId, domainSeparator));
    }

    function getActiveLockCount() external view returns (uint256) { return 0; }
    function getLock(bytes32 lockId) external view returns (ZKSLock memory) { return locks[lockId]; }
    function canUnlock(bytes32) external view returns (bool) { return false; }

    function getStats() external pure returns (uint256, uint256, uint256, uint256, uint256) {
        return (0, 0, 0, 0, 0);
    }

    function getActiveLockIds(uint256, uint256) external view returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    function pause() external onlyRole(LOCK_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(LOCK_ADMIN_ROLE) { _unpause(); }
}
