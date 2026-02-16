// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title ZKBoundStateLocksUpgradeable (ZK-SLocks)
 * @author Soul v2 - Soul Protocol
 * @notice UUPS-upgradeable version of ZKBoundStateLocks for proxy deployments
 * @dev Cross-Chain Confidential State Lock Manager with UUPS upgrade capability.
 *
 * UPGRADE NOTES:
 * - Immutable `proofVerifier` is converted to a regular storage variable
 * - Constructor replaced with `initialize(address admin, address _proofVerifier)`
 * - All OZ base contracts replaced with upgradeable variants
 * - UPGRADER_ROLE required for `_authorizeUpgrade`
 * - Storage gap (`__gap[50]`) reserved for future upgrades
 * - `contractVersion` tracks upgrade count
 *
 * @custom:oz-upgrades-from ZKBoundStateLocks
 */
contract ZKBoundStateLocksUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeCast for uint256;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed role hashes save ~200 gas per access vs runtime keccak256
    bytes32 public constant LOCK_ADMIN_ROLE =
        0xb5f42d4ed74356fb5b5979d37d3950e53ab205fdb50ef14ba7816ef87259fef6;
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70;
    bytes32 public constant DOMAIN_ADMIN_ROLE =
        0x8601f95000f9db10f888b55a4dcf204d495f7b7e45e94a5425cd4562bae08468;
    bytes32 public constant DISPUTE_RESOLVER_ROLE =
        0x7b8bb8356a3f32f5c111ff23f050d97f08988e0883529ea7bff3b918887a6e0e;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant RECOVERY_ROLE =
        0x0acf805600123ef007091da3b3ffb39474074c656c127aa68cb0ffec232a8ff8;
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when attempting to create a lock with an ID that already exists
    error LockAlreadyExists(bytes32 lockId);
    /// @notice Thrown when referencing a lock ID not present in the registry
    error LockDoesNotExist(bytes32 lockId);
    /// @notice Thrown when attempting to unlock or recover a lock that is already unlocked
    error LockAlreadyUnlocked(bytes32 lockId);
    /// @notice Thrown when a lock's deadline has passed
    error LockExpired(bytes32 lockId, uint256 deadline);
    /// @notice Thrown when a nullifier has already been consumed (double-spend prevention)
    error NullifierAlreadyUsed(bytes32 nullifier);
    /// @notice Thrown when referencing a verifier key hash not in the registry
    error VerifierNotRegistered(bytes32 verifierKeyHash);
    /// @notice Thrown when a ZK proof fails verification
    error InvalidProof(bytes32 lockId);
    /// @notice Thrown when the dispute window configuration is invalid
    error InvalidDisputeWindow();
    /// @notice Thrown when the bond amount for optimistic unlock is below MIN_BOND_AMOUNT
    error InsufficientBond(uint256 required, uint256 provided);
    /// @notice Thrown when the challenger's stake is below MIN_CHALLENGER_STAKE
    error InsufficientChallengerStake(uint256 required, uint256 provided);
    /// @notice Thrown when referencing a domain separator not registered or inactive
    error InvalidDomainSeparator(bytes32 domain);
    /// @notice Thrown when the transition predicate hash doesn't match the lock's constraint
    error TransitionPredicateMismatch(bytes32 expected, bytes32 provided);
    /// @notice Thrown when the state commitment doesn't match the expected value
    error StateCommitmentMismatch(bytes32 expected, bytes32 provided);
    /// @notice Thrown when attempting to challenge after the dispute window has closed
    error ChallengeWindowClosed(bytes32 lockId);
    /// @notice Thrown when attempting to finalize while the dispute window is still open
    error DisputeWindowStillOpen(bytes32 lockId, uint64 finalizeAfter);
    /// @notice Thrown when referencing a non-existent optimistic unlock
    error NoOptimisticUnlock(bytes32 lockId);
    /// @notice Thrown when an optimistic unlock has already been disputed
    error AlreadyDisputed(bytes32 lockId);
    /// @notice Thrown when the conflict proof evidence doesn't reference the correct lock
    error InvalidConflictProof(bytes32 lockId);
    /// @notice Thrown when an ETH transfer via call() fails
    error ETHTransferFailed();
    /// @notice Thrown when registering a verifier key hash that already has a verifier mapped
    error VerifierAlreadyRegistered(bytes32 verifierKeyHash);
    /// @notice Thrown when a zero-address is provided as the verifier contract
    error InvalidVerifierAddress();
    /// @notice Thrown when registering a domain separator that is already registered
    error DomainAlreadyExists(bytes32 domainSeparator);
    /// @notice Thrown when the lock ID resolves to an empty/uninitialized lock struct
    error InvalidLock(bytes32 lockId);
    /// @notice Thrown when active lock count reaches MAX_ACTIVE_LOCKS
    error TooManyActiveLocks();

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @dev ZKSLock represents a cryptographic lock on a confidential state commitment
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

    /// @dev UnlockProof bundles all data required to verify and execute unlock
    struct UnlockProof {
        bytes32 lockId;
        bytes zkProof;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 verifierKeyHash;
        bytes auxiliaryData;
    }

    /// @dev OptimisticUnlock enables cross-chain race condition prevention
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

    /// @dev Domain configuration for cross-chain coordination
    struct Domain {
        uint64 chainId;
        uint64 appId;
        uint32 epoch;
        string name;
        bool isActive;
        uint64 registeredAt;
    }

    /// @dev Unlock receipt for event emission
    struct UnlockReceipt {
        bytes32 lockId;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 domainSeparator;
        address unlockedBy;
        uint64 unlockedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Primary lock registry: lockId → ZKSLock
    mapping(bytes32 => ZKSLock) public locks;

    /// @notice Active lock IDs for enumeration
    bytes32[] private _activeLockIds;
    mapping(bytes32 => uint256) private _activeLockIndex;

    /// @notice Nullifier registry for cross-domain double-spend prevention
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Verifier registry: verifierKeyHash → verifier contract address
    mapping(bytes32 => address) public verifiers;

    /// @notice Optimistic unlock tracking for dispute resolution
    mapping(bytes32 => OptimisticUnlock) public optimisticUnlocks;

    /// @notice State commitment chain for provenance tracking
    mapping(bytes32 => bytes32) public commitmentSuccessor;
    mapping(bytes32 => bytes32) public commitmentPredecessor;

    /// @notice Domain registry: domainSeparator → Domain
    mapping(bytes32 => Domain) public domains;

    /// @notice Lock count per user
    mapping(address => uint256) public userLockCount;

    /// @notice Unlock receipts for auditing
    mapping(bytes32 => UnlockReceipt) public unlockReceipts;

    /// @notice Reference to external proof verifier (storage, not immutable — proxy compatible)
    IProofVerifier public proofVerifier;

    /// @notice Constants
    uint256 public constant DISPUTE_WINDOW = 2 hours;
    uint256 public constant MIN_BOND_AMOUNT = 0.01 ether;
    uint256 public constant MIN_CHALLENGER_STAKE = 0.01 ether;
    uint256 public constant MAX_ACTIVE_LOCKS = 1000000;

    /// @notice Packed statistics (saves 3 storage slots = ~6000 gas on updates)
    uint256 private _packedStats;

    /// @dev Bit shifts for packed stats
    uint256 private constant _STAT_SHIFT_UNLOCKED = 64;
    uint256 private constant _STAT_SHIFT_OPTIMISTIC = 128;
    uint256 private constant _STAT_SHIFT_DISPUTES = 192;

    /// @notice State to track if role separation has been confirmed
    bool public rolesSeparated;

    /// @notice Tracks contract upgrade version
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new ZK-bound state lock is created
    event LockCreated(
        bytes32 indexed lockId,
        bytes32 indexed oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        bytes32 domainSeparator,
        address indexed lockedBy,
        uint64 unlockDeadline
    );

    /// @notice Emitted when a lock is unlocked via ZK proof verification
    event LockUnlocked(
        bytes32 indexed lockId,
        bytes32 indexed newStateCommitment,
        bytes32 nullifier,
        bytes32 indexed domainSeparator,
        address unlockedBy
    );

    /// @notice Emitted when an optimistic unlock is initiated with a bond
    event OptimisticUnlockInitiated(
        bytes32 indexed lockId,
        address indexed unlocker,
        uint256 bondAmount,
        uint64 finalizeAfter
    );

    /// @notice Emitted when a successful challenge disputes an optimistic unlock
    event LockDisputed(
        bytes32 indexed lockId,
        address indexed disputer,
        bytes32 conflictProofHash,
        uint256 bondForfeited
    );

    /// @notice Emitted when a challenge fails and the challenger's stake is forfeited
    event ChallengeRejected(
        bytes32 indexed lockId,
        address indexed challenger,
        uint256 stakeLost
    );

    /// @notice Emitted when a new verifier contract is registered for a given key hash
    event VerifierRegistered(
        bytes32 indexed verifierKeyHash,
        address indexed verifierContract
    );

    /// @notice Emitted when a new cross-chain domain is registered
    event DomainRegistered(
        bytes32 indexed domainSeparator,
        uint64 chainId,
        uint64 appId,
        uint32 epoch,
        string name
    );

    /// @notice Emitted when an optimistic unlock is finalized after the dispute window
    event OptimisticUnlockFinalized(
        bytes32 indexed lockId,
        address indexed unlocker
    );

    /// @notice Emitted when the contract is upgraded to a new implementation
    event ContractUpgraded(address indexed newImplementation, uint256 version);

    /// @notice Error thrown when roles are not properly separated
    error RolesNotSeparated();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes the ZKBoundStateLocks proxy with admin and verifier
     * @param admin Address granted all administrative roles
     * @param _proofVerifier Address of the IProofVerifier contract for ZK proof verification
     */
    function initialize(
        address admin,
        address _proofVerifier
    ) external initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        // Grant roles to admin
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(LOCK_ADMIN_ROLE, admin);
        _grantRole(VERIFIER_ADMIN_ROLE, admin);
        _grantRole(DOMAIN_ADMIN_ROLE, admin);
        _grantRole(DISPUTE_RESOLVER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(RECOVERY_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Set proof verifier (storage variable, proxy-compatible)
        proofVerifier = IProofVerifier(_proofVerifier);

        // Initialize default domains
        _registerDefaultDomains();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW STATS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get total locks created
    function totalLocksCreated() external view returns (uint256) {
        return uint64(_packedStats);
    }

    /// @notice Get total locks unlocked
    function totalLocksUnlocked() external view returns (uint256) {
        return uint64(_packedStats >> _STAT_SHIFT_UNLOCKED);
    }

    /// @notice Get total optimistic unlocks
    function totalOptimisticUnlocks() external view returns (uint256) {
        return uint64(_packedStats >> _STAT_SHIFT_OPTIMISTIC);
    }

    /// @notice Get total disputes
    function totalDisputes() external view returns (uint256) {
        return uint64(_packedStats >> _STAT_SHIFT_DISPUTES);
    }

    /*//////////////////////////////////////////////////////////////
                            LOCK FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a new ZK-Bound State Lock
     * @dev Locks a confidential state commitment with transition constraints
     * @param oldStateCommitment Poseidon hash of current confidential state
     * @param transitionPredicateHash Hash of circuit defining allowed transitions
     * @param policyHash Hash of disclosure policy (bytes32(0) for no policy)
     * @param domainSeparator Cross-domain identifier
     * @param unlockDeadline Optional deadline (0 for no deadline)
     * @return lockId Deterministic lock identifier
     */
    function createLock(
        bytes32 oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        bytes32 domainSeparator,
        uint64 unlockDeadline
    ) external whenNotPaused returns (bytes32 lockId) {
        if (unlockDeadline != 0 && unlockDeadline <= uint64(block.timestamp)) {
            revert LockExpired(bytes32(0), unlockDeadline);
        }

        if (_activeLockIds.length >= MAX_ACTIVE_LOCKS) {
            revert TooManyActiveLocks();
        }

        lockId = keccak256(
            abi.encode(
                oldStateCommitment,
                transitionPredicateHash,
                policyHash,
                domainSeparator,
                msg.sender,
                block.chainid,
                block.timestamp
            )
        );

        if (locks[lockId].lockId != bytes32(0)) {
            revert LockAlreadyExists(lockId);
        }

        if (!_isValidDomain(domainSeparator)) {
            revert InvalidDomainSeparator(domainSeparator);
        }

        locks[lockId] = ZKSLock({
            lockId: lockId,
            oldStateCommitment: oldStateCommitment,
            transitionPredicateHash: transitionPredicateHash,
            policyHash: policyHash,
            domainSeparator: domainSeparator,
            lockedBy: msg.sender,
            createdAt: uint64(block.timestamp),
            unlockDeadline: unlockDeadline,
            isUnlocked: false
        });

        _activeLockIndex[lockId] = _activeLockIds.length;
        _activeLockIds.push(lockId);

        unchecked {
            _packedStats += 1;
        }
        userLockCount[msg.sender]++;

        emit LockCreated(
            lockId,
            oldStateCommitment,
            transitionPredicateHash,
            policyHash,
            domainSeparator,
            msg.sender,
            unlockDeadline
        );
    }

    /**
     * @notice Unlocks a ZKSLock with valid zero-knowledge proof
     * @dev Verifies proof and executes state transition atomically
     * @param unlockProof Struct containing proof, new commitment, and nullifier
     */
    function unlock(
        UnlockProof calldata unlockProof
    ) external nonReentrant whenNotPaused {
        ZKSLock storage lock = locks[unlockProof.lockId];

        _validateLockForUnlock(lock);

        if (nullifierUsed[unlockProof.nullifier]) {
            revert NullifierAlreadyUsed(unlockProof.nullifier);
        }

        nullifierUsed[unlockProof.nullifier] = true;

        if (!_verifyProof(lock, unlockProof)) {
            nullifierUsed[unlockProof.nullifier] = false;
            revert InvalidProof(unlockProof.lockId);
        }

        _executeUnlock(
            unlockProof.lockId,
            unlockProof.newStateCommitment,
            unlockProof.nullifier,
            lock.domainSeparator
        );
    }

    /**
     * @notice Optimistic unlock with economic security
     * @dev Allows faster unlocking with bond-based dispute resolution
     * @param unlockProof Full unlock proof
     */
    function optimisticUnlock(
        UnlockProof calldata unlockProof
    ) external payable nonReentrant whenNotPaused {
        if (msg.value < MIN_BOND_AMOUNT) {
            revert InsufficientBond(MIN_BOND_AMOUNT, msg.value);
        }

        ZKSLock storage lock = locks[unlockProof.lockId];
        _validateLockForUnlock(lock);

        if (nullifierUsed[unlockProof.nullifier]) {
            revert NullifierAlreadyUsed(unlockProof.nullifier);
        }
        nullifierUsed[unlockProof.nullifier] = true;

        optimisticUnlocks[unlockProof.lockId] = OptimisticUnlock({
            unlocker: msg.sender,
            unlockTime: uint64(block.timestamp),
            bondAmount: msg.value.toUint128(),
            proofHash: keccak256(abi.encode(unlockProof)),
            finalizeAfter: uint64(block.timestamp + DISPUTE_WINDOW),
            disputed: false,
            newStateCommitment: unlockProof.newStateCommitment,
            nullifier: unlockProof.nullifier
        });

        unchecked {
            _packedStats += uint256(1) << _STAT_SHIFT_OPTIMISTIC;
        }

        emit OptimisticUnlockInitiated(
            unlockProof.lockId,
            msg.sender,
            msg.value,
            uint64(block.timestamp + DISPUTE_WINDOW)
        );
    }

    /**
     * @notice Finalize an optimistic unlock after dispute window
     * @param lockId Lock to finalize
     */
    function finalizeOptimisticUnlock(bytes32 lockId) external nonReentrant {
        OptimisticUnlock storage optimistic = optimisticUnlocks[lockId];

        if (optimistic.unlocker == address(0)) {
            revert NoOptimisticUnlock(lockId);
        }

        if (optimistic.disputed) {
            revert AlreadyDisputed(lockId);
        }

        if (block.timestamp < optimistic.finalizeAfter) {
            revert DisputeWindowStillOpen(lockId, optimistic.finalizeAfter);
        }

        ZKSLock storage lock = locks[lockId];

        _executeUnlock(
            lockId,
            optimistic.newStateCommitment,
            optimistic.nullifier,
            lock.domainSeparator
        );

        (bool success, ) = payable(optimistic.unlocker).call{
            value: optimistic.bondAmount
        }("");
        if (!success) revert ETHTransferFailed();

        emit OptimisticUnlockFinalized(lockId, optimistic.unlocker);
    }

    /**
     * @notice Challenge an optimistic unlock
     * @dev Supports fraud proof and conflict proof modes
     * @param lockId Lock to challenge
     * @param evidence The proof data (original or conflicting)
     */
    function challengeOptimisticUnlock(
        bytes32 lockId,
        UnlockProof calldata evidence
    ) external payable nonReentrant {
        if (msg.value < MIN_CHALLENGER_STAKE) {
            revert InsufficientChallengerStake(MIN_CHALLENGER_STAKE, msg.value);
        }

        OptimisticUnlock storage optimistic = optimisticUnlocks[lockId];

        if (optimistic.unlocker == address(0)) {
            revert NoOptimisticUnlock(lockId);
        }

        if (optimistic.disputed) {
            revert AlreadyDisputed(lockId);
        }

        if (block.timestamp >= optimistic.finalizeAfter) {
            revert ChallengeWindowClosed(lockId);
        }

        ZKSLock storage lock = locks[lockId];
        if (evidence.lockId != lockId) {
            revert InvalidConflictProof(lockId);
        }

        bool challengeSuccessful = false;
        bytes32 evidenceHash = keccak256(abi.encode(evidence));

        // CASE 1: Fraud Proof
        if (evidenceHash == optimistic.proofHash) {
            if (!_verifyProof(lock, evidence)) {
                challengeSuccessful = true;
            }
        }
        // CASE 2: Conflict Proof
        else {
            if (evidence.newStateCommitment != optimistic.newStateCommitment) {
                if (_verifyProof(lock, evidence)) {
                    challengeSuccessful = true;
                }
            }
        }

        if (challengeSuccessful) {
            optimistic.disputed = true;

            unchecked {
                _packedStats += uint256(1) << _STAT_SHIFT_DISPUTES;
            }

            uint256 totalReward = optimistic.bondAmount + msg.value;
            (bool success, ) = payable(msg.sender).call{value: totalReward}("");
            if (!success) revert ETHTransferFailed();

            emit LockDisputed(
                lockId,
                msg.sender,
                evidenceHash,
                optimistic.bondAmount
            );
        } else {
            (bool success, ) = payable(optimistic.unlocker).call{
                value: msg.value
            }("");
            if (!success) revert ETHTransferFailed();

            emit ChallengeRejected(lockId, msg.sender, msg.value);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFIER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Registers a new verifier contract
     * @param verifierKeyHash Hash of verification key
     * @param verifierContract Address of verifier contract
     */
    function registerVerifier(
        bytes32 verifierKeyHash,
        address verifierContract
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifiers[verifierKeyHash] != address(0)) {
            revert VerifierAlreadyRegistered(verifierKeyHash);
        }
        if (verifierContract == address(0)) revert InvalidVerifierAddress();

        verifiers[verifierKeyHash] = verifierContract;

        emit VerifierRegistered(verifierKeyHash, verifierContract);
    }

    /*//////////////////////////////////////////////////////////////
                           DOMAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Registers a new domain with extended chain ID support
     * @dev H-3 FIX: Uses uint64 chainId to support Arbitrum, Linea, Scroll, etc.
     * @param chainId The chain ID (supports values > 65535)
     * @param appId The application ID
     * @param epoch The epoch for versioning
     * @param name Human-readable domain name
     */
    function registerDomain(
        uint64 chainId,
        uint64 appId,
        uint32 epoch,
        string calldata name
    ) external onlyRole(DOMAIN_ADMIN_ROLE) returns (bytes32 domainSeparator) {
        domainSeparator = generateDomainSeparatorExtended(
            chainId,
            appId,
            epoch
        );

        if (domains[domainSeparator].registeredAt != 0) {
            revert DomainAlreadyExists(domainSeparator);
        }

        domains[domainSeparator] = Domain({
            chainId: chainId,
            appId: appId,
            epoch: epoch,
            name: name,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });

        emit DomainRegistered(domainSeparator, chainId, appId, epoch, name);
    }

    /**
     * @notice Force unlock a lock (Emergency Recovery)
     * @dev Only callable by RECOVERY_ROLE
     * @param lockId The lock to recover
     * @param recipient The address that initiated recovery (for event tracking)
     */
    function recoverLock(
        bytes32 lockId,
        address recipient
    ) external nonReentrant onlyRole(RECOVERY_ROLE) {
        ZKSLock storage lock = locks[lockId];
        if (lock.lockId == bytes32(0)) revert InvalidLock(lockId);
        if (lock.isUnlocked) revert LockAlreadyUnlocked(lockId);

        bytes32 recoveryNullifier = keccak256(
            abi.encode(lockId, "RECOVERY", block.chainid)
        );

        if (nullifierUsed[recoveryNullifier]) {
            revert NullifierAlreadyUsed(recoveryNullifier);
        }
        nullifierUsed[recoveryNullifier] = true;

        lock.isUnlocked = true;
        _removeActiveLock(lockId);
        delete optimisticUnlocks[lockId];

        emit LockUnlocked(
            lockId,
            bytes32(0),
            recoveryNullifier,
            lock.domainSeparator,
            recipient
        );
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validateLockForUnlock(ZKSLock storage lock) internal view {
        if (lock.lockId == bytes32(0)) {
            revert LockDoesNotExist(lock.lockId);
        }

        if (lock.isUnlocked) {
            revert LockAlreadyUnlocked(lock.lockId);
        }

        if (lock.unlockDeadline > 0 && block.timestamp > lock.unlockDeadline) {
            revert LockExpired(lock.lockId, lock.unlockDeadline);
        }
    }

    function _verifyProof(
        ZKSLock storage lock,
        UnlockProof calldata unlockProof
    ) internal view returns (bool) {
        address verifier = verifiers[unlockProof.verifierKeyHash];

        if (verifier != address(0)) {
            bytes32[] memory publicInputs = new bytes32[](6);
            publicInputs[0] = lock.oldStateCommitment;
            publicInputs[1] = unlockProof.newStateCommitment;
            publicInputs[2] = lock.transitionPredicateHash;
            publicInputs[3] = lock.policyHash;
            publicInputs[4] = lock.domainSeparator;
            publicInputs[5] = unlockProof.nullifier;

            (bool success, bytes memory returnData) = verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes,bytes32[])",
                    unlockProof.zkProof,
                    publicInputs
                )
            );

            if (!success) return false;

            return abi.decode(returnData, (bool));
        } else if (address(proofVerifier) != address(0)) {
            uint256[] memory inputs = new uint256[](6);
            inputs[0] = uint256(lock.oldStateCommitment);
            inputs[1] = uint256(unlockProof.newStateCommitment);
            inputs[2] = uint256(lock.transitionPredicateHash);
            inputs[3] = uint256(lock.policyHash);
            inputs[4] = uint256(lock.domainSeparator);
            inputs[5] = uint256(unlockProof.nullifier);

            return proofVerifier.verify(unlockProof.zkProof, inputs);
        } else {
            return false;
        }
    }

    function _executeUnlock(
        bytes32 lockId,
        bytes32 newStateCommitment,
        bytes32 nullifier,
        bytes32 domainSeparator
    ) internal {
        ZKSLock storage lock = locks[lockId];

        lock.isUnlocked = true;
        nullifierUsed[nullifier] = true;

        commitmentSuccessor[lock.oldStateCommitment] = newStateCommitment;
        commitmentPredecessor[newStateCommitment] = lock.oldStateCommitment;

        unlockReceipts[lockId] = UnlockReceipt({
            lockId: lockId,
            newStateCommitment: newStateCommitment,
            nullifier: nullifier,
            domainSeparator: domainSeparator,
            unlockedBy: msg.sender,
            unlockedAt: uint64(block.timestamp)
        });

        _removeActiveLock(lockId);

        unchecked {
            _packedStats += uint256(1) << _STAT_SHIFT_UNLOCKED;
        }

        emit LockUnlocked(
            lockId,
            newStateCommitment,
            nullifier,
            domainSeparator,
            msg.sender
        );
    }

    function _removeActiveLock(bytes32 lockId) internal {
        uint256 index = _activeLockIndex[lockId];
        uint256 lastIndex = _activeLockIds.length - 1;

        if (index != lastIndex) {
            bytes32 lastLockId = _activeLockIds[lastIndex];
            _activeLockIds[index] = lastLockId;
            _activeLockIndex[lastLockId] = index;
        }

        _activeLockIds.pop();
        delete _activeLockIndex[lockId];
    }

    function _registerDefaultDomains() internal {
        _registerDomainInternal(1, 0, 0, "Ethereum Mainnet");
        _registerDomainInternalExtended(11155111, 0, 0, "Sepolia Testnet");
        _registerDomainInternalExtended(42161, 0, 0, "Arbitrum One");
        _registerDomainInternal(10, 0, 0, "Optimism");
        _registerDomainInternal(137, 0, 0, "Polygon");
        _registerDomainInternalExtended(8453, 0, 0, "Base");
    }

    function _registerDomainInternal(
        uint16 chainId,
        uint16 appId,
        uint32 epoch,
        string memory name
    ) internal {
        bytes32 domainSep = generateDomainSeparator(chainId, appId, epoch);
        domains[domainSep] = Domain({
            chainId: chainId,
            appId: appId,
            epoch: epoch,
            name: name,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });
    }

    function _registerDomainInternalExtended(
        uint64 chainId,
        uint64 appId,
        uint32 epoch,
        string memory name
    ) internal {
        bytes32 domainSep = generateDomainSeparatorExtended(
            chainId,
            appId,
            epoch
        );
        domains[domainSep] = Domain({
            chainId: chainId,
            appId: appId,
            epoch: epoch,
            name: name,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });
    }

    function _isValidDomain(
        bytes32 domainSeparator
    ) internal view returns (bool) {
        return domains[domainSeparator].isActive;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generates a domain separator from components
     * @dev Uses explicit masking to prevent LLVM optimization bugs on L2s
     */
    function generateDomainSeparator(
        uint16 chainId,
        uint16 appId,
        uint32 epoch
    ) public pure returns (bytes32) {
        uint256 result = 0;
        uint256 chainIdMasked = uint256(chainId) & 0xFFFF;
        uint256 appIdMasked = uint256(appId) & 0xFFFF;
        uint256 epochMasked = uint256(epoch) & 0xFFFFFFFF;

        result = result | (chainIdMasked << 224);
        result = result | (appIdMasked << 208);
        result = result | (epochMasked << 176);

        return bytes32(result);
    }

    /**
     * @notice Generates domain separator with extended chain ID support
     */
    function generateDomainSeparatorExtended(
        uint64 chainId,
        uint64 appId,
        uint32 epoch
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainId, appId, epoch, "ZKSLock"));
    }

    /**
     * @notice Generates cross-domain nullifier
     */
    function generateNullifier(
        bytes32 secret,
        bytes32 lockId,
        bytes32 domainSeparator
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    keccak256(abi.encodePacked(secret, "ZKSLock")),
                    lockId,
                    domainSeparator,
                    uint256(0)
                )
            );
    }

    /**
     * @notice Get active lock IDs with pagination
     * @param offset Start index
     * @param limit Maximum number of items to return
     */
    function getActiveLockIds(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory) {
        uint256 total = _activeLockIds.length;
        if (offset >= total) {
            return new bytes32[](0);
        }

        uint256 count = limit;
        if (offset + count > total) {
            count = total - offset;
        }

        bytes32[] memory result = new bytes32[](count);
        for (uint256 i = 0; i < count; ) {
            result[i] = _activeLockIds[offset + i];
            unchecked {
                ++i;
            }
        }
        return result;
    }

    /**
     * @notice Returns the number of active locks
     */
    function getActiveLockCount() external view returns (uint256) {
        return _activeLockIds.length;
    }

    /**
     * @notice Returns all active lock IDs (up to 100)
     * @dev Convenience method for tests — in production use the paginated version
     */
    function getActiveLockIds() external view returns (bytes32[] memory) {
        uint256 count = _activeLockIds.length;
        if (count > 100) {
            count = 100;
        }
        bytes32[] memory result = new bytes32[](count);
        for (uint256 i = 0; i < count; ) {
            result[i] = _activeLockIds[i];
            unchecked {
                ++i;
            }
        }
        return result;
    }

    /**
     * @notice Returns lock details
     */
    function getLock(bytes32 lockId) external view returns (ZKSLock memory) {
        return locks[lockId];
    }

    /**
     * @notice Checks if lock can be unlocked
     */
    function canUnlock(bytes32 lockId) external view returns (bool) {
        ZKSLock storage lock = locks[lockId];
        return
            lock.lockId != bytes32(0) &&
            !lock.isUnlocked &&
            (lock.unlockDeadline == 0 || block.timestamp < lock.unlockDeadline);
    }

    /**
     * @notice Returns commitment chain history
     */
    function getCommitmentChain(
        bytes32 startCommitment,
        uint256 maxDepth
    ) external view returns (bytes32[] memory chain) {
        chain = new bytes32[](maxDepth);
        bytes32 current = startCommitment;

        for (uint256 i = 0; i < maxDepth; ) {
            chain[i] = current;
            current = commitmentSuccessor[current];
            if (current == bytes32(0)) {
                bytes32[] memory resized = new bytes32[](i + 1);
                for (uint256 j = 0; j <= i; ) {
                    resized[j] = chain[j];
                    unchecked {
                        ++j;
                    }
                }
                return resized;
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Get statistics
     * @return created Total locks created
     * @return unlocked Total locks unlocked
     * @return active Current active lock count
     * @return optimistic Total optimistic unlocks
     * @return disputed Total disputes
     */
    function getStats()
        external
        view
        returns (
            uint256 created,
            uint256 unlocked,
            uint256 active,
            uint256 optimistic,
            uint256 disputed
        )
    {
        uint256 stats = _packedStats;
        return (
            uint64(stats),
            uint64(stats >> _STAT_SHIFT_UNLOCKED),
            _activeLockIds.length,
            uint64(stats >> _STAT_SHIFT_OPTIMISTIC),
            uint64(stats >> _STAT_SHIFT_DISPUTES)
        );
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Confirms that critical roles have been separated
     * @dev M-15: Adds centralization protection — call before mainnet to verify
     *      different addresses hold different roles
     */
    function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        address admin = msg.sender;

        require(
            !hasRole(DISPUTE_RESOLVER_ROLE, admin) &&
                !hasRole(RECOVERY_ROLE, admin) &&
                !hasRole(OPERATOR_ROLE, admin),
            "Admin must not hold operational roles"
        );

        rolesSeparated = true;
    }

    /// @notice Pause all lock operations (emergency use)
    function pause() external onlyRole(LOCK_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume lock operations after pause
    function unpause() external onlyRole(LOCK_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                            UUPS UPGRADE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Authorizes an upgrade to a new implementation
     * @dev Only callable by addresses with UPGRADER_ROLE. Increments contractVersion.
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        contractVersion++;
        emit ContractUpgraded(newImplementation, contractVersion);
    }

    /*//////////////////////////////////////////////////////////////
                           STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage gap for future upgrades (50 slots)
    uint256[50] private __gap;
}
