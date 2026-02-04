// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../primitives/ZKBoundStateLocks.sol";
import "../primitives/ProofCarryingContainer.sol";
import "../primitives/CrossDomainNullifierAlgebra.sol";

/// @title ZKSLockIntegration
/// @author Soul Protocol - Soul v2
/// @notice Integration library connecting ZK-Bound State Locks with PC³, CDNA, and other Soul primitives
/// @dev Provides unified interface for cross-primitive operations involving ZK-SLocks
///
/// Key Integrations:
/// - PC³: Container locking/unlocking with ZK proofs
/// - CDNA: Cross-domain nullifier generation and verification
/// - EASC: Execution-agnostic state transitions
/// - PBP: Policy-bound proof enforcement
contract ZKSLockIntegration {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

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


    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event ContainerLocked(
        bytes32 indexed containerId,
        bytes32 indexed lockId,
        bytes32 stateCommitment
    );

    event ContainerUnlocked(
        bytes32 indexed containerId,
        bytes32 indexed lockId,
        bytes32 newStateCommitment
    );

    event CrossDomainLockCreated(
        bytes32 indexed lockId,
        bytes32 indexed sourceDomainId,
        bytes32 indexed targetDomainId,
        bytes32 nullifier
    );

    event NullifierBound(
        bytes32 indexed lockId,
        bytes32 indexed nullifier,
        bytes32 domainId
    );

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Reference to ZKBoundStateLocks contract
    ZKBoundStateLocks public immutable zkSlocks;

    /// @notice Reference to ProofCarryingContainer contract
    ProofCarryingContainer public immutable pc3;

    /// @notice Reference to CrossDomainNullifierAlgebra contract
    CrossDomainNullifierAlgebra public immutable cdna;

    /// @notice Mapping from container ID to lock ID
    mapping(bytes32 => bytes32) public containerToLock;

    /// @notice Mapping from lock ID to container ID
    mapping(bytes32 => bytes32) public lockToContainer;

    /// @notice Mapping from lock ID to CDNA nullifier
    mapping(bytes32 => bytes32) public lockToNullifier;

    /// @notice Mapping of nullifier to lock ID
    mapping(bytes32 => bytes32) public nullifierToLock;

    /// @notice Default domain separator for this chain
    bytes32 public defaultDomainSeparator;

    /// @notice Whether integration is enabled
    bool public integrationEnabled;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _zkSlocks, address _pc3, address _cdna) {
        zkSlocks = ZKBoundStateLocks(_zkSlocks);
        pc3 = ProofCarryingContainer(_pc3);
        cdna = CrossDomainNullifierAlgebra(_cdna);
        integrationEnabled = true;

        // Generate default domain separator for this chain
        defaultDomainSeparator = keccak256(
            abi.encodePacked(block.chainid, address(this), "ZKSLockIntegration")
        );
    }

    /*//////////////////////////////////////////////////////////////
                           PC³ INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a ZK-SLock bound to a PC³ container
    /// @param containerId The PC³ container to lock
    /// @param transitionPredicateHash Hash of the required transition
    /// @param policyBinding Policy requirements for unlock
    /// @param domainSeparator Domain separator to use
    /// @param unlockDeadline Deadline for unlock
    /// @return lockId The created lock ID
    function lockContainer(
        bytes32 containerId,
        bytes32 transitionPredicateHash,
        bytes32 policyBinding,
        bytes32 domainSeparator,
        uint64 unlockDeadline
    ) external returns (bytes32 lockId) {
        if (!integrationEnabled) revert IntegrationDisabled();
        if (containerToLock[containerId] != bytes32(0)) {
            revert ContainerAlreadyLocked();
        }

        // Get container state commitment
        (, bytes32 stateCommitment, , , , , , , , ) = pc3.containers(
            containerId
        );

        // Create ZK-SLock using the actual function signature
        lockId = zkSlocks.createLock(
            stateCommitment,
            transitionPredicateHash,
            policyBinding,
            domainSeparator != bytes32(0)
                ? domainSeparator
                : defaultDomainSeparator,
            unlockDeadline
        );

        // Store bindings
        containerToLock[containerId] = lockId;
        lockToContainer[lockId] = containerId;

        emit ContainerLocked(containerId, lockId, stateCommitment);
    }

    /// @notice Unlocks a PC³ container with a ZK proof
    /// @param containerId The container to unlock
    /// @param unlockProof Full unlock proof struct
    function unlockContainer(
        bytes32 containerId,
        ZKBoundStateLocks.UnlockProof calldata unlockProof
    ) external {
        if (!integrationEnabled) revert IntegrationDisabled();

        bytes32 lockId = containerToLock[containerId];
        if (lockId == bytes32(0)) revert InvalidLockId();
        if (lockId != unlockProof.lockId) revert InvalidLockId();

        // Unlock the ZK-SLock
        zkSlocks.unlock(unlockProof);

        // Clear bindings
        delete containerToLock[containerId];
        delete lockToContainer[lockId];

        emit ContainerUnlocked(
            containerId,
            lockId,
            unlockProof.newStateCommitment
        );
    }

    /*//////////////////////////////////////////////////////////////
                           CDNA INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a cross-domain ZK-SLock with CDNA nullifier binding
    /// @param stateCommitment State to lock
    /// @param transitionPredicateHash Required transition
    /// @param domainId CDNA domain for nullifier
    /// @param commitmentHash Associated commitment for CDNA
    /// @param policyHash Policy hash for the lock
    /// @param userEntropy User-provided randomness for nullifier generation
    /// @dev SECURITY: Requires user entropy to prevent front-running attacks.
    ///      block.timestamp is manipulable by miners/sequencers on L2s.
    /// @return lockId The created lock ID
    /// @return nullifier The generated CDNA nullifier
    function createCrossDomainLock(
        bytes32 stateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 domainId,
        bytes32 commitmentHash,
        bytes32 policyHash,
        bytes32 userEntropy
    ) external returns (bytes32 lockId, bytes32 nullifier) {
        if (!integrationEnabled) revert IntegrationDisabled();
        if (userEntropy == bytes32(0)) revert UserEntropyRequired();

        // Create the ZK-SLock
        lockId = zkSlocks.createLock(
            stateCommitment,
            transitionPredicateHash,
            policyHash,
            domainId, // Use domainId as domainSeparator
            0 // No deadline
        );

        // Generate nullifier with user-provided entropy
        // SECURITY: Combines user entropy with msg.sender and block.number for unpredictability
        nullifier = zkSlocks.generateNullifier(
            keccak256(abi.encodePacked(userEntropy, msg.sender, block.number)),
            lockId,
            domainId
        );

        // Register nullifier in CDNA
        cdna.registerNullifier(
            nullifier,
            domainId,
            commitmentHash,
            lockId // Use lockId as transitionId
        );

        // Store bindings
        lockToNullifier[lockId] = nullifier;
        nullifierToLock[nullifier] = lockId;

        emit NullifierBound(lockId, nullifier, domainId);
    }

    /*//////////////////////////////////////////////////////////////
                        ATOMIC OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Atomically creates lock, binds nullifier, and prepares container
    /// @dev One-transaction cross-primitive operation
    struct AtomicLockParams {
        bytes32 stateCommitment;
        bytes32 transitionPredicateHash;
        bytes32 policyBinding;
        bytes32 domainSeparator;
        bytes32 commitmentHash;
        uint64 unlockDeadline;
        bytes32 userEntropy; // SECURITY: User-provided randomness
        bytes encryptedPayload;
    }

    /// @notice Creates an atomic lock across all integrated primitives
    /// @dev SECURITY: Requires userEntropy in params to prevent front-running
    function createAtomicLock(
        AtomicLockParams calldata params
    )
        external
        returns (bytes32 lockId, bytes32 containerId, bytes32 nullifier)
    {
        if (!integrationEnabled) revert IntegrationDisabled();
        if (params.userEntropy == bytes32(0)) revert UserEntropyRequired();

        bytes32 domainSep = params.domainSeparator != bytes32(0)
            ? params.domainSeparator
            : defaultDomainSeparator;

        // 1. Create ZK-SLock
        lockId = zkSlocks.createLock(
            params.stateCommitment,
            params.transitionPredicateHash,
            params.policyBinding,
            domainSep,
            params.unlockDeadline
        );

        // 2. Generate nullifier with user entropy
        // SECURITY: Uses user entropy + msg.sender + block.number for unpredictability
        nullifier = zkSlocks.generateNullifier(
            keccak256(
                abi.encodePacked(params.userEntropy, msg.sender, block.number)
            ),
            lockId,
            domainSep
        );

        // 3. Store nullifier binding
        lockToNullifier[lockId] = nullifier;
        nullifierToLock[nullifier] = lockId;

        // 4. Create container ID (PC³ container creation would happen externally)
        if (params.encryptedPayload.length > 0) {
            containerId = keccak256(abi.encode(lockId, block.number));
            containerToLock[containerId] = lockId;
            lockToContainer[lockId] = containerId;
        }

        emit CrossDomainLockCreated(
            lockId,
            domainSep,
            bytes32(block.chainid),
            nullifier
        );
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Batch create multiple locks
    function batchCreateLocks(
        bytes32[] calldata stateCommitments,
        bytes32[] calldata transitionPredicates,
        bytes32[] calldata policyHashes,
        bytes32 domainSeparator,
        uint64[] calldata unlockDeadlines
    ) external returns (bytes32[] memory lockIds) {
        if (!integrationEnabled) revert IntegrationDisabled();

        uint256 count = stateCommitments.length;
        lockIds = new bytes32[](count);

        bytes32 domainSep = domainSeparator != bytes32(0)
            ? domainSeparator
            : defaultDomainSeparator;

        for (uint256 i = 0; i < count; i++) {
            lockIds[i] = zkSlocks.createLock(
                stateCommitments[i],
                transitionPredicates[i],
                policyHashes[i],
                domainSep,
                unlockDeadlines[i]
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get full lock info including container and nullifier bindings
    function getLockInfo(
        bytes32 lockId
    )
        external
        view
        returns (
            bytes32 stateCommitment,
            bytes32 containerId,
            bytes32 nullifier,
            bool isLocked
        )
    {
        (
            ,
            // lockId
            bytes32 oldStateCommitment, // transitionPredicateHash // policyHash // domainSeparator // lockedBy // createdAt // unlockDeadline
            ,
            ,
            ,
            ,
            ,
            ,
            bool isUnlocked
        ) = zkSlocks.locks(lockId);
        stateCommitment = oldStateCommitment;
        containerId = lockToContainer[lockId];
        nullifier = lockToNullifier[lockId];
        isLocked = !isUnlocked;
    }

    /// @notice Check if a container is currently locked
    function isContainerLocked(
        bytes32 containerId
    ) external view returns (bool) {
        bytes32 lockId = containerToLock[containerId];
        if (lockId == bytes32(0)) return false;

        (, , , , , , , , bool isUnlocked) = zkSlocks.locks(lockId);
        return !isUnlocked;
    }

    /// @notice Get the lock ID for a nullifier
    function getLockForNullifier(
        bytes32 nullifier
    ) external view returns (bytes32) {
        return nullifierToLock[nullifier];
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Toggle integration status
    function setIntegrationEnabled(bool enabled) external {
        // In production, add access control
        integrationEnabled = enabled;
    }

    /// @notice Set default domain separator
    function setDefaultDomainSeparator(bytes32 separator) external {
        // In production, add access control
        defaultDomainSeparator = separator;
    }
}
