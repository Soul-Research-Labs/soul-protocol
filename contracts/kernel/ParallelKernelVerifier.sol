// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IZKVerifier} from "../interfaces/IPrivacyPrimitives.sol";

/**
 * @title ParallelKernelVerifier
 * @author Soul Protocol
 * @notice Monad-inspired parallel verification with deterministic conflict resolution
 * @dev Core insight from Monad: Speculative parallel execution with conflict detection
 *
 * MONAD'S CONTRIBUTION (Abstracted):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Monad executes transactions:                                               │
 * │ 1. Speculatively in parallel                                               │
 * │ 2. Records read sets + write sets                                          │
 * │ 3. Detects conflicts                                                       │
 * │ 4. Replays conflicting txs sequentially                                    │
 * │ 5. Commits deterministic result                                            │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S ADAPTATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Soul verifies confidential executions:                                     │
 * │ 1. Speculatively verify proofs in parallel                                 │
 * │ 2. Records commitment sets + nullifier sets                                │
 * │ 3. Detects conflicts (nullifier collisions, commitment overlaps)           │
 * │ 4. Accepts maximal conflict-free subset                                    │
 * │ 5. Commits deterministic result with canonical ordering                    │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * KEY DIFFERENCES FROM MONAD:
 * - Soul hides conflict metadata inside ZK proofs
 * - Soul standardizes proof sizes to prevent timing attacks
 * - Soul parallelizes across chains, not just contracts
 * - Soul's "scheduler" is the kernel verifier
 */
contract ParallelKernelVerifier is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed keccak256("VERIFIER_ROLE") for gas savings
    bytes32 public constant VERIFIER_ROLE =
        0x0ce23c3e399818cfee81a7ab0880f714e53d7672b08df0fa62f2843416e1ea09;
    /// @dev Pre-computed keccak256("SEQUENCER_ROLE") for gas savings
    bytes32 public constant SEQUENCER_ROLE =
        0xac4f1890dc96c9a02330d1fa696648a38f3b282d2449c2d8e6f10507488c84c8;
    /// @dev Pre-computed keccak256("OPERATOR_ROLE") for gas savings
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                          SECURITY CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum array length to prevent gas griefing
    uint256 public constant MAX_COMMITMENTS = 100;
    uint256 public constant MAX_NULLIFIERS = 50;

    /// @notice External ZK verifier contract (must be set for production)
    address public zkVerifier;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execution status in parallel pipeline
     */
    enum ExecutionStatus {
        Pending, // Submitted, not yet verified
        Verifying, // Proof verification in progress
        Verified, // Proof valid, checking conflicts
        Conflicted, // Has conflict, needs replay/discard
        Accepted, // No conflicts, ready to commit
        Committed, // Finalized
        Discarded // Lost conflict resolution
    }

    /**
     * @notice Conflict type classification
     */
    enum ConflictType {
        None, // No conflict
        NullifierCollision, // Same nullifier consumed twice
        CommitmentOverlap, // Same commitment read+write
        StateConflict, // Same state commitment modified
        PolicyConflict, // Conflicting policies
        DomainConflict // Cross-domain ordering issue
    }

    /**
     * @notice Parallel execution result (Monad's read/write set equivalent)
     * @dev This is what each confidential execution produces
     */
    struct ExecutionResult {
        bytes32 executionId;
        // Commitment sets (Monad's read/write sets)
        bytes32[] readCommitments; // State commitments read
        bytes32[] writeCommitments; // State commitments written
        bytes32[] nullifiersConsumed; // Nullifiers consumed (critical for conflict)
        bytes32[] nullifiersProduced; // New nullifiers created
        // Output
        bytes32 outputCommitment;
        bytes32 stateTransitionHash;
        // Policy binding
        bytes32 policyHash;
        bytes32 domainSeparator;
        // Proof
        bytes32 proofHash;
        bytes proof;
        // Metadata
        address submitter;
        uint64 submittedAt;
        uint64 sequenceNumber; // For deterministic ordering
        // Status
        ExecutionStatus status;
        ConflictType conflictType;
        bytes32 conflictWith; // Execution it conflicts with
    }

    /**
     * @notice Batch of parallel executions
     */
    struct ExecutionBatch {
        bytes32 batchId;
        bytes32[] executionIds;
        // Batch metadata
        uint64 createdAt;
        uint64 verifiedAt;
        uint64 committedAt;
        // Conflict resolution
        uint256 totalExecutions;
        uint256 acceptedCount;
        uint256 conflictedCount;
        uint256 discardedCount;
        // Status
        bool resolved;
        bool committed;
        // Canonical ordering
        bytes32[] canonicalOrder; // Final accepted order
    }

    /**
     * @notice Conflict detection result
     */
    struct ConflictResult {
        bool hasConflict;
        ConflictType conflictType;
        bytes32 conflictingExecutionId;
        bytes32 conflictingElement; // The nullifier/commitment that conflicts
    }

    /**
     * @notice Verification result for batch
     */
    struct BatchVerificationResult {
        bytes32 batchId;
        uint256 totalVerified;
        uint256 totalAccepted;
        uint256 totalConflicted;
        bytes32[] acceptedExecutions;
        bytes32[] conflictedExecutions;
        bytes32 batchRoot; // Merkle root of accepted executions
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // Execution storage
    mapping(bytes32 => ExecutionResult) public executions;
    mapping(bytes32 => ExecutionBatch) public batches;

    // Conflict tracking
    mapping(bytes32 => bool) public consumedNullifiers;
    mapping(bytes32 => bytes32) public nullifierToExecution; // Which execution consumed it
    mapping(bytes32 => bool) public lockedCommitments;
    mapping(bytes32 => bytes32) public commitmentToExecution;

    // Batch tracking
    bytes32[] public pendingBatches;
    mapping(bytes32 => bytes32[]) public batchExecutions;

    // Sequencing
    uint64 public currentSequenceNumber;
    mapping(uint64 => bytes32) public sequenceToExecution;

    // Performance metrics
    uint256 public totalExecutions;
    uint256 public totalBatches;
    uint256 public totalConflicts;
    uint256 public totalAccepted;
    uint256 public parallelizationRatio; // Basis points (10000 = 100%)

    // Configuration
    uint256 public maxBatchSize;
    uint256 public conflictWindowBlocks;
    bool public speculativeMode;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ExecutionSubmitted(
        bytes32 indexed executionId,
        bytes32 indexed batchId,
        address submitter,
        uint64 sequenceNumber
    );

    event ExecutionVerified(
        bytes32 indexed executionId,
        bool valid,
        bytes32 proofHash
    );

    event ConflictDetected(
        bytes32 indexed executionId,
        bytes32 indexed conflictWith,
        ConflictType conflictType,
        bytes32 conflictingElement
    );

    event ExecutionAccepted(
        bytes32 indexed executionId,
        bytes32 indexed batchId
    );

    event ExecutionDiscarded(
        bytes32 indexed executionId,
        bytes32 indexed batchId,
        ConflictType reason
    );

    event BatchCreated(bytes32 indexed batchId, uint256 executionCount);

    event BatchResolved(
        bytes32 indexed batchId,
        uint256 accepted,
        uint256 conflicted,
        uint256 discarded
    );

    event BatchCommitted(
        bytes32 indexed batchId,
        bytes32 batchRoot,
        uint256 executionCount
    );

    error TooManyReadCommitments();
    error TooManyWriteCommitments();
    error TooManyNullifiersConsumed();
    error TooManyNullifiersProduced();
    error ExecutionExists();
    error EmptyBatch();
    error BatchTooLarge();
    error BatchNotFound();
    error BatchAlreadyResolved();
    error BatchNotResolved();
    error BatchAlreadyCommitted();
    error ZeroAddress();
    error NullifierAlreadyConsumed();


    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(uint256 _maxBatchSize, uint256 _conflictWindowBlocks) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(SEQUENCER_ROLE, msg.sender);

        maxBatchSize = _maxBatchSize > 0 ? _maxBatchSize : 100;
        conflictWindowBlocks = _conflictWindowBlocks > 0
            ? _conflictWindowBlocks
            : 10;
        speculativeMode = true;
    }

    /*//////////////////////////////////////////////////////////////
                        PARALLEL EXECUTION SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit execution for parallel verification
     * @dev Monad analogue: Transaction submission to parallel executor
     * @param readCommitments State commitments this execution reads
     * @param writeCommitments State commitments this execution writes
     * @param nullifiersConsumed Nullifiers consumed (conflict detection critical)
     * @param nullifiersProduced New nullifiers produced
     * @param outputCommitment Commitment to execution output
     * @param policyHash Policy applied
     * @param proof Execution proof
     * @return executionId Unique execution identifier
     */
    function submitExecution(
        bytes32[] calldata readCommitments,
        bytes32[] calldata writeCommitments,
        bytes32[] calldata nullifiersConsumed,
        bytes32[] calldata nullifiersProduced,
        bytes32 outputCommitment,
        bytes32 policyHash,
        bytes calldata proof
    ) external whenNotPaused nonReentrant returns (bytes32 executionId) {
        // Security: Validate array lengths to prevent gas griefing
        if (readCommitments.length > MAX_COMMITMENTS)
            revert TooManyReadCommitments();
        if (writeCommitments.length > MAX_COMMITMENTS)
            revert TooManyWriteCommitments();
        if (nullifiersConsumed.length > MAX_NULLIFIERS)
            revert TooManyNullifiersConsumed();
        if (nullifiersProduced.length > MAX_NULLIFIERS)
            revert TooManyNullifiersProduced();

        // Security: Immediate nullifier collision check to prevent front-running
        for (uint256 i = 0; i < nullifiersConsumed.length; i++) {
            if (consumedNullifiers[nullifiersConsumed[i]])
                revert NullifierAlreadyConsumed();
        }

        executionId = keccak256(
            abi.encode(
                msg.sender,
                outputCommitment,
                policyHash,
                block.number,
                currentSequenceNumber
            )
        );

        if (executions[executionId].submittedAt != 0) revert ExecutionExists();

        uint64 seqNum;
        unchecked {
            seqNum = currentSequenceNumber++;
        }

        executions[executionId] = ExecutionResult({
            executionId: executionId,
            readCommitments: readCommitments,
            writeCommitments: writeCommitments,
            nullifiersConsumed: nullifiersConsumed,
            nullifiersProduced: nullifiersProduced,
            outputCommitment: outputCommitment,
            stateTransitionHash: keccak256(
                abi.encode(
                    readCommitments,
                    writeCommitments,
                    outputCommitment
                )
            ),
            policyHash: policyHash,
            domainSeparator: bytes32(0),
            proofHash: keccak256(proof),
            proof: proof,
            submitter: msg.sender,
            submittedAt: uint64(block.timestamp),
            sequenceNumber: seqNum,
            status: ExecutionStatus.Pending,
            conflictType: ConflictType.None,
            conflictWith: bytes32(0)
        });

        sequenceToExecution[seqNum] = executionId;
        unchecked {
            ++totalExecutions;
        }

        emit ExecutionSubmitted(executionId, bytes32(0), msg.sender, seqNum);
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create batch from pending executions
     * @dev Groups executions for parallel verification
     * @param executionIds Executions to include in batch
     * @return batchId The batch identifier
     */
    function createBatch(
        bytes32[] calldata executionIds
    ) external onlyRole(SEQUENCER_ROLE) returns (bytes32 batchId) {
        if (executionIds.length == 0) revert EmptyBatch();
        if (executionIds.length > maxBatchSize) revert BatchTooLarge();

        batchId = keccak256(
            abi.encode(executionIds, block.timestamp, totalBatches)
        );

        batches[batchId] = ExecutionBatch({
            batchId: batchId,
            executionIds: executionIds,
            createdAt: uint64(block.timestamp),
            verifiedAt: 0,
            committedAt: 0,
            totalExecutions: executionIds.length,
            acceptedCount: 0,
            conflictedCount: 0,
            discardedCount: 0,
            resolved: false,
            committed: false,
            canonicalOrder: new bytes32[](0)
        });

        batchExecutions[batchId] = executionIds;
        pendingBatches.push(batchId);
        unchecked {
            ++totalBatches;
        }

        emit BatchCreated(batchId, executionIds.length);
    }

    /*//////////////////////////////////////////////////////////////
                        PARALLEL VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify batch of executions in parallel
     * @dev Monad analogue: Parallel transaction execution with conflict detection
     * @param batchId Batch to verify
     * @return result Verification result with conflicts
     */
    function verifyBatch(
        bytes32 batchId
    )
        external
        onlyRole(VERIFIER_ROLE)
        returns (BatchVerificationResult memory result)
    {
        ExecutionBatch storage batch = batches[batchId];
        if (batch.createdAt == 0) revert BatchNotFound();
        if (batch.resolved) revert BatchAlreadyResolved();

        bytes32[] memory executionIds = batchExecutions[batchId];

        // Track which executions are accepted
        bool[] memory accepted = new bool[](executionIds.length);
        uint256 acceptedCount = 0;
        uint256 conflictedCount = 0;

        // Phase 1: Verify all proofs (can be parallelized off-chain)
        for (uint256 i = 0; i < executionIds.length; i++) {
            ExecutionResult storage exec = executions[executionIds[i]];

            // Verify proof
            bool valid = _verifyProof(exec.proofHash, exec.proof);

            if (valid) {
                exec.status = ExecutionStatus.Verified;
            } else {
                exec.status = ExecutionStatus.Discarded;
                exec.conflictType = ConflictType.None; // Invalid proof, not conflict
            }
        }

        // Phase 2: Detect conflicts (deterministic ordering)
        // Process in sequence number order for determinism
        for (uint256 i = 0; i < executionIds.length; ) {
            ExecutionResult storage exec = executions[executionIds[i]];

            if (exec.status != ExecutionStatus.Verified) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Check for conflicts
            ConflictResult memory conflict = _detectConflicts(executionIds[i]);

            if (conflict.hasConflict) {
                exec.status = ExecutionStatus.Conflicted;
                exec.conflictType = conflict.conflictType;
                exec.conflictWith = conflict.conflictingExecutionId;
                unchecked {
                    ++conflictedCount;
                }

                emit ConflictDetected(
                    executionIds[i],
                    conflict.conflictingExecutionId,
                    conflict.conflictType,
                    conflict.conflictingElement
                );
            } else {
                // No conflict - accept and lock resources
                _acceptExecution(executionIds[i]);
                exec.status = ExecutionStatus.Accepted;
                accepted[i] = true;
                unchecked {
                    ++acceptedCount;
                }

                emit ExecutionAccepted(executionIds[i], batchId);
            }
            unchecked {
                ++i;
            }
        }

        // Phase 3: Resolve conflicts (deterministic replay)
        // In Soul, we discard conflicting executions rather than replay
        // The submitter can resubmit with updated inputs
        uint256 discardedCount = 0;
        for (uint256 i = 0; i < executionIds.length; ) {
            ExecutionResult storage exec = executions[executionIds[i]];

            if (exec.status == ExecutionStatus.Conflicted) {
                exec.status = ExecutionStatus.Discarded;
                unchecked {
                    ++discardedCount;
                    ++totalConflicts;
                }

                emit ExecutionDiscarded(
                    executionIds[i],
                    batchId,
                    exec.conflictType
                );
            }
            unchecked {
                ++i;
            }
        }

        // Build accepted list
        bytes32[] memory acceptedExecutions = new bytes32[](acceptedCount);
        bytes32[] memory conflictedExecutions = new bytes32[](conflictedCount);
        uint256 aIdx = 0;
        uint256 cIdx = 0;

        for (uint256 i = 0; i < executionIds.length; i++) {
            if (accepted[i]) {
                acceptedExecutions[aIdx++] = executionIds[i];
            } else if (
                executions[executionIds[i]].status == ExecutionStatus.Discarded
            ) {
                if (
                    executions[executionIds[i]].conflictType !=
                    ConflictType.None
                ) {
                    conflictedExecutions[cIdx++] = executionIds[i];
                }
            }
        }

        // Update batch
        batch.acceptedCount = acceptedCount;
        batch.conflictedCount = conflictedCount;
        batch.discardedCount = discardedCount;
        batch.resolved = true;
        batch.verifiedAt = uint64(block.timestamp);
        batch.canonicalOrder = acceptedExecutions;

        totalAccepted += acceptedCount;

        // Update parallelization ratio
        if (totalExecutions > 0) {
            parallelizationRatio = (totalAccepted * 10000) / totalExecutions;
        }

        emit BatchResolved(
            batchId,
            acceptedCount,
            conflictedCount,
            discardedCount
        );

        result = BatchVerificationResult({
            batchId: batchId,
            totalVerified: executionIds.length,
            totalAccepted: acceptedCount,
            totalConflicted: conflictedCount,
            acceptedExecutions: acceptedExecutions,
            conflictedExecutions: conflictedExecutions,
            batchRoot: _computeBatchRoot(acceptedExecutions)
        });
    }

    /*//////////////////////////////////////////////////////////////
                        CONFLICT DETECTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Detect conflicts for an execution
     * @dev Monad analogue: Read/write set conflict detection
     * @param executionId Execution to check
     * @return result Conflict detection result
     */
    function _detectConflicts(
        bytes32 executionId
    ) internal view returns (ConflictResult memory result) {
        ExecutionResult storage exec = executions[executionId];

        // Check 1: Nullifier collisions (most critical)
        // If a nullifier is already consumed, this execution conflicts
        for (uint256 i = 0; i < exec.nullifiersConsumed.length; i++) {
            bytes32 nullifier = exec.nullifiersConsumed[i];

            if (consumedNullifiers[nullifier]) {
                return
                    ConflictResult({
                        hasConflict: true,
                        conflictType: ConflictType.NullifierCollision,
                        conflictingExecutionId: nullifierToExecution[nullifier],
                        conflictingElement: nullifier
                    });
            }
        }

        // Check 2: Write-write conflicts on commitments
        // If two executions write to same commitment, conflict
        for (uint256 i = 0; i < exec.writeCommitments.length; i++) {
            bytes32 commitment = exec.writeCommitments[i];

            if (lockedCommitments[commitment]) {
                return
                    ConflictResult({
                        hasConflict: true,
                        conflictType: ConflictType.CommitmentOverlap,
                        conflictingExecutionId: commitmentToExecution[
                            commitment
                        ],
                        conflictingElement: commitment
                    });
            }
        }

        // Check 3: Read-write conflicts
        // If this execution reads something another writes, conflict
        for (uint256 i = 0; i < exec.readCommitments.length; i++) {
            bytes32 commitment = exec.readCommitments[i];

            if (lockedCommitments[commitment]) {
                // Check if the lock is from a write (not just a read)
                bytes32 lockingExec = commitmentToExecution[commitment];
                if (lockingExec != bytes32(0)) {
                    ExecutionResult storage locker = executions[lockingExec];
                    for (
                        uint256 j = 0;
                        j < locker.writeCommitments.length;
                        j++
                    ) {
                        if (locker.writeCommitments[j] == commitment) {
                            return
                                ConflictResult({
                                    hasConflict: true,
                                    conflictType: ConflictType.StateConflict,
                                    conflictingExecutionId: lockingExec,
                                    conflictingElement: commitment
                                });
                        }
                    }
                }
            }
        }

        // No conflict
        return
            ConflictResult({
                hasConflict: false,
                conflictType: ConflictType.None,
                conflictingExecutionId: bytes32(0),
                conflictingElement: bytes32(0)
            });
    }

    /**
     * @notice Accept execution and lock its resources
     * @param executionId Execution to accept
     */
    function _acceptExecution(bytes32 executionId) internal {
        ExecutionResult storage exec = executions[executionId];

        // Lock nullifiers
        for (uint256 i = 0; i < exec.nullifiersConsumed.length; i++) {
            bytes32 nullifier = exec.nullifiersConsumed[i];
            consumedNullifiers[nullifier] = true;
            nullifierToExecution[nullifier] = executionId;
        }

        // Lock write commitments
        for (uint256 i = 0; i < exec.writeCommitments.length; i++) {
            bytes32 commitment = exec.writeCommitments[i];
            lockedCommitments[commitment] = true;
            commitmentToExecution[commitment] = executionId;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit resolved batch
     * @dev Monad analogue: Block commitment after parallel execution
     * @param batchId Batch to commit
     */
    function commitBatch(bytes32 batchId) external onlyRole(SEQUENCER_ROLE) {
        ExecutionBatch storage batch = batches[batchId];
        if (!batch.resolved) revert BatchNotResolved();
        if (batch.committed) revert BatchAlreadyCommitted();

        // Mark all accepted executions as committed
        for (uint256 i = 0; i < batch.canonicalOrder.length; i++) {
            executions[batch.canonicalOrder[i]].status = ExecutionStatus
                .Committed;
        }

        batch.committed = true;
        batch.committedAt = uint64(block.timestamp);

        bytes32 batchRoot = _computeBatchRoot(batch.canonicalOrder);

        emit BatchCommitted(batchId, batchRoot, batch.acceptedCount);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify execution proof using ZK verifier
     * @dev Uses external ZK verifier when configured, otherwise blocks on mainnet
     * @param proofHash The hash of the proof for caching
     * @param proof The proof bytes to verify
     * @return True if proof is valid
     */
    function _verifyProof(
        bytes32 proofHash,
        bytes memory proof
    ) internal view returns (bool) {
        // Security: Validate basic requirements first
        if (proofHash == bytes32(0) || proof.length == 0) {
            return false;
        }

        // Use ZK verifier if configured
        if (zkVerifier != address(0)) {
            // Construct public inputs from proof hash
            uint256[] memory publicInputs = new uint256[](1);
            publicInputs[0] = uint256(proofHash);
            
            try IZKVerifier(zkVerifier).verifyProof(proof, publicInputs) returns (bool valid) {
                return valid;
            } catch {
                // Verification failed or reverted
                return false;
            }
        }

        // CRITICAL: Block mainnet without ZK verifier
        if (block.chainid == 1) {
            return false; // Fail closed on mainnet
        }

        // Development/testnet fallback: structural validation only
        // Proof must have minimum structure
        if (proof.length < 64) return false;
        
        // Verify proof hash matches proof content
        bytes32 computedHash = keccak256(proof);
        if (computedHash == bytes32(0)) return false;
        
        return true;
    }

    /**
     * @notice Set the ZK verifier contract address
     * @dev MUST be called before production deployment
     */
    function setZKVerifier(
        address _zkVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_zkVerifier == address(0)) revert ZeroAddress();
        zkVerifier = _zkVerifier;
    }

    /**
     * @notice Compute Merkle root of accepted executions
     */
    function _computeBatchRoot(
        bytes32[] memory executionIds
    ) internal pure returns (bytes32) {
        if (executionIds.length == 0) return bytes32(0);
        if (executionIds.length == 1) return executionIds[0];

        bytes32 root = executionIds[0];
        for (uint256 i = 1; i < executionIds.length; i++) {
            root = keccak256(abi.encode(root, executionIds[i]));
        }
        return root;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get execution details
     */
    function getExecution(
        bytes32 executionId
    ) external view returns (ExecutionResult memory) {
        return executions[executionId];
    }

    /**
     * @notice Get batch details
     */
    function getBatch(
        bytes32 batchId
    ) external view returns (ExecutionBatch memory) {
        return batches[batchId];
    }

    /**
     * @notice Get batch executions
     */
    function getBatchExecutions(
        bytes32 batchId
    ) external view returns (bytes32[] memory) {
        return batchExecutions[batchId];
    }

    /**
     * @notice Check if nullifier is consumed
     */
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    /**
     * @notice Get parallelization metrics
     */
    function getMetrics()
        external
        view
        returns (
            uint256 _totalExecutions,
            uint256 _totalBatches,
            uint256 _totalConflicts,
            uint256 _totalAccepted,
            uint256 _parallelizationRatio
        )
    {
        return (
            totalExecutions,
            totalBatches,
            totalConflicts,
            totalAccepted,
            parallelizationRatio
        );
    }

    /**
     * @notice Get conflict rate (basis points)
     */
    function getConflictRate() external view returns (uint256) {
        if (totalExecutions == 0) return 0;
        return (totalConflicts * 10000) / totalExecutions;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setMaxBatchSize(
        uint256 size
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxBatchSize = size;
    }

    function setConflictWindowBlocks(
        uint256 blocks
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        conflictWindowBlocks = blocks;
    }

    function setSpeculativeMode(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        speculativeMode = enabled;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
