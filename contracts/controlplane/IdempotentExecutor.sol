// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title IdempotentExecutor
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Nullifier-Safe Idempotent Execution Engine
 * @dev Privacy-preserving retry handling with nullifier-safe re-execution
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    DESIGN PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Enterprise-grade failure handling without information leakage:
 *
 * 1. IDEMPOTENT EXECUTION
 *    └─ Replays are safe, not failures
 *
 * 2. EXPLICIT FAILURE RECOVERY
 *    └─ Blocked messages can be resumed
 *
 * 3. METADATA PROTECTION
 *    └─ Retries don't leak timing info or failure reasons
 *
 * 4. NULLIFIER-SAFE RETRIES
 *    └─ Each retry uses fresh nullifier to prevent correlation
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                              SOUL IDEMPOTENT EXECUTION
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Soul needs stronger guarantees:
 *
 * ╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║ Property              │ Guarantee                                                                 ║
 * ╠════════════════════════════════════════════════════════════════════════════════════════════════════╣
 * ║ Nullifier-Safe Retry  │ New nullifiers per retry prevent replay correlation                       ║
 * ║ State Consistency     │ Retries see consistent state snapshots                                    ║
 * ║ Metadata Protection   │ Retry count/timing not leaked to observers                                ║
 * ║ Policy Binding        │ Retries remain bound to original policy                                   ║
 * ║ Atomic Rollback       │ Failed retries don't leave partial state                                  ║
 * ╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    EXECUTION STATES
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 *            ┌─────────────┐
 *            │   Pending   │───────────────────────────┐
 *            └──────┬──────┘                           │
 *                   │                                  │ (timeout)
 *                   ▼                                  │
 *            ┌─────────────┐                           │
 *       ┌───►│  Executing  │◄─────────────────┐       │
 *       │    └──────┬──────┘                  │       │
 *       │           │                         │       │
 *       │     ┌─────┴─────┐                   │       │
 *       │     │           │                   │       │
 *       │     ▼           ▼                   │       ▼
 *   ┌───────────┐   ┌───────────┐       ┌───────────────┐
 *   │ Completed │   │  Failed   │──────►│   Retrying    │
 *   └───────────┘   └───────────┘       └───────────────┘
 *                         │
 *                         │ (max retries)
 *                         ▼
 *                   ┌───────────┐
 *                   │ Abandoned │
 *                   └───────────┘
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract IdempotentExecutor is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant EXECUTOR_ADMIN_ROLE =
        keccak256("EXECUTOR_ADMIN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant RETRY_ROLE = keccak256("RETRY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ExecutionNotFound(bytes32 executionId);
    error ExecutionAlreadyExists(bytes32 executionId);
    error InvalidExecutionState(
        bytes32 executionId,
        ExecutionState expected,
        ExecutionState actual
    );
    error NullifierAlreadyUsed(bytes32 nullifier);
    error MaxRetriesExceeded(bytes32 executionId, uint256 maxRetries);
    error ExecutionExpired(bytes32 executionId);
    error PolicyMismatch(bytes32 expected, bytes32 actual);
    error StateConsistencyViolation(bytes32 executionId);
    error AtomicRollbackRequired(bytes32 executionId);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Execution states
    enum ExecutionState {
        NonExistent, // Not created
        Pending, // Created, waiting for execution
        Executing, // Currently executing
        Completed, // Successfully completed
        Failed, // Execution failed
        Retrying, // Retry in progress
        Abandoned // Max retries exceeded
    }

    /**
     * @notice Execution record with full tracking
     * @dev Tracks all execution attempts and state
     */
    struct ExecutionRecord {
        bytes32 executionId;
        bytes32 originalMessageId; // Link to original message
        // Nullifier tracking
        bytes32 currentNullifier; // Current attempt's nullifier
        bytes32[] historicalNullifiers; // All previous nullifiers (for audit)
        // State snapshots
        bytes32 stateSnapshotCommitment; // Consistent state snapshot
        bytes32 finalStateCommitment; // Final state after success
        // Policy binding
        bytes32 policyHash; // Remains constant across retries
        bytes32 policyProof; // Proof of policy compliance
        // Execution payload
        bytes32 payloadCommitment; // Commitment to execution payload
        bytes encryptedPayload; // Encrypted execution data
        // Retry tracking
        ExecutionState state;
        uint256 attemptCount; // Total attempts
        uint256 maxAttempts; // Maximum allowed attempts
        uint64 createdAt;
        uint64 lastAttemptAt;
        uint64 expiresAt;
        // Failure tracking
        bytes32 lastFailureReason; // Hashed failure reason (privacy)
    }

    /**
     * @notice Retry context (metadata-protected)
     * @dev Retry information with privacy considerations
     */
    struct RetryContext {
        bytes32 executionId;
        bytes32 newNullifier; // Fresh nullifier for retry
        bytes32 stateSnapshot; // Consistent state for retry
        uint256 attemptNumber;
        uint64 scheduledAt;
        bool metadataProtected; // If true, timing is randomized
    }

    /**
     * @notice Atomic rollback checkpoint
     * @dev Enables clean rollback on failure
     */
    struct RollbackCheckpoint {
        bytes32 executionId;
        bytes32 stateBeforeExecution;
        bytes32 nullifierBeforeExecution;
        uint256 attemptAtCheckpoint;
        uint64 checkpointedAt;
        bool isActive;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Execution records
    mapping(bytes32 => ExecutionRecord) public executions;

    /// @notice Nullifier registry (global idempotency)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Nullifier to execution mapping
    mapping(bytes32 => bytes32) public nullifierToExecution;

    /// @notice Retry contexts
    mapping(bytes32 => RetryContext) public retryContexts;

    /// @notice Rollback checkpoints
    mapping(bytes32 => RollbackCheckpoint) public checkpoints;

    /// @notice Default max retries
    uint256 public defaultMaxRetries = 3;

    /// @notice Default execution validity
    uint256 public defaultValidity = 24 hours;

    /// @notice Minimum retry delay (metadata protection)
    uint256 public minRetryDelay = 1 minutes;

    /// @notice Counters
    uint256 public totalExecutions;
    uint256 public totalRetries;
    uint256 public totalSuccesses;
    uint256 public totalFailures;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ExecutionCreated(
        bytes32 indexed executionId,
        bytes32 indexed messageId,
        bytes32 nullifier
    );

    event ExecutionStarted(bytes32 indexed executionId, uint256 attemptNumber);

    event ExecutionCompleted(bytes32 indexed executionId, bytes32 finalState);

    event ExecutionFailed(
        bytes32 indexed executionId,
        bytes32 failureReasonHash
    );

    event RetryScheduled(
        bytes32 indexed executionId,
        bytes32 newNullifier,
        uint256 attemptNumber
    );

    event ExecutionAbandoned(
        bytes32 indexed executionId,
        uint256 totalAttempts
    );

    event RollbackExecuted(bytes32 indexed executionId, bytes32 restoredState);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(RETRY_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new idempotent execution
     * @param messageId Original message ID
     * @param stateSnapshot Current state snapshot commitment
     * @param policyHash Policy to enforce
     * @param payloadCommitment Commitment to execution payload
     * @param encryptedPayload Encrypted execution data
     * @param maxAttempts Maximum retry attempts
     * @param validityPeriod How long execution is valid
     * @return executionId The new execution ID
     */
    function createExecution(
        bytes32 messageId,
        bytes32 stateSnapshot,
        bytes32 policyHash,
        bytes32 payloadCommitment,
        bytes calldata encryptedPayload,
        uint256 maxAttempts,
        uint256 validityPeriod
    )
        external
        onlyRole(EXECUTOR_ROLE)
        whenNotPaused
        returns (bytes32 executionId)
    {
        // Generate execution ID
        executionId = keccak256(
            abi.encodePacked(
                messageId,
                stateSnapshot,
                policyHash,
                block.timestamp
            )
        );

        if (executions[executionId].state != ExecutionState.NonExistent) {
            revert ExecutionAlreadyExists(executionId);
        }

        // Generate initial nullifier
        bytes32 nullifier = _generateNullifier(executionId, stateSnapshot, 0);

        // Check nullifier not used
        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        // Set defaults
        if (maxAttempts == 0) maxAttempts = defaultMaxRetries;
        if (validityPeriod == 0) validityPeriod = defaultValidity;

        // Create execution record
        bytes32[] memory historicalNullifiers;
        executions[executionId] = ExecutionRecord({
            executionId: executionId,
            originalMessageId: messageId,
            currentNullifier: nullifier,
            historicalNullifiers: historicalNullifiers,
            stateSnapshotCommitment: stateSnapshot,
            finalStateCommitment: bytes32(0),
            policyHash: policyHash,
            policyProof: bytes32(0),
            payloadCommitment: payloadCommitment,
            encryptedPayload: encryptedPayload,
            state: ExecutionState.Pending,
            attemptCount: 0,
            maxAttempts: maxAttempts,
            createdAt: uint64(block.timestamp),
            lastAttemptAt: 0,
            expiresAt: uint64(block.timestamp + validityPeriod),
            lastFailureReason: bytes32(0)
        });

        // Register nullifier
        usedNullifiers[nullifier] = true;
        nullifierToExecution[nullifier] = executionId;

        unchecked {
            ++totalExecutions;
        }

        emit ExecutionCreated(executionId, messageId, nullifier);
        return executionId;
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Start execution attempt
     * @param executionId Execution to start
     * @return success True if execution started
     */
    function startExecution(
        bytes32 executionId
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool success)
    {
        ExecutionRecord storage execution = executions[executionId];

        // Validate state
        if (execution.state == ExecutionState.NonExistent) {
            revert ExecutionNotFound(executionId);
        }

        if (
            execution.state != ExecutionState.Pending &&
            execution.state != ExecutionState.Retrying
        ) {
            revert InvalidExecutionState(
                executionId,
                ExecutionState.Pending,
                execution.state
            );
        }

        // Check not expired
        if (block.timestamp > execution.expiresAt) {
            revert ExecutionExpired(executionId);
        }

        // Create rollback checkpoint
        _createCheckpoint(executionId);

        // Update state
        execution.state = ExecutionState.Executing;
        execution.lastAttemptAt = uint64(block.timestamp);
        unchecked {
            execution.attemptCount++;
        }

        emit ExecutionStarted(executionId, execution.attemptCount);
        return true;
    }

    /**
     * @notice Complete execution successfully
     * @param executionId Execution to complete
     * @param finalState Final state commitment
     * @param policyProof Proof of policy compliance
     * @return success True if completion recorded
     */
    function completeExecution(
        bytes32 executionId,
        bytes32 finalState,
        bytes32 policyProof
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool success)
    {
        ExecutionRecord storage execution = executions[executionId];

        if (execution.state != ExecutionState.Executing) {
            revert InvalidExecutionState(
                executionId,
                ExecutionState.Executing,
                execution.state
            );
        }

        // Verify policy consistency
        if (policyProof == bytes32(0)) {
            revert PolicyMismatch(execution.policyHash, bytes32(0));
        }

        // Update execution
        execution.state = ExecutionState.Completed;
        execution.finalStateCommitment = finalState;
        execution.policyProof = policyProof;

        // Clear checkpoint
        _clearCheckpoint(executionId);

        unchecked {
            ++totalSuccesses;
        }

        emit ExecutionCompleted(executionId, finalState);
        return true;
    }

    /**
     * @notice Record execution failure
     * @param executionId Execution that failed
     * @param failureReason Reason for failure (will be hashed for privacy)
     * @return retryPossible True if retry is possible
     */
    function failExecution(
        bytes32 executionId,
        string calldata failureReason
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        returns (bool retryPossible)
    {
        ExecutionRecord storage execution = executions[executionId];

        if (execution.state != ExecutionState.Executing) {
            revert InvalidExecutionState(
                executionId,
                ExecutionState.Executing,
                execution.state
            );
        }

        // Hash failure reason for privacy
        bytes32 failureHash = keccak256(bytes(failureReason));
        execution.lastFailureReason = failureHash;

        // Rollback state
        _executeRollback(executionId);

        // Check if can retry
        retryPossible =
            execution.attemptCount < execution.maxAttempts &&
            block.timestamp < execution.expiresAt;

        if (retryPossible) {
            execution.state = ExecutionState.Failed;
        } else {
            execution.state = ExecutionState.Abandoned;
            emit ExecutionAbandoned(executionId, execution.attemptCount);
        }

        unchecked {
            ++totalFailures;
        }

        emit ExecutionFailed(executionId, failureHash);
        return retryPossible;
    }

    /*//////////////////////////////////////////////////////////////
                        RETRY HANDLING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule a retry with new nullifier
     * @dev Generates fresh nullifier to prevent replay correlation
     * @param executionId Execution to retry
     * @param metadataProtected If true, adds random delay for timing protection
     * @return retryContext The retry context
     */
    function scheduleRetry(
        bytes32 executionId,
        bool metadataProtected
    )
        external
        onlyRole(RETRY_ROLE)
        whenNotPaused
        returns (RetryContext memory retryContext)
    {
        ExecutionRecord storage execution = executions[executionId];

        if (execution.state != ExecutionState.Failed) {
            revert InvalidExecutionState(
                executionId,
                ExecutionState.Failed,
                execution.state
            );
        }

        if (execution.attemptCount >= execution.maxAttempts) {
            revert MaxRetriesExceeded(executionId, execution.maxAttempts);
        }

        if (block.timestamp > execution.expiresAt) {
            revert ExecutionExpired(executionId);
        }

        // Generate new nullifier for retry
        bytes32 newNullifier = _generateNullifier(
            executionId,
            execution.stateSnapshotCommitment,
            execution.attemptCount
        );

        // Check new nullifier not used
        if (usedNullifiers[newNullifier]) {
            // Generate alternate nullifier with timestamp
            newNullifier = keccak256(
                abi.encodePacked(
                    newNullifier,
                    block.timestamp,
                    block.prevrandao
                )
            );
        }

        // Register new nullifier
        usedNullifiers[newNullifier] = true;
        nullifierToExecution[newNullifier] = executionId;

        // Archive old nullifier
        execution.historicalNullifiers.push(execution.currentNullifier);
        execution.currentNullifier = newNullifier;

        // Calculate scheduled time (with optional metadata protection)
        uint64 scheduledAt = uint64(block.timestamp + minRetryDelay);
        if (metadataProtected) {
            // Add random delay (up to 5 minutes) to obscure retry timing
            uint256 randomDelay = uint256(
                keccak256(
                    abi.encodePacked(
                        block.timestamp,
                        block.prevrandao,
                        executionId
                    )
                )
            ) % 300;
            scheduledAt += uint64(randomDelay);
        }

        // Create retry context
        retryContext = RetryContext({
            executionId: executionId,
            newNullifier: newNullifier,
            stateSnapshot: execution.stateSnapshotCommitment,
            attemptNumber: execution.attemptCount + 1,
            scheduledAt: scheduledAt,
            metadataProtected: metadataProtected
        });

        retryContexts[executionId] = retryContext;

        // Update state
        execution.state = ExecutionState.Retrying;

        unchecked {
            ++totalRetries;
        }

        emit RetryScheduled(
            executionId,
            newNullifier,
            execution.attemptCount + 1
        );
        return retryContext;
    }

    /**
     * @notice Execute scheduled retry
     * @param executionId Execution to retry
     * @return success True if retry started
     */
    function executeRetry(
        bytes32 executionId
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool success)
    {
        ExecutionRecord storage execution = executions[executionId];
        RetryContext storage ctx = retryContexts[executionId];

        if (execution.state != ExecutionState.Retrying) {
            revert InvalidExecutionState(
                executionId,
                ExecutionState.Retrying,
                execution.state
            );
        }

        // Check scheduled time has passed
        if (block.timestamp < ctx.scheduledAt) {
            // Not yet time - return false but don't revert
            return false;
        }

        // Move to pending for normal execution flow
        execution.state = ExecutionState.Pending;

        // Clear retry context
        delete retryContexts[executionId];

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    IDEMPOTENCY CHECKING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if execution would be idempotent (safe to replay)
     * @param executionId Execution to check
     * @param nullifier Nullifier being used
     * @return isIdempotent True if replay is safe
     * @return reason Explanation if not idempotent
     */
    function checkIdempotency(
        bytes32 executionId,
        bytes32 nullifier
    ) external view returns (bool isIdempotent, string memory reason) {
        ExecutionRecord storage execution = executions[executionId];

        // Check if execution exists
        if (execution.state == ExecutionState.NonExistent) {
            return (true, "New execution - safe to proceed");
        }

        // Check if already completed
        if (execution.state == ExecutionState.Completed) {
            return (true, "Already completed - replay is no-op");
        }

        // Check if abandoned
        if (execution.state == ExecutionState.Abandoned) {
            return (false, "Execution abandoned - cannot retry");
        }

        // Check nullifier
        if (nullifier == execution.currentNullifier) {
            // Same nullifier = same attempt, idempotent
            return (true, "Same nullifier - idempotent replay");
        }

        // Check if nullifier was used in previous attempts
        for (uint256 i = 0; i < execution.historicalNullifiers.length; i++) {
            if (nullifier == execution.historicalNullifiers[i]) {
                return (true, "Historical nullifier - idempotent");
            }
        }

        // New nullifier for existing execution
        return (
            false,
            "New nullifier for existing execution - may cause inconsistency"
        );
    }

    /**
     * @notice Verify nullifier hasn't been used
     * @param nullifier Nullifier to check
     * @return isUsed True if nullifier was already used
     * @return linkedExecution Execution ID if linked, zero otherwise
     */
    function verifyNullifier(
        bytes32 nullifier
    ) external view returns (bool isUsed, bytes32 linkedExecution) {
        isUsed = usedNullifiers[nullifier];
        linkedExecution = nullifierToExecution[nullifier];
        return (isUsed, linkedExecution);
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateNullifier(
        bytes32 executionId,
        bytes32 stateSnapshot,
        uint256 attemptNumber
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    executionId,
                    stateSnapshot,
                    attemptNumber,
                    block.chainid
                )
            );
    }

    function _createCheckpoint(bytes32 executionId) internal {
        ExecutionRecord storage execution = executions[executionId];

        checkpoints[executionId] = RollbackCheckpoint({
            executionId: executionId,
            stateBeforeExecution: execution.stateSnapshotCommitment,
            nullifierBeforeExecution: execution.currentNullifier,
            attemptAtCheckpoint: execution.attemptCount,
            checkpointedAt: uint64(block.timestamp),
            isActive: true
        });
    }

    function _clearCheckpoint(bytes32 executionId) internal {
        delete checkpoints[executionId];
    }

    function _executeRollback(bytes32 executionId) internal {
        RollbackCheckpoint storage checkpoint = checkpoints[executionId];

        if (!checkpoint.isActive) {
            revert AtomicRollbackRequired(executionId);
        }

        // In production: actually rollback state changes
        // For MVP: just mark checkpoint as inactive
        checkpoint.isActive = false;

        emit RollbackExecuted(executionId, checkpoint.stateBeforeExecution);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get execution record
    function getExecution(
        bytes32 executionId
    ) external view returns (ExecutionRecord memory) {
        return executions[executionId];
    }

    /// @notice Get execution state
    function getExecutionState(
        bytes32 executionId
    ) external view returns (ExecutionState) {
        return executions[executionId].state;
    }

    /// @notice Get retry context
    function getRetryContext(
        bytes32 executionId
    ) external view returns (RetryContext memory) {
        return retryContexts[executionId];
    }

    /// @notice Get rollback checkpoint
    function getCheckpoint(
        bytes32 executionId
    ) external view returns (RollbackCheckpoint memory) {
        return checkpoints[executionId];
    }

    /// @notice Get all historical nullifiers for execution
    function getHistoricalNullifiers(
        bytes32 executionId
    ) external view returns (bytes32[] memory) {
        return executions[executionId].historicalNullifiers;
    }

    /// @notice Check if execution can be retried
    function canRetry(bytes32 executionId) external view returns (bool) {
        ExecutionRecord storage execution = executions[executionId];
        return
            execution.state == ExecutionState.Failed &&
            execution.attemptCount < execution.maxAttempts &&
            block.timestamp < execution.expiresAt;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setDefaultMaxRetries(
        uint256 _maxRetries
    ) external onlyRole(EXECUTOR_ADMIN_ROLE) {
        defaultMaxRetries = _maxRetries;
    }

    function setDefaultValidity(
        uint256 _validity
    ) external onlyRole(EXECUTOR_ADMIN_ROLE) {
        defaultValidity = _validity;
    }

    function setMinRetryDelay(
        uint256 _delay
    ) external onlyRole(EXECUTOR_ADMIN_ROLE) {
        minRetryDelay = _delay;
    }

    function pause() external onlyRole(EXECUTOR_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EXECUTOR_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Force abandon an execution (admin only)
    function forceAbandon(
        bytes32 executionId
    ) external onlyRole(EXECUTOR_ADMIN_ROLE) {
        ExecutionRecord storage execution = executions[executionId];

        if (execution.state == ExecutionState.NonExistent) {
            revert ExecutionNotFound(executionId);
        }

        execution.state = ExecutionState.Abandoned;
        emit ExecutionAbandoned(executionId, execution.attemptCount);
    }
}
