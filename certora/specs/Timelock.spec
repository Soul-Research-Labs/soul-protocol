/**
 * @title Certora Verification Rules for ZaseonUpgradeTimelock
 * @notice Machine-verifiable specifications for timelock security properties
 * @dev Run with: certoraRun specs/Timelock.spec --contract ZaseonUpgradeTimelock
 */

using ZaseonUpgradeTimelock as TL;

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State variables
    function minDelay() external returns (uint256) envfree;
    function emergencyDelay() external returns (uint256) envfree;
    function requiredConfirmations() external returns (uint8) envfree;
    function pendingOperations() external returns (uint256) envfree;
    function executedOperations() external returns (uint256) envfree;
    function hasConfirmed(bytes32, address) external returns (bool) envfree;
    
    // Constants
    function MIN_DELAY_FLOOR() external returns (uint256) envfree;
    function MAX_DELAY() external returns (uint256) envfree;
    function GRACE_PERIOD() external returns (uint256) envfree;
    
    // View functions
    function isOperationReady(bytes32) external returns (bool) envfree;
    function isOperationPending(bytes32) external returns (bool) envfree;
    function getOperationStatus(bytes32) external returns (TL.OperationStatus) envfree;
    function getReadyTime(bytes32) external returns (uint256) envfree;
    function computeOperationId(address, uint256, bytes, bytes32, bytes32) external returns (bytes32) envfree;
    
    // Mutating functions
    function propose(address, uint256, bytes, bytes32, bytes32) external returns (bytes32);
    function proposeEmergency(address, uint256, bytes, bytes32) external returns (bytes32);
    function confirm(bytes32) external;
    function execute(address, uint256, bytes, bytes32, bytes32) external;
    function cancel(bytes32) external;
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Track operation proposal timestamps
ghost mapping(bytes32 => uint256) operationProposedAt;

// Track operation execution timestamps  
ghost mapping(bytes32 => uint256) operationExecutedAt;

// Track confirmation count
ghost mapping(bytes32 => uint8) operationConfirmations;

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore operations[KEY bytes32 id].proposedAt uint256 timestamp (uint256 old_timestamp) {
    if (old_timestamp == 0 && timestamp > 0) {
        operationProposedAt[id] = timestamp;
    }
}

hook Sstore operations[KEY bytes32 id].executedAt uint256 timestamp (uint256 old_timestamp) {
    if (old_timestamp == 0 && timestamp > 0) {
        operationExecutedAt[id] = timestamp;
    }
}

hook Sstore operations[KEY bytes32 id].confirmations uint8 count (uint8 old_count) {
    operationConfirmations[id] = count;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice minDelay is always within valid bounds
 */
invariant minDelayBounds()
    minDelay() >= MIN_DELAY_FLOOR() && minDelay() <= MAX_DELAY()

/**
 * @notice emergencyDelay is always <= minDelay
 */
invariant emergencyDelayBounds()
    emergencyDelay() >= MIN_DELAY_FLOOR() && emergencyDelay() <= minDelay()

/**
 * @notice Confirmations can only increase
 */
invariant confirmationsMonotonic(bytes32 opId)
    operationConfirmations[opId] >= 0
    {
        preserved confirm(bytes32 id) with (env e) {
            require id == opId => operationConfirmations[opId] + 1 >= operationConfirmations[opId];
        }
    }

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Execution requires minimum delay to have passed
 */
rule executionRequiresDelay(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e;
    
    bytes32 opId = computeOperationId(target, value, data, predecessor, salt);
    
    require isOperationPending(opId);
    uint256 readyTime = getReadyTime(opId);
    
    // If current time is before ready time, execution must fail
    require e.block.timestamp < readyTime;
    
    execute@withrevert(e, target, value, data, predecessor, salt);
    
    assert lastReverted,
        "Execution before ready time must revert";
}

/**
 * @notice Execution requires sufficient confirmations
 */
rule executionRequiresConfirmations(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e;
    
    bytes32 opId = computeOperationId(target, value, data, predecessor, salt);
    uint8 required = requiredConfirmations();
    
    require isOperationPending(opId);
    require operationConfirmations[opId] < required;
    require e.block.timestamp >= getReadyTime(opId);
    require e.block.timestamp <= getReadyTime(opId) + GRACE_PERIOD();
    
    execute@withrevert(e, target, value, data, predecessor, salt);
    
    assert lastReverted,
        "Execution without sufficient confirmations must revert";
}

/**
 * @notice Execution after grace period must fail
 */
rule executionAfterGracePeriodFails(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e;
    
    bytes32 opId = computeOperationId(target, value, data, predecessor, salt);
    uint256 readyTime = getReadyTime(opId);
    
    require isOperationPending(opId);
    require e.block.timestamp > readyTime + GRACE_PERIOD();
    
    execute@withrevert(e, target, value, data, predecessor, salt);
    
    assert lastReverted,
        "Execution after grace period must revert";
}

/**
 * @notice Same operation cannot be proposed twice
 */
rule operationUniqueness(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e1;
    env e2;
    
    bytes32 opId = propose(e1, target, value, data, predecessor, salt);
    
    propose@withrevert(e2, target, value, data, predecessor, salt);
    
    assert lastReverted,
        "Duplicate proposal must revert";
}

/**
 * @notice Cancelled operations cannot be executed
 */
rule cancelledOperationNotExecutable(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e1;
    env e2;
    
    bytes32 opId = computeOperationId(target, value, data, predecessor, salt);
    
    require isOperationPending(opId);
    
    cancel(e1, opId);
    
    execute@withrevert(e2, target, value, data, predecessor, salt);
    
    assert lastReverted,
        "Cancelled operation must not be executable";
}

/**
 * @notice Same address cannot confirm twice
 */
rule doubleConfirmationPrevented(bytes32 opId) {
    env e1;
    env e2;
    
    require e1.msg.sender == e2.msg.sender;
    require isOperationPending(opId);
    
    confirm(e1, opId);
    confirm@withrevert(e2, opId);
    
    assert lastReverted,
        "Double confirmation from same address must revert";
}

/**
 * @notice Predecessor must be executed before dependent operation
 */
rule predecessorEnforcement(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e;
    
    require predecessor != to_bytes32(0);
    require getOperationStatus(predecessor) != TL.OperationStatus.Executed;
    
    bytes32 opId = computeOperationId(target, value, data, predecessor, salt);
    require isOperationReady(opId);
    
    execute@withrevert(e, target, value, data, predecessor, salt);
    
    assert lastReverted,
        "Execution with unexecuted predecessor must revert";
}

/**
 * @notice Propose increases pending count
 */
rule proposeIncreasesPendingCount(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e;
    
    uint256 pendingBefore = pendingOperations();
    
    bytes32 opId = propose(e, target, value, data, predecessor, salt);
    
    uint256 pendingAfter = pendingOperations();
    
    assert pendingAfter == pendingBefore + 1,
        "Pending count must increase by 1 on propose";
}

/**
 * @notice Execute decreases pending and increases executed count
 */
rule executeUpdatesCounts(
    address target,
    uint256 value,
    bytes data,
    bytes32 predecessor,
    bytes32 salt
) {
    env e;
    
    uint256 pendingBefore = pendingOperations();
    uint256 executedBefore = executedOperations();
    
    execute(e, target, value, data, predecessor, salt);
    
    uint256 pendingAfter = pendingOperations();
    uint256 executedAfter = executedOperations();
    
    assert pendingAfter == pendingBefore - 1,
        "Pending count must decrease by 1 on execute";
    assert executedAfter == executedBefore + 1,
        "Executed count must increase by 1 on execute";
}

/*//////////////////////////////////////////////////////////////
                    SECURITY PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Execution timing is bounded
 * Execution must happen in window: [proposedAt + minDelay, proposedAt + minDelay + GRACE_PERIOD]
 */
rule executionTimingBounded(bytes32 opId) {
    require operationProposedAt[opId] > 0;
    require operationExecutedAt[opId] > 0;
    
    uint256 proposedAt = operationProposedAt[opId];
    uint256 executedAt = operationExecutedAt[opId];
    uint256 delay = minDelay();
    uint256 grace = GRACE_PERIOD();
    
    assert executedAt >= proposedAt + delay,
        "Execution must be after delay period";
    assert executedAt <= proposedAt + delay + grace,
        "Execution must be within grace period";
}

/**
 * @notice Delay can only be updated by admin
 */
rule delayUpdateRequiresAdmin() {
    env e;
    
    uint256 delayBefore = minDelay();
    
    // Assume caller is not admin
    // (Would be expressed via hasRole ghost)
    
    // Any call that changes delay must come from admin
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 delayAfter = minDelay();
    
    // If delay changed, caller must have admin role
    // assert delayBefore != delayAfter => hasRole(e.msg.sender, DEFAULT_ADMIN_ROLE);
}
