// SPDX-License-Identifier: MIT
// Certora CVL Specification for OperationTimelockModule

using OperationTimelockModule as otm;

// ============================================================================
//                             METHOD DECLARATIONS
// ============================================================================

methods {
    // View / Pure — envfree
    function nonce() external returns (uint256) envfree;
    function totalQueued() external returns (uint256) envfree;
    function totalExecuted() external returns (uint256) envfree;
    function totalCancelled() external returns (uint256) envfree;
    function GRACE_PERIOD() external returns (uint48) envfree;
    function MIN_EMERGENCY_APPROVALS() external returns (uint8) envfree;

    // AccessControl (OZ)
    function hasRole(bytes32, address) external returns (bool) envfree;
    function PROPOSER_ROLE() external returns (bytes32) envfree;
    function EXECUTOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;

    // State-changing
    function queueOperation(address, bytes, uint256, uint8, string) external returns (bytes32);
    function executeOperation(bytes32) external;
    function cancelOperation(bytes32, string) external;
    function approveEmergencyBypass(bytes32) external;
    function executeEmergencyBypass(bytes32) external;
    function updateTierDelay(uint8, uint48) external;
}

// ============================================================================
//                            GHOST VARIABLES
// ============================================================================

/// @dev Track operation status changes
ghost mapping(bytes32 => uint8) ghostStatus {
    init_state axiom forall bytes32 id. ghostStatus[id] == 0;
}

// ============================================================================
//                         NONCE MONOTONICITY
// ============================================================================

/// @title Nonce only increases
/// @notice The nonce variable must be monotonically increasing
rule nonceMonotonic(method f) filtered { f -> !f.isView } {
    uint256 nonceBefore = nonce();

    env e;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = nonce();
    assert nonceAfter >= nonceBefore,
        "Nonce must never decrease";
}

// ============================================================================
//                        COUNTER CONSISTENCY
// ============================================================================

/// @title Counter consistency: totalQueued >= totalExecuted + totalCancelled
/// @notice The sum of executed and cancelled operations cannot exceed total queued
rule counterConsistency(method f) filtered { f -> !f.isView } {
    uint256 queued = totalQueued();
    uint256 executed = totalExecuted();
    uint256 cancelled = totalCancelled();
    require queued >= executed + cancelled; // Inductive: assume holds before

    env e;
    calldataarg args;
    f(e, args);

    uint256 queuedAfter = totalQueued();
    uint256 executedAfter = totalExecuted();
    uint256 cancelledAfter = totalCancelled();
    assert queuedAfter >= executedAfter + cancelledAfter,
        "totalQueued must always >= totalExecuted + totalCancelled";
}

/// @title Queued counter only increases
rule totalQueuedMonotonic(method f) filtered { f -> !f.isView } {
    uint256 before = totalQueued();

    env e;
    calldataarg args;
    f(e, args);

    uint256 after = totalQueued();
    assert after >= before,
        "totalQueued must never decrease";
}

/// @title Executed counter only increases
rule totalExecutedMonotonic(method f) filtered { f -> !f.isView } {
    uint256 before = totalExecuted();

    env e;
    calldataarg args;
    f(e, args);

    uint256 after = totalExecuted();
    assert after >= before,
        "totalExecuted must never decrease";
}

/// @title Cancelled counter only increases
rule totalCancelledMonotonic(method f) filtered { f -> !f.isView } {
    uint256 before = totalCancelled();

    env e;
    calldataarg args;
    f(e, args);

    uint256 after = totalCancelled();
    assert after >= before,
        "totalCancelled must never decrease";
}

// ============================================================================
//                          ACCESS CONTROL
// ============================================================================

/// @title Only PROPOSER can queue operations
rule onlyProposerCanQueue(
    address target,
    bytes callData,
    uint256 value,
    uint8 tier,
    string description
) {
    env e;
    require !hasRole(PROPOSER_ROLE(), e.msg.sender);

    queueOperation@withrevert(e, target, callData, value, tier, description);
    assert lastReverted,
        "Non-proposer must not queue operations";
}

/// @title Only EXECUTOR can execute operations
rule onlyExecutorCanExecute(bytes32 operationId) {
    env e;
    require !hasRole(EXECUTOR_ROLE(), e.msg.sender);

    executeOperation@withrevert(e, operationId);
    assert lastReverted,
        "Non-executor must not execute operations";
}

/// @title Only GUARDIAN can approve emergency bypass
rule onlyGuardianCanApproveBypass(bytes32 operationId) {
    env e;
    require !hasRole(GUARDIAN_ROLE(), e.msg.sender);

    approveEmergencyBypass@withrevert(e, operationId);
    assert lastReverted,
        "Non-guardian must not approve emergency bypasses";
}

/// @title Only EXECUTOR can execute emergency bypass
rule onlyExecutorCanExecuteBypass(bytes32 operationId) {
    env e;
    require !hasRole(EXECUTOR_ROLE(), e.msg.sender);

    executeEmergencyBypass@withrevert(e, operationId);
    assert lastReverted,
        "Non-executor must not execute emergency bypasses";
}

/// @title Only DEFAULT_ADMIN can update tier delays
rule onlyAdminCanUpdateDelay(uint8 tier, uint48 newDelay) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    updateTierDelay@withrevert(e, tier, newDelay);
    assert lastReverted,
        "Non-admin must not update tier delays";
}

// ============================================================================
//                      QUEUE INCREASES NONCE
// ============================================================================

/// @title queueOperation increments nonce by exactly 1
rule queueIncreasesNonce(
    address target,
    bytes callData,
    uint256 value,
    uint8 tier,
    string description
) {
    uint256 nonceBefore = nonce();

    env e;
    queueOperation(e, target, callData, value, tier, description);

    uint256 nonceAfter = nonce();
    assert nonceAfter == nonceBefore + 1,
        "queueOperation must increment nonce by exactly 1";
}

/// @title queueOperation increments totalQueued by exactly 1
rule queueIncreasesQueued(
    address target,
    bytes callData,
    uint256 value,
    uint8 tier,
    string description
) {
    uint256 queuedBefore = totalQueued();

    env e;
    queueOperation(e, target, callData, value, tier, description);

    uint256 queuedAfter = totalQueued();
    assert queuedAfter == queuedBefore + 1,
        "queueOperation must increment totalQueued by exactly 1";
}

// ============================================================================
//                        EXECUTE EFFECTS
// ============================================================================

/// @title Successful execution increments totalExecuted
rule executeIncreasesExecuted(bytes32 operationId) {
    uint256 executedBefore = totalExecuted();

    env e;
    executeOperation(e, operationId);

    uint256 executedAfter = totalExecuted();
    assert executedAfter == executedBefore + 1,
        "executeOperation must increment totalExecuted by exactly 1";
}

/// @title Cancel increments totalCancelled
rule cancelIncreasesCancelled(bytes32 operationId, string reason) {
    uint256 cancelledBefore = totalCancelled();

    env e;
    cancelOperation(e, operationId, reason);

    uint256 cancelledAfter = totalCancelled();
    assert cancelledAfter == cancelledBefore + 1,
        "cancelOperation must increment totalCancelled by exactly 1";
}

// ============================================================================
//                     GRACE PERIOD IMMUTABLE
// ============================================================================

/// @title GRACE_PERIOD is constant at 7 days
invariant gracePeriodConstant()
    GRACE_PERIOD() == 604800; // 7 * 24 * 60 * 60

/// @title MIN_EMERGENCY_APPROVALS is constant at 3
invariant minEmergencyApprovalsConstant()
    MIN_EMERGENCY_APPROVALS() == 3;
