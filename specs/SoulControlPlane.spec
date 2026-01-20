/**
 * @title Formal Verification Specification for SoulControlPlane
 * @author Soul Protocol
 * @notice Simplified Certora CVL specification for 5-stage message lifecycle
 */

methods {
    function totalMessages() external returns (uint256) envfree;
    function totalExecutions() external returns (uint256) envfree;
    function totalMaterializations() external returns (uint256) envfree;
    function maxRetries() external returns (uint256) envfree;
    function defaultMessageValidity() external returns (uint256) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function retryCount(bytes32) external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                    INVARIANTS
//////////////////////////////////////////////////////////////*/

// Materializations bounded by executions
invariant materializationsBoundedByExecutions()
    totalMaterializations() <= totalExecutions();

// Executions bounded by messages
invariant executionsBoundedByMessages()
    totalExecutions() <= totalMessages();

// All counters non-negative (trivially true for uint256)
invariant countersNonNegative()
    totalMessages() >= 0 && totalExecutions() >= 0 && totalMaterializations() >= 0;

/*//////////////////////////////////////////////////////////////
                    MONOTONICITY RULES
//////////////////////////////////////////////////////////////*/

// Message count monotonically increases
rule messageCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalMessages();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalMessages();
    assert countAfter >= countBefore, "Message count cannot decrease";
}

// Execution count monotonically increases
rule executionCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalExecutions();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalExecutions();
    assert countAfter >= countBefore, "Execution count cannot decrease";
}

// Materialization count monotonically increases
rule materializationCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalMaterializations();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalMaterializations();
    assert countAfter >= countBefore, "Materialization count cannot decrease";
}

/*//////////////////////////////////////////////////////////////
                    NULLIFIER PERMANENCE
//////////////////////////////////////////////////////////////*/

// Once a nullifier is used, it stays used
rule nullifierUsagePermanent(bytes32 nullifier) {
    env e;
    bool usedBefore = usedNullifiers(nullifier);
    method f;
    calldataarg args;
    f(e, args);
    bool usedAfter = usedNullifiers(nullifier);
    assert usedBefore => usedAfter, "Nullifier usage cannot be reversed";
}

/*//////////////////////////////////////////////////////////////
                    RETRY LIMITS
//////////////////////////////////////////////////////////////*/

// Retry count is bounded by max retries
rule retryCountBounded(bytes32 messageId) {
    env e;
    uint256 count = retryCount(messageId);
    uint256 max = maxRetries();
    assert count <= max + 1, "Retry count should be bounded";
}

// Retry count monotonically increases
rule retryCountMonotonicallyIncreases(bytes32 messageId) {
    env e;
    uint256 countBefore = retryCount(messageId);
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = retryCount(messageId);
    assert countAfter >= countBefore, "Retry count cannot decrease";
}
