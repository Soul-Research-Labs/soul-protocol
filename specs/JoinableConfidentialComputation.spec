/**
 * @title Formal Verification Specification for JoinableConfidentialComputation
 * @author Soul Protocol
 * @notice Simplified Certora CVL specification for JAM-style joinable computations
 */

methods {
    function totalFragments() external returns (uint256) envfree;
    function totalJoins() external returns (uint256) envfree;
    function totalJoinSpecs() external returns (uint256) envfree;
    function getFragmentStatus(bytes32) external returns (uint8) envfree;
    function getJoinStatus(bytes32) external returns (uint8) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function verifyFragment(bytes32) external returns (bool);
    function pause() external;
    function unpause() external;
}

// Joins bounded by fragments
invariant joinsBoundedByFragments()
    totalJoins() <= totalFragments();

// Total fragments is non-negative
invariant totalFragmentsNonNegative()
    totalFragments() >= 0;

// Total joins is non-negative
invariant totalJoinsNonNegative()
    totalJoins() >= 0;

// Fragment status transitions are valid
rule validFragmentStatusTransitions(bytes32 fragmentId) {
    env e;
    uint8 statusBefore = getFragmentStatus(fragmentId);
    method f;
    calldataarg args;
    f(e, args);
    uint8 statusAfter = getFragmentStatus(fragmentId);
    // Rejected fragments cannot change (status 3)
    assert statusBefore == 3 => statusAfter == 3, "Rejected fragments cannot change";
    // Joined fragments cannot change (status 2)
    assert statusBefore == 2 => statusAfter == 2, "Joined fragments cannot change";
}

// Join status transitions are valid
rule validJoinStatusTransitions(bytes32 joinId) {
    env e;
    uint8 statusBefore = getJoinStatus(joinId);
    method f;
    calldataarg args;
    f(e, args);
    uint8 statusAfter = getJoinStatus(joinId);
    // Terminal states (>=3) are final
    assert statusBefore >= 3 => statusAfter == statusBefore, "Terminal join states are final";
}

// Fragment count monotonically increases
rule fragmentCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalFragments();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalFragments();
    assert countAfter >= countBefore, "Fragment count cannot decrease";
}

// Join count monotonically increases
rule joinCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalJoins();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalJoins();
    assert countAfter >= countBefore, "Join count cannot decrease";
}

// Paused contract blocks verification
rule pausedBlocksVerification(bytes32 fragmentId) {
    env e;
    require paused();
    verifyFragment@withrevert(e, fragmentId);
    assert lastReverted, "Paused contract must block verification";
}

// Only admin can pause
rule onlyAdminCanPause() {
    env e;
    bytes32 ADMIN_ROLE = to_bytes32(0);
    require !hasRole(ADMIN_ROLE, e.msg.sender);
    require !paused();
    pause@withrevert(e);
    assert lastReverted, "Only admin can pause";
}
