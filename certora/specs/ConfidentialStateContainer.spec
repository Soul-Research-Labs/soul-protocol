/**
 * Certora Formal Verification Specification
 * ZASEON - ConfidentialStateContainerV3
 * Phase 4: Production Readiness — real invariants and rules
 */

using ConfidentialStateContainerV3 as csc;

methods {
    function totalStates() external returns (uint256) envfree;
    function activeStates() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                         INVARIANTS
//////////////////////////////////////////////////////////////*/

/// @notice Active states can never exceed total states
invariant activeNeverExceedsTotal()
    activeStates() <= totalStates();

/// @notice Total states is monotonically non-decreasing
/// (states are created but never removed from count)
rule totalStatesMonotonic(method f, env e, calldataarg args) {
    uint256 totalBefore = totalStates();
    f(e, args);
    uint256 totalAfter = totalStates();
    assert totalAfter >= totalBefore,
        "Total states must be monotonically non-decreasing";
}

/// @notice Active states are bounded by total states
/// (replaces vacuous uint256 >= 0 check with a meaningful bound)
rule activeStatesBoundedByTotal(method f, env e, calldataarg args) {
    f(e, args);
    assert activeStates() <= totalStates(),
        "Active states must never exceed total states";
}

/// @notice No state mutation while paused
rule noStateMutationWhenPaused(method f, env e, calldataarg args)
    filtered { f -> !f.isView && f.selector != sig:unpause().selector } {
    uint256 totalBefore = totalStates();
    uint256 activeBefore = activeStates();
    require paused();
    f@withrevert(e, args);
    // If tx didn't revert, state counts should not have changed
    // (paused modifier should have reverted any state-changing call)
    assert lastReverted || (totalStates() == totalBefore && activeStates() == activeBefore),
        "State-changing operations must revert when paused";
}
