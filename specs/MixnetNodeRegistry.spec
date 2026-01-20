/**
 * @title Formal Verification Specification for MixnetNodeRegistry
 * @author Soul Protocol
 * @notice Simplified Certora CVL specification for mix node registration
 */

methods {
    function totalNodes() external returns (uint256) envfree;
    function activeNodes() external returns (uint256) envfree;
    function minStake() external returns (uint256) envfree;
    function slashPercent() external returns (uint256) envfree;
    function exitDelay() external returns (uint256) envfree;
    function getNodeStatus(bytes32) external returns (uint8) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function pause() external;
    function unpause() external;
}

// Active nodes bounded by total
invariant activeNodesBoundedByTotal()
    activeNodes() <= totalNodes();

// Min stake is positive
invariant minStakePositive()
    minStake() > 0;

// Slash percent is bounded (0-100)
invariant slashPercentBounded()
    slashPercent() <= 100;

// Total nodes is non-negative
invariant totalNodesNonNegative()
    totalNodes() >= 0;

// Node status transitions are valid
rule validNodeStatusTransitions(bytes32 nodeId) {
    env e;
    uint8 statusBefore = getNodeStatus(nodeId);
    method f;
    calldataarg args;
    f(e, args);
    uint8 statusAfter = getNodeStatus(nodeId);
    // Slashed nodes cannot change (status 4)
    assert statusBefore == 4 => statusAfter == 4, "Slashed nodes cannot change status";
}

// Total nodes monotonically increases
rule totalNodesMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalNodes();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalNodes();
    assert countAfter >= countBefore, "Total nodes cannot decrease";
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
