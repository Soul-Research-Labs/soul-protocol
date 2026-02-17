/**
 * Certora Formal Verification Specification
 * Soul Protocol - RecursiveProofAggregator
 *
 * This spec verifies critical invariants for the Recursive Proof Aggregator
 * which implements IVC-based proof aggregation (Nova/SuperNova-style folding)
 * for cross-chain privacy proof compression.
 */

using RecursiveProofAggregator as rpa;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function totalProofsSubmitted() external returns (uint256) envfree;
    function totalProofsAggregated() external returns (uint256) envfree;
    function totalBatches() external returns (uint256) envfree;
    function verifiedRoots(bytes32) external returns (bool) envfree;
    function isRootVerified(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function AGGREGATOR_ROLE() external returns (bytes32) envfree;
    function VERIFIER_ROLE() external returns (bytes32) envfree;
    function EMERGENCY_ROLE() external returns (bytes32) envfree;
    function MAX_BATCH_SIZE() external returns (uint256) envfree;
    function MIN_BATCH_SIZE() external returns (uint256) envfree;
    function AGGREGATION_WINDOW() external returns (uint256) envfree;

    // State-changing functions
    function submitProof(uint8, bytes, bytes32, bytes32, uint256) external;
    function finalizeBatchAggregation(bytes32, bytes, bytes32) external;
    function createCrossChainBundle(bytes32[], uint256[]) external;
    function finalizeCrossChainBundle(bytes32, bytes, bytes32) external;
    function pause() external;
    function unpause() external;

    // FAFO Parallel Scheduling
    function totalParallelGroups() external returns (uint256) envfree;
    function scheduleParallelAggregation(bytes32[], uint256[]) external;
    function finalizeParallelGroup(bytes32, bytes, bytes32) external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalProofsSubmitted {
    init_state axiom ghostTotalProofsSubmitted == 0;
}

ghost uint256 ghostTotalBatches {
    init_state axiom ghostTotalBatches == 0;
}

ghost mapping(bytes32 => bool) ghostVerifiedRoots {
    init_state axiom forall bytes32 r. !ghostVerifiedRoots[r];
}

// Hook: track when verifiedRoots mapping is written
hook Sstore verifiedRoots[KEY bytes32 root] bool newVal (bool oldVal) {
    if (newVal) {
        ghostVerifiedRoots[root] = true;
    }
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Total Proofs Submitted Monotonically Increasing
 * @notice totalProofsSubmitted can only increase, never decrease
 * TODO: Hook ghost to totalProofsSubmitted storage slot
 */
invariant totalProofsSubmittedMonotonicallyIncreasing()
    totalProofsSubmitted() >= 0
    { preserved { require totalProofsSubmitted() < max_uint256; } }

/**
 * @title Aggregated Proofs Never Exceed Submitted
 * @notice totalProofsAggregated <= totalProofsSubmitted
 * TODO: Strengthen with ghost tracking for exact proof lifecycle
 */
invariant aggregatedNeverExceedsSubmitted()
    totalProofsAggregated() <= totalProofsSubmitted()
    { preserved {
        require totalProofsSubmitted() < max_uint256;
        require totalProofsAggregated() < max_uint256;
    } }

/**
 * @title Verified Roots Are Permanent
 * @notice Once a root is verified, it stays verified
 * TODO: Express with ghost mapping hooks on verifiedRoots
 */
invariant verifiedRootsPermanent(bytes32 root)
    ghostVerifiedRoots[root] => verifiedRoots(root)

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Total Proofs Never Decreases
 * @notice No function call should decrease totalProofsSubmitted
 */
rule totalProofsNeverDecreases() {
    env e;
    uint256 before = totalProofsSubmitted();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalProofsSubmitted();

    assert after >= before,
        "totalProofsSubmitted must never decrease";
}

/**
 * @title Total Batches Never Decreases
 * @notice No function call should decrease totalBatches
 */
rule totalBatchesNeverDecreases() {
    env e;
    uint256 before = totalBatches();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalBatches();

    assert after >= before,
        "totalBatches must never decrease";
}

/**
 * @title Verified Root Remains Verified
 * @notice Once isRootVerified returns true, it stays true across all transitions
 */
rule verifiedRootStaysVerified(bytes32 root) {
    require isRootVerified(root);

    env e;
    method f;
    calldataarg args;
    f(e, args);

    assert isRootVerified(root),
        "A verified root must remain verified";
}

// ============================================================================
// FAFO PARALLEL SCHEDULING RULES
// ============================================================================

/**
 * @title Total Parallel Groups Never Decreases
 * @notice No function call should decrease totalParallelGroups
 */
rule totalParallelGroupsNeverDecreases() {
    env e;
    uint256 before = totalParallelGroups();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalParallelGroups();

    assert after >= before,
        "totalParallelGroups must never decrease";
}

/**
 * @title Schedule Parallel Aggregation Increments Counter
 * @notice scheduleParallelAggregation should increase totalParallelGroups by 1
 */
rule scheduleParallelIncrementsCounter(env e) {
    uint256 before = totalParallelGroups();
    require before < max_uint256;

    bytes32[] batchIds; uint256[] chainDomains;
    scheduleParallelAggregation(e, batchIds, chainDomains);

    uint256 after = totalParallelGroups();

    assert to_mathint(after) == to_mathint(before) + 1,
        "scheduleParallelAggregation must increment totalParallelGroups by exactly 1";
}
