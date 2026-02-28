/**
 * Certora Formal Verification Specification
 * ZASEON - RecursiveProofAggregator
 *
 * This spec verifies critical invariants for the Recursive Proof Aggregator
 * which implements IVC-based proof aggregation (Nova/SuperNova-style folding)
 * for cross-chain privacy proof compression.
 *
 * Ghost variable hooks track: totalProofsSubmitted, totalBatches, verifiedRoots,
 * totalParallelGroups.
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

ghost uint256 ghostPriorTotalProofs {
    init_state axiom ghostPriorTotalProofs == 0;
}

ghost uint256 ghostTotalBatches {
    init_state axiom ghostTotalBatches == 0;
}

ghost uint256 ghostPriorTotalBatches {
    init_state axiom ghostPriorTotalBatches == 0;
}

ghost mapping(bytes32 => bool) ghostVerifiedRoots {
    init_state axiom forall bytes32 r. !ghostVerifiedRoots[r];
}

ghost uint256 ghostTotalParallelGroups {
    init_state axiom ghostTotalParallelGroups == 0;
}

// Hook: track totalProofsSubmitted storage writes
hook Sstore totalProofsSubmitted uint256 newVal (uint256 oldVal) {
    ghostPriorTotalProofs = oldVal;
    ghostTotalProofsSubmitted = newVal;
}

// Hook: track totalBatches storage writes
hook Sstore totalBatches uint256 newVal (uint256 oldVal) {
    ghostPriorTotalBatches = oldVal;
    ghostTotalBatches = newVal;
}

// Hook: track when verifiedRoots mapping is written
hook Sstore verifiedRoots[KEY bytes32 root] bool newVal (bool oldVal) {
    if (newVal) {
        ghostVerifiedRoots[root] = true;
    }
}

// Hook: track totalParallelGroups storage writes
hook Sstore totalParallelGroups uint256 newVal (uint256 oldVal) {
    ghostTotalParallelGroups = newVal;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Ghost Proofs Match Contract
 * @notice Ghost variable always equals on-chain totalProofsSubmitted
 */
invariant ghostProofsMatchContract()
    ghostTotalProofsSubmitted == totalProofsSubmitted()
    { preserved { require totalProofsSubmitted() < max_uint256; } }

/**
 * @title Total Proofs Submitted Monotonically Increasing
 * @notice totalProofsSubmitted can only increase (tracked via ghost hook)
 */
invariant totalProofsSubmittedMonotonicallyIncreasing()
    ghostTotalProofsSubmitted >= ghostPriorTotalProofs
    { preserved { require ghostTotalProofsSubmitted < max_uint256; } }

/**
 * @title Aggregated Proofs Never Exceed Submitted
 * @notice totalProofsAggregated <= totalProofsSubmitted
 */
invariant aggregatedNeverExceedsSubmitted()
    totalProofsAggregated() <= totalProofsSubmitted()
    { preserved {
        require totalProofsSubmitted() < max_uint256;
        require totalProofsAggregated() < max_uint256;
    } }

/**
 * @title Ghost Batches Match Contract
 * @notice Ghost variable always equals on-chain totalBatches
 */
invariant ghostBatchesMatchContract()
    ghostTotalBatches == totalBatches()
    { preserved { require totalBatches() < max_uint256; } }

/**
 * @title Verified Roots Are Permanent
 * @notice Once root is verified, ghost hook ensures it stays verified.
 *         The Sstore hook only sets ghostVerifiedRoots[root] = true when
 *         newVal is true, so it can never be reverted to false.
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
    uint256 proofsBefore = totalProofsSubmitted();

    method f;
    calldataarg args;
    f(e, args);

    uint256 proofsAfter = totalProofsSubmitted();

    assert proofsAfter >= proofsBefore,
        "totalProofsSubmitted must never decrease";
}

/**
 * @title Total Batches Never Decreases
 * @notice No function call should decrease totalBatches
 */
rule totalBatchesNeverDecreases() {
    env e;
    uint256 batchesBefore = totalBatches();

    method f;
    calldataarg args;
    f(e, args);

    uint256 batchesAfter = totalBatches();

    assert batchesAfter >= batchesBefore,
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

/**
 * @title Pause Prevents Proof Submission
 * @notice When paused, submitProof should revert
 */
rule pausePreventsSubmission(uint8 proofSystem, bytes proof, bytes32 circuitHash, bytes32 nullifier, uint256 chainId) {
    env e;
    require paused();

    submitProof@withrevert(e, proofSystem, proof, circuitHash, nullifier, chainId);

    assert lastReverted,
        "Proof submission should fail when paused";
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
    uint256 groupsBefore = totalParallelGroups();

    method f;
    calldataarg args;
    f(e, args);

    uint256 groupsAfter = totalParallelGroups();

    assert groupsAfter >= groupsBefore,
        "totalParallelGroups must never decrease";
}

/**
 * @title Schedule Parallel Aggregation Increments Counter
 * @notice scheduleParallelAggregation should increase totalParallelGroups by 1
 */
rule scheduleParallelIncrementsCounter(env e) {
    uint256 groupsBefore = totalParallelGroups();
    require groupsBefore < max_uint256;

    bytes32[] batchIds; uint256[] chainDomains;
    scheduleParallelAggregation(e, batchIds, chainDomains);

    uint256 groupsAfter = totalParallelGroups();

    assert to_mathint(groupsAfter) == to_mathint(groupsBefore) + 1,
        "scheduleParallelAggregation must increment totalParallelGroups by exactly 1";
}
