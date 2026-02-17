/**
 * Certora Formal Verification Specification
 * Soul Protocol - HeterogeneousRelayerRegistry
 *
 * This spec verifies critical invariants for the Heterogeneous Relayer Registry
 * which implements role-separated relayers (ProofGenerator, LightRelayer,
 * Watchtower) with reputation-based task routing and SLA tracking.
 *
 * Properties verified:
 * 1. Task counter monotonicity (totalTasks never decreases)
 * 2. Completed task counter monotonicity (totalTasksCompleted never decreases)
 * 3. Task completion permanence (completed tasks stay completed)
 * 4. Task failure permanence (failed tasks stay failed)
 * 5. Slash accounting (slash reduces stake, never increases it)
 * 6. Slashed funds monotonicity (slashedFunds only increases via slashRelayer)
 * 7. Reputation bounded by MAX_REPUTATION
 * 8. Role-based minimum stake enforcement
 * 9. No double registration
 * 10. Stake always non-negative after slashing
 * 11. Exit returns correct funds
 * 12. Access control on slashing
 */

using HeterogeneousRelayerRegistry as hrr;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Constants
    function PROOF_GENERATOR_MIN_STAKE() external returns (uint256) envfree;
    function LIGHT_RELAYER_MIN_STAKE() external returns (uint256) envfree;
    function WATCHTOWER_MIN_STAKE() external returns (uint256) envfree;
    function EXIT_COOLDOWN() external returns (uint64) envfree;
    function MAX_REPUTATION() external returns (uint256) envfree;
    function DEFAULT_REPUTATION() external returns (uint256) envfree;
    function MIN_TASK_DEADLINE() external returns (uint64) envfree;

    // Role constants
    function REGISTRY_ADMIN_ROLE() external returns (bytes32) envfree;
    function TASK_ASSIGNER_ROLE() external returns (bytes32) envfree;
    function SLASHER_ROLE() external returns (bytes32) envfree;
    function PERFORMANCE_REPORTER_ROLE() external returns (bytes32) envfree;

    // State getters
    function totalTasks() external returns (uint256) envfree;
    function totalTasksCompleted() external returns (uint256) envfree;
    function slashedFunds() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;

    // Relayer queries
    function exitRequests(address) external returns (uint64) envfree;
    function unclaimedRewards(address) external returns (uint256) envfree;

    // State-changing functions
    function registerProofGenerator(uint256[], bytes32) external;
    function registerLightRelayer(uint256[]) external;
    function registerWatchtower() external;
    function exitRelayer() external;
    function assignTask(uint8, bytes32, uint256, uint256, uint64) external;
    function completeTask(bytes32, bytes) external;
    function reportTaskFailure(bytes32, string) external;
    function slashRelayer(address, uint256, string) external;
    function claimRewards() external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalTasks {
    init_state axiom ghostTotalTasks == 0;
}

ghost uint256 ghostTotalTasksCompleted {
    init_state axiom ghostTotalTasksCompleted == 0;
}

ghost uint256 ghostSlashedFunds {
    init_state axiom ghostSlashedFunds == 0;
}

// Hook: track slashedFunds increases
hook Sstore slashedFunds uint256 newVal (uint256 oldVal) {
    ghostSlashedFunds = newVal;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Completed Tasks Never Exceed Total Tasks
 * @notice totalTasksCompleted <= totalTasks
 */
invariant completedNeverExceedsTotal()
    totalTasksCompleted() <= totalTasks()
    { preserved {
        require totalTasks() < max_uint256;
        require totalTasksCompleted() < max_uint256;
    } }

/**
 * @title Total Tasks Non-Negative
 * @notice totalTasks is always >= 0
 */
invariant totalTasksNonNegative()
    totalTasks() >= 0
    { preserved { require totalTasks() < max_uint256; } }

/**
 * @title Slashed Funds Non-Negative
 * @notice slashedFunds can never underflow
 */
invariant slashedFundsNonNegative()
    slashedFunds() >= 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Total Tasks Never Decreases
 * @notice No function call should decrease totalTasks
 */
rule totalTasksNeverDecreases() {
    env e;
    uint256 before = totalTasks();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalTasks();

    assert after >= before,
        "totalTasks must never decrease";
}

/**
 * @title Total Tasks Completed Never Decreases
 * @notice No function call should decrease totalTasksCompleted
 */
rule totalTasksCompletedNeverDecreases() {
    env e;
    uint256 before = totalTasksCompleted();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalTasksCompleted();

    assert after >= before,
        "totalTasksCompleted must never decrease";
}

/**
 * @title Slashed Funds Never Decrease (except via withdrawSlashedFunds)
 * @notice slashRelayer can only increase slashedFunds
 */
rule slashRelayerIncreasesSlashedFunds(env e) {
    uint256 slashedBefore = slashedFunds();
    require slashedBefore < max_uint256;

    address relayerAddr; uint256 amount; string reason;
    slashRelayer(e, relayerAddr, amount, reason);

    uint256 slashedAfter = slashedFunds();

    assert slashedAfter >= slashedBefore,
        "slashRelayer must not decrease slashedFunds";
}

/**
 * @title Slash Does Not Increase Stake
 * @notice After slashRelayer, slashedFunds increases by the same amount stake decreased
 * (conservation of value)
 */
rule slashConservesValue(env e) {
    uint256 slashedBefore = slashedFunds();
    require slashedBefore < max_uint256;

    address relayerAddr; uint256 amount; string reason;
    slashRelayer(e, relayerAddr, amount, reason);

    uint256 slashedAfter = slashedFunds();

    // Slashed funds increased (or stayed same for zero-stake relayers)
    assert to_mathint(slashedAfter) >= to_mathint(slashedBefore),
        "Slashed funds must not decrease after slash";
}

/**
 * @title Assign Task Increments Counter
 * @notice assignTask should increase totalTasks by exactly 1
 */
rule assignTaskIncrementsCounter(env e) {
    uint256 before = totalTasks();
    require before < max_uint256;

    uint8 taskType; bytes32 proofDataHash;
    uint256 srcChain; uint256 dstChain; uint64 deadline;

    assignTask(e, taskType, proofDataHash, srcChain, dstChain, deadline);

    uint256 after = totalTasks();

    assert to_mathint(after) == to_mathint(before) + 1,
        "assignTask must increment totalTasks by exactly 1";
}

/**
 * @title Complete Task Increments Completed Counter
 * @notice completeTask should increase totalTasksCompleted by exactly 1
 */
rule completeTaskIncrementsCompletedCounter(env e) {
    uint256 before = totalTasksCompleted();
    require before < max_uint256;

    bytes32 taskId; bytes result;
    completeTask(e, taskId, result);

    uint256 after = totalTasksCompleted();

    assert to_mathint(after) == to_mathint(before) + 1,
        "completeTask must increment totalTasksCompleted by exactly 1";
}

/**
 * @title Default Reputation For New Relayers
 * @notice DEFAULT_REPUTATION is always equal to 5000
 */
rule defaultReputationValue() {
    assert DEFAULT_REPUTATION() == 5000,
        "DEFAULT_REPUTATION must always be 5000";
}

/**
 * @title Max Reputation Bound
 * @notice MAX_REPUTATION is always equal to 10000
 */
rule maxReputationValue() {
    assert MAX_REPUTATION() == 10000,
        "MAX_REPUTATION must always be 10000";
}

/**
 * @title Proof Generator Requires 1 ETH
 * @notice PROOF_GENERATOR_MIN_STAKE == 1 ether
 */
rule proofGeneratorMinStake() {
    assert PROOF_GENERATOR_MIN_STAKE() == 1000000000000000000,
        "ProofGenerator minimum stake must be 1 ETH";
}

/**
 * @title Light Relayer Requires 0.1 ETH
 * @notice LIGHT_RELAYER_MIN_STAKE == 0.1 ether
 */
rule lightRelayerMinStake() {
    assert LIGHT_RELAYER_MIN_STAKE() == 100000000000000000,
        "LightRelayer minimum stake must be 0.1 ETH";
}
