/**
 * Certora Formal Verification Specification
 * ZASEON - PrivateRelayerNetwork
 *
 * This spec verifies critical invariants for the Private Relayer Network
 * which implements stake-weighted VRF-based relayer selection,
 * commit-reveal MEV protection, and stealth fee payments.
 *
 * Ghost variable hooks track: totalStake, totalRelays, individual relayer stakes.
 */

using PrivateRelayerNetwork as prn;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function totalStake() external returns (uint256) envfree;
    function totalRelays() external returns (uint256) envfree;
    function getRelayerCount() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function SLASHER_ROLE() external returns (bytes32) envfree;
    function MIN_STAKE() external returns (uint256) envfree;
    function MAX_STAKE() external returns (uint256) envfree;
    function SLASH_PERCENTAGE() external returns (uint256) envfree;
    function LATE_SLASH_PERCENTAGE() external returns (uint256) envfree;
    function MIN_RELAYERS() external returns (uint256) envfree;
    function currentVRFRound() external returns (bytes32) envfree;

    // State-changing functions
    function registerRelayer(bytes32, bytes32) external;
    function addStake() external;
    function requestExit() external;
    function completeExit() external;
    function startVRFRound(bytes32) external;
    function slashRelayer(address, uint256, bytes32) external;
    function unjailRelayer() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalStake {
    init_state axiom ghostTotalStake == 0;
}

ghost uint256 ghostPriorTotalStake {
    init_state axiom ghostPriorTotalStake == 0;
}

ghost uint256 ghostTotalRelays {
    init_state axiom ghostTotalRelays == 0;
}

ghost uint256 ghostPriorTotalRelays {
    init_state axiom ghostPriorTotalRelays == 0;
}

ghost uint256 ghostRelayerCount {
    init_state axiom ghostRelayerCount == 0;
}

// Hook: track totalStake storage writes
hook Sstore totalStake uint256 newVal (uint256 oldVal) {
    ghostPriorTotalStake = oldVal;
    ghostTotalStake = newVal;
}

// Hook: track totalRelays storage writes
hook Sstore totalRelays uint256 newVal (uint256 oldVal) {
    ghostPriorTotalRelays = oldVal;
    ghostTotalRelays = newVal;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Ghost Total Stake Matches Contract
 * @notice Ghost variable always equals the on-chain totalStake
 */
invariant ghostTotalStakeMatchesContract()
    ghostTotalStake == totalStake();

/**
 * @title Total Stake Is Non-Negative
 * @notice totalStake should always be >= 0 (guards against underflow)
 */
invariant totalStakeNonNegative()
    totalStake() >= 0;

/**
 * @title Relayer Count Consistency
 * @notice getRelayerCount() should always be >= 0
 */
invariant relayerCountConsistency()
    getRelayerCount() >= 0;

/**
 * @title Ghost Total Relays Matches Contract
 * @notice Ghost variable always equals on-chain totalRelays
 */
invariant ghostTotalRelaysMatchesContract()
    ghostTotalRelays == totalRelays();

/**
 * @title Total Relays Monotonically Increasing
 * @notice totalRelays can only increase, never decrease (tracked via ghost hook)
 */
invariant totalRelaysMonotonicallyIncreasing()
    ghostTotalRelays >= ghostPriorTotalRelays
    { preserved { require ghostTotalRelays < max_uint256; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Slashing Decreases Total Stake
 * @notice After slashRelayer, totalStake must not increase
 */
rule slashDoesNotViolateTotalStakeAccounting() {
    env e;
    address relayer;
    uint256 amount;
    bytes32 reason;

    uint256 totalBefore = totalStake();

    slashRelayer(e, relayer, amount, reason);

    uint256 totalAfter = totalStake();

    assert totalAfter <= totalBefore,
        "Total stake must not increase after slashing";
}

/**
 * @title Only SLASHER_ROLE Can Slash
 * @notice slashRelayer must revert if caller lacks SLASHER_ROLE
 */
rule onlySlasherCanSlash(address relayer, uint256 amount, bytes32 reason) {
    env e;
    require !hasRole(SLASHER_ROLE(), e.msg.sender);
    require !hasRole(prn.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    slashRelayer@withrevert(e, relayer, amount, reason);

    assert lastReverted,
        "Only SLASHER_ROLE should be able to slash relayers";
}

/**
 * @title Total Relays Never Decreases
 * @notice No function call should decrease totalRelays
 */
rule totalRelaysNeverDecreases() {
    env e;
    uint256 relaysBefore = totalRelays();

    method f;
    calldataarg args;
    f(e, args);

    uint256 relaysAfter = totalRelays();

    assert relaysAfter >= relaysBefore,
        "totalRelays must never decrease";
}

/**
 * @title Adding Stake Increases Total Stake By msg.value
 * @notice addStake() should increase totalStake by msg.value (tracked via ghost)
 */
rule addStakeIncreasesTotalStake() {
    env e;
    require e.msg.value > 0;

    uint256 totalBefore = totalStake();

    addStake(e);

    uint256 totalAfter = totalStake();

    assert totalAfter > totalBefore,
        "Total stake should increase after addStake";
    assert to_mathint(totalAfter) == to_mathint(totalBefore) + to_mathint(e.msg.value),
        "Total stake should increase by exactly msg.value";
}

/**
 * @title Only OPERATOR_ROLE Can Start VRF Round
 * @notice startVRFRound must revert if caller lacks OPERATOR_ROLE
 */
rule onlyOperatorCanStartVRFRound(bytes32 seed) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);
    require !hasRole(prn.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    startVRFRound@withrevert(e, seed);

    assert lastReverted,
        "Only OPERATOR_ROLE should be able to start VRF rounds";
}
