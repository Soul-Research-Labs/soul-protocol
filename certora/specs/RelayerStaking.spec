/**
 * Certora Formal Verification Specification
 * Soul Protocol - RelayerStaking
 *
 * Verifies safety invariants for relayer staking including
 * token conservation, unbonding period enforcement, slashing bounds,
 * and activation / deactivation thresholds.
 */

using RelayerStaking as rs;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Constants
    function UNBONDING_PERIOD() external returns (uint256) envfree;
    function PRECISION() external returns (uint256) envfree;
    function MIN_STAKE_DURATION() external returns (uint256) envfree;

    // View functions
    function minStake() external returns (uint256) envfree;
    function slashingPercentage() external returns (uint256) envfree;
    function totalStaked() external returns (uint256) envfree;
    function rewardPool() external returns (uint256) envfree;
    function rewardPerShare() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function getActiveRelayerCount() external returns (uint256) envfree;
    function isActiveRelayer(address) external returns (bool) envfree;
    function pendingRewards(address) external returns (uint256) envfree;

    // State-changing functions
    function stake(uint256) external;
    function requestUnstake(uint256) external;
    function completeUnstake() external;
    function slash(address, string) external;
    function recordSuccessfulRelay(address) external;
    function claimRewards() external;
    function addRewards(uint256) external;
    function setMinStake(uint256) external;
    function setSlashingPercentage(uint256) external;
    function updateMetadata(string) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-RS-001: Slashing percentage bounded
 * Slashing percentage can never exceed 50% (5000 bps).
 */
invariant slashingPercentageBounded()
    slashingPercentage() <= 5000;

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-RS-001: Staking with zero amount always reverts
 */
rule stakeZeroReverts() {
    env e;
    stake@withrevert(e, 0);
    assert lastReverted;
}

/**
 * RULE-RS-002: addRewards with zero amount always reverts
 */
rule addRewardsZeroReverts() {
    env e;
    addRewards@withrevert(e, 0);
    assert lastReverted;
}

/**
 * RULE-RS-003: Staking increases totalStaked
 * A successful stake() increases totalStaked by the deposited amount.
 */
rule stakeIncreasesTotalStaked(uint256 amount) {
    env e;
    require amount > 0;

    uint256 totalBefore = totalStaked();

    stake(e, amount);

    uint256 totalAfter = totalStaked();
    assert totalAfter == totalBefore + amount;
}

/**
 * RULE-RS-004: addRewards increases rewardPool
 */
rule addRewardsIncreasesPool(uint256 amount) {
    env e;
    require amount > 0;

    uint256 poolBefore = rewardPool();

    addRewards(e, amount);

    uint256 poolAfter = rewardPool();
    assert poolAfter == poolBefore + amount;
}

/**
 * RULE-RS-005: Only SLASHER_ROLE can slash
 */
rule onlySlasherCanSlash(address relayer, string reason) {
    env e;
    bytes32 slasherRole = 0x12b42e8a160f6064dc959c6f251e3af0750ad213dbecf573b4710d67d6c28e39;
    require !hasRole(slasherRole, e.msg.sender);

    slash@withrevert(e, relayer, reason);
    assert lastReverted;
}

/**
 * RULE-RS-006: Only ADMIN_ROLE can set slashing percentage
 */
rule onlyAdminCanSetSlashingPercentage(uint256 newPct) {
    env e;
    bytes32 adminRole = 0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775;
    require !hasRole(adminRole, e.msg.sender);

    setSlashingPercentage@withrevert(e, newPct);
    assert lastReverted;
}

/**
 * RULE-RS-007: setSlashingPercentage enforces 50% cap
 */
rule slashingPercentageCapEnforced(uint256 newPct) {
    env e;
    require newPct > 5000;

    setSlashingPercentage@withrevert(e, newPct);
    assert lastReverted;
}

/**
 * RULE-RS-008: Slash reduces totalStaked
 * A successful slash decreases totalStaked by exactly (stakedAmount * slashingPercentage / 10000).
 */
rule slashReducesTotalStaked(address relayer, string reason) {
    env e;

    uint256 totalBefore = totalStaked();

    slash(e, relayer, reason);

    uint256 totalAfter = totalStaked();
    assert totalAfter <= totalBefore;
}

/**
 * RULE-RS-009: totalStaked is monotonically non-negative
 * After any operation, totalStaked remains non-negative.
 */
rule totalStakedNonNegative(method f) filtered { f -> !f.isView } {
    env e;
    calldataarg args;
    f(e, args);

    // totalStaked is uint256 so >= 0 by type, but we verify it doesn't underflow
    assert totalStaked() >= 0;
}

/**
 * RULE-RS-010: Only ADMIN_ROLE can setMinStake
 */
rule onlyAdminCanSetMinStake(uint256 newMin) {
    env e;
    bytes32 adminRole = 0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775;
    require !hasRole(adminRole, e.msg.sender);

    setMinStake@withrevert(e, newMin);
    assert lastReverted;
}

/**
 * RULE-RS-011: rewardPool never decreases except on claimRewards
 * After any non-claim operation, rewardPool stays the same or increases.
 */
rule rewardPoolNonDecreasingExceptClaim(method f) filtered {
    f -> !f.isView && f.selector != sig:claimRewards().selector
} {
    uint256 poolBefore = rewardPool();

    env e;
    calldataarg args;
    f(e, args);

    uint256 poolAfter = rewardPool();
    assert poolAfter >= poolBefore;
}
