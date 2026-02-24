/**
 * Certora Formal Verification Specification
 * Soul Protocol - MEVProtection
 *
 * Verifies safety invariants for the commit-reveal scheme used to
 * prevent front-running and MEV extraction in privacy operations.
 */

using MEVProtection as mev;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Constants
    function MAX_PENDING_COMMITMENTS() external returns (uint256) envfree;

    // View functions
    function minRevealDelay() external returns (uint256) envfree;
    function maxCommitmentAge() external returns (uint256) envfree;
    function pendingCommitmentCount(address) external returns (uint256) envfree;
    function commitmentNonce(address) external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function calculateCommitHash(address, bytes32, bytes, bytes32) external returns (bytes32) envfree;

    // State-changing functions
    function commit(bytes32) external returns (bytes32);
    function reveal(bytes32, bytes32, bytes, bytes32) external returns (bool);
    function cancelCommitment(bytes32) external;
    function updateDelays(uint256, uint256) external;
    function cleanupExpiredCommitments(address, uint256) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-MEV-001: MAX_PENDING_COMMITMENTS is always 10
 */
invariant maxPendingIsConstant()
    MAX_PENDING_COMMITMENTS() == 10;

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-MEV-001: Pending commitment count never exceeds maximum
 * For any user, the count of pending commitments is always ≤ 10.
 */
rule pendingCountBounded(address user) {
    assert pendingCommitmentCount(user) <= MAX_PENDING_COMMITMENTS();
}

/**
 * RULE-MEV-002: Commitment nonce only increases
 * After any state-changing operation, a user's nonce never decreases.
 */
rule nonceMonotonicity(method f, address user) filtered { f -> !f.isView } {
    uint256 nonceBefore = commitmentNonce(user);

    env e;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = commitmentNonce(user);
    assert nonceAfter >= nonceBefore;
}

/**
 * RULE-MEV-003: Commit requires non-paused state
 */
rule noCommitWhenPaused(bytes32 commitHash) {
    env e;
    require paused();

    commit@withrevert(e, commitHash);
    assert lastReverted;
}

/**
 * RULE-MEV-004: Commit increases nonce by exactly 1
 */
rule commitIncreasesNonce(bytes32 commitHash) {
    env e;
    uint256 nonceBefore = commitmentNonce(e.msg.sender);

    commit(e, commitHash);

    uint256 nonceAfter = commitmentNonce(e.msg.sender);
    assert nonceAfter == nonceBefore + 1;
}

/**
 * RULE-MEV-005: Commit increases pending count by exactly 1
 */
rule commitIncreasesPendingCount(bytes32 commitHash) {
    env e;
    uint256 countBefore = pendingCommitmentCount(e.msg.sender);

    commit(e, commitHash);

    uint256 countAfter = pendingCommitmentCount(e.msg.sender);
    assert countAfter == countBefore + 1;
}

/**
 * RULE-MEV-006: Only DEFAULT_ADMIN_ROLE can update delays
 */
rule onlyAdminCanUpdateDelays(uint256 newMinDelay, uint256 newMaxAge) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    updateDelays@withrevert(e, newMinDelay, newMaxAge);
    assert lastReverted;
}

/**
 * RULE-MEV-007: Cancellation decreases pending count
 */
rule cancelDecreasesPendingCount(bytes32 commitmentId) {
    env e;
    uint256 countBefore = pendingCommitmentCount(e.msg.sender);

    cancelCommitment(e, commitmentId);

    uint256 countAfter = pendingCommitmentCount(e.msg.sender);
    assert countAfter == countBefore - 1;
}

/**
 * RULE-MEV-008: Reveal decreases pending count
 */
rule revealDecreasesPendingCount(bytes32 commitmentId, bytes32 opType, bytes data, bytes32 salt) {
    env e;
    uint256 countBefore = pendingCommitmentCount(e.msg.sender);

    reveal(e, commitmentId, opType, data, salt);

    uint256 countAfter = pendingCommitmentCount(e.msg.sender);
    assert countAfter == countBefore - 1;
}

/**
 * RULE-MEV-009: Delay bounds are enforced on updateDelays
 * minRevealDelay >= 1 and maxCommitmentAge <= 7200 after any successful update.
 */
rule delayBoundsEnforced(uint256 newMinDelay, uint256 newMaxAge) {
    env e;

    updateDelays(e, newMinDelay, newMaxAge);

    assert minRevealDelay() >= 1;
    assert maxCommitmentAge() <= 7200;
}
