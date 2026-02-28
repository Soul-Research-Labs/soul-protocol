/**
 * Certora Formal Verification Specification
 * ZASEON - SecurityModule
 *
 * Verifies safety invariants for the abstract security module including
 * rate limiting, circuit breaker, flash loan guard, and withdrawal limits.
 * Uses SecurityModuleHarness (a concrete implementation) for verification.
 */

// NOTE: A concrete harness inheriting SecurityModule is required for verification.
// The harness should expose internal functions through external wrappers.

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions (flags)
    function rateLimitingEnabled() external returns (bool) envfree;
    function circuitBreakerEnabled() external returns (bool) envfree;
    function circuitBreakerTripped() external returns (bool) envfree;
    function flashLoanGuardEnabled() external returns (bool) envfree;
    function withdrawalLimitsEnabled() external returns (bool) envfree;

    // View functions (config)
    function rateLimitWindow() external returns (uint256) envfree;
    function maxActionsPerWindow() external returns (uint256) envfree;
    function volumeThreshold() external returns (uint256) envfree;
    function circuitBreakerCooldown() external returns (uint256) envfree;
    function maxSingleWithdrawal() external returns (uint256) envfree;
    function maxDailyWithdrawal() external returns (uint256) envfree;
    function accountMaxDailyWithdrawal() external returns (uint256) envfree;
    function minBlocksForWithdrawal() external returns (uint256) envfree;
    function dailyWithdrawn() external returns (uint256) envfree;
    function lastWithdrawalDay() external returns (uint256) envfree;
    function circuitBreakerTrippedAt() external returns (uint256) envfree;
    function lastHourlyVolume() external returns (uint256) envfree;

    // View helper functions
    function getRemainingActions(address) external returns (uint256) envfree;

    // Harness wrappers
    function setRateLimitConfig(uint256, uint256) external;
    function setCircuitBreakerConfig(uint256, uint256) external;
    function setWithdrawalLimits(uint256, uint256, uint256) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-SM-001: maxSingleWithdrawal never exceeds maxDailyWithdrawal
 */
invariant singleWithdrawalBounded()
    maxSingleWithdrawal() <= maxDailyWithdrawal();

/**
 * INV-SM-002: accountMaxDailyWithdrawal never exceeds maxDailyWithdrawal
 */
invariant accountDailyBounded()
    accountMaxDailyWithdrawal() <= maxDailyWithdrawal();

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-SM-001: Rate limit window has valid bounds
 * After successful setRateLimitConfig, window is within [5 minutes, 24 hours].
 */
rule rateLimitWindowBounds(uint256 window, uint256 maxActions) {
    env e;

    setRateLimitConfig(e, window, maxActions);

    assert rateLimitWindow() >= 300;      // 5 minutes
    assert rateLimitWindow() <= 86400;    // 24 hours
}

/**
 * RULE-SM-002: Max actions per window has valid bounds
 * After successful setRateLimitConfig, maxActions is within [1, 1000].
 */
rule maxActionsBounds(uint256 window, uint256 maxActions) {
    env e;

    setRateLimitConfig(e, window, maxActions);

    assert maxActionsPerWindow() >= 1;
    assert maxActionsPerWindow() <= 1000;
}

/**
 * RULE-SM-003: Circuit breaker cooldown has valid bounds
 * After successful setCircuitBreakerConfig, cooldown is within [15 minutes, 24 hours].
 */
rule circuitBreakerCooldownBounds(uint256 threshold, uint256 cooldown) {
    env e;

    setCircuitBreakerConfig(e, threshold, cooldown);

    assert circuitBreakerCooldown() >= 900;    // 15 minutes
    assert circuitBreakerCooldown() <= 86400;  // 24 hours
}

/**
 * RULE-SM-004: Volume threshold has minimum
 * After successful setCircuitBreakerConfig, threshold >= 1000e18.
 */
rule volumeThresholdMinimum(uint256 threshold, uint256 cooldown) {
    env e;

    setCircuitBreakerConfig(e, threshold, cooldown);

    assert volumeThreshold() >= 1000000000000000000000; // 1000e18
}

/**
 * RULE-SM-005: Withdrawal limits ordering is preserved
 */
rule withdrawalLimitsOrdering(uint256 singleMax, uint256 dailyMax, uint256 accountDailyMax) {
    env e;

    setWithdrawalLimits(e, singleMax, dailyMax, accountDailyMax);

    assert maxSingleWithdrawal() <= maxDailyWithdrawal();
    assert accountMaxDailyWithdrawal() <= maxDailyWithdrawal();
}

/**
 * RULE-SM-006: Invalid rate limit window reverts (too short)
 */
rule rateLimitWindowTooShortReverts(uint256 maxActions) {
    env e;

    setRateLimitConfig@withrevert(e, 299, maxActions);  // Below 5 minutes
    assert lastReverted;
}

/**
 * RULE-SM-007: Invalid rate limit window reverts (too long)
 */
rule rateLimitWindowTooLongReverts(uint256 maxActions) {
    env e;

    setRateLimitConfig@withrevert(e, 86401, maxActions);  // Above 24 hours
    assert lastReverted;
}

/**
 * RULE-SM-008: Circuit breaker tripped implies trippedAt > 0
 */
rule trippedImpliesTimestamp() {
    require circuitBreakerTripped();
    assert circuitBreakerTrippedAt() > 0;
}

/**
 * RULE-SM-009: Daily withdrawn never exceeds maxDailyWithdrawal
 * This is the core solvency invariant for withdrawal limits.
 */
invariant dailyWithdrawnBounded()
    dailyWithdrawn() <= maxDailyWithdrawal();
