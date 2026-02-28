/**
 * Certora Formal Verification Specification
 * ZASEON - RelayRateLimiter
 *
 * Verifies safety invariants for the bridge rate limiting system
 * that prevents excessive fund movement velocity.
 */

using RelayRateLimiter as rl;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function paused() external returns (bool) envfree;
    function tvlCap() external returns (uint256) envfree;
    function whitelisted(address) external returns (bool) envfree;
    function blacklisted(address) external returns (bool) envfree;
    function isCircuitBreakerActive() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function MAX_HOURLY_LIMIT() external returns (uint256) envfree;
    function MAX_DAILY_LIMIT() external returns (uint256) envfree;
    function MAX_TVL_CAP() external returns (uint256) envfree;

    // State-changing functions
    function checkTransfer(address, uint256, uint256) external;
    function recordTransfer(address, uint256, uint256) external;
    function triggerCircuitBreaker(string) external;
    function resetCircuitBreaker() external;
    function setWhitelist(address, bool) external;
    function setBlacklist(address, bool) external;
    function setTVLCap(uint256) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-RL-001: TVL cap bounded
 * TVL cap must not exceed the maximum allowed by the contract
 */
invariant tvlCapBounded()
    tvlCap() <= MAX_TVL_CAP();

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-RL-001: Blacklisted addresses cannot transfer
 * Any transfer check for a blacklisted address must revert
 */
rule blacklistedCannotTransfer(address user, uint256 amount, uint256 chainId) {
    env e;
    require blacklisted(user);

    checkTransfer@withrevert(e, user, amount, chainId);

    assert lastReverted,
        "Blacklisted addresses must be blocked";
}

/**
 * RULE-RL-002: Circuit breaker blocks all transfers
 * When circuit breaker is active, all transfers should fail
 */
rule circuitBreakerBlocksTransfers(address user, uint256 amount, uint256 chainId) {
    env e;
    require isCircuitBreakerActive();
    require !whitelisted(user);

    checkTransfer@withrevert(e, user, amount, chainId);

    assert lastReverted,
        "Active circuit breaker must block transfers";
}

/**
 * RULE-RL-003: Only admin can reset circuit breaker
 * resetCircuitBreaker requires DEFAULT_ADMIN_ROLE
 */
rule onlyAdminCanResetCircuitBreaker() {
    env e;
    require !hasRole(rl.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    resetCircuitBreaker@withrevert(e);

    assert lastReverted,
        "Only admin can reset circuit breaker";
}

/**
 * RULE-RL-004: Only guardian can pause
 * pause() requires GUARDIAN_ROLE
 */
rule onlyGuardianCanPause() {
    env e;
    require !hasRole(rl.GUARDIAN_ROLE(), e.msg.sender);

    pause@withrevert(e);

    assert lastReverted,
        "Only guardian can pause";
}

/**
 * RULE-RL-005: Paused state blocks transfers
 * When paused, transfer checks should fail
 */
rule pausedBlocksTransfers(address user, uint256 amount, uint256 chainId) {
    env e;
    require paused();

    checkTransfer@withrevert(e, user, amount, chainId);

    assert lastReverted,
        "Paused state must block all transfers";
}

/**
 * RULE-RL-006: Blacklist is permanent until admin changes it
 * An arbitrary function call should not change blacklist status
 */
rule blacklistPermanence(address user, method f) filtered { f -> !f.isView } {
    env e;

    bool blacklistBefore = blacklisted(user);

    calldataarg args;
    f(e, args);

    bool blacklistAfter = blacklisted(user);

    // Blacklist can only change via setBlacklist
    assert blacklistBefore != blacklistAfter =>
        f.selector == sig:setBlacklist(address,bool).selector,
        "Blacklist can only change through setBlacklist";
}

/**
 * RULE-RL-007: Whitelist is permanent until admin changes it
 */
rule whitelistPermanence(address user, method f) filtered { f -> !f.isView } {
    env e;

    bool whitelistBefore = whitelisted(user);

    calldataarg args;
    f(e, args);

    bool whitelistAfter = whitelisted(user);

    assert whitelistBefore != whitelistAfter =>
        f.selector == sig:setWhitelist(address,bool).selector,
        "Whitelist can only change through setWhitelist";
}

/**
 * RULE-RL-008: Circuit breaker monotonic activation
 * triggerCircuitBreaker transitions from inactive to active
 */
rule triggerCircuitBreakerActivates() {
    env e;
    require hasRole(rl.GUARDIAN_ROLE(), e.msg.sender);
    require !isCircuitBreakerActive();

    triggerCircuitBreaker(e, "threat detected");

    assert isCircuitBreakerActive(),
        "Trigger must activate the circuit breaker";
}
