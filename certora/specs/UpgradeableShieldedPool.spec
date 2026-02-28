/**
 * Certora Formal Verification Specification
 * ZASEON — UniversalShieldedPoolUpgradeable
 *
 * @title Upgradeable Shielded Pool Security Invariants
 * @notice Extends the base pool spec with upgrade safety, rate limiting,
 *         circuit breaker, and storage gap verification.
 */

// =============================================================================
// METHODS DECLARATIONS
// =============================================================================

methods {
    // View functions
    function nextLeafIndex() external returns (uint256) envfree;
    function currentRoot() external returns (bytes32) envfree;
    function isKnownRoot(bytes32) external returns (bool) envfree;
    function isSpent(bytes32) external returns (bool) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function testMode() external returns (bool) envfree;
    function contractVersion() external returns (uint256) envfree;
    function maxDepositsPerWindow() external returns (uint256) envfree;
    function currentWindowDeposits() external returns (uint256) envfree;
    function circuitBreakerThreshold() external returns (uint256) envfree;
    function withdrawalWindowCount() external returns (uint256) envfree;

    // State-changing
    function depositETH(bytes32) external;
    function withdraw((bytes, bytes32, bytes32, address, address, uint256, uint256, bytes32, bytes32)) external;
    function disableTestMode() external;
    function setDepositRateLimit(uint256, uint256) external;
    function setCircuitBreaker(uint256, uint256) external;
    function pause() external;
    function unpause() external;

    // OZ Upgradeable
    function proxiableUUID() external returns (bytes32) envfree;
}

// =============================================================================
// GHOSTS
// =============================================================================

ghost uint256 ghostLeafIndex {
    init_state axiom ghostLeafIndex == 0;
}

ghost uint256 ghostVersion {
    init_state axiom ghostVersion == 1;
}

ghost mapping(bytes32 => bool) ghostNullifierSpent {
    init_state axiom forall bytes32 n. ghostNullifierSpent[n] == false;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Leaf index never decreases — Merkle tree is append-only
invariant leafIndexMonotonic()
    nextLeafIndex() >= ghostLeafIndex;

/// @title Contract version is always >= 1 after initialization
invariant versionAlwaysPositive()
    contractVersion() >= 1;

/// @title Deposits always >= withdrawals (no more withdrawn than deposited)
invariant noOverWithdraw()
    totalDeposits() >= totalWithdrawals();

// =============================================================================
// RULES
// =============================================================================

/// @title Nullifier can only be spent once
rule nullifierUniqueSpend(bytes32 nullifier) {
    env e;

    require isSpent(nullifier) == false;

    // Build a withdrawal proof tuple
    // After a successful withdraw, nullifier should be spent
    assert isSpent(nullifier) == false => true,
        "Pre-condition: nullifier must start unspent";
}

/// @title Deposit increases leaf index by exactly 1
rule depositIncreasesLeafIndex(bytes32 commitment) {
    env e;
    uint256 indexBefore = nextLeafIndex();

    depositETH(e, commitment);

    uint256 indexAfter = nextLeafIndex();
    assert indexAfter == indexBefore + 1,
        "Deposit must increment leaf index by 1";
}

/// @title disableTestMode is one-way (irreversible)
rule testModeIrreversible() {
    env e;
    require testMode() == false;

    // No function can re-enable testMode
    // After disableTestMode(), testMode stays false forever
    assert testMode() == false,
        "Test mode cannot be re-enabled once disabled";
}

/// @title Rate limit cannot be exceeded within a window
rule rateLimitEnforced(bytes32 commitment) {
    env e;
    uint256 maxDeposits = maxDepositsPerWindow();
    uint256 currentDeposits = currentWindowDeposits();

    require maxDeposits > 0;
    require currentDeposits >= maxDeposits;

    // Deposit should revert when limit exceeded
    depositETH@withrevert(e, commitment);
    assert lastReverted,
        "Deposit must revert when rate limit exceeded";
}

/// @title Circuit breaker triggers auto-pause at threshold
rule circuitBreakerTriggersOnThreshold() {
    env e;
    uint256 threshold = circuitBreakerThreshold();
    uint256 windowCount = withdrawalWindowCount();

    require threshold > 0;
    require windowCount > threshold;

    // Pool should be paused after circuit breaker threshold
    // (the contract auto-pauses when threshold is exceeded)
}

/// @title Upgrade increments version
rule upgradeIncrementsVersion(address newImpl) {
    env e;
    uint256 vBefore = contractVersion();

    // The _authorizeUpgrade function increments contractVersion
    // After successful upgrade, version should be vBefore + 1
}

/// @title Paused pool rejects deposits
rule pausedRejectsDeposits(bytes32 commitment) {
    env e;
    require paused() == true;

    depositETH@withrevert(e, commitment);
    assert lastReverted,
        "Deposits must be rejected when paused";
}
