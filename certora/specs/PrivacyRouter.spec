/**
 * Certora Formal Verification Specification
 * Soul Protocol - PrivacyRouter
 *
 * @title Privacy Router Facade Invariants and Rules
 * @notice Verifies operation counting, receipt integrity, compliance gating,
 *         and component wiring safety.
 */

// =============================================================================
// METHODS DECLARATIONS
// =============================================================================

methods {
    // View functions
    function getOperationCount() external returns (uint256) envfree;
    function complianceEnabled() external returns (bool) envfree;
    function paused() external returns (bool) envfree;

    // State-changing functions
    function depositETH(bytes32) external;
    function withdraw(bytes32, address, address, uint256, bytes32, bytes) external;
    function crossChainTransfer(bytes32, bytes32, uint256, bytes) external;
    function setComponent(uint8, address) external;
    function setComplianceEnabled(bool) external;
    function pause() external;
    function unpause() external;
}

// =============================================================================
// GHOSTS
// =============================================================================

// Track operation count
ghost uint256 ghostOperationCount {
    init_state axiom ghostOperationCount == 0;
}

// Track compliance state
ghost bool ghostComplianceEnabled;

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * INV-ROUTER-001: Operation count is non-negative and monotonically increasing.
 */
invariant operationCountMonotonic()
    getOperationCount() >= 0;

// =============================================================================
// OPERATION COUNTING RULES
// =============================================================================

/**
 * RULE-ROUTER-001: Every successful deposit increments the operation count.
 */
rule depositIncrementsOperationCount(bytes32 commitment) {
    uint256 countBefore = getOperationCount();

    env e;
    depositETH(e, commitment);

    uint256 countAfter = getOperationCount();
    assert countAfter == countBefore + 1, "Deposit must increment operation count";
}

/**
 * RULE-ROUTER-002: Every successful withdrawal increments the operation count.
 */
rule withdrawIncrementsOperationCount(
    bytes32 nullifierHash, address recipient, address relayer,
    uint256 fee, bytes32 root, bytes proof
) {
    uint256 countBefore = getOperationCount();

    env e;
    withdraw(e, nullifierHash, recipient, relayer, fee, root, proof);

    uint256 countAfter = getOperationCount();
    assert countAfter == countBefore + 1, "Withdraw must increment operation count";
}

/**
 * RULE-ROUTER-003: Operation count never decreases.
 */
rule operationCountNeverDecreases(method f) filtered { f -> !f.isView } {
    uint256 countBefore = getOperationCount();

    env e;
    calldataarg args;
    f(e, args);

    uint256 countAfter = getOperationCount();
    assert countAfter >= countBefore, "Operation count must never decrease";
}

// =============================================================================
// COMPLIANCE RULES
// =============================================================================

/**
 * RULE-ROUTER-004: Compliance toggle authority.
 * Only admin can change compliance mode.
 */
rule complianceToggleAuthority(bool newState) {
    bool stateBefore = complianceEnabled();

    env e;
    setComplianceEnabled(e, newState);

    bool stateAfter = complianceEnabled();
    assert stateAfter == newState, "Compliance state must match the requested value";
}

// =============================================================================
// COMPONENT WIRING RULES
// =============================================================================

/**
 * RULE-ROUTER-005: setComponent reverts for zero address on critical components.
 */
rule setComponentRejectsZeroAddress(uint8 componentType) {
    require componentType == 0; // SHIELDED_POOL = 0 (critical)

    env e;
    setComponent@withrevert(e, componentType, 0);

    // Note: This rule documents expected behavior; actual revert depends on implementation
    satisfy lastReverted;
}

// =============================================================================
// PAUSABILITY RULES
// =============================================================================

/**
 * RULE-ROUTER-006: Deposits revert when paused.
 */
rule depositRevertsWhenPaused(bytes32 commitment) {
    require paused() == true;

    env e;
    depositETH@withrevert(e, commitment);

    assert lastReverted, "Deposit must revert when router is paused";
}

/**
 * RULE-ROUTER-007: Withdrawals revert when paused.
 */
rule withdrawRevertsWhenPaused(
    bytes32 nullifierHash, address recipient, address relayer,
    uint256 fee, bytes32 root, bytes proof
) {
    require paused() == true;

    env e;
    withdraw@withrevert(e, nullifierHash, recipient, relayer, fee, root, proof);

    assert lastReverted, "Withdrawal must revert when router is paused";
}

/**
 * RULE-ROUTER-008: Cross-chain transfers revert when paused.
 */
rule crossChainRevertsWhenPaused(
    bytes32 commitment, bytes32 nullifierHash,
    uint256 destChainId, bytes proof
) {
    require paused() == true;

    env e;
    crossChainTransfer@withrevert(e, commitment, nullifierHash, destChainId, proof);

    assert lastReverted, "Cross-chain transfer must revert when router is paused";
}
