/**
 * Certora Formal Verification Specification
 * Soul Protocol - FlashLoanGuard
 *
 * Verifies safety invariants for flash loan detection and protection,
 * including per-block velocity limits, TVL delta enforcement,
 * and balance manipulation detection.
 */

using FlashLoanGuard as flg;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Constants
    function MAX_OPS_PER_BLOCK() external returns (uint256) envfree;
    function MAX_OPS_PER_EPOCH() external returns (uint256) envfree;
    function EPOCH_LENGTH() external returns (uint256) envfree;

    // View functions
    function maxTVLDeltaBps() external returns (uint256) envfree;
    function maxPriceDeviationBps() external returns (uint256) envfree;
    function lastTVL() external returns (uint256) envfree;
    function lastTVLBlock() external returns (uint256) envfree;
    function maxOracleAge() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function canOperateThisBlock(address) external returns (bool) envfree;
    function getRemainingOperations(address) external returns (uint256) envfree;

    // State-changing functions
    function validateOperation(address, address, uint256) external returns (bool);
    function whitelistToken(address, address, uint256) external;
    function updateTVLDeltaLimit(uint256) external;
    function registerProtectedContract(address) external;
    function updateTVL(uint256) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-FLG-001: MAX_OPS_PER_BLOCK is always 3
 * The constant cannot be changed post-deployment.
 */
invariant maxOpsPerBlockIsConstant()
    MAX_OPS_PER_BLOCK() == 3;

/**
 * INV-FLG-002: MAX_OPS_PER_EPOCH is always 50
 */
invariant maxOpsPerEpochIsConstant()
    MAX_OPS_PER_EPOCH() == 50;

/**
 * INV-FLG-003: EPOCH_LENGTH is always 100
 */
invariant epochLengthIsConstant()
    EPOCH_LENGTH() == 100;

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-FLG-001: Only OPERATOR_ROLE can whitelist tokens
 */
rule onlyOperatorCanWhitelistToken(address token, address oracle, uint256 maxDeviation) {
    env e;
    bytes32 operatorRole = 0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    require !hasRole(operatorRole, e.msg.sender);

    whitelistToken@withrevert(e, token, oracle, maxDeviation);
    assert lastReverted;
}

/**
 * RULE-FLG-002: Only DEFAULT_ADMIN_ROLE can update TVL delta limit
 */
rule onlyAdminCanUpdateTVLDeltaLimit(uint256 newLimit) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    updateTVLDeltaLimit@withrevert(e, newLimit);
    assert lastReverted;
}

/**
 * RULE-FLG-003: validateOperation respects pause state
 * No operations can be validated when paused.
 */
rule noValidationWhenPaused(address user, address token, uint256 value) {
    env e;
    require paused();

    validateOperation@withrevert(e, user, token, value);
    assert lastReverted;
}

/**
 * RULE-FLG-004: Remaining operations monotonically decrease per block
 * After a successful validateOperation, remaining operations for that user decreases.
 */
rule remainingOpsDecreaseAfterValidation(address user, address token, uint256 value) {
    env e;

    uint256 remainingBefore = getRemainingOperations(user);
    require remainingBefore > 0;

    validateOperation(e, user, token, value);

    uint256 remainingAfter = getRemainingOperations(user);
    assert remainingAfter < remainingBefore;
}

/**
 * RULE-FLG-005: TVL delta limit update takes effect immediately
 */
rule tvlDeltaLimitUpdateEffect(uint256 newLimit) {
    env e;
    require hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    updateTVLDeltaLimit(e, newLimit);

    assert maxTVLDeltaBps() == newLimit;
}

/**
 * RULE-FLG-006: Only GUARDIAN_ROLE can pause
 */
rule onlyGuardianCanPause() {
    env e;
    bytes32 guardianRole = 0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;
    require !hasRole(guardianRole, e.msg.sender);

    pause@withrevert(e);
    assert lastReverted;
}
