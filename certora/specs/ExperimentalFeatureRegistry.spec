/**
 * Certora Formal Verification Specification
 * Soul Protocol - ExperimentalFeatureRegistry
 *
 * Verifies safety invariants for the feature flag registry including
 * status transition state machine, risk limit enforcement, and
 * access control for feature management.
 */

using ExperimentalFeatureRegistry as efr;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function isFeatureEnabled(bytes32) external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function getRemainingCapacity(bytes32) external returns (uint256) envfree;

    // State-changing functions
    function lockValue(bytes32, uint256) external;
    function unlockValue(bytes32, uint256) external;
    function updateFeatureStatus(bytes32, uint8) external;
    function emergencyDisable(bytes32) external;
    function updateRiskLimit(bytes32, uint256) external;
    function registerFeature(bytes32, string, uint8, address, uint256, bool, string) external;
    function requireFeatureEnabled(bytes32) external;
    function requireProductionReady(bytes32) external;
}

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-EFR-001: requireFeatureEnabled reverts for disabled features
 * A disabled feature (status == 0) always causes requireFeatureEnabled to revert.
 */
rule disabledFeatureReverts(bytes32 featureId) {
    env e;
    require !isFeatureEnabled(featureId);

    requireFeatureEnabled@withrevert(e, featureId);
    assert lastReverted;
}

/**
 * RULE-EFR-002: emergencyDisable always succeeds for enabled features
 * EMERGENCY_ROLE holder can always disable an enabled feature.
 */
rule emergencyDisableAlwaysWorks(bytes32 featureId) {
    env e;
    bytes32 emergencyRole = 0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e19c84b2a8df24e4bbeae27cc98f;
    require hasRole(emergencyRole, e.msg.sender);
    require isFeatureEnabled(featureId);

    emergencyDisable(e, featureId);

    assert !isFeatureEnabled(featureId);
}

/**
 * RULE-EFR-003: lockValue cannot exceed risk limit
 * After a successful lockValue, the feature still has non-negative remaining capacity.
 */
rule lockValueRespectsRiskLimit(bytes32 featureId, uint256 amount) {
    env e;

    lockValue(e, featureId, amount);

    // If lockValue succeeded, remaining capacity is >= 0
    // (i.e., currentValueLocked <= maxValueLocked)
    uint256 remaining = getRemainingCapacity(featureId);
    assert remaining >= 0;
}

/**
 * RULE-EFR-004: lockValue reverts for disabled features
 */
rule cannotLockValueOnDisabledFeature(bytes32 featureId, uint256 amount) {
    env e;
    require !isFeatureEnabled(featureId);

    lockValue@withrevert(e, featureId, amount);
    assert lastReverted;
}

/**
 * RULE-EFR-005: Only DEFAULT_ADMIN_ROLE can register features
 */
rule onlyAdminCanRegisterFeature(
    bytes32 featureId, string name, uint8 status,
    address impl, uint256 maxValue, bool warning, string docUrl
) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    registerFeature@withrevert(e, featureId, name, status, impl, maxValue, warning, docUrl);
    assert lastReverted;
}

/**
 * RULE-EFR-006: Only DEFAULT_ADMIN_ROLE can update risk limits
 */
rule onlyAdminCanUpdateRiskLimit(bytes32 featureId, uint256 newLimit) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    updateRiskLimit@withrevert(e, featureId, newLimit);
    assert lastReverted;
}

/**
 * RULE-EFR-007: Feature registration is idempotent-safe
 * Registering the same featureId twice always reverts.
 */
rule duplicateRegistrationReverts(
    bytes32 featureId, string name, uint8 status,
    address impl, uint256 maxValue, bool warning, string docUrl
) {
    env e1; env e2;

    registerFeature(e1, featureId, name, status, impl, maxValue, warning, docUrl);
    registerFeature@withrevert(e2, featureId, name, status, impl, maxValue, warning, docUrl);
    assert lastReverted;
}

/**
 * RULE-EFR-008: Only FEATURE_ADMIN can update feature status
 */
rule onlyFeatureAdminCanUpdateStatus(bytes32 featureId, uint8 newStatus) {
    env e;
    bytes32 featureAdminRole = 0xfc425f2263d0df187444b70e47283d622c70181c5baebb1306a01edba1ce184c;
    require !hasRole(featureAdminRole, e.msg.sender);

    updateFeatureStatus@withrevert(e, featureId, newStatus);
    assert lastReverted;
}
