/**
 * Certora Formal Verification Specification
 * ZASEON - EnhancedKillSwitch
 *
 * Verifies safety invariants for the multi-level emergency stop
 * system with guardian consensus and recovery procedures.
 */

using EnhancedKillSwitch as ks;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions  
    function currentLevel() external returns (uint8) envfree;
    function previousLevel() external returns (uint8) envfree;
    function pendingLevel() external returns (uint8) envfree;
    function requiredConfirmations() external returns (uint256) envfree;
    function confirmationCount(uint8) external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function RECOVERY_ROLE() external returns (bytes32) envfree;

    // State-changing functions
    function escalateEmergency(uint8, string) external;
    function confirmEscalation(uint8) external;
    function executeEscalation() external;
    function cancelEscalation() external;
    function initiateRecovery(uint8, string) external;
    function confirmRecovery() external;
    function executeRecovery() external;
    function cancelRecovery() external;
    function addGuardian(address) external;
    function removeGuardian(address) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-KS-001: Emergency level bounded
 * EmergencyLevel enum: NONE=0, WARNING=1, DEGRADED=2, HALTED=3, LOCKED=4, PERMANENT=5
 * Current level must be within valid range
 */
invariant emergencyLevelBounded()
    currentLevel() <= 5;

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-KS-001: PERMANENT level is irreversible
 * Once emergency level reaches PERMANENT (5), no operation can lower it
 */
rule permanentIsIrreversible(method f) filtered { f -> !f.isView } {
    env e;
    require currentLevel() == 5; // PERMANENT

    calldataarg args;
    f@withrevert(e, args);

    // If the call succeeded, level must still be PERMANENT
    assert !lastReverted => currentLevel() == 5,
        "PERMANENT level must be irreversible";
}

/**
 * RULE-KS-002: Escalation only goes up
 * Emergency escalation cannot decrease the emergency level
 */
rule escalationOnlyGoesUp(uint8 targetLevel, string reason) {
    env e;
    uint8 levelBefore = currentLevel();

    escalateEmergency@withrevert(e, targetLevel, reason);

    // If escalation succeeded, the target must be higher
    assert !lastReverted => targetLevel > levelBefore,
        "Escalation must increase emergency level";
}

/**
 * RULE-KS-003: Only guardians can escalate
 * escalateEmergency requires GUARDIAN_ROLE
 */
rule onlyGuardianCanEscalate(uint8 level, string reason) {
    env e;
    require !hasRole(ks.GUARDIAN_ROLE(), e.msg.sender);

    escalateEmergency@withrevert(e, level, reason);

    assert lastReverted,
        "Only guardians can escalate emergency";
}

/**
 * RULE-KS-004: Only recovery role can execute recovery
 * executeRecovery requires RECOVERY_ROLE
 */
rule onlyRecoveryRoleCanExecuteRecovery() {
    env e;
    require !hasRole(ks.RECOVERY_ROLE(), e.msg.sender);

    executeRecovery@withrevert(e);

    assert lastReverted,
        "Only RECOVERY_ROLE can execute recovery";
}

/**
 * RULE-KS-005: Only admin can cancel escalation
 * cancelEscalation requires DEFAULT_ADMIN_ROLE
 */
rule onlyAdminCanCancelEscalation() {
    env e;
    require !hasRole(ks.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    cancelEscalation@withrevert(e);

    assert lastReverted,
        "Only admin can cancel escalation";
}

/**
 * RULE-KS-006: Level can only change via escalation or recovery
 * Any function that changes current level must be an escalation/recovery entry point
 */
rule levelOnlyChangesThroughEscalationOrRecovery(method f)
    filtered { f -> !f.isView }
{
    env e;
    uint8 levelBefore = currentLevel();

    calldataarg args;
    f(e, args);

    uint8 levelAfter = currentLevel();

    assert levelBefore != levelAfter =>
        f.selector == sig:executeEscalation().selector ||
        f.selector == sig:executeRecovery().selector,
        "Level can only change via executeEscalation or executeRecovery";
}

/**
 * RULE-KS-007: Required confirmations must be positive
 * The contract must always require at least 1 confirmation
 */
rule requiredConfirmationsPositive() {
    assert requiredConfirmations() > 0,
        "Must require at least one confirmation";
}
