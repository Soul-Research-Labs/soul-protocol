/**
 * Certora Formal Verification Specification
 * ZASEON - ProtocolEmergencyCoordinator
 *
 * Verifies safety invariants for the multi-role emergency incident
 * coordination system with severity escalation, emergency plan execution,
 * and validated recovery procedures.
 */

using ProtocolEmergencyCoordinator as pec;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function currentSeverity() external returns (uint8) envfree;
    function activeIncidentId() external returns (uint256) envfree;
    function incidentCount() external returns (uint256) envfree;
    function lastEscalationAt() external returns (uint48) envfree;
    function planExecuted(uint256, uint8) external returns (bool) envfree;
    function hasActiveIncident() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function RESPONDER_ROLE() external returns (bytes32) envfree;
    function RECOVERY_ROLE() external returns (bytes32) envfree;
    function ESCALATION_COOLDOWN() external returns (uint48) envfree;
    function RECOVERY_COOLDOWN() external returns (uint48) envfree;
    function MAX_INCIDENTS() external returns (uint256) envfree;

    // State-changing functions
    function openIncident(uint8, string, bytes32) external;
    function escalateIncident(uint256, uint8) external;
    function executeEmergencyPlan(uint256) external;
    function executeRecovery(uint256) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-PEC-001: Severity bounded
 * Severity enum: GREEN=0, YELLOW=1, ORANGE=2, RED=3, BLACK=4
 * Current severity must be within valid range.
 */
invariant severityBounded()
    currentSeverity() <= 4;

/**
 * INV-PEC-002: Incident count monotonically increases
 * incidentCount can never decrease.
 */
invariant incidentCountMonotonic()
    incidentCount() >= 0;

/**
 * INV-PEC-003: Active incident ID bounded by count
 * The active incident ID must be zero (no incident) or a valid incident index.
 */
invariant activeIncidentBounded()
    activeIncidentId() <= incidentCount();

/**
 * INV-PEC-004: No active incident implies GREEN severity
 * When there is no active incident, the protocol must be at GREEN.
 */
invariant noActiveIncidentMeansGreen()
    activeIncidentId() == 0 => currentSeverity() == 0;

/**
 * INV-PEC-005: Active incident implies non-GREEN severity
 * When there is an active incident, severity must be at least YELLOW.
 */
invariant activeIncidentMeansNonGreen()
    activeIncidentId() != 0 => currentSeverity() > 0;

// ============================================================================
// RULES — ROLE SEPARATION
// ============================================================================

/**
 * RULE-PEC-001: Only RESPONDER can open incidents
 * Opening an incident without RESPONDER_ROLE must revert.
 */
rule onlyResponderCanOpenIncident(env e) {
    require !hasRole(pec.RESPONDER_ROLE(), e.msg.sender);

    openIncident@withrevert(e, 1, "", 0);
    assert lastReverted, "openIncident must revert without RESPONDER_ROLE";
}

/**
 * RULE-PEC-002: Only RESPONDER can escalate incidents
 * Escalating an incident without RESPONDER_ROLE must revert.
 */
rule onlyResponderCanEscalate(env e) {
    require !hasRole(pec.RESPONDER_ROLE(), e.msg.sender);

    uint256 incId = activeIncidentId();
    escalateIncident@withrevert(e, incId, 3);
    assert lastReverted, "escalateIncident must revert without RESPONDER_ROLE";
}

/**
 * RULE-PEC-003: Only GUARDIAN can execute emergency plan
 * Executing an emergency plan without GUARDIAN_ROLE must revert.
 */
rule onlyGuardianCanExecutePlan(env e) {
    require !hasRole(pec.GUARDIAN_ROLE(), e.msg.sender);

    uint256 incId = activeIncidentId();
    executeEmergencyPlan@withrevert(e, incId);
    assert lastReverted, "executeEmergencyPlan must revert without GUARDIAN_ROLE";
}

/**
 * RULE-PEC-004: Only RECOVERY can execute recovery
 * Executing recovery without RECOVERY_ROLE must revert.
 */
rule onlyRecoveryCanRecover(env e) {
    require !hasRole(pec.RECOVERY_ROLE(), e.msg.sender);

    uint256 incId = activeIncidentId();
    executeRecovery@withrevert(e, incId);
    assert lastReverted, "executeRecovery must revert without RECOVERY_ROLE";
}

// ============================================================================
// RULES — INCIDENT LIFECYCLE
// ============================================================================

/**
 * RULE-PEC-005: Cannot open incident when one is already active
 * openIncident must revert if activeIncidentId != 0.
 */
rule cannotOpenWhileIncidentActive(env e) {
    require activeIncidentId() != 0;
    require hasRole(pec.RESPONDER_ROLE(), e.msg.sender);

    openIncident@withrevert(e, 2, "test", 0);
    assert lastReverted, "openIncident must revert when incident is already active";
}

/**
 * RULE-PEC-006: Cannot open GREEN severity incident
 * Opening an incident with GREEN (0) severity must always revert.
 */
rule cannotOpenGreenIncident(env e) {
    require hasRole(pec.RESPONDER_ROLE(), e.msg.sender);
    require activeIncidentId() == 0;

    openIncident@withrevert(e, 0, "should fail", 0);
    assert lastReverted, "openIncident must revert for GREEN severity";
}

/**
 * RULE-PEC-007: Opening incident sets active state correctly
 * After successfully opening an incident, activeIncidentId and
 * currentSeverity reflect the new incident.
 */
rule openIncidentSetsState(env e) {
    uint256 countBefore = incidentCount();
    require activeIncidentId() == 0;
    require hasRole(pec.RESPONDER_ROLE(), e.msg.sender);

    uint8 severity = 2; // ORANGE
    openIncident(e, severity, "test", 0);

    assert incidentCount() == countBefore + 1,
        "incidentCount must increment by 1";
    assert activeIncidentId() == countBefore + 1,
        "activeIncidentId must be the new incident ID";
    assert currentSeverity() == severity,
        "currentSeverity must match the opened severity";
}

/**
 * RULE-PEC-008: Escalation is strictly monotonic
 * escalateIncident must increase severity — caller cannot set lower or equal severity.
 */
rule escalationIsStrictlyMonotonic(env e) {
    require hasRole(pec.RESPONDER_ROLE(), e.msg.sender);
    uint256 incId = activeIncidentId();
    require incId != 0;

    uint8 severityBefore = currentSeverity();

    // Attempt to escalate to same or lower severity
    uint8 targetSeverity;
    require targetSeverity <= severityBefore;

    escalateIncident@withrevert(e, incId, targetSeverity);
    assert lastReverted, "escalateIncident must revert for non-increasing severity";
}

/**
 * RULE-PEC-009: Escalation cooldown enforced
 * escalateIncident must revert if the escalation cooldown has not elapsed.
 */
rule escalationCooldownEnforced(env e) {
    require hasRole(pec.RESPONDER_ROLE(), e.msg.sender);
    uint256 incId = activeIncidentId();
    require incId != 0;

    uint48 lastEsc = lastEscalationAt();
    uint48 cooldown = ESCALATION_COOLDOWN();
    require to_mathint(e.block.timestamp) < to_mathint(lastEsc) + to_mathint(cooldown);

    uint8 newSev = currentSeverity() + 1;
    require newSev <= 4;

    escalateIncident@withrevert(e, incId, newSev);
    assert lastReverted, "escalateIncident must revert during cooldown period";
}

/**
 * RULE-PEC-010: Successful escalation updates severity and timestamp
 * After a successful escalation, currentSeverity is the new value and
 * lastEscalationAt is updated to the current timestamp.
 */
rule escalationUpdatesState(env e) {
    require hasRole(pec.RESPONDER_ROLE(), e.msg.sender);
    uint256 incId = activeIncidentId();
    require incId != 0;

    uint8 severityBefore = currentSeverity();
    uint8 newSev;
    require newSev > severityBefore;
    require newSev <= 4;

    escalateIncident(e, incId, newSev);

    assert currentSeverity() == newSev,
        "currentSeverity must match the escalated severity";
}

// ============================================================================
// RULES — EMERGENCY PLAN EXECUTION
// ============================================================================

/**
 * RULE-PEC-011: Emergency plan idempotency
 * executeEmergencyPlan must revert if the plan for the current severity
 * of the given incident was already executed.
 */
rule emergencyPlanIdempotent(env e) {
    require hasRole(pec.GUARDIAN_ROLE(), e.msg.sender);
    uint256 incId = activeIncidentId();
    require incId != 0;

    uint8 sev = currentSeverity();
    require planExecuted(incId, sev) == true;

    executeEmergencyPlan@withrevert(e, incId);
    assert lastReverted, "executeEmergencyPlan must revert for already-executed plan";
}

// ============================================================================
// RULES — RECOVERY
// ============================================================================

/**
 * RULE-PEC-012: Recovery resets to GREEN
 * After successful executeRecovery, currentSeverity is GREEN (0) and
 * activeIncidentId is 0.
 */
rule recoveryResetsToGreen(env e) {
    require hasRole(pec.RECOVERY_ROLE(), e.msg.sender);
    uint256 incId = activeIncidentId();
    require incId != 0;

    executeRecovery(e, incId);

    assert currentSeverity() == 0,
        "currentSeverity must be GREEN after recovery";
    assert activeIncidentId() == 0,
        "activeIncidentId must be 0 after recovery";
}

/**
 * RULE-PEC-013: Recovery cooldown enforced
 * executeRecovery must revert if the recovery cooldown has not elapsed
 * since the last escalation.
 */
rule recoveryCooldownEnforced(env e) {
    require hasRole(pec.RECOVERY_ROLE(), e.msg.sender);
    uint256 incId = activeIncidentId();
    require incId != 0;

    uint48 lastEsc = lastEscalationAt();
    uint48 cooldown = RECOVERY_COOLDOWN();
    require to_mathint(e.block.timestamp) < to_mathint(lastEsc) + to_mathint(cooldown);

    executeRecovery@withrevert(e, incId);
    assert lastReverted, "executeRecovery must revert during cooldown period";
}

// ============================================================================
// RULES — UNIVERSAL STATE INTEGRITY
// ============================================================================

/**
 * RULE-PEC-014: incidentCount only increases via openIncident
 * Any function other than openIncident must not change incidentCount.
 */
rule incidentCountOnlyChangedByOpen(method f, env e, calldataarg args)
    filtered { f -> !f.isView && f.selector != sig:openIncident(uint8, string, bytes32).selector }
{
    uint256 countBefore = incidentCount();
    f(e, args);
    assert incidentCount() == countBefore,
        "incidentCount must not change from non-openIncident functions";
}

/**
 * RULE-PEC-015: activeIncidentId only changes through openIncident or executeRecovery
 * Any function other than openIncident and executeRecovery must not change activeIncidentId.
 */
rule activeIncidentOnlyChangedByOpenOrRecovery(method f, env e, calldataarg args)
    filtered {
        f -> !f.isView
             && f.selector != sig:openIncident(uint8, string, bytes32).selector
             && f.selector != sig:executeRecovery(uint256).selector
    }
{
    uint256 idBefore = activeIncidentId();
    f(e, args);
    assert activeIncidentId() == idBefore,
        "activeIncidentId must not change from non-open/non-recovery functions";
}

/**
 * RULE-PEC-016: Severity only changes through open, escalate, or recovery
 * Any function other than openIncident, escalateIncident, and executeRecovery
 * must leave currentSeverity unchanged.
 */
rule severityOnlyChangedByTargetedFunctions(method f, env e, calldataarg args)
    filtered {
        f -> !f.isView
             && f.selector != sig:openIncident(uint8, string, bytes32).selector
             && f.selector != sig:escalateIncident(uint256, uint8).selector
             && f.selector != sig:executeRecovery(uint256).selector
    }
{
    uint8 severityBefore = currentSeverity();
    f(e, args);
    assert currentSeverity() == severityBefore,
        "currentSeverity must not change from non-targeted functions";
}
