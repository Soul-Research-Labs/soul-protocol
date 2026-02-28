/**
 * Certora Formal Verification Specification
 * ZASEON - RelayCircuitBreaker
 *
 * Verifies safety invariants for the anomaly-driven circuit breaker
 * that protects bridge operations from suspicious activity.
 */

using RelayCircuitBreaker as cb;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // State getters
    function currentState() external returns (uint8) envfree;
    function anomalyScore() external returns (uint256) envfree;
    function activeAnomalyCount() external returns (uint256) envfree;
    function currentTVL() external returns (uint256) envfree;
    function baselineTVL() external returns (uint256) envfree;
    function lastStateChange() external returns (uint256) envfree;
    function warningCooldown() external returns (uint256) envfree;
    function degradedCooldown() external returns (uint256) envfree;
    function isOperational() external returns (bool) envfree;
    function isDegraded() external returns (bool) envfree;
    function getActiveAnomalyCount() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function MONITOR_ROLE() external returns (bytes32) envfree;

    // State-changing functions
    function emergencyHalt() external;
    function recordTransaction(uint256, uint256, address) external;
    function updateTVL(uint256) external;
    function reportAnomaly(uint8, uint256, string) external;
    function resolveAnomaly(uint256) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-CB-001: Anomaly score bounded
 * Score must never exceed MAX_SCORE (100)
 */
invariant anomalyScoreBounded()
    anomalyScore() <= 100;

/**
 * INV-CB-002: State is valid enum value
 * SystemState enum has values 0-3 (NORMAL, WARNING, DEGRADED, HALTED)
 */
invariant stateInValidRange()
    currentState() <= 3;

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-CB-001: Emergency halt transitions to HALTED
 * After emergencyHalt(), system must be in HALTED state (3)
 */
rule emergencyHaltSetsHaltedState() {
    env e;
    require hasRole(cb.GUARDIAN_ROLE(), e.msg.sender);

    emergencyHalt(e);

    uint8 stateAfter = currentState();
    assert stateAfter == 3, "Emergency halt must set state to HALTED";
}

/**
 * RULE-CB-002: State can only escalate via normal operations
 * Non-recovery operations cannot decrease system severity
 * (except through the recovery proposal mechanism)
 */
rule stateOnlyEscalates(uint256 amount, uint256 chainId, address sender) {
    env e;

    uint8 stateBefore = currentState();

    recordTransaction(e, amount, chainId, sender);

    uint8 stateAfter = currentState();
    assert stateAfter >= stateBefore,
        "Transaction recording can only escalate state";
}

/**
 * RULE-CB-003: Halted state blocks transactions
 * When system is HALTED, operations should be blocked
 */
rule haltedBlocksOperations() {
    env e;
    require currentState() == 3; // HALTED

    recordTransaction@withrevert(e, 1, 1, e.msg.sender);

    assert lastReverted,
        "HALTED state must block all transactions";
}

/**
 * RULE-CB-004: Only guardians can halt
 * emergencyHalt requires GUARDIAN_ROLE
 */
rule onlyGuardianCanHalt() {
    env e;
    require !hasRole(cb.GUARDIAN_ROLE(), e.msg.sender);

    emergencyHalt@withrevert(e);

    assert lastReverted,
        "Only guardians can trigger emergency halt";
}

/**
 * RULE-CB-005: Only monitors can report anomalies
 * reportAnomaly requires MONITOR_ROLE
 */
rule onlyMonitorCanReport(uint8 anomalyType, uint256 severity) {
    env e;
    require !hasRole(cb.MONITOR_ROLE(), e.msg.sender);

    reportAnomaly@withrevert(e, anomalyType, severity, "test");

    assert lastReverted,
        "Only monitors can report anomalies";
}

/**
 * RULE-CB-006: Anomaly score monotonically increases on reports
 * Reporting an anomaly should increase the score (or keep it at max)
 */
rule reportAnomalyIncreasesScore(uint8 anomalyType, uint256 severity) {
    env e;
    require hasRole(cb.MONITOR_ROLE(), e.msg.sender);

    uint256 scoreBefore = anomalyScore();

    reportAnomaly(e, anomalyType, severity, "anomaly");

    uint256 scoreAfter = anomalyScore();
    assert scoreAfter >= scoreBefore,
        "Anomaly report must not decrease score";
}
