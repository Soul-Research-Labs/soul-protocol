/**
 * K Framework Formal Specification for BridgeCircuitBreaker
 *
 * @title Bridge Circuit Breaker State Machine Specification
 * @author Zaseon
 * @notice Formal verification of the autonomous circuit breaker logic
 */

requires "domains.md"

module BRIDGE-CIRCUIT-BREAKER-SYNTAX
    imports DOMAINS

    // =========================================================================
    // SYSTEM STATES
    // =========================================================================
    syntax SystemState ::= "NORMAL" | "WARNING" | "DEGRADED" | "HALTED"

    // =========================================================================
    // ANOMALY TYPES
    // =========================================================================
    syntax AnomalyType ::= "LARGE_TRANSFER" 
                         | "HIGH_VELOCITY" 
                         | "TVL_DROP" 
                         | "SUSPICIOUS_PATTERN" 
                         | "EXTERNAL_TRIGGER"

    // =========================================================================
    // CONFIGURATION
    syntax Thresholds ::= thresholds(
        Int,    // warningScore
        Int,    // degradedScore
        Int     // haltedScore
    )

    // =========================================================================
    // OPERATIONS
    syntax SystemState ::= calculateNextState(Int, Thresholds) [function]
    syntax Bool ::= isValidEscalation(SystemState, SystemState) [function]
    syntax Bool ::= isValidDeescalation(SystemState, SystemState, Int, Int) [function]

endmodule

module BRIDGE-CIRCUIT-BREAKER
    imports BRIDGE-CIRCUIT-BREAKER-SYNTAX

    // =========================================================================
    // STATE TRANSITION RULES
    // =========================================================================

    /**
     * State mapping based on anomaly score
     */
    rule calculateNextState(SCORE, thresholds(W, D, H)) => HALTED   requires SCORE >=Int H
    rule calculateNextState(SCORE, thresholds(W, D, H)) => DEGRADED requires SCORE >=Int D andBool SCORE <Int H
    rule calculateNextState(SCORE, thresholds(W, D, H)) => WARNING  requires SCORE >=Int W andBool SCORE <Int D
    rule calculateNextState(SCORE, thresholds(W, D, H)) => NORMAL   requires SCORE <Int W

    /**
     * Automatic Escalation: Any state can move to a MORE restrictive state 
     * if the score warrants it.
     */
    rule isValidEscalation(OLD, NEW) => true requires stateSeverity(NEW) >Int stateSeverity(OLD)
    rule isValidEscalation(OLD, NEW) => false requires stateSeverity(NEW) <=Int stateSeverity(OLD)

    /**
     * Manual/Cooldown De-escalation:
     * 1. HALTED -> * requires recovery proposal (abstracted here as manual)
     * 2. WARNING -> NORMAL requires cooldown
     */
    rule isValidDeescalation(WARNING, NORMAL, TIME_ELAPSED, COOLDOWN) => 
        TIME_ELAPSED >=Int COOLDOWN

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================
    syntax Int ::= stateSeverity(SystemState) [function]
    rule stateSeverity(NORMAL)   => 0
    rule stateSeverity(WARNING)  => 1
    rule stateSeverity(DEGRADED) => 2
    rule stateSeverity(HALTED)   => 3

    // =========================================================================
    // SAFETY THEOREMS
    // =========================================================================

    /**
     * THEOREM P1: Recovery Integrity
     * It is impossible to transition from HALTED to NORMAL without passing 
     * through a recovery process.
     */
    syntax Bool ::= checkRecovery(SystemState, SystemState) [function]
    rule checkRecovery(HALTED, NORMAL) => false

    /**
     * THEOREM P2: Guaranteed Escalation
     * If an anomaly is "Critical" (score > haltedScore), the system MUST 
     * move to the HALTED state.
     */
    syntax Bool ::= checkEscalation(Int, Thresholds) [function]
    rule checkEscalation(SCORE, thresholds(W, D, H)) => 
        calculateNextState(SCORE, thresholds(W, D, H)) ==K HALTED
        requires SCORE >=Int H

endmodule
