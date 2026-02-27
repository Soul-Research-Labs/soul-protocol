// SPDX-License-Identifier: MIT
// K Framework Specification for Emergency Coordination Protocol
//
// Formalizes cross-chain emergency propagation, heartbeat liveness,
// and severity escalation invariants.
//
// EMERGENCY COORDINATION ARCHITECTURE:
// ┌──────────────────────────────────────────────────────────────────┐
// │                    Emergency Coordination                        │
// │                                                                  │
// │   Severity Levels:                                              │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  NONE(0) → LOW(1) → MEDIUM(2) → HIGH(3) → CRITICAL(4)   ││
// │   │                                                            ││
// │   │  Escalation is monotonic within an incident window.        ││
// │   │  Only explicit resolution can return to NONE.              ││
// │   │                                                            ││
// │   │  ∀ incident I: severity(t+1) ≥ severity(t)                ││
// │   │       until resolved(I)                                    ││
// │   └────────────────────────────────────────────────────────────┘│
// │                                                                  │
// │   Heartbeat Liveness:                                           │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  heartbeat_overdue :=                                      ││
// │   │    now - lastHeartbeatAt > heartbeatInterval                ││
// │   │                                                            ││
// │   │  If heartbeat_overdue → auto_pause triggers               ││
// │   │  Auto-pause is conservative: better to pause than miss    ││
// │   │  an emergency on a silenced chain.                         ││
// │   └────────────────────────────────────────────────────────────┘│
// │                                                                  │
// │   Nonce Ordering:                                               │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  globalNonce: ℕ → ℕ, strictly monotonic                    ││
// │   │  lastReceivedNonce[chainId]: ℕ → ℕ, strictly monotonic    ││
// │   │                                                            ││
// │   │  Replay protection:                                        ││
// │   │  ∀ msg M from chain C:                                     ││
// │   │    M.nonce > lastReceivedNonce[C]                          ││
// │   │    → accept and update lastReceivedNonce[C] = M.nonce      ││
// │   │    M.nonce ≤ lastReceivedNonce[C]                          ││
// │   │    → reject (ReplayDetected)                               ││
// │   └────────────────────────────────────────────────────────────┘│
// └──────────────────────────────────────────────────────────────────┘

module EMERGENCY-SYNTAX
    imports INT
    imports BOOL
    imports MAP
    imports SET

    // Severity type
    syntax Severity ::= "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

    // Chain configuration
    syntax ChainConfig ::= chainConfig(
        chainId: Int,
        messenger: Int,       // address as Int
        remoteReceiver: Int,  // address as Int
        active: Bool,
        lastBroadcastAt: Int  // timestamp
    )

    // Emergency message
    syntax EmergencyMessage ::= emergencyMsg(
        nonce: Int,
        sourceChainId: Int,
        targetChainId: Int,
        severity: Severity,
        incidentId: Int,
        timestamp: Int
    )

    // Heartbeat state
    syntax HeartbeatState ::= heartbeat(
        lastHeartbeatAt: Int,
        interval: Int,
        autoPauseTriggered: Bool
    )

    // Actions
    syntax Action ::= "broadcastEmergency" "(" Severity "," Int ")"
                     | "broadcastRecovery" "(" Int ")"
                     | "receiveEmergency" "(" EmergencyMessage ")"
                     | "sendHeartbeat" "(" Int ")"
                     | "receiveHeartbeat" "(" Int ")"
                     | "registerChain" "(" ChainConfig ")"
                     | "deactivateChain" "(" Int ")"
                     | "checkHeartbeatLiveness"
endmodule

module EMERGENCY-COORDINATION
    imports EMERGENCY-SYNTAX
    imports INT
    imports BOOL
    imports MAP
    imports SET

    // ================================================================
    //                     CONFIGURATION
    // ================================================================

    configuration
        <emergency>
            <globalNonce> 0 </globalNonce>
            <lastReceivedNonce> .Map </lastReceivedNonce>  // chainId |-> nonce
            <chains> .Map </chains>                         // chainId |-> ChainConfig
            <registeredChainIds> .Set </registeredChainIds>
            <activeChainCount> 0 </activeChainCount>
            <currentSeverity> NONE </currentSeverity>
            <heartbeatState> heartbeat(0, 3600, false) </heartbeatState>
            <paused> false </paused>
            <maxMessageAge> 3600 </maxMessageAge>
            <currentTime> 0 </currentTime>
        </emergency>

    // ================================================================
    //                    SEVERITY ORDERING
    // ================================================================

    // Define severity as integer for ordering
    syntax Int ::= severityToInt(Severity) [function]
    rule severityToInt(NONE) => 0
    rule severityToInt(LOW) => 1
    rule severityToInt(MEDIUM) => 2
    rule severityToInt(HIGH) => 3
    rule severityToInt(CRITICAL) => 4

    syntax Bool ::= severityGe(Severity, Severity) [function]
    rule severityGe(S1, S2) => severityToInt(S1) >=Int severityToInt(S2)

    // ================================================================
    //                EMERGENCY BROADCAST RULES
    // ================================================================

    // Successful broadcast: increments nonce, updates severity
    rule <emergency>
            <globalNonce> N => N +Int 1 </globalNonce>
            <currentSeverity> OLD => SEV </currentSeverity>
            <paused> false </paused>
            ...
         </emergency>
    requires severityGe(SEV, OLD)

    // ================================================================
    //                RECEIVE EMERGENCY RULES
    // ================================================================

    // Accept message: nonce must be strictly greater than last received
    rule <emergency>
            <lastReceivedNonce>
                M => M[CHAIN <- NONCE]
            </lastReceivedNonce>
            <currentSeverity> _ => SEV </currentSeverity>
            <currentTime> NOW </currentTime>
            <maxMessageAge> MAX_AGE </maxMessageAge>
            ...
         </emergency>
    requires NONCE >Int {M[CHAIN]}:>Int          // replay protection
     andBool NOW -Int TS <=Int MAX_AGE             // message freshness
     andBool TS >Int 0                              // valid timestamp
      where emergencyMsg(NONCE, CHAIN, _, SEV, _, TS) := _MSG

    // ================================================================
    //                HEARTBEAT RULES
    // ================================================================

    // Heartbeat liveness check: if overdue, trigger auto-pause
    rule <emergency>
            <heartbeatState>
                heartbeat(LAST, INTERVAL, false)
                => heartbeat(LAST, INTERVAL, true)
            </heartbeatState>
            <paused> false => true </paused>
            <currentTime> NOW </currentTime>
            ...
         </emergency>
    requires NOW -Int LAST >Int INTERVAL

    // ================================================================
    //              FORMAL PROPERTIES (CLAIMS)
    // ================================================================

    // Property 1: Nonce monotonicity
    // After any transition, globalNonce ≥ previous globalNonce
    // claim: ∀ state S, S': S →* S' implies S'.globalNonce ≥ S.globalNonce

    // Property 2: Severity escalation monotonicity (within incident)
    // claim: ∀ S1 →_broadcast S2: severityToInt(S2.currentSeverity)
    //        ≥ severityToInt(S1.currentSeverity)
    //   UNLESS S2 is a recovery (resolves to NONE)

    // Property 3: Replay protection completeness
    // claim: ∀ msg M accepted from chain C:
    //        M.nonce > S.lastReceivedNonce[C]
    //   After acceptance: S'.lastReceivedNonce[C] = M.nonce

    // Property 4: Active chain count accuracy
    // claim: activeChainCount = |{ c ∈ registeredChainIds : chains[c].active }|

    // Property 5: Auto-pause safety
    // claim: ∀ S where (now - lastHeartbeatAt > interval):
    //        checkHeartbeatLiveness transitions S.paused → true

    // Property 6: Message freshness
    // claim: ∀ accepted msg M: now - M.timestamp ≤ maxMessageAge

endmodule
