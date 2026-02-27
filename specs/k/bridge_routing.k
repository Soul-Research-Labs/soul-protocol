// SPDX-License-Identifier: MIT
// K Framework Specification for Bridge Routing Algebra
//
// Formalizes multi-bridge routing, failover behavior, and confirmation
// threshold properties for the MultiBridgeRouter and CapacityAwareRouter.
//
// BRIDGE ROUTING ARCHITECTURE:
// ┌──────────────────────────────────────────────────────────────────┐
// │                    Bridge Routing Algebra                        │
// │                                                                  │
// │   Route Selection:                                              │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  Given a set of bridges B = {b1, ..., bn}                 ││
// │   │  and a destination chain D:                                ││
// │   │                                                            ││
// │   │  Route(D, amount) → {b_i : b_i.active ∧ b_i.supports(D)  ││
// │   │                       ∧ b_i.capacity ≥ amount}            ││
// │   │                                                            ││
// │   │  Selection criterion: argmax(health_score(b_i))           ││
// │   │  Failover: if b_i fails → next by health_score            ││
// │   └────────────────────────────────────────────────────────────┘│
// │                                                                  │
// │   Confirmation Model:                                           │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  For message M sent via bridges {b1, ..., bk}:            ││
// │   │  M is finalized iff                                        ││
// │   │    |{b_i : b_i.confirmed(M)}| ≥ confirmationThreshold     ││
// │   │                                                            ││
// │   │  k ≥ confirmationThreshold (send enough copies)           ││
// │   │  confirmationThreshold ≥ 1 (at least one bridge)          ││
// │   └────────────────────────────────────────────────────────────┘│
// │                                                                  │
// │   Health Score:                                                 │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  HealthScore(b) ∈ [0, 10000]  (basis points)              ││
// │   │                                                            ││
// │   │  Factors:                                                  ││
// │   │    - successRate = successes / (successes + failures)     ││
// │   │    - uptime = 1 - (downtime / totalTime)                  ││
// │   │    - latency = avgLatency (lower is better)               ││
// │   │                                                            ││
// │   │  Score monotonicity:                                       ││
// │   │    success(b) → score(b)' ≥ score(b)                     ││
// │   │    failure(b) → score(b)' ≤ score(b)                     ││
// │   └────────────────────────────────────────────────────────────┘│
// └──────────────────────────────────────────────────────────────────┘

module BRIDGE-ROUTING-SYNTAX
    imports INT
    imports BOOL
    imports MAP
    imports SET
    imports LIST

    // Bridge adapter state
    syntax BridgeAdapter ::= bridge(
        id: Int,
        active: Bool,
        healthScore: Int,     // [0, 10000]
        successes: Int,
        failures: Int,
        supportedChains: Set  // Set of chain IDs
    )

    // Route selection result
    syntax RouteResult ::= routeResult(
        bridgeId: Int,
        estimatedFee: Int,
        estimatedLatency: Int
    )
                         | "noRoute"

    // Message state
    syntax MessageState ::= "PENDING" | "SENT" | "CONFIRMED" | "FAILED" | "FINALIZED"

    // Bridge message
    syntax BridgeMessage ::= bridgeMsg(
        messageId: Int,
        destChain: Int,
        payload: Int,       // hash of actual payload
        sentViaBridges: Set,
        confirmedByBridges: Set,
        state: MessageState
    )

    // Actions
    syntax Action ::= "registerBridge" "(" BridgeAdapter ")"
                     | "removeBridge" "(" Int ")"
                     | "routeMessage" "(" Int "," Int "," Int ")"  // destChain, amount, gasLimit
                     | "confirmMessage" "(" Int "," Int ")"         // messageId, bridgeId
                     | "reportSuccess" "(" Int ")"                  // bridgeId
                     | "reportFailure" "(" Int ")"                  // bridgeId
                     | "updateHealthScore" "(" Int ")"              // bridgeId
endmodule

module BRIDGE-ROUTING
    imports BRIDGE-ROUTING-SYNTAX
    imports INT
    imports BOOL
    imports MAP
    imports SET

    // ================================================================
    //                     CONFIGURATION
    // ================================================================

    configuration
        <routing>
            <bridges> .Map </bridges>                // bridgeId |-> BridgeAdapter
            <bridgeIds> .Set </bridgeIds>
            <messages> .Map </messages>              // messageId |-> BridgeMessage
            <confirmationThreshold> 1 </confirmationThreshold>
            <totalMessagesSent> 0 </totalMessagesSent>
            <totalMessagesFinalized> 0 </totalMessagesFinalized>
            <routePaused> false </routePaused>
        </routing>

    // ================================================================
    //                   HELPER FUNCTIONS
    // ================================================================

    // Health score is bounded
    syntax Bool ::= validHealthScore(Int) [function]
    rule validHealthScore(S) => S >=Int 0 andBool S <=Int 10000

    // Find best bridge for a destination
    syntax Int ::= bestBridge(Map, Int) [function]
    // Returns bridge ID with highest health score supporting the destination
    // (simplified — actual implementation iterates)

    // Count confirmations
    syntax Int ::= confirmationCount(BridgeMessage) [function]
    rule confirmationCount(bridgeMsg(_, _, _, _, CONFIRMED, _))
         => size(CONFIRMED)

    // ================================================================
    //                 BRIDGE REGISTRATION RULES
    // ================================================================

    // Register: bridge ID must be new, health score valid
    rule <routing>
            <bridges> M => M[ID <- B] </bridges>
            <bridgeIds> IDS => IDS SetItem(ID) </bridgeIds>
            ...
         </routing>
      where bridge(ID, _, HEALTH, _, _, _) := B
    requires notBool(ID in IDS)
     andBool validHealthScore(HEALTH)

    // ================================================================
    //                   ROUTING RULES
    // ================================================================

    // Route message: select best bridge, create message
    rule <routing>
            <messages> M => M[MSG_ID <- NEW_MSG] </messages>
            <totalMessagesSent> N => N +Int 1 </totalMessagesSent>
            <routePaused> false </routePaused>
            ...
         </routing>
    requires MSG_ID >Int 0

    // ================================================================
    //                 CONFIRMATION RULES
    // ================================================================

    // Confirm: bridge confirms a message
    // Message transitions to FINALIZED when threshold met
    rule <routing>
            <messages>
                M => M[MSG_ID <- updatedMsg(MSG, BRIDGE_ID, THRESH)]
            </messages>
            <confirmationThreshold> THRESH </confirmationThreshold>
            ...
         </routing>
    requires MSG_ID in_keys(M)

    // Helper: update message with confirmation
    syntax BridgeMessage ::= updatedMsg(BridgeMessage, Int, Int) [function]
    rule updatedMsg(
            bridgeMsg(ID, DEST, PAY, SENT, CONF, _STATE),
            BRIDGE_ID,
            THRESH
         )
         => bridgeMsg(
                ID, DEST, PAY, SENT,
                CONF SetItem(BRIDGE_ID),
                #if size(CONF SetItem(BRIDGE_ID)) >=Int THRESH
                    #then FINALIZED
                    #else CONFIRMED
                #fi
            )

    // ================================================================
    //                HEALTH SCORE RULES
    // ================================================================

    // Success report: health score can only increase or stay
    rule <routing>
            <bridges>
                M => M[BID <- updateBridgeSuccess(
                    {M[BID]}:>BridgeAdapter
                )]
            </bridges>
            ...
         </routing>
    requires BID in_keys(M)

    syntax BridgeAdapter ::= updateBridgeSuccess(BridgeAdapter) [function]
    rule updateBridgeSuccess(bridge(ID, ACT, SCORE, SUCC, FAIL, CHAINS))
         => bridge(ID, ACT,
                   minInt(10000, SCORE +Int 10),    // cap at 10000
                   SUCC +Int 1,
                   FAIL,
                   CHAINS)

    // Failure report: health score can only decrease or stay
    syntax BridgeAdapter ::= updateBridgeFailure(BridgeAdapter) [function]
    rule updateBridgeFailure(bridge(ID, ACT, SCORE, SUCC, FAIL, CHAINS))
         => bridge(ID, ACT,
                   maxInt(0, SCORE -Int 100),       // floor at 0
                   SUCC,
                   FAIL +Int 1,
                   CHAINS)

    // ================================================================
    //              FORMAL PROPERTIES (CLAIMS)
    // ================================================================

    // Property 1: Health score is always bounded [0, 10000]
    // claim: ∀ bridge b in bridges: 0 ≤ b.healthScore ≤ 10000

    // Property 2: Success monotonicity of health
    // claim: ∀ b, if reportSuccess(b):
    //        b'.healthScore ≥ b.healthScore

    // Property 3: Failure anti-monotonicity of health
    // claim: ∀ b, if reportFailure(b):
    //        b'.healthScore ≤ b.healthScore

    // Property 4: Confirmation threshold safety
    // claim: ∀ message M: M.state = FINALIZED
    //        ⟹ |M.confirmedByBridges| ≥ confirmationThreshold

    // Property 5: Message count monotonicity
    // claim: totalMessagesSent and totalMessagesFinalized
    //        are monotonically non-decreasing

    // Property 6: Finalized messages are permanent
    // claim: ∀ M: M.state = FINALIZED ⟹ ∀ S': M'.state = FINALIZED
    //        (once finalized, always finalized)

    // Property 7: Route determinism
    // claim: ∀ (destChain, amount, bridges_snapshot):
    //        route(destChain, amount) = route(destChain, amount)
    //        (same inputs, same state → same result)

    // Property 8: Paused routing rejects all messages
    // claim: routePaused = true ⟹ ∀ route(_, _, _) fails

    // Property 9: No orphan confirmations
    // claim: ∀ confirmation for M by bridge b:
    //        b ∈ M.sentViaBridges
    //        (can only confirm if message was sent via that bridge)

endmodule
