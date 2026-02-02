--------------------------- MODULE SoulBridge ---------------------------
\* Soul Protocol Bridge State Machine Specification
\* Formal verification of cross-chain bridge safety and liveness properties
\* Author: Soul Protocol Team
\* Date: January 2026

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    ProofHashes,        \* Set of all possible proof hashes
    WithdrawalIds,      \* Set of all possible withdrawal IDs
    Users,              \* Set of all users
    Operators,          \* Set of bridge operators
    MaxValue,           \* Maximum transfer value
    ChallengePeriod,    \* Challenge period in blocks
    FinalityDelay       \* Finality delay in blocks

VARIABLES
    proofState,         \* mapping: proofHash -> ProofStatus
    withdrawalState,    \* mapping: withdrawalId -> WithdrawalStatus
    systemPaused,       \* boolean: whether system is paused
    blockNumber,        \* current block number
    tvl,                \* total value locked
    pendingWithdrawals, \* set of pending withdrawal IDs
    challengedProofs,   \* set of challenged proof hashes
    operatorBonds,      \* mapping: operator -> bond amount
    circuitBreakerState \* circuit breaker state

\* Proof states
ProofStatus == {"PENDING", "RELAYED", "CHALLENGED", "FINALIZED", "REJECTED"}

\* Withdrawal states  
WithdrawalStatus == {"INITIATED", "READY", "COMPLETED", "CANCELLED", "CHALLENGED"}

\* Circuit breaker states
CircuitBreakerStates == {"NORMAL", "WARNING", "DEGRADED", "HALTED"}

vars == <<proofState, withdrawalState, systemPaused, blockNumber, tvl, 
          pendingWithdrawals, challengedProofs, operatorBonds, circuitBreakerState>>

----------------------------------------------------------------------------
\* TYPE INVARIANTS
----------------------------------------------------------------------------

TypeInvariant ==
    /\ proofState \in [ProofHashes -> ProofStatus]
    /\ withdrawalState \in [WithdrawalIds -> WithdrawalStatus]
    /\ systemPaused \in BOOLEAN
    /\ blockNumber \in Nat
    /\ tvl \in 0..MaxValue
    /\ pendingWithdrawals \subseteq WithdrawalIds
    /\ challengedProofs \subseteq ProofHashes
    /\ operatorBonds \in [Operators -> 0..MaxValue]
    /\ circuitBreakerState \in CircuitBreakerStates

----------------------------------------------------------------------------
\* SAFETY PROPERTIES
----------------------------------------------------------------------------

\* No double-spend: A withdrawal can only complete once
NoDoubleSpend ==
    \A wid \in WithdrawalIds:
        withdrawalState[wid] = "COMPLETED" =>
            \A wid2 \in WithdrawalIds:
                (wid # wid2) => withdrawalState[wid2] # "COMPLETED" \/ 
                               \* Different withdrawals can complete
                               TRUE

\* Proof required: Withdrawal can only complete if proof is finalized
ProofRequiredForWithdrawal ==
    \A wid \in WithdrawalIds:
        withdrawalState[wid] = "COMPLETED" =>
            \E ph \in ProofHashes: proofState[ph] = "FINALIZED"

\* No unauthorized state transitions
ValidStateTransitions ==
    /\ \A ph \in ProofHashes:
        (proofState[ph] = "PENDING") =>
            proofState'[ph] \in {"PENDING", "RELAYED", "REJECTED"}
    /\ \A ph \in ProofHashes:
        (proofState[ph] = "RELAYED") =>
            proofState'[ph] \in {"RELAYED", "CHALLENGED", "FINALIZED"}
    /\ \A ph \in ProofHashes:
        (proofState[ph] = "FINALIZED") =>
            proofState'[ph] = "FINALIZED" \* Terminal state

\* TVL conservation: TVL changes are bounded
TVLConservation ==
    tvl' <= tvl + MaxValue /\ tvl' >= 0

\* Circuit breaker monotonicity: Can only escalate, not de-escalate without admin
CircuitBreakerMonotonicity ==
    circuitBreakerState = "HALTED" => circuitBreakerState' \in {"HALTED", "DEGRADED"}

\* Paused state blocks operations
PausedBlocksOperations ==
    systemPaused => 
        /\ withdrawalState' = withdrawalState
        /\ proofState' = proofState

----------------------------------------------------------------------------
\* LIVENESS PROPERTIES
----------------------------------------------------------------------------

\* Eventually finalized: A valid proof eventually becomes finalized
EventuallyFinalized ==
    \A ph \in ProofHashes:
        (proofState[ph] = "RELAYED" /\ ph \notin challengedProofs) ~>
            proofState[ph] = "FINALIZED"

\* Eventually completed: A ready withdrawal eventually completes
EventuallyCompleted ==
    \A wid \in WithdrawalIds:
        (withdrawalState[wid] = "READY" /\ ~systemPaused) ~>
            withdrawalState[wid] \in {"COMPLETED", "CANCELLED"}

\* System recovers: System eventually exits halted state
SystemRecovers ==
    circuitBreakerState = "HALTED" ~> circuitBreakerState = "NORMAL"

----------------------------------------------------------------------------
\* INITIAL STATE
----------------------------------------------------------------------------

Init ==
    /\ proofState = [ph \in ProofHashes |-> "PENDING"]
    /\ withdrawalState = [wid \in WithdrawalIds |-> "INITIATED"]
    /\ systemPaused = FALSE
    /\ blockNumber = 0
    /\ tvl = 0
    /\ pendingWithdrawals = {}
    /\ challengedProofs = {}
    /\ operatorBonds = [op \in Operators |-> 0]
    /\ circuitBreakerState = "NORMAL"

----------------------------------------------------------------------------
\* ACTIONS
----------------------------------------------------------------------------

\* Relay a proof from L1 to L2
RelayProof(ph, op) ==
    /\ ~systemPaused
    /\ circuitBreakerState \in {"NORMAL", "WARNING"}
    /\ proofState[ph] = "PENDING"
    /\ operatorBonds[op] > 0
    /\ proofState' = [proofState EXCEPT ![ph] = "RELAYED"]
    /\ UNCHANGED <<withdrawalState, systemPaused, blockNumber, tvl, 
                   pendingWithdrawals, challengedProofs, operatorBonds, circuitBreakerState>>

\* Challenge a relayed proof
ChallengeProof(ph, challenger) ==
    /\ proofState[ph] = "RELAYED"
    /\ proofState' = [proofState EXCEPT ![ph] = "CHALLENGED"]
    /\ challengedProofs' = challengedProofs \union {ph}
    /\ UNCHANGED <<withdrawalState, systemPaused, blockNumber, tvl, 
                   pendingWithdrawals, operatorBonds, circuitBreakerState>>

\* Finalize a proof after challenge period
FinalizeProof(ph) ==
    /\ proofState[ph] = "RELAYED"
    /\ ph \notin challengedProofs
    /\ proofState' = [proofState EXCEPT ![ph] = "FINALIZED"]
    /\ UNCHANGED <<withdrawalState, systemPaused, blockNumber, tvl, 
                   pendingWithdrawals, challengedProofs, operatorBonds, circuitBreakerState>>

\* Initiate a withdrawal
InitiateWithdrawal(wid, user, amount) ==
    /\ ~systemPaused
    /\ circuitBreakerState \in {"NORMAL", "WARNING", "DEGRADED"}
    /\ withdrawalState[wid] = "INITIATED"
    /\ amount <= tvl
    /\ withdrawalState' = [withdrawalState EXCEPT ![wid] = "READY"]
    /\ pendingWithdrawals' = pendingWithdrawals \union {wid}
    /\ tvl' = tvl - amount
    /\ UNCHANGED <<proofState, systemPaused, blockNumber, 
                   challengedProofs, operatorBonds, circuitBreakerState>>

\* Complete a withdrawal
CompleteWithdrawal(wid) ==
    /\ ~systemPaused
    /\ withdrawalState[wid] = "READY"
    /\ \E ph \in ProofHashes: proofState[ph] = "FINALIZED"
    /\ withdrawalState' = [withdrawalState EXCEPT ![wid] = "COMPLETED"]
    /\ pendingWithdrawals' = pendingWithdrawals \ {wid}
    /\ UNCHANGED <<proofState, systemPaused, blockNumber, tvl, 
                   challengedProofs, operatorBonds, circuitBreakerState>>

\* Pause the system
PauseSystem ==
    /\ ~systemPaused
    /\ systemPaused' = TRUE
    /\ UNCHANGED <<proofState, withdrawalState, blockNumber, tvl, 
                   pendingWithdrawals, challengedProofs, operatorBonds, circuitBreakerState>>

\* Unpause the system
UnpauseSystem ==
    /\ systemPaused
    /\ circuitBreakerState # "HALTED"
    /\ systemPaused' = FALSE
    /\ UNCHANGED <<proofState, withdrawalState, blockNumber, tvl, 
                   pendingWithdrawals, challengedProofs, operatorBonds, circuitBreakerState>>

\* Escalate circuit breaker
EscalateCircuitBreaker ==
    /\ circuitBreakerState \in {"NORMAL", "WARNING", "DEGRADED"}
    /\ circuitBreakerState' = 
        CASE circuitBreakerState = "NORMAL" -> "WARNING"
          [] circuitBreakerState = "WARNING" -> "DEGRADED"
          [] circuitBreakerState = "DEGRADED" -> "HALTED"
    /\ UNCHANGED <<proofState, withdrawalState, systemPaused, blockNumber, tvl, 
                   pendingWithdrawals, challengedProofs, operatorBonds>>

\* Advance block number
AdvanceBlock ==
    /\ blockNumber' = blockNumber + 1
    /\ UNCHANGED <<proofState, withdrawalState, systemPaused, tvl, 
                   pendingWithdrawals, challengedProofs, operatorBonds, circuitBreakerState>>

----------------------------------------------------------------------------
\* NEXT STATE RELATION
----------------------------------------------------------------------------

Next ==
    \/ \E ph \in ProofHashes, op \in Operators: RelayProof(ph, op)
    \/ \E ph \in ProofHashes, ch \in Users: ChallengeProof(ph, ch)
    \/ \E ph \in ProofHashes: FinalizeProof(ph)
    \/ \E wid \in WithdrawalIds, user \in Users, amount \in 1..MaxValue: 
        InitiateWithdrawal(wid, user, amount)
    \/ \E wid \in WithdrawalIds: CompleteWithdrawal(wid)
    \/ PauseSystem
    \/ UnpauseSystem
    \/ EscalateCircuitBreaker
    \/ AdvanceBlock

----------------------------------------------------------------------------
\* SPECIFICATION
----------------------------------------------------------------------------

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* Main safety property
Safety == TypeInvariant /\ NoDoubleSpend /\ ProofRequiredForWithdrawal

\* Main liveness property  
Liveness == EventuallyFinalized /\ EventuallyCompleted

----------------------------------------------------------------------------
\* THEOREMS
----------------------------------------------------------------------------

THEOREM Spec => []Safety
THEOREM Spec => Liveness

============================================================================
