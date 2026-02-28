--------------------------- MODULE MC_ZaseonBridge ---------------------------
\* Model checking configuration for ZaseonBridge.tla
\* Run: java -cp ~/tla/tla2tools.jar tlc2.TLC MC_ZaseonBridge.tla -workers auto

EXTENDS ZaseonBridge

\* =========================================================================
\* FINITE CONSTANTS FOR MODEL CHECKING
\* =========================================================================

\* Small finite sets for bounded model checking
MC_ProofHashes == {"ph1", "ph2", "ph3"}
MC_WithdrawalIds == {"w1", "w2", "w3"}
MC_Users == {"alice", "bob"}
MC_Operators == {"op1", "op2"}
MC_MaxValue == 100
MC_ChallengePeriod == 3
MC_FinalityDelay == 2

\* =========================================================================
\* SYMMETRY SETS (optimization)
\* =========================================================================
\* ProofHashes, WithdrawalIds, Users, Operators are symmetric sets
\* TLC can exploit this to reduce state space

\* =========================================================================
\* SUBSTITUTIONS
\* =========================================================================
ProofHashes <- MC_ProofHashes
WithdrawalIds <- MC_WithdrawalIds
Users <- MC_Users
Operators <- MC_Operators
MaxValue <- MC_MaxValue
ChallengePeriod <- MC_ChallengePeriod
FinalityDelay <- MC_FinalityDelay

\* =========================================================================
\* PROPERTIES TO CHECK
\* =========================================================================
\* INVARIANTS (checked in every reachable state):
\*   - TypeInvariant
\*   - NoDoubleSpend
\*   - ProofRequiredForWithdrawal
\*   - TVLConservation
\*
\* PROPERTIES (temporal):
\*   - ValidStateTransitions
\*   - CircuitBreakerMonotonicity
\*   - PausedBlocksOperations

=========================================================================
