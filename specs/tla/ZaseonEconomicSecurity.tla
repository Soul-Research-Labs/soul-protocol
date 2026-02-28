--------------------------- MODULE ZaseonEconomicSecurity ---------------------------
\* ZASEON Economic Security Specification
\* Formal verification of economic attack resistance
\* Author: ZASEON Team
\* Date: January 2026

EXTENDS Naturals, Sequences, FiniteSets, TLC, Reals

CONSTANTS
    Operators,          \* Set of operators
    Attackers,          \* Set of potential attackers
    MaxBond,            \* Maximum bond amount
    MinBond,            \* Minimum bond amount
    SlashingRatio,      \* Percentage of bond slashed (0-100)
    InsuranceFund,      \* Initial insurance fund
    AttackCost,         \* Cost to attempt attack
    MaxProfit           \* Maximum potential profit from attack

VARIABLES
    operatorBonds,      \* mapping: operator -> bond amount
    operatorReputation, \* mapping: operator -> reputation score
    slashedAmounts,     \* mapping: operator -> slashed amount
    insuranceBalance,   \* current insurance fund balance
    attackAttempts,     \* number of attack attempts
    successfulAttacks,  \* number of successful attacks
    protocolTVL         \* total value locked

vars == <<operatorBonds, operatorReputation, slashedAmounts, 
          insuranceBalance, attackAttempts, successfulAttacks, protocolTVL>>

----------------------------------------------------------------------------
\* TYPE INVARIANTS
----------------------------------------------------------------------------

TypeInvariant ==
    /\ operatorBonds \in [Operators -> 0..MaxBond]
    /\ operatorReputation \in [Operators -> 0..10000]
    /\ slashedAmounts \in [Operators -> 0..MaxBond]
    /\ insuranceBalance \in 0..InsuranceFund * 10
    /\ attackAttempts \in Nat
    /\ successfulAttacks \in Nat
    /\ protocolTVL \in Nat

----------------------------------------------------------------------------
\* ECONOMIC SECURITY INVARIANTS
----------------------------------------------------------------------------

\* Attack cost exceeds profit: Rational attacker won't attack
AttackCostExceedsProfit ==
    \A a \in Attackers:
        AttackCost + MinBond > MaxProfit

\* Insurance fund covers losses
InsuranceCoverageAdequate ==
    insuranceBalance >= protocolTVL * 10 \div 100  \* 10% coverage

\* Slashing provides deterrence
SlashingDeterrence ==
    \A op \in Operators:
        operatorBonds[op] * SlashingRatio \div 100 > MaxProfit

\* Reputation affects risk
ReputationRisk ==
    \A op \in Operators:
        operatorReputation[op] < 3000 => 
            operatorBonds[op] >= MinBond * 2

\* No profitable attack exists
NoProfitableAttack ==
    \A a \in Attackers:
        LET attackProfit == MaxProfit - AttackCost - MinBond
        IN attackProfit < 0

----------------------------------------------------------------------------
\* GAME THEORY PROPERTIES
----------------------------------------------------------------------------

\* Nash equilibrium: Honest behavior is optimal
HonestBehaviorOptimal ==
    \A op \in Operators:
        \* Expected profit from honest behavior
        LET honestProfit == operatorBonds[op] * 5 \div 100  \* 5% yield
        \* Expected loss from dishonest behavior
            dishonestLoss == operatorBonds[op] * SlashingRatio \div 100
        IN honestProfit > 0 /\ dishonestLoss > MaxProfit

\* Collusion resistance: Collusion is unprofitable
\* Combined slashing of colluding operators must exceed their combined profit.
RECURSIVE SumBonds(_)
SumBonds(S) ==
    IF S = {} THEN 0
    ELSE LET op == CHOOSE x \in S : TRUE
         IN operatorBonds[op] + SumBonds(S \ {op})

CollusionResistance ==
    \A subset \in SUBSET Operators:
        Cardinality(subset) > 1 =>
            LET combinedBonds == SumBonds(subset)
                combinedSlash == combinedBonds * SlashingRatio \div 100
            IN combinedSlash > MaxProfit * Cardinality(subset)

\* Griefing resistance: Griefing is expensive
GriefingResistance ==
    AttackCost > 0

----------------------------------------------------------------------------
\* INITIAL STATE
----------------------------------------------------------------------------

Init ==
    /\ operatorBonds = [op \in Operators |-> MinBond]
    /\ operatorReputation = [op \in Operators |-> 5000]
    /\ slashedAmounts = [op \in Operators |-> 0]
    /\ insuranceBalance = InsuranceFund
    /\ attackAttempts = 0
    /\ successfulAttacks = 0
    /\ protocolTVL = 0

----------------------------------------------------------------------------
\* ACTIONS
----------------------------------------------------------------------------

\* Operator deposits bond
DepositBond(op, amount) ==
    /\ amount > 0
    /\ operatorBonds[op] + amount <= MaxBond
    /\ operatorBonds' = [operatorBonds EXCEPT ![op] = @ + amount]
    /\ UNCHANGED <<operatorReputation, slashedAmounts, insuranceBalance, 
                   attackAttempts, successfulAttacks, protocolTVL>>

\* Slash operator for misbehavior
SlashOperator(op) ==
    /\ operatorBonds[op] > 0
    /\ LET slashAmount == operatorBonds[op] * SlashingRatio \div 100
       IN /\ operatorBonds' = [operatorBonds EXCEPT ![op] = @ - slashAmount]
          /\ slashedAmounts' = [slashedAmounts EXCEPT ![op] = @ + slashAmount]
          /\ insuranceBalance' = insuranceBalance + slashAmount
          /\ operatorReputation' = [operatorReputation EXCEPT ![op] = 
                IF @ > 500 THEN @ - 500 ELSE 0]
    /\ UNCHANGED <<attackAttempts, successfulAttacks, protocolTVL>>

\* Attacker attempts attack
AttemptAttack(attacker) ==
    /\ attackAttempts' = attackAttempts + 1
    /\ \* Attack fails if cost exceeds profit
       IF AttackCost + MinBond > MaxProfit
       THEN successfulAttacks' = successfulAttacks
       ELSE successfulAttacks' = successfulAttacks + 1
    /\ UNCHANGED <<operatorBonds, operatorReputation, slashedAmounts, 
                   insuranceBalance, protocolTVL>>

\* Increase reputation for good behavior
IncreaseReputation(op) ==
    /\ operatorReputation[op] < 10000
    /\ operatorReputation' = [operatorReputation EXCEPT ![op] = 
        IF @ + 100 > 10000 THEN 10000 ELSE @ + 100]
    /\ UNCHANGED <<operatorBonds, slashedAmounts, insuranceBalance, 
                   attackAttempts, successfulAttacks, protocolTVL>>

\* Claim from insurance
ClaimInsurance(amount) ==
    /\ amount <= insuranceBalance
    /\ insuranceBalance' = insuranceBalance - amount
    /\ UNCHANGED <<operatorBonds, operatorReputation, slashedAmounts, 
                   attackAttempts, successfulAttacks, protocolTVL>>

----------------------------------------------------------------------------
\* NEXT STATE RELATION
----------------------------------------------------------------------------

Next ==
    \/ \E op \in Operators, amount \in 1..MaxBond: DepositBond(op, amount)
    \/ \E op \in Operators: SlashOperator(op)
    \/ \E a \in Attackers: AttemptAttack(a)
    \/ \E op \in Operators: IncreaseReputation(op)
    \/ \E amount \in 1..InsuranceFund: ClaimInsurance(amount)

----------------------------------------------------------------------------
\* SPECIFICATION
----------------------------------------------------------------------------

Spec == Init /\ [][Next]_vars

\* Economic security holds
EconomicSecurity == 
    TypeInvariant /\ AttackCostExceedsProfit /\ NoProfitableAttack

THEOREM Spec => []EconomicSecurity

============================================================================
