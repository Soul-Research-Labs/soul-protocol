---------------------- MODULE MC_ZaseonEconomicSecurity ----------------------
\* Model-checking configuration for ZaseonEconomicSecurity
\* Run: tlc MC_ZaseonEconomicSecurity.tla

EXTENDS ZaseonEconomicSecurity

\* Small operator/attacker sets for feasible model checking
MC_Operators == {"op1", "op2", "op3"}
MC_Attackers == {"atk1"}
MC_MaxBond == 10000
MC_MinBond == 1000
MC_SlashingRatio == 30       \* 30% slashing
MC_InsuranceFund == 50000
MC_AttackCost == 5000
MC_MaxProfit == 3000         \* Attack profit < cost + bond -> unprofitable

\* Symmetry set for operators — reduces state space
MC_Symmetry == Permutations(MC_Operators)

============================================================================
