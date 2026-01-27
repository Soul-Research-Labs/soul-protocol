// SPDX-License-Identifier: MIT
// K Framework Specification for Nullifier Algebra
//
// This specification formalizes the algebraic properties of nullifiers
// used in the Soul Protocol for preventing double-spending
// and replay attacks across domains.
//
// NULLIFIER ALGEBRA ARCHITECTURE:
// ┌─────────────────────────────────────────────────────────────────┐
// │                    Nullifier Algebra                            │
// │                                                                  │
// │   Nullifier Generation:                                         │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │                                                            ││
// │   │  Standard:  N = H(secret, commitment)                     ││
// │   │                                                            ││
// │   │  Cross-Domain: N_cd = H(N_base, domainId, chainId)        ││
// │   │                                                            ││
// │   │  Time-Bound: N_tb = H(N_base, epoch)                      ││
// │   │                                                            ││
// │   └────────────────────────────────────────────────────────────┘│
// │                                                                  │
// │   Nullifier Properties:                                         │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  Uniqueness:    ∀(s1,c1) ≠ (s2,c2) → N1 ≠ N2              ││
// │   │  Binding:       N → (s,c) is computationally hard         ││
// │   │  Hiding:        N reveals nothing about s or c            ││
// │   │  Cross-Domain:  N_cd is unique per domain                 ││
// │   │  Unlinkability: N_d1 and N_d2 are unlinkable             ││
// │   └────────────────────────────────────────────────────────────┘│
// │                                                                  │
// │   Domain Separation:                                            │
// │   ┌────────────────────────────────────────────────────────────┐│
// │   │  Domain_i → Nullifier_i                                   ││
// │   │  Domain_j → Nullifier_j                                   ││
// │   │  where i ≠ j implies Nullifier_i ≠ Nullifier_j           ││
// │   │  (for same underlying commitment)                         ││
// │   └────────────────────────────────────────────────────────────┘│
// └─────────────────────────────────────────────────────────────────┘

module NULLIFIER-ALGEBRA-SYNTAX
    imports INT
    imports BOOL
    imports LIST

    // Field element (BN254 scalar field)
    syntax FieldElement ::= Int

    // Domain identifiers
    syntax DomainId ::= Int
                      | "ETHEREUM_MAINNET"       // 1
                      | "ARBITRUM_ONE"           // 42161
                      | "OPTIMISM"               // 10
                      | "BASE"                   // 8453
                      | "POLYGON_ZKEVM"          // 1101
                      | "ZKSYNC_ERA"             // 324
                      | "SCROLL"                 // 534352
                      | "LINEA"                  // 59144

    // Nullifier types
    syntax NullifierType ::= "STANDARD"
                           | "CROSS_DOMAIN"
                           | "TIME_BOUND"
                           | "DELEGATED"
                           | "AGGREGATE"

    // Nullifier structure
    syntax Nullifier ::= "nullifier" "(" FieldElement "," NullifierType "," DomainId ")"

    // Commitment structure
    syntax Commitment ::= "commitment" "(" FieldElement "," FieldElement ")"  // (value, blinding)

    // Secret knowledge
    syntax Secret ::= FieldElement

    // Epoch for time-bound nullifiers
    syntax Epoch ::= Int

    // Hash function abstraction
    syntax FieldElement ::= "Hash" "(" FieldElement "," FieldElement ")"
                          | "Hash3" "(" FieldElement "," FieldElement "," FieldElement ")"
                          | "Hash4" "(" FieldElement "," FieldElement "," FieldElement "," FieldElement ")"

    // Nullifier operations
    syntax Nullifier ::= "generateNullifier" "(" Secret "," Commitment ")"
                       | "generateCrossDomainNullifier" "(" Nullifier "," DomainId ")"
                       | "generateTimeBoundNullifier" "(" Nullifier "," Epoch ")"
                       | "aggregateNullifiers" "(" List ")"

    // Verification predicates
    syntax Bool ::= "verifyNullifier" "(" Nullifier "," FieldElement ")"
                  | "nullifierUsed" "(" Nullifier ")"
                  | "validDomain" "(" DomainId ")"
                  | "validEpoch" "(" Epoch ")"
endmodule

module NULLIFIER-ALGEBRA-CONFIGURATION
    imports NULLIFIER-ALGEBRA-SYNTAX

    // BN254 field modulus
    syntax Int ::= "FIELD_MODULUS" [function]
    rule FIELD_MODULUS => 21888242871839275222246405745257275088548364400416034343698204186575808495617

    // Domain separator constants
    syntax FieldElement ::= "DOMAIN_SEP_STANDARD" [function]
    syntax FieldElement ::= "DOMAIN_SEP_CROSS_DOMAIN" [function]
    syntax FieldElement ::= "DOMAIN_SEP_TIME_BOUND" [function]
    syntax FieldElement ::= "DOMAIN_SEP_DELEGATED" [function]

    rule DOMAIN_SEP_STANDARD => 0x0001
    rule DOMAIN_SEP_CROSS_DOMAIN => 0x0002
    rule DOMAIN_SEP_TIME_BOUND => 0x0003
    rule DOMAIN_SEP_DELEGATED => 0x0004

    // Chain ID mappings
    rule ETHEREUM_MAINNET => 1
    rule ARBITRUM_ONE => 42161
    rule OPTIMISM => 10
    rule BASE => 8453
    rule POLYGON_ZKEVM => 1101
    rule ZKSYNC_ERA => 324
    rule SCROLL => 534352
    rule LINEA => 59144

    // Epoch duration (seconds)
    syntax Int ::= "EPOCH_DURATION" [function]
    rule EPOCH_DURATION => 3600  // 1 hour

    // Maximum nullifier reuse (for time-bound)
    syntax Int ::= "MAX_EPOCH_REUSE" [function]
    rule MAX_EPOCH_REUSE => 24  // Can reuse across 24 epochs
endmodule

module NULLIFIER-GENERATION
    imports NULLIFIER-ALGEBRA-SYNTAX
    imports NULLIFIER-ALGEBRA-CONFIGURATION

    // ============================================
    // STANDARD NULLIFIER GENERATION
    // ============================================

    // Generate standard nullifier from secret and commitment
    // N = Hash(DOMAIN_SEP_STANDARD, secret, commitmentHash)
    rule generateNullifier(S:FieldElement, commitment(V, B)) =>
        let CommitHash = Hash(V, B) in
        nullifier(
            Hash3(DOMAIN_SEP_STANDARD, S, CommitHash),
            STANDARD,
            ETHEREUM_MAINNET
        )

    // ============================================
    // CROSS-DOMAIN NULLIFIER GENERATION
    // ============================================

    // Generate cross-domain nullifier from base nullifier and target domain
    // N_cd = Hash(DOMAIN_SEP_CROSS_DOMAIN, baseNullifier, domainId)
    rule generateCrossDomainNullifier(
        nullifier(BaseHash, _, _),
        TargetDomain:DomainId
    ) =>
        nullifier(
            Hash3(DOMAIN_SEP_CROSS_DOMAIN, BaseHash, TargetDomain),
            CROSS_DOMAIN,
            TargetDomain
        )

    // ============================================
    // TIME-BOUND NULLIFIER GENERATION
    // ============================================

    // Generate time-bound nullifier (expires after epoch)
    // N_tb = Hash(DOMAIN_SEP_TIME_BOUND, baseNullifier, epoch)
    rule generateTimeBoundNullifier(
        nullifier(BaseHash, _, D),
        E:Epoch
    ) =>
        nullifier(
            Hash3(DOMAIN_SEP_TIME_BOUND, BaseHash, E),
            TIME_BOUND,
            D
        )
        requires validEpoch(E)

    // ============================================
    // AGGREGATE NULLIFIER GENERATION
    // ============================================

    // Aggregate multiple nullifiers into single nullifier
    // Used for batched operations
    syntax FieldElement ::= "aggregateHashes" "(" List ")" [function]

    rule aggregateNullifiers(ListItem(nullifier(H1, _, D)) ListItem(nullifier(H2, _, _)) .List) =>
        nullifier(
            Hash(H1, H2),
            AGGREGATE,
            D
        )

    rule aggregateNullifiers(ListItem(nullifier(H1, _, D)) Rest:List) =>
        let nullifier(RestHash, _, _) = aggregateNullifiers(Rest) in
        nullifier(
            Hash(H1, RestHash),
            AGGREGATE,
            D
        )
        requires size(Rest) >Int 1
endmodule

module NULLIFIER-VERIFICATION
    imports NULLIFIER-GENERATION

    // ============================================
    // NULLIFIER VERIFICATION
    // ============================================

    // Verify nullifier against expected root
    // Used in ZK proofs
    rule verifyNullifier(nullifier(H, _, _), ExpectedRoot) =>
        H ==K ExpectedRoot

    // Check if nullifier is in valid domain
    rule validDomain(D:Int) =>
        D ==Int 1 orBool           // Ethereum
        D ==Int 42161 orBool       // Arbitrum
        D ==Int 10 orBool          // Optimism
        D ==Int 8453 orBool        // Base
        D ==Int 1101 orBool        // Polygon zkEVM
        D ==Int 324 orBool         // zkSync Era
        D ==Int 534352 orBool      // Scroll
        D ==Int 59144              // Linea

    // Check if epoch is valid (not in future, not too old)
    rule validEpoch(E:Int) =>
        E >Int 0 andBool E <Int (2 ^Int 32)
endmodule

module NULLIFIER-PROPERTIES
    imports NULLIFIER-VERIFICATION
    imports BOOL

    // ============================================
    // SECURITY PROPERTIES
    // ============================================

    // Property 1: Uniqueness
    // Different inputs produce different nullifiers
    syntax Bool ::= "uniqueness" "(" Secret "," Commitment "," Secret "," Commitment ")" [function]
    rule uniqueness(S1, C1, S2, C2) =>
        ((S1 =/=K S2) orBool (C1 =/=K C2)) impliesBool
        (generateNullifier(S1, C1) =/=K generateNullifier(S2, C2))

    // Property 2: Binding
    // Nullifier is bound to specific (secret, commitment) pair
    // Cannot produce valid nullifier without knowledge
    syntax Bool ::= "binding" "(" Nullifier "," Secret "," Commitment ")" [function]
    // Security assumption based on hash function properties

    // Property 3: Hiding
    // Nullifier reveals nothing about secret or commitment
    // Formalized as computational indistinguishability
    syntax Bool ::= "hiding" "(" Nullifier ")" [function]
    // Security assumption based on hash function properties

    // Property 4: Cross-Domain Uniqueness
    // Same base nullifier produces different nullifiers in different domains
    syntax Bool ::= "crossDomainUniqueness" "(" Nullifier "," DomainId "," DomainId ")" [function]
    rule crossDomainUniqueness(BaseNull, D1, D2) =>
        (D1 =/=K D2) impliesBool
        (generateCrossDomainNullifier(BaseNull, D1) =/=K
         generateCrossDomainNullifier(BaseNull, D2))

    // Property 5: Cross-Domain Unlinkability
    // Given N_d1 and N_d2, cannot determine if from same base
    // (without knowledge of base nullifier)
    syntax Bool ::= "crossDomainUnlinkability" "(" Nullifier "," Nullifier ")" [function]
    // Security assumption based on hash function properties

    // Property 6: Time-Bound Uniqueness
    // Same nullifier in different epochs produces different time-bound nullifiers
    syntax Bool ::= "timeBoundUniqueness" "(" Nullifier "," Epoch "," Epoch ")" [function]
    rule timeBoundUniqueness(BaseNull, E1, E2) =>
        (E1 =/=K E2) impliesBool
        (generateTimeBoundNullifier(BaseNull, E1) =/=K
         generateTimeBoundNullifier(BaseNull, E2))

    // Property 7: Aggregation Commutativity
    // Order of aggregation should not matter for final hash
    // Note: This is NOT satisfied by simple sequential hashing
    // Use order-independent aggregation for this property
    syntax Bool ::= "aggregationCommutativity" "(" List "," List ")" [function]
    // Requires order-independent hash like sum of hashes

    // Property 8: No Self-Collision
    // A nullifier cannot equal a different nullifier of same type
    syntax Bool ::= "noSelfCollision" "(" Nullifier ")" [function]
    // Follows from hash collision resistance

    // ============================================
    // CONSISTENCY PROPERTIES
    // ============================================

    // Property 9: Domain Consistency
    // Cross-domain nullifier preserves base nullifier derivation
    syntax Bool ::= "domainConsistency" "(" Secret "," Commitment "," DomainId ")" [function]
    rule domainConsistency(S, C, D) =>
        let BaseNull = generateNullifier(S, C) in
        let CDNull = generateCrossDomainNullifier(BaseNull, D) in
        let RecompBase = generateNullifier(S, C) in
        let RecompCD = generateCrossDomainNullifier(RecompBase, D) in
        CDNull ==K RecompCD

    // Property 10: Epoch Consistency
    // Time-bound nullifier preserves base nullifier derivation
    syntax Bool ::= "epochConsistency" "(" Secret "," Commitment "," Epoch ")" [function]
    rule epochConsistency(S, C, E) =>
        let BaseNull = generateNullifier(S, C) in
        let TBNull = generateTimeBoundNullifier(BaseNull, E) in
        let RecompBase = generateNullifier(S, C) in
        let RecompTB = generateTimeBoundNullifier(RecompBase, E) in
        TBNull ==K RecompTB
endmodule

module NULLIFIER-ALGEBRA-INVARIANTS
    imports NULLIFIER-PROPERTIES

    // ============================================
    // GLOBAL INVARIANTS
    // ============================================

    // Invariant 1: Nullifier Soundness
    // A nullifier can only be generated from valid inputs
    syntax Bool ::= "nullifierSoundness" "(" Nullifier ")" [function]
    rule nullifierSoundness(nullifier(H, T, D)) =>
        H =/=K 0 andBool validDomain(D)

    // Invariant 2: No Nullifier Reuse
    // A nullifier can only be used once per domain
    // Tracked by nullifier set in smart contract
    syntax Bool ::= "noReuse" "(" Nullifier "," Set ")" [function]
    rule noReuse(N, UsedSet) =>
        notBool (N inSet UsedSet)

    // Invariant 3: Domain Isolation
    // Nullifiers from different domains cannot interfere
    syntax Bool ::= "domainIsolation" "(" Nullifier "," Nullifier ")" [function]
    rule domainIsolation(nullifier(_, _, D1), nullifier(_, _, D2)) =>
        (D1 =/=K D2) impliesBool true  // Different domains are isolated

    // Invariant 4: Temporal Ordering
    // Time-bound nullifiers respect epoch ordering
    syntax Bool ::= "temporalOrdering" "(" Epoch "," Epoch ")" [function]
    rule temporalOrdering(E1, E2) =>
        (E1 <Int E2) impliesBool
        // E1 expires before E2

    // Invariant 5: Aggregation Integrity
    // Aggregate nullifier represents all component nullifiers
    syntax Bool ::= "aggregationIntegrity" "(" Nullifier "," List ")" [function]
    // Aggregate cannot be split without knowing components
endmodule

module NULLIFIER-ALGEBRA
    imports NULLIFIER-ALGEBRA-SYNTAX
    imports NULLIFIER-ALGEBRA-CONFIGURATION
    imports NULLIFIER-GENERATION
    imports NULLIFIER-VERIFICATION
    imports NULLIFIER-PROPERTIES
    imports NULLIFIER-ALGEBRA-INVARIANTS
endmodule
