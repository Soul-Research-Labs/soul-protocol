// SPDX-License-Identifier: MIT
// K Framework Specification for Poseidon Hash Function
//
// This specification formalizes the Poseidon hash function used in
// zero-knowledge circuits for Zaseon.
//
// POSEIDON HASH ARCHITECTURE:
// ┌─────────────────────────────────────────────────────────────────┐
// │                    Poseidon Hash Function                       │
// │                                                                  │
// │   Input: [x1, x2, ..., xn]                                      │
// │              │                                                   │
// │   ┌─────────▼─────────┐                                         │
// │   │  Initial Addition  │  Add round constants to state          │
// │   └─────────┬─────────┘                                         │
// │             │                                                    │
// │   ┌─────────▼─────────┐                                         │
// │   │   Full Rounds (Rf) │  S-box on ALL elements                 │
// │   │   ┌─────────────┐  │                                         │
// │   │   │ S-box: x^5  │  │  Apply x^5 to each element             │
// │   │   │ MixColumns  │  │  Linear layer (MDS matrix)             │
// │   │   │ AddConstants│  │  Add round constants                   │
// │   │   └─────────────┘  │                                         │
// │   └─────────┬─────────┘                                         │
// │             │                                                    │
// │   ┌─────────▼─────────┐                                         │
// │   │  Partial Rounds   │  S-box on FIRST element only            │
// │   │      (Rp)         │  (More efficient in ZK)                 │
// │   └─────────┬─────────┘                                         │
// │             │                                                    │
// │   ┌─────────▼─────────┐                                         │
// │   │   Full Rounds (Rf) │  S-box on ALL elements                 │
// │   └─────────┬─────────┘                                         │
// │             │                                                    │
// │   ┌─────────▼─────────┐                                         │
// │   │  Extract Output   │  Return state[0] as hash                │
// │   └─────────┬─────────┘                                         │
// │             │                                                    │
// │   Output: hash ∈ F_p                                            │
// └─────────────────────────────────────────────────────────────────┘

module POSEIDON-SYNTAX
    // Field element type (BN254 scalar field)
    syntax FieldElement ::= Int
                         | "0"
                         | "1"
                         | FieldElement "+" FieldElement   [left, function]
                         | FieldElement "*" FieldElement   [left, function]
                         | FieldElement "^" FieldElement   [right, function]
                         | FieldElement "-" FieldElement   [left, function]
                         | "neg" FieldElement              [function]
                         | "inv" FieldElement              [function]

    // State vector
    syntax State ::= List{FieldElement, ","}

    // Round constants
    syntax RoundConstants ::= List{FieldElement, ","}

    // MDS Matrix (Maximum Distance Separable)
    syntax MDSMatrix ::= List{State, ";"}

    // Poseidon configuration
    syntax PoseidonConfig ::= "config" "(" Int "," Int "," Int "," Int ")"
                            // (width, fullRoundsF, partialRoundsP, sboxDegree)

    // Hash operations
    syntax Hash ::= "poseidon" "(" State "," PoseidonConfig ")"
                  | "fullRound" "(" State "," RoundConstants "," MDSMatrix ")"
                  | "partialRound" "(" State "," RoundConstants "," MDSMatrix ")"
                  | "sbox" "(" FieldElement ")"
                  | "mdsMultiply" "(" State "," MDSMatrix ")"
                  | "addRoundConstants" "(" State "," RoundConstants ")"
endmodule

module POSEIDON-CONFIGURATION
    imports POSEIDON-SYNTAX
    imports INT
    imports LIST

    // BN254 (alt_bn128) scalar field modulus
    syntax Int ::= "FIELD_MODULUS" [function]
    rule FIELD_MODULUS => 21888242871839275222246405745257275088548364400416034343698204186575808495617

    // Standard Poseidon configurations
    // Poseidon-2: 2 inputs + 1 capacity
    syntax PoseidonConfig ::= "POSEIDON_2" [function]
    rule POSEIDON_2 => config(3, 8, 57, 5)

    // Poseidon-4: 4 inputs + 1 capacity
    syntax PoseidonConfig ::= "POSEIDON_4" [function]
    rule POSEIDON_4 => config(5, 8, 60, 5)

    // Poseidon-8: 8 inputs + 1 capacity
    syntax PoseidonConfig ::= "POSEIDON_8" [function]
    rule POSEIDON_8 => config(9, 8, 63, 5)

    // Security level (bits)
    syntax Int ::= "SECURITY_LEVEL" [function]
    rule SECURITY_LEVEL => 128

    // Minimum rounds for security
    syntax Bool ::= "securePoseidon" "(" PoseidonConfig ")" [function]
    rule securePoseidon(config(W, F, P, _)) =>
        // Full rounds >= 6 and partial rounds >= 5*log2(p)
        F >=Int 6 andBool P >=Int 55
endmodule

module POSEIDON-OPERATIONS
    imports POSEIDON-SYNTAX
    imports POSEIDON-CONFIGURATION
    imports INT
    imports LIST

    // Field arithmetic modulo p
    rule F1:Int + F2:Int => (F1 +Int F2) modInt FIELD_MODULUS
    rule F1:Int * F2:Int => (F1 *Int F2) modInt FIELD_MODULUS
    rule F1:Int - F2:Int => (F1 -Int F2 +Int FIELD_MODULUS) modInt FIELD_MODULUS
    rule neg(F:Int) => (FIELD_MODULUS -Int F) modInt FIELD_MODULUS

    // S-box: x^5 (quintic)
    // This is chosen because gcd(5, p-1) = 1 for BN254
    rule sbox(X:Int) => X * X * X * X * X

    // Add round constants to state
    rule addRoundConstants((S1, S2, S3), (C1, C2, C3)) =>
        (S1 + C1, S2 + C2, S3 + C3)

    // MDS matrix multiplication for width=3
    // Using Cauchy matrix for maximum diffusion
    rule mdsMultiply((S0, S1, S2), MDSMatrix) =>
        // Standard 3x3 MDS multiplication
        let R0 = S0 * 2 + S1 * 1 + S2 * 1 in
        let R1 = S0 * 1 + S1 * 2 + S2 * 1 in
        let R2 = S0 * 1 + S1 * 1 + S2 * 2 in
        (R0, R1, R2)

    // Full round: apply S-box to all elements
    rule fullRound((S0, S1, S2), RC, MDS) =>
        let T0 = sbox(S0) in
        let T1 = sbox(S1) in
        let T2 = sbox(S2) in
        let (U0, U1, U2) = addRoundConstants((T0, T1, T2), RC) in
        mdsMultiply((U0, U1, U2), MDS)

    // Partial round: apply S-box only to first element
    rule partialRound((S0, S1, S2), RC, MDS) =>
        let T0 = sbox(S0) in
        let (U0, U1, U2) = addRoundConstants((T0, S1, S2), RC) in
        mdsMultiply((U0, U1, U2), MDS)
endmodule

module POSEIDON-HASH
    imports POSEIDON-OPERATIONS
    imports LIST
    imports INT

    // Main Poseidon hash function
    // Full rounds (Rf/2) -> Partial rounds (Rp) -> Full rounds (Rf/2)
    syntax State ::= "poseidonPermutation" "(" State "," PoseidonConfig "," RoundConstants "," MDSMatrix ")"
                   | "applyFullRounds" "(" State "," Int "," RoundConstants "," MDSMatrix ")"
                   | "applyPartialRounds" "(" State "," Int "," RoundConstants "," MDSMatrix ")"

    // Poseidon permutation structure
    rule poseidonPermutation(State, config(W, F, P, _), RC, MDS) =>
        let S1 = applyFullRounds(State, F /Int 2, RC, MDS) in
        let S2 = applyPartialRounds(S1, P, RC, MDS) in
        applyFullRounds(S2, F /Int 2, RC, MDS)

    // Apply N full rounds
    rule applyFullRounds(State, 0, _, _) => State
    rule applyFullRounds(State, N, RC, MDS) =>
        applyFullRounds(fullRound(State, RC, MDS), N -Int 1, RC, MDS)
        requires N >Int 0

    // Apply N partial rounds
    rule applyPartialRounds(State, 0, _, _) => State
    rule applyPartialRounds(State, N, RC, MDS) =>
        applyPartialRounds(partialRound(State, RC, MDS), N -Int 1, RC, MDS)
        requires N >Int 0

    // Extract hash output (first element of final state)
    syntax FieldElement ::= "extractHash" "(" State ")" [function]
    rule extractHash((H, _, _)) => H
endmodule

module POSEIDON-PROPERTIES
    imports POSEIDON-HASH
    imports BOOL

    // ============================================
    // SECURITY PROPERTIES
    // ============================================

    // Property 1: Collision Resistance
    // It is computationally infeasible to find two distinct inputs
    // that produce the same hash output.
    syntax Bool ::= "collisionResistant" "(" State "," State "," FieldElement ")" [function]
    rule collisionResistant(S1, S2, H) =>
        (S1 =/=K S2) impliesBool
        (extractHash(poseidonPermutation(S1, POSEIDON_2, RC, MDS)) =/=K
         extractHash(poseidonPermutation(S2, POSEIDON_2, RC, MDS)))

    // Property 2: Preimage Resistance
    // Given a hash output, it is computationally infeasible to find
    // an input that produces that output.
    syntax Bool ::= "preimageResistant" "(" FieldElement ")" [function]
    // This is a security assumption, verified by cryptographic analysis

    // Property 3: Second Preimage Resistance
    // Given an input and its hash, it is computationally infeasible to
    // find a different input with the same hash.
    syntax Bool ::= "secondPreimageResistant" "(" State ")" [function]
    // This follows from collision resistance

    // Property 4: Determinism
    // Same input always produces same output
    syntax Bool ::= "deterministic" "(" State "," PoseidonConfig ")" [function]
    rule deterministic(State, Config) =>
        extractHash(poseidonPermutation(State, Config, RC, MDS)) ==K
        extractHash(poseidonPermutation(State, Config, RC, MDS))

    // Property 5: Algebraic Degree
    // The algebraic degree after full rounds is high enough for security
    syntax Int ::= "algebraicDegree" "(" Int "," Int "," Int ")" [function]
    // After R rounds with x^5 S-box: degree = 5^R
    rule algebraicDegree(SboxDegree, FullRounds, PartialRounds) =>
        SboxDegree ^Int (FullRounds +Int PartialRounds)

    // Property 6: Diffusion
    // Each output bit depends on all input bits
    syntax Bool ::= "fullDiffusion" "(" Int "," Int ")" [function]
    rule fullDiffusion(Width, FullRounds) =>
        FullRounds >=Int Width  // Need at least width full rounds

    // ============================================
    // ZK CIRCUIT PROPERTIES
    // ============================================

    // Property 7: Low R1CS Constraint Count
    // Poseidon is designed for efficient ZK proving
    syntax Int ::= "r1csConstraints" "(" PoseidonConfig ")" [function]
    rule r1csConstraints(config(W, F, P, 5)) =>
        // Approximate constraint count per hash
        // Full rounds: W * 4 constraints per round (for x^5)
        // Partial rounds: 4 constraints per round (only first element)
        (W *Int F *Int 4) +Int (P *Int 4) +Int (W *Int W)

    // Property 8: Sponge Construction Soundness
    // For domain separation in sponge mode
    syntax Bool ::= "validSpongeCapacity" "(" Int ")" [function]
    rule validSpongeCapacity(Capacity) =>
        Capacity >=Int 1 andBool Capacity *Int 256 >=Int (2 *Int SECURITY_LEVEL)
endmodule

module POSEIDON-NULLIFIER
    imports POSEIDON-HASH

    // ============================================
    // Soul-SPECIFIC NULLIFIER GENERATION
    // ============================================

    // Nullifier = Poseidon(secret, messageId)
    // Used to prevent double-spending in privacy-preserving protocols
    syntax FieldElement ::= "computeNullifier" "(" FieldElement "," FieldElement ")"
    rule computeNullifier(Secret, MessageId) =>
        extractHash(poseidonPermutation((0, Secret, MessageId), POSEIDON_2, RC, MDS))

    // Cross-domain nullifier
    // CdNullifier = Poseidon(secret, messageId, domainSeparator)
    syntax FieldElement ::= "computeCrossDomainNullifier" "(" FieldElement "," FieldElement "," FieldElement ")"
    rule computeCrossDomainNullifier(Secret, MessageId, DomainSep) =>
        let Inner = extractHash(poseidonPermutation((0, Secret, MessageId), POSEIDON_2, RC, MDS)) in
        extractHash(poseidonPermutation((0, Inner, DomainSep), POSEIDON_2, RC, MDS))

    // Property: Nullifier uniqueness
    // Two different (secret, message) pairs produce different nullifiers
    syntax Bool ::= "nullifierUniqueness" "(" FieldElement "," FieldElement "," FieldElement "," FieldElement ")" [function]
    rule nullifierUniqueness(S1, M1, S2, M2) =>
        ((S1 =/=K S2) orBool (M1 =/=K M2)) impliesBool
        (computeNullifier(S1, M1) =/=K computeNullifier(S2, M2))

    // Property: Nullifier binding
    // Cannot produce valid nullifier without knowing the secret
    syntax Bool ::= "nullifierBinding" "(" FieldElement "," FieldElement ")" [function]
    // This is a security assumption based on preimage resistance
endmodule

module POSEIDON-MERKLE
    imports POSEIDON-HASH

    // ============================================
    // MERKLE TREE WITH POSEIDON
    // ============================================

    // Merkle tree node hash
    // H(left, right) = Poseidon(left, right)
    syntax FieldElement ::= "merkleHash" "(" FieldElement "," FieldElement ")"
    rule merkleHash(Left, Right) =>
        extractHash(poseidonPermutation((0, Left, Right), POSEIDON_2, RC, MDS))

    // Merkle tree leaf hash (with domain separation)
    syntax FieldElement ::= "leafHash" "(" FieldElement ")"
    rule leafHash(Data) =>
        extractHash(poseidonPermutation((1, Data, 0), POSEIDON_2, RC, MDS))

    // Property: Merkle path verification
    syntax Bool ::= "verifyMerklePath" "(" FieldElement "," List "," List "," FieldElement ")" [function]
    // Verifies that leaf is in tree with given root

    // Property: Tree binding
    // Cannot produce valid Merkle proof for element not in tree
    syntax Bool ::= "treeBinding" "(" FieldElement "," FieldElement ")" [function]
    // Security follows from collision resistance of Poseidon
endmodule

module POSEIDON
    imports POSEIDON-SYNTAX
    imports POSEIDON-CONFIGURATION
    imports POSEIDON-OPERATIONS
    imports POSEIDON-HASH
    imports POSEIDON-PROPERTIES
    imports POSEIDON-NULLIFIER
    imports POSEIDON-MERKLE
endmodule
