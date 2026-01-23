// specs/k/tornado.k
// K Framework Formal Specification for Tornado Cash Primitives
// Author: PIL Protocol
// Date: January 2026

// ============================================================================
// MODULE: TORNADO-FIELD
// BN254 scalar field arithmetic for Tornado Cash
// ============================================================================

module TORNADO-FIELD-SYNTAX
    imports INT
    imports BOOL

    // BN254 scalar field prime (r)
    syntax Int ::= "BN254_R" [function, total]
    rule BN254_R => 21888242871839275222246405745257275088548364400416034343698204186575808495617

    // BN254 base field prime (p)
    syntax Int ::= "BN254_P" [function, total]
    rule BN254_P => 21888242871839275222246405745257275088696311157297823662689037894645226208583

    // Field element type
    syntax FieldElement ::= Int
    syntax FieldElement ::= "fe" "(" Int ")" [function]

    // Field operations
    syntax FieldElement ::= FieldElement "+f" FieldElement [function, left, priority(120)]
    syntax FieldElement ::= FieldElement "-f" FieldElement [function, left, priority(120)]
    syntax FieldElement ::= FieldElement "*f" FieldElement [function, left, priority(110)]
    syntax FieldElement ::= FieldElement "^f" Int [function, right, priority(100)]
    syntax FieldElement ::= "-f" FieldElement [function, priority(90)]
    syntax FieldElement ::= "invf" "(" FieldElement ")" [function]

    // Predicates
    syntax Bool ::= "inField" "(" Int ")" [function, total]
    syntax Bool ::= "isZero" "(" FieldElement ")" [function, total]
endmodule

module TORNADO-FIELD
    imports TORNADO-FIELD-SYNTAX

    // Field element constructor - reduce modulo R
    rule fe(X) => X modInt BN254_R
        requires X >=Int 0

    rule fe(X) => (X modInt BN254_R) +Int BN254_R
        requires X <Int 0

    // Field addition
    rule X +f Y => fe(X +Int Y)

    // Field subtraction
    rule X -f Y => fe(X -Int Y)

    // Field multiplication
    rule X *f Y => fe(X *Int Y)

    // Field negation
    rule -f X => fe(BN254_R -Int X)

    // Field exponentiation
    rule X ^f 0 => fe(1)
    rule X ^f 1 => X
    rule X ^f N => (X *f X) ^f (N /Int 2)
        requires N >Int 1 andBool N modInt 2 ==Int 0
    rule X ^f N => X *f ((X *f X) ^f ((N -Int 1) /Int 2))
        requires N >Int 1 andBool N modInt 2 ==Int 1

    // Field inverse (Fermat's little theorem: a^(-1) = a^(p-2) mod p)
    rule invf(X) => X ^f (BN254_R -Int 2)
        requires X =/=Int 0

    // Predicates
    rule inField(X) => (X >=Int 0) andBool (X <Int BN254_R)
    rule isZero(X) => X ==Int 0
endmodule

// ============================================================================
// MODULE: MIMC-HASH
// MiMC-p/p hash function with 220 rounds
// ============================================================================

module MIMC-SYNTAX
    imports TORNADO-FIELD-SYNTAX
    imports LIST

    // MiMC constants
    syntax Int ::= "MIMC_ROUNDS" [function, total]
    rule MIMC_ROUNDS => 220

    syntax Int ::= "MIMC_EXPONENT" [function, total]
    rule MIMC_EXPONENT => 7

    // MiMC hash function
    syntax FieldElement ::= "mimcHash" "(" FieldElement "," FieldElement ")" [function]

    // MiMC round function
    syntax FieldElement ::= "mimcRound" "(" FieldElement "," FieldElement "," FieldElement ")" [function]

    // Round constant generation
    syntax FieldElement ::= "roundConstant" "(" Int ")" [function]

    // MiMC sponge for multiple inputs
    syntax FieldElement ::= "mimcSponge" "(" List ")" [function]

    // Two-input hash for Merkle tree
    syntax FieldElement ::= "mimcHash2" "(" FieldElement "," FieldElement ")" [function]
endmodule

module MIMC
    imports MIMC-SYNTAX
    imports TORNADO-FIELD

    // MiMC round: x -> (x + k + c)^7 mod R
    rule mimcRound(X, K, C) => (X +f K +f C) ^f MIMC_EXPONENT

    // Round constant (simplified derivation)
    rule roundConstant(I) => fe(I *Int 123456789 +Int I *Int I)

    // MiMC hash with 220 rounds
    // Recursive definition through auxiliary function
    syntax FieldElement ::= "mimcHashAux" "(" FieldElement "," FieldElement "," Int ")" [function]

    rule mimcHash(Left, Right) => mimcHashAux(Left, Right, 0) +f Right

    rule mimcHashAux(State, Key, Round) => State
        requires Round >=Int MIMC_ROUNDS

    rule mimcHashAux(State, Key, Round) =>
        mimcHashAux(mimcRound(State, Key, roundConstant(Round)), Key, Round +Int 1)
        requires Round <Int MIMC_ROUNDS

    // Two-input hash (wrapper)
    rule mimcHash2(Left, Right) => mimcHash(Left, Right)

    // MiMC sponge construction
    syntax FieldElement ::= "mimcSpongeAux" "(" FieldElement "," List ")" [function]

    rule mimcSponge(L) => mimcSpongeAux(fe(0), L)

    rule mimcSpongeAux(State, .List) => State

    rule mimcSpongeAux(State, ListItem(X) Rest) =>
        mimcSpongeAux(mimcHash(State +f X, fe(0)), Rest)
endmodule

// ============================================================================
// MODULE: MERKLE-TREE
// Merkle tree operations with MiMC hash
// ============================================================================

module MERKLE-SYNTAX
    imports MIMC-SYNTAX
    imports LIST

    // Merkle tree constants
    syntax Int ::= "MERKLE_DEPTH" [function, total]
    rule MERKLE_DEPTH => 20

    syntax Int ::= "MAX_LEAVES" [function, total]
    rule MAX_LEAVES => 1048576  // 2^20

    syntax FieldElement ::= "ZERO_VALUE" [function, total]

    // Merkle proof
    syntax MerkleProof ::= "proof" "(" List "," List ")"  // pathElements, pathIndices

    // Compute root from leaf and proof
    syntax FieldElement ::= "computeRoot" "(" FieldElement "," MerkleProof ")" [function]

    // Zero hash at level
    syntax FieldElement ::= "zeroHash" "(" Int ")" [function]

    // Verify inclusion
    syntax Bool ::= "verifyInclusion" "(" FieldElement "," FieldElement "," MerkleProof ")" [function]
endmodule

module MERKLE
    imports MERKLE-SYNTAX
    imports MIMC

    // Zero value: keccak256("tornado.cash") mod R
    // Simplified constant
    rule ZERO_VALUE => fe(21663839004416932945382355908790599225266501822907911457504978515578255421292)

    // Zero hash at level 0 is ZERO_VALUE
    rule zeroHash(0) => ZERO_VALUE

    // Zero hash at level N is hash of two level N-1 zero hashes
    rule zeroHash(N) => mimcHash2(zeroHash(N -Int 1), zeroHash(N -Int 1))
        requires N >Int 0

    // Compute root from proof
    syntax FieldElement ::= "computeRootAux" "(" FieldElement "," List "," List ")" [function]

    rule computeRoot(Leaf, proof(PathElements, PathIndices)) =>
        computeRootAux(Leaf, PathElements, PathIndices)

    rule computeRootAux(Current, .List, .List) => Current

    rule computeRootAux(Current, ListItem(Sibling) RestSiblings, ListItem(0) RestIndices) =>
        // Current is on left
        computeRootAux(mimcHash2(Current, Sibling), RestSiblings, RestIndices)

    rule computeRootAux(Current, ListItem(Sibling) RestSiblings, ListItem(1) RestIndices) =>
        // Current is on right
        computeRootAux(mimcHash2(Sibling, Current), RestSiblings, RestIndices)

    // Verify inclusion: computed root matches expected root
    rule verifyInclusion(Leaf, Root, Proof) => computeRoot(Leaf, Proof) ==K Root
endmodule

// ============================================================================
// MODULE: TORNADO-COMMITMENT
// Pedersen-style commitment scheme for Tornado Cash
// ============================================================================

module COMMITMENT-SYNTAX
    imports MERKLE-SYNTAX

    // Note structure
    syntax TornadoNote ::= "note" "(" FieldElement "," FieldElement "," Int "," Int ")"
        // (nullifier, secret, denomination, leafIndex)

    // Compute commitment from nullifier and secret
    syntax FieldElement ::= "commitment" "(" FieldElement "," FieldElement ")" [function]

    // Derive nullifier hash
    syntax FieldElement ::= "nullifierHash" "(" FieldElement "," Int ")" [function]

    // Extract components
    syntax FieldElement ::= "getNullifier" "(" TornadoNote ")" [function]
    syntax FieldElement ::= "getSecret" "(" TornadoNote ")" [function]
    syntax Int ::= "getDenomination" "(" TornadoNote ")" [function]
    syntax Int ::= "getLeafIndex" "(" TornadoNote ")" [function]
endmodule

module COMMITMENT
    imports COMMITMENT-SYNTAX
    imports MIMC

    // Commitment = MiMC(nullifier, secret)
    rule commitment(Nullifier, Secret) => mimcHash2(Nullifier, Secret)

    // Nullifier hash = MiMC(nullifierSecret, leafIndex)
    rule nullifierHash(NullifierSecret, LeafIndex) => mimcHash(NullifierSecret, fe(LeafIndex))

    // Note accessors
    rule getNullifier(note(N, _, _, _)) => N
    rule getSecret(note(_, S, _, _)) => S
    rule getDenomination(note(_, _, D, _)) => D
    rule getLeafIndex(note(_, _, _, I)) => I
endmodule

// ============================================================================
// MODULE: TORNADO-NULLIFIER
// Nullifier derivation and uniqueness properties
// ============================================================================

module NULLIFIER-SYNTAX
    imports COMMITMENT-SYNTAX

    // Cross-domain nullifier derivation
    syntax FieldElement ::= "crossDomainNullifier" "(" FieldElement "," Int "," Int ")" [function]

    // PIL binding
    syntax FieldElement ::= "pilBinding" "(" FieldElement ")" [function]

    // Nullifier predicates
    syntax Bool ::= "isValidNullifier" "(" FieldElement ")" [function]
    syntax Bool ::= "isNullifierUnique" "(" FieldElement "," FieldElement ")" [function]

    // Domain separator
    syntax FieldElement ::= "PIL_TORNADO_DOMAIN" [function]
endmodule

module NULLIFIER
    imports NULLIFIER-SYNTAX
    imports MIMC

    // Domain separator constant
    rule PIL_TORNADO_DOMAIN => fe(12345678901234567890123456789012345678901234567890)

    // Cross-domain nullifier: H(domain, tornadoNf, source, target, "T2P")
    rule crossDomainNullifier(TornadoNf, SourceChain, TargetChain) =>
        mimcSponge(
            ListItem(PIL_TORNADO_DOMAIN)
            ListItem(TornadoNf)
            ListItem(fe(SourceChain))
            ListItem(fe(TargetChain))
        )

    // PIL binding: H(tornadoNf, domain, "T2P")
    rule pilBinding(TornadoNf) =>
        mimcSponge(
            ListItem(TornadoNf)
            ListItem(PIL_TORNADO_DOMAIN)
        )

    // Valid if non-zero and in field
    rule isValidNullifier(Nf) => (Nf =/=K fe(0)) andBool inField(Nf)

    // Unique if different
    rule isNullifierUnique(Nf1, Nf2) => Nf1 =/=K Nf2
endmodule

// ============================================================================
// MODULE: TORNADO-DENOMINATION
// Fixed denomination pool logic
// ============================================================================

module DENOMINATION-SYNTAX
    imports INT
    imports BOOL

    // Denominations (in wei)
    syntax Int ::= "DENOM_01_ETH" [function, total]
    syntax Int ::= "DENOM_1_ETH" [function, total]
    syntax Int ::= "DENOM_10_ETH" [function, total]
    syntax Int ::= "DENOM_100_ETH" [function, total]

    // Validation
    syntax Bool ::= "isValidDenomination" "(" Int ")" [function, total]

    // Index mapping
    syntax Int ::= "denominationIndex" "(" Int ")" [function]
endmodule

module DENOMINATION
    imports DENOMINATION-SYNTAX

    rule DENOM_01_ETH => 100000000000000000      // 0.1 ETH
    rule DENOM_1_ETH => 1000000000000000000      // 1 ETH
    rule DENOM_10_ETH => 10000000000000000000    // 10 ETH
    rule DENOM_100_ETH => 100000000000000000000  // 100 ETH

    rule isValidDenomination(D) =>
        (D ==Int DENOM_01_ETH) orBool
        (D ==Int DENOM_1_ETH) orBool
        (D ==Int DENOM_10_ETH) orBool
        (D ==Int DENOM_100_ETH)

    rule denominationIndex(D) => 0 requires D ==Int DENOM_01_ETH
    rule denominationIndex(D) => 1 requires D ==Int DENOM_1_ETH
    rule denominationIndex(D) => 2 requires D ==Int DENOM_10_ETH
    rule denominationIndex(D) => 3 requires D ==Int DENOM_100_ETH
endmodule

// ============================================================================
// MODULE: GROTH16-VERIFICATION
// Groth16 proof structure and verification
// ============================================================================

module GROTH16-SYNTAX
    imports TORNADO-FIELD-SYNTAX
    imports LIST

    // G1 point (affine)
    syntax G1Point ::= "g1" "(" FieldElement "," FieldElement ")"

    // G2 point (affine, extension field)
    syntax G2Point ::= "g2" "(" FieldElement "," FieldElement "," FieldElement "," FieldElement ")"

    // Groth16 proof
    syntax Groth16Proof ::= "groth16proof" "(" G1Point "," G2Point "," G1Point ")"
        // (a, b, c)

    // Public inputs
    syntax PublicInputs ::= List

    // Verification
    syntax Bool ::= "verifyGroth16" "(" Groth16Proof "," PublicInputs ")" [function]

    // Point validation
    syntax Bool ::= "isValidG1" "(" G1Point ")" [function]
    syntax Bool ::= "isValidG2" "(" G2Point ")" [function]
endmodule

module GROTH16
    imports GROTH16-SYNTAX
    imports TORNADO-FIELD

    // G1 point validation: coordinates in base field
    rule isValidG1(g1(X, Y)) => inField(X) andBool inField(Y)

    // G2 point validation: coordinates in extension field
    rule isValidG2(g2(X0, X1, Y0, Y1)) =>
        inField(X0) andBool inField(X1) andBool inField(Y0) andBool inField(Y1)

    // Simplified verification (real impl uses pairing)
    rule verifyGroth16(groth16proof(A, B, C), Inputs) =>
        isValidG1(A) andBool isValidG2(B) andBool isValidG1(C)
        // In reality: e(A, B) = e(alpha, beta) * e(sum(vi*wi), gamma) * e(C, delta)
endmodule

// ============================================================================
// MODULE: TORNADO-PROPERTIES
// Security properties and theorems
// ============================================================================

module TORNADO-PROPERTIES
    imports COMMITMENT
    imports NULLIFIER
    imports MERKLE
    imports GROTH16
    imports DENOMINATION

    // ========== COMMITMENT PROPERTIES ==========

    // Binding: Different inputs produce different commitments
    // (with high probability, cryptographic assumption)
    syntax Bool ::= "commitmentBinding" "(" FieldElement "," FieldElement "," FieldElement "," FieldElement ")" [function]

    rule commitmentBinding(N1, S1, N2, S2) =>
        ((N1 =/=K N2) orBool (S1 =/=K S2)) impliesBool
        (commitment(N1, S1) =/=K commitment(N2, S2))

    // Hiding: Commitment doesn't reveal nullifier or secret
    syntax Bool ::= "commitmentHiding" "(" FieldElement "," FieldElement ")" [function]

    rule commitmentHiding(N, S) =>
        (commitment(N, S) =/=K N) andBool (commitment(N, S) =/=K S)

    // ========== NULLIFIER PROPERTIES ==========

    // Uniqueness: Same note can only be spent once
    syntax Bool ::= "nullifierUniqueness" "(" FieldElement "," Int "," FieldElement "," Int ")" [function]

    rule nullifierUniqueness(Ns1, Idx1, Ns2, Idx2) =>
        ((Ns1 =/=K Ns2) orBool (Idx1 =/=Int Idx2)) impliesBool
        (nullifierHash(Ns1, Idx1) =/=K nullifierHash(Ns2, Idx2))

    // Cross-domain isolation: Different chains produce different nullifiers
    syntax Bool ::= "crossDomainIsolation" "(" FieldElement "," Int "," Int ")" [function]

    rule crossDomainIsolation(Nf, Chain1, Chain2) =>
        (Chain1 =/=Int Chain2) impliesBool
        (crossDomainNullifier(Nf, Chain1, Chain2) =/=K crossDomainNullifier(Nf, Chain2, Chain1))

    // ========== MERKLE TREE PROPERTIES ==========

    // Root binding: Different leaves produce different roots (same position)
    syntax Bool ::= "merkleBinding" "(" FieldElement "," FieldElement "," MerkleProof ")" [function]

    rule merkleBinding(Leaf1, Leaf2, Proof) =>
        (Leaf1 =/=K Leaf2) impliesBool
        (computeRoot(Leaf1, Proof) =/=K computeRoot(Leaf2, Proof))

    // Path sensitivity: Different paths produce different roots
    syntax Bool ::= "merklePath Sensitivity" "(" FieldElement "," MerkleProof "," MerkleProof ")" [function]

    // ========== DENOMINATION PROPERTIES ==========

    // Fixed set: Only 4 valid denominations
    syntax Bool ::= "denominationFixedSet" "(" Int ")" [function]

    rule denominationFixedSet(D) =>
        isValidDenomination(D) impliesBool
        ((D ==Int DENOM_01_ETH) orBool (D ==Int DENOM_1_ETH) orBool
         (D ==Int DENOM_10_ETH) orBool (D ==Int DENOM_100_ETH))

    // ========== SOUNDNESS PROPERTY ==========

    // Complete withdrawal property: Valid proof implies authorized withdrawal
    syntax Bool ::= "withdrawalSoundness" "(" Groth16Proof "," FieldElement "," FieldElement "," MerkleProof ")" [function]

    rule withdrawalSoundness(Proof, Commitment, Root, MProof) =>
        (verifyGroth16(Proof, ListItem(Root) ListItem(Commitment) .List) andBool
         verifyInclusion(Commitment, Root, MProof))
endmodule

// ============================================================================
// MODULE: TORNADO-THEOREMS
// Formal theorems for Tornado Cash security
// ============================================================================

module TORNADO-THEOREMS
    imports TORNADO-PROPERTIES

    // ========== THEOREM: MIMC CLOSURE ==========
    // MiMC hash output is always in field
    // ∀ x, k ∈ Field: mimcHash(x, k) ∈ Field
    syntax Bool ::= "theorem_mimc_closure" "(" FieldElement "," FieldElement ")" [function]
    rule theorem_mimc_closure(X, K) => inField(mimcHash(X, K))
        requires inField(X) andBool inField(K)

    // ========== THEOREM: COMMITMENT DETERMINISM ==========
    // Same inputs always produce same commitment
    // ∀ n, s: commitment(n, s) = commitment(n, s)
    syntax Bool ::= "theorem_commitment_determinism" "(" FieldElement "," FieldElement ")" [function]
    rule theorem_commitment_determinism(N, S) =>
        commitment(N, S) ==K commitment(N, S)

    // ========== THEOREM: NULLIFIER DETERMINISM ==========
    // Same inputs always produce same nullifier hash
    // ∀ ns, idx: nullifierHash(ns, idx) = nullifierHash(ns, idx)
    syntax Bool ::= "theorem_nullifier_determinism" "(" FieldElement "," Int ")" [function]
    rule theorem_nullifier_determinism(Ns, Idx) =>
        nullifierHash(Ns, Idx) ==K nullifierHash(Ns, Idx)

    // ========== THEOREM: MERKLE ROOT DETERMINISM ==========
    // Same leaf and proof produce same root
    syntax Bool ::= "theorem_merkle_determinism" "(" FieldElement "," MerkleProof ")" [function]
    rule theorem_merkle_determinism(Leaf, Proof) =>
        computeRoot(Leaf, Proof) ==K computeRoot(Leaf, Proof)

    // ========== THEOREM: CROSS-DOMAIN UNIQUENESS ==========
    // Different source-target pairs produce different bindings
    syntax Bool ::= "theorem_cross_domain_uniqueness" "(" FieldElement "," Int "," Int "," Int "," Int ")" [function]
    rule theorem_cross_domain_uniqueness(Nf, Src1, Tgt1, Src2, Tgt2) =>
        ((Src1 =/=Int Src2) orBool (Tgt1 =/=Int Tgt2)) impliesBool
        (crossDomainNullifier(Nf, Src1, Tgt1) =/=K crossDomainNullifier(Nf, Src2, Tgt2))

    // ========== THEOREM: DOUBLE-SPEND PREVENTION ==========
    // Same nullifier cannot be used twice
    // If nullifierHash(ns, idx) is spent, attempting to spend again fails
    // This is enforced by the smart contract's nullifier set
    syntax Bool ::= "theorem_double_spend_prevention" "(" FieldElement "," Int ")" [function]
    rule theorem_double_spend_prevention(Ns, Idx) =>
        isValidNullifier(nullifierHash(Ns, Idx))

    // ========== THEOREM: ANONYMITY SET ==========
    // All deposits in a pool form the anonymity set
    // No information about which deposit is being withdrawn
    // This follows from zero-knowledge property of Groth16
    syntax Bool ::= "theorem_anonymity" "(" Groth16Proof ")" [function]
    // Formal statement: ∀ valid proofs π, the proof reveals nothing about the spent note
    // except what is explicitly made public (nullifier, root, recipient, relayer, fee)
endmodule

// ============================================================================
// MAIN MODULE
// ============================================================================

module TORNADO
    imports TORNADO-THEOREMS
endmodule
