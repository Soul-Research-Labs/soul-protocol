// SPDX-License-Identifier: MIT
/**
 * @title Cross-Chain Privacy K Framework Specification
 * @author Soul Protocol
 * @notice Formal specification for cross-chain privacy algebra
 */

module CROSS-CHAIN-PRIVACY-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports MAP
    imports SET

    // ==========================================================================
    // BASIC TYPES
    // ==========================================================================

    syntax Hash ::= "hash" "(" ByteArray ")"
    syntax ByteArray ::= Bytes | Hash | Int
    
    syntax FieldElement ::= Int
    syntax Point ::= "(" FieldElement "," FieldElement ")"
    syntax Scalar ::= Int

    // ==========================================================================
    // PRIVACY LEVELS
    // ==========================================================================

    syntax PrivacyLevel ::= "NONE" | "BASIC" | "MEDIUM" | "HIGH" | "MAXIMUM"

    // ==========================================================================
    // CHAIN TYPES
    // ==========================================================================

    syntax ChainType ::= "EVM" | "UTXO" | "ACCOUNT" | "PRIVACY" | "COSMOS" | "ENTERPRISE"

    syntax ChainId ::= Int

    syntax ChainDomain ::= "domain" "(" ChainId "," ChainType "," Hash ")"

    // ==========================================================================
    // NULLIFIER TYPES
    // ==========================================================================

    syntax NullifierType ::= "STANDARD" | "CROSS_DOMAIN" | "TIME_BOUND" | "BATCH" | "RECURSIVE"

    syntax NullifierStatus ::= "UNKNOWN" | "REGISTERED" | "SPENT" | "REVOKED" | "EXPIRED"

    syntax Nullifier ::= "nf" "(" Hash "," NullifierType "," ChainId ")"

    // ==========================================================================
    // STEALTH ADDRESS TYPES
    // ==========================================================================

    syntax CurveType ::= "SECP256K1" | "ED25519" | "BLS12_381" | "PALLAS" | "VESTA" | "BN254"

    syntax KeyStatus ::= "INACTIVE" | "ACTIVE" | "REVOKED_KEY"

    syntax StealthMetaAddress ::= "meta" "(" Point "," Point "," CurveType ")"
    
    syntax StealthAddress ::= "stealth" "(" Point "," Hash "," Point ")"  // (address, viewTag, ephemeralPubKey)

    // ==========================================================================
    // PEDERSEN COMMITMENTS
    // ==========================================================================

    syntax PedersenCommitment ::= "C" "(" FieldElement "," FieldElement ")"  // C(amount, blinding)

    syntax CommitmentOpening ::= "open" "(" FieldElement "," FieldElement ")"  // (amount, blinding)

    // ==========================================================================
    // KEY IMAGES
    // ==========================================================================

    syntax KeyImage ::= "I" "(" Point ")"

    // ==========================================================================
    // RING SIGNATURES
    // ==========================================================================

    syntax RingMember ::= "member" "(" Point "," PedersenCommitment ")"

    syntax Ring ::= List{RingMember, ","}

    syntax CLSAGSignature ::= "clsag" "(" FieldElement "," List "," KeyImage "," Hash ")"

    // ==========================================================================
    // CROSS-DOMAIN BINDING
    // ==========================================================================

    syntax CrossDomainBinding ::= "binding" "(" Nullifier "," Nullifier "," Hash "," ChainId "," ChainId ")"

    // ==========================================================================
    // TRANSACTIONS
    // ==========================================================================

    syntax RCTInput ::= "input" "(" Ring "," CLSAGSignature ")"

    syntax RCTOutput ::= "output" "(" StealthAddress "," PedersenCommitment "," Bytes ")"  // (addr, commitment, rangeProof)

    syntax RCTTransaction ::= "rct" "(" List "," List "," FieldElement ")"  // (inputs, outputs, fee)

endmodule

module CROSS-CHAIN-PRIVACY-SEMANTICS
    imports CROSS-CHAIN-PRIVACY-SYNTAX
    imports INT
    imports BOOL

    // ==========================================================================
    // CURVE CONSTANTS
    // ==========================================================================

    syntax Int ::= "SECP256K1_N" [function]
    rule SECP256K1_N => 115792089237316195423570985008687907852837564279074904382605163141518161494337

    syntax Int ::= "BLS12_381_R" [function]  
    rule BLS12_381_R => 52435875175126190479447740508185965837690552500527637822603658699938581184513

    syntax Int ::= "ED25519_L" [function]
    rule ED25519_L => 7237005577332262213973186563042994240857116359379907606001950938285454250989

    // ==========================================================================
    // DOMAIN SEPARATORS
    // ==========================================================================

    syntax Hash ::= "NULLIFIER_DOMAIN" [function]
    syntax Hash ::= "STEALTH_DOMAIN" [function]
    syntax Hash ::= "RINGCT_DOMAIN" [function]
    syntax Hash ::= "CROSS_DOMAIN_TAG" [function]
    syntax Hash ::= "Soul_BINDING_TAG" [function]

    // ==========================================================================
    // STEALTH ADDRESS OPERATIONS
    // ==========================================================================

    /**
     * Derive stealth address from meta-address and ephemeral key
     * 
     * Protocol:
     * 1. Compute shared secret: S = ephemeralPriv * viewingPubKey
     * 2. Derive stealth pubkey: P' = spendingPubKey + hash(S) * G
     * 3. Compute view tag: viewTag = first_byte(S)
     */
    syntax StealthAddress ::= deriveStealthAddress(StealthMetaAddress, Scalar) [function]
    
    rule deriveStealthAddress(meta(SpendPub, ViewPub, Curve), EphemeralPriv) =>
        stealth(
            pointAdd(SpendPub, scalarMul(hashToScalar(ecdh(EphemeralPriv, ViewPub)), generator(Curve))),
            viewTag(ecdh(EphemeralPriv, ViewPub)),
            scalarMul(EphemeralPriv, generator(Curve))
        )

    /**
     * Check if stealth address belongs to recipient
     */
    syntax Bool ::= checkStealthOwnership(StealthAddress, Scalar, Point) [function]
    
    rule checkStealthOwnership(stealth(Addr, _, EphPub), ViewPriv, SpendPub) =>
        Addr ==K pointAdd(SpendPub, scalarMul(hashToScalar(ecdh(ViewPriv, EphPub)), generator(SECP256K1)))

    // ==========================================================================
    // NULLIFIER OPERATIONS
    // ==========================================================================

    /**
     * Derive chain-specific nullifier
     * nf_chain = H(secret || commitment || chainId || "CHAIN_NULLIFIER")
     */
    syntax Hash ::= deriveChainNullifier(Hash, Hash, ChainId) [function]
    
    rule deriveChainNullifier(Secret, Commitment, Chain) =>
        hash(concat(Secret, concat(Commitment, concat(intToBytes(Chain), "CHAIN_NULLIFIER"))))

    /**
     * Derive cross-domain nullifier
     * nf_cross = H(nf_source || sourceChain || destChain || "CROSS_DOMAIN")
     */
    syntax Hash ::= deriveCrossDomainNullifier(Hash, ChainId, ChainId) [function]
    
    rule deriveCrossDomainNullifier(SourceNf, SourceChain, DestChain) =>
        hash(concat(SourceNf, concat(intToBytes(SourceChain), concat(intToBytes(DestChain), "CROSS_DOMAIN"))))

    /**
     * Derive Soul unified nullifier
     * nf_pil = H(nf_source || domain || "Soul_BINDING")
     */
    syntax Hash ::= deriveSoulNullifier(Hash, Hash) [function]
    
    rule deriveSoulNullifier(SourceNf, Domain) =>
        hash(concat(SourceNf, concat(Domain, "Soul_BINDING")))

    // ==========================================================================
    // PEDERSEN COMMITMENT OPERATIONS
    // ==========================================================================

    /**
     * Create Pedersen commitment: C = amount*H + blinding*G
     */
    syntax Point ::= createCommitment(FieldElement, FieldElement) [function]
    
    rule createCommitment(Amount, Blinding) =>
        pointAdd(scalarMul(Amount, H_POINT), scalarMul(Blinding, G_POINT))

    /**
     * Verify commitment opens to claimed values
     */
    syntax Bool ::= verifyCommitmentOpening(Point, CommitmentOpening) [function]
    
    rule verifyCommitmentOpening(C, open(Amount, Blinding)) =>
        C ==K createCommitment(Amount, Blinding)

    /**
     * Verify homomorphic balance: sum(inputs) = sum(outputs) + fee
     */
    syntax Bool ::= verifyCommitmentBalance(List, List, PedersenCommitment) [function]
    
    rule verifyCommitmentBalance(InputCommitments, OutputCommitments, FeeCommitment) =>
        sumCommitments(InputCommitments) ==K 
        pointAdd(sumCommitments(OutputCommitments), commitmentToPoint(FeeCommitment))

    // ==========================================================================
    // KEY IMAGE OPERATIONS
    // ==========================================================================

    /**
     * Compute key image: I = privKey * H_p(pubKey)
     */
    syntax KeyImage ::= computeKeyImage(Scalar, Point) [function]
    
    rule computeKeyImage(PrivKey, PubKey) =>
        I(scalarMul(PrivKey, hashToPoint(PubKey)))

    /**
     * Verify key image is valid for public key
     */
    syntax Bool ::= verifyKeyImage(KeyImage, Point, Scalar) [function]
    
    rule verifyKeyImage(I(Img), PubKey, PrivKey) =>
        Img ==K scalarMul(PrivKey, hashToPoint(PubKey))

    // ==========================================================================
    // CLSAG RING SIGNATURE OPERATIONS
    // ==========================================================================

    /**
     * Verify CLSAG signature
     */
    syntax Bool ::= verifyCLSAG(Ring, CLSAGSignature) [function]
    
    rule verifyCLSAG(R, clsag(C0, S, I, M)) =>
        computeFinalChallenge(R, S, I, M) ==K C0

    /**
     * Compute final challenge (should equal initial challenge if valid)
     */
    syntax FieldElement ::= computeFinalChallenge(Ring, List, KeyImage, Hash) [function]

    // ==========================================================================
    // CROSS-DOMAIN BINDING OPERATIONS
    // ==========================================================================

    /**
     * Create cross-domain binding
     */
    syntax CrossDomainBinding ::= createBinding(Nullifier, ChainId, ChainId) [function]
    
    rule createBinding(nf(H, T, SrcChain), SrcChain, DstChain) =>
        binding(
            nf(H, T, SrcChain),
            nf(deriveCrossDomainNullifier(H, SrcChain, DstChain), CROSS_DOMAIN, DstChain),
            deriveSoulNullifier(H, chainDomainHash(SrcChain)),
            SrcChain,
            DstChain
        )

    /**
     * Verify cross-domain binding is valid
     */
    syntax Bool ::= verifyBinding(CrossDomainBinding) [function]
    
    rule verifyBinding(binding(SrcNf, DstNf, PilNf, SrcChain, DstChain)) =>
        nfHash(DstNf) ==K deriveCrossDomainNullifier(nfHash(SrcNf), SrcChain, DstChain)
        andBool PilNf ==K deriveSoulNullifier(nfHash(SrcNf), chainDomainHash(SrcChain))

    // ==========================================================================
    // PRIVACY LEVEL OPERATIONS
    // ==========================================================================

    /**
     * Check if privacy level is sufficient for operation
     */
    syntax Bool ::= privacyLevelSufficient(PrivacyLevel, PrivacyLevel) [function]
    
    rule privacyLevelSufficient(Actual, Required) =>
        privacyLevelToInt(Actual) >=Int privacyLevelToInt(Required)

    syntax Int ::= privacyLevelToInt(PrivacyLevel) [function]
    rule privacyLevelToInt(NONE) => 0
    rule privacyLevelToInt(BASIC) => 1
    rule privacyLevelToInt(MEDIUM) => 2
    rule privacyLevelToInt(HIGH) => 3
    rule privacyLevelToInt(MAXIMUM) => 4

    // ==========================================================================
    // HELPER FUNCTIONS
    // ==========================================================================

    syntax Point ::= generator(CurveType) [function]
    syntax Point ::= "G_POINT" [function]
    syntax Point ::= "H_POINT" [function]
    
    syntax Point ::= pointAdd(Point, Point) [function]
    syntax Point ::= scalarMul(Scalar, Point) [function]
    syntax Point ::= hashToPoint(Point) [function]
    syntax Scalar ::= hashToScalar(Bytes) [function]
    
    syntax Bytes ::= ecdh(Scalar, Point) [function]
    syntax Hash ::= viewTag(Bytes) [function]
    
    syntax Bytes ::= concat(ByteArray, ByteArray) [function]
    syntax Bytes ::= intToBytes(Int) [function]
    
    syntax Point ::= sumCommitments(List) [function]
    syntax Point ::= commitmentToPoint(PedersenCommitment) [function]
    
    syntax Hash ::= nfHash(Nullifier) [function]
    rule nfHash(nf(H, _, _)) => H
    
    syntax Hash ::= chainDomainHash(ChainId) [function]

endmodule

module CROSS-CHAIN-PRIVACY-PROPERTIES
    imports CROSS-CHAIN-PRIVACY-SEMANTICS

    // ==========================================================================
    // STEALTH ADDRESS PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 1: Stealth address derivation is deterministic
     * Same inputs always produce same stealth address
     */
    claim deriveStealthAddress(Meta, Eph) ==K deriveStealthAddress(Meta, Eph)
        requires true
        [trusted]

    /**
     * PROPERTY 2: Different ephemeral keys produce different stealth addresses
     * Ensures unlinkability between payments
     */
    claim deriveStealthAddress(Meta, Eph1) =/=K deriveStealthAddress(Meta, Eph2)
        requires Eph1 =/=Int Eph2
        [trusted]

    /**
     * PROPERTY 3: Recipient can detect their stealth addresses
     */
    claim checkStealthOwnership(deriveStealthAddress(meta(SpendPub, ViewPub, C), EphPriv), ViewPriv, SpendPub) ==K true
        requires scalarMul(ViewPriv, generator(C)) ==K ViewPub
        [trusted]

    // ==========================================================================
    // NULLIFIER PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 4: Nullifier uniqueness - same inputs produce same nullifier
     */
    claim deriveChainNullifier(S, C, Chain) ==K deriveChainNullifier(S, C, Chain)
        requires true
        [trusted]

    /**
     * PROPERTY 5: Cross-domain nullifiers are directional
     * A→B ≠ B→A prevents replay attacks
     */
    claim deriveCrossDomainNullifier(Nf, ChainA, ChainB) =/=K deriveCrossDomainNullifier(Nf, ChainB, ChainA)
        requires ChainA =/=Int ChainB
        [trusted]

    /**
     * PROPERTY 6: Soul nullifiers are unique per domain
     */
    claim deriveSoulNullifier(Nf, Domain1) =/=K deriveSoulNullifier(Nf, Domain2)
        requires Domain1 =/=K Domain2
        [trusted]

    /**
     * PROPERTY 7: Different secrets produce different nullifiers
     * Binding property
     */
    claim deriveChainNullifier(S1, C, Chain) =/=K deriveChainNullifier(S2, C, Chain)
        requires S1 =/=K S2
        [trusted]

    // ==========================================================================
    // COMMITMENT PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 8: Commitment hiding - cannot determine amount without blinding
     * (Formalized as computational assumption)
     */

    /**
     * PROPERTY 9: Commitment binding - cannot change amount without changing commitment
     */
    claim createCommitment(A1, B1) ==K createCommitment(A2, B2) impliesBool (A1 ==Int A2 andBool B1 ==Int B2)
        requires true
        [trusted]

    /**
     * PROPERTY 10: Commitment homomorphism
     * C(a) + C(b) = C(a+b) with appropriate blinding
     */
    claim pointAdd(createCommitment(A1, B1), createCommitment(A2, B2)) ==K 
          createCommitment(A1 +Int A2, B1 +Int B2)
        requires (A1 +Int A2) <Int SECP256K1_N andBool (B1 +Int B2) <Int SECP256K1_N
        [trusted]

    // ==========================================================================
    // KEY IMAGE PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 11: Key images are deterministic
     */
    claim computeKeyImage(PrivKey, PubKey) ==K computeKeyImage(PrivKey, PubKey)
        requires true
        [trusted]

    /**
     * PROPERTY 12: Different private keys produce different key images
     * Prevents double-spending
     */
    claim computeKeyImage(Priv1, scalarMul(Priv1, G)) =/=K computeKeyImage(Priv2, scalarMul(Priv2, G))
        requires Priv1 =/=Int Priv2
        [trusted]

    // ==========================================================================
    // RING SIGNATURE PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 13: Valid signature verifies
     * Completeness
     */

    /**
     * PROPERTY 14: Invalid signature does not verify
     * Soundness
     */

    /**
     * PROPERTY 15: Cannot determine which ring member signed
     * Anonymity (computational assumption)
     */

    // ==========================================================================
    // CROSS-DOMAIN BINDING PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 16: Binding verification is sound
     */
    claim verifyBinding(createBinding(Nf, SrcChain, DstChain)) ==K true
        requires true
        [trusted]

    /**
     * PROPERTY 17: Cannot create valid binding without source nullifier
     * Binding soundness
     */

    // ==========================================================================
    // PRIVACY LEVEL PROPERTIES
    // ==========================================================================

    /**
     * PROPERTY 18: Privacy levels are totally ordered
     */
    claim privacyLevelToInt(NONE) <Int privacyLevelToInt(BASIC)
        requires true
        [trusted]

    claim privacyLevelToInt(BASIC) <Int privacyLevelToInt(MEDIUM)
        requires true
        [trusted]

    claim privacyLevelToInt(MEDIUM) <Int privacyLevelToInt(HIGH)
        requires true
        [trusted]

    claim privacyLevelToInt(HIGH) <Int privacyLevelToInt(MAXIMUM)
        requires true
        [trusted]

endmodule

module CROSS-CHAIN-PRIVACY
    imports CROSS-CHAIN-PRIVACY-PROPERTIES
endmodule
