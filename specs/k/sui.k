// SPDX-License-Identifier: MIT

/**
 * K Framework Specification for Sui Blockchain Integration
 * ========================================================
 * 
 * This specification formalizes:
 * - BLS12-381 curve operations (validator signatures)
 * - Ed25519 operations (user signatures)
 * - Blake2b-256 hashing (Sui's native hash)
 * - Object model (owned, shared, immutable)
 * - Nullifier derivation and cross-domain binding
 * - Checkpoint-based finality
 * 
 * Sui uses a unique object-centric data model with parallel
 * transaction execution via DAG-based mempool (Narwhal) and
 * BFT consensus (Bullshark/Mysticeti).
 */

module SUI-PRIMITIVES
    imports BOOL
    imports INT
    imports BYTES
    imports STRING
    imports MAP
    imports SET
    imports LIST

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    configuration
        <sui>
            <epoch> 0 </epoch>
            <checkpoints>
                <checkpoint multiplicity="*" type="Map">
                    <seqNum> 0 </seqNum>
                    <digest> .Bytes </digest>
                    <previousDigest> .Bytes </previousDigest>
                    <transactions> .List </transactions>
                </checkpoint>
            </checkpoints>
            <validators>
                <validator multiplicity="*" type="Map">
                    <validatorAddr> .Bytes </validatorAddr>
                    <blsPublicKey> .Bytes </blsPublicKey>
                    <stake> 0 </stake>
                    <active> false </active>
                </validator>
            </validators>
            <objects>
                <object multiplicity="*" type="Map">
                    <objectId> .Bytes </objectId>
                    <version> 0 </version>
                    <owner> .Bytes </owner>
                    <ownership> "ADDRESS_OWNED" </ownership>
                    <data> .Bytes </data>
                </object>
            </objects>
            <nullifiers> .Set </nullifiers>
            <crossDomainBindings> .Map </crossDomainBindings>
        </sui>

    // =========================================================================
    // BLS12-381 CONSTANTS
    // =========================================================================

    /**
     * BLS12-381 scalar field order (r)
     * Used for validator BLS signatures
     */
    syntax Int ::= "BLS12_381_ORDER"
    rule BLS12_381_ORDER => 52435875175126190479447740508185965837690552500527637822603658699938581184513

    /**
     * BLS12-381 field modulus (p)
     */
    syntax Int ::= "BLS12_381_MODULUS"  
    rule BLS12_381_MODULUS => 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

    /**
     * BLS12-381 G1 generator
     */
    syntax Point ::= "BLS_G1_GENERATOR"
    rule BLS_G1_GENERATOR => Point(
        3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,
        1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
    )

    // =========================================================================
    // ED25519 CONSTANTS
    // =========================================================================

    /**
     * Ed25519 curve order
     * Used for user signatures
     */
    syntax Int ::= "ED25519_ORDER"
    rule ED25519_ORDER => 7237005577332262213973186563042994240857116359379907606001950938285454250989

    /**
     * Ed25519 field prime (2^255 - 19)
     */
    syntax Int ::= "ED25519_PRIME"
    rule ED25519_PRIME => 57896044618658097711785492504343953926634992332820282019728792003956564819949

    // =========================================================================
    // TYPE DEFINITIONS
    // =========================================================================

    syntax Point ::= Point(Int, Int)
                   | "POINT_INFINITY"

    syntax ObjectOwnership ::= "ADDRESS_OWNED"
                             | "OBJECT_OWNED"
                             | "SHARED"
                             | "IMMUTABLE"

    syntax TransactionKind ::= "PROGRAMMABLE_TRANSACTION"
                             | "CHANGE_EPOCH"
                             | "GENESIS"
                             | "CONSENSUS_COMMIT_PROLOGUE"

    syntax SignatureScheme ::= "ED25519"
                             | "SECP256K1"
                             | "SECP256R1"
                             | "MULTISIG"
                             | "BLS12381"
                             | "ZK_LOGIN"

    // =========================================================================
    // BLAKE2B-256 HASHING
    // =========================================================================

    /**
     * Blake2b-256 hash function (Sui's native hash)
     * Properties:
     * - Deterministic
     * - Collision resistant
     * - 256-bit output
     */
    syntax Bytes ::= blake2b256(Bytes) [function, total]
    syntax Bytes ::= blake2b256Pair(Bytes, Bytes) [function, total]

    // Hash determinism
    rule blake2b256(D) ==K blake2b256(D) => true

    // Hash pair
    rule blake2b256Pair(L, R) => blake2b256(L +Bytes R)

    /**
     * Hash chain for multiple inputs
     */
    syntax Bytes ::= hashChain(List) [function]
    
    rule hashChain(.List) => 0x0000000000000000000000000000000000000000000000000000000000000000
    rule hashChain(ListItem(H:Bytes)) => H
    rule hashChain(ListItem(H1:Bytes) ListItem(H2:Bytes) REST) =>
        hashChain(ListItem(blake2b256Pair(H1, H2)) REST)

    // =========================================================================
    // OBJECT OPERATIONS
    // =========================================================================

    /**
     * Derive object ID from transaction digest and creation index
     * ObjectID = Blake2b256(txDigest || creationIndex)
     */
    syntax Bytes ::= deriveObjectId(Bytes, Int) [function, total]
    rule deriveObjectId(TxDigest, Index) => 
        blake2b256(TxDigest +Bytes Int2Bytes(Index, 8, BE))

    /**
     * Compute object digest
     */
    syntax Bytes ::= computeObjectDigest(Bytes, Int, Bytes, Bytes) [function, total]
    rule computeObjectDigest(ObjectId, Version, TypeTag, Data) =>
        blake2b256(ObjectId +Bytes Int2Bytes(Version, 8, BE) +Bytes TypeTag +Bytes Data)

    /**
     * Check if object is shared (requires consensus)
     */
    syntax Bool ::= isSharedObject(ObjectOwnership) [function, total]
    rule isSharedObject(SHARED) => true
    rule isSharedObject(_) => false [owise]

    /**
     * Check if object is immutable
     */
    syntax Bool ::= isImmutableObject(ObjectOwnership) [function, total]
    rule isImmutableObject(IMMUTABLE) => true
    rule isImmutableObject(_) => false [owise]

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * Derive nullifier from deleted/wrapped object
     * Nullifier = Blake2b256(objectId || version || actionDigest || "SUI_NF")
     */
    syntax Bytes ::= deriveNullifier(Bytes, Int, Bytes) [function, total]
    rule deriveNullifier(ObjectId, Version, ActionDigest) =>
        blake2b256(ObjectId +Bytes Int2Bytes(Version, 8, BE) +Bytes ActionDigest +Bytes String2Bytes("SUI_NF"))

    /**
     * Derive cross-domain nullifier for PIL binding
     * CrossNullifier = Blake2b256(suiNullifier || sourceChain || targetChain || "S2P")
     */
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int, Int) [function, total]
    rule deriveCrossDomainNullifier(SuiNullifier, SourceChain, TargetChain) =>
        blake2b256(SuiNullifier +Bytes Int2Bytes(SourceChain, 32, BE) +Bytes Int2Bytes(TargetChain, 32, BE) +Bytes String2Bytes("S2P"))

    /**
     * Derive PIL binding
     */
    syntax Bytes ::= derivePILBinding(Bytes) [function, total]
    rule derivePILBinding(SuiNullifier) =>
        blake2b256(SuiNullifier +Bytes String2Bytes("SUI_TO_PIL"))

    // =========================================================================
    // NULLIFIER CONSUMPTION
    // =========================================================================

    /**
     * Consume a nullifier (mark as used)
     */
    syntax KItem ::= consumeNullifier(Bytes)

    rule <sui>
            <nullifiers> NFS => NFS SetItem(NF) </nullifiers>
            ...
         </sui>
         consumeNullifier(NF)
        requires notBool NF in NFS

    /**
     * Check if nullifier is consumed
     */
    syntax Bool ::= isNullifierConsumed(Bytes) [function]

    rule [[ isNullifierConsumed(NF) => NF in NFS ]]
         <nullifiers> NFS </nullifiers>

    /**
     * Bind nullifiers across domains
     */
    syntax KItem ::= bindNullifier(Bytes, Bytes)

    rule <sui>
            <crossDomainBindings> BINDINGS => BINDINGS[SuiNf <- PilNf] </crossDomainBindings>
            ...
         </sui>
         bindNullifier(SuiNf, PilNf)

    // =========================================================================
    // COMMITTEE AND QUORUM
    // =========================================================================

    /**
     * Quorum threshold: 2/3 + 1 of total stake
     */
    syntax Int ::= "QUORUM_THRESHOLD_BPS"
    rule QUORUM_THRESHOLD_BPS => 6667  // 66.67%

    /**
     * Check if signing stake meets quorum
     */
    syntax Bool ::= hasQuorum(Int, Int) [function, total]
    rule hasQuorum(SigningStake, TotalStake) =>
        SigningStake *Int 10000 >=Int TotalStake *Int QUORUM_THRESHOLD_BPS
        requires TotalStake >Int 0

    rule hasQuorum(_, 0) => false

    /**
     * Compute total stake from validator list
     */
    syntax Int ::= computeTotalStake(List) [function]
    rule computeTotalStake(.List) => 0
    rule computeTotalStake(ListItem(Stake:Int) REST) => Stake +Int computeTotalStake(REST)

    /**
     * Committee hash
     */
    syntax Bytes ::= computeCommitteeHash(Int, List, Int) [function]
    rule computeCommitteeHash(Epoch, Validators, TotalStake) =>
        blake2b256(Int2Bytes(Epoch, 8, BE) +Bytes hashChain(Validators) +Bytes Int2Bytes(TotalStake, 32, BE))

    // =========================================================================
    // CHECKPOINT OPERATIONS
    // =========================================================================

    /**
     * Compute checkpoint digest
     */
    syntax Bytes ::= computeCheckpointDigest(Int, Int, Bytes, Bytes, Int) [function, total]
    rule computeCheckpointDigest(Epoch, SeqNum, ContentDigest, PreviousDigest, TimestampMs) =>
        blake2b256(
            Int2Bytes(Epoch, 8, BE) +Bytes
            Int2Bytes(SeqNum, 8, BE) +Bytes
            ContentDigest +Bytes
            PreviousDigest +Bytes
            Int2Bytes(TimestampMs, 8, BE)
        )

    /**
     * Verify checkpoint chain
     */
    syntax Bool ::= verifyCheckpointChain(Bytes, Int, Bytes, Int) [function]
    rule verifyCheckpointChain(CurrentPrevDigest, CurrentSeqNum, PreviousDigest, PreviousSeqNum) =>
        CurrentPrevDigest ==K PreviousDigest andBool
        CurrentSeqNum ==Int PreviousSeqNum +Int 1

    /**
     * Submit checkpoint
     */
    syntax KItem ::= submitCheckpoint(Int, Bytes, Bytes)

    rule <sui>
            <checkpoints>
                (.Bag => <checkpoint>
                    <seqNum> SeqNum </seqNum>
                    <digest> Digest </digest>
                    <previousDigest> PrevDigest </previousDigest>
                    <transactions> .List </transactions>
                </checkpoint>)
                ...
            </checkpoints>
            ...
         </sui>
         submitCheckpoint(SeqNum, Digest, PrevDigest)

    // =========================================================================
    // VALIDATOR OPERATIONS
    // =========================================================================

    /**
     * Register a validator
     */
    syntax KItem ::= registerValidator(Bytes, Bytes, Int)

    rule <sui>
            <validators>
                (.Bag => <validator>
                    <validatorAddr> Addr </validatorAddr>
                    <blsPublicKey> BlsKey </blsPublicKey>
                    <stake> Stake </stake>
                    <active> true </active>
                </validator>)
                ...
            </validators>
            ...
         </sui>
         registerValidator(Addr, BlsKey, Stake)
        requires Stake >Int 0 andBool lengthBytes(BlsKey) ==Int 96

    /**
     * Remove a validator
     */
    syntax KItem ::= removeValidator(Bytes)

    rule <sui>
            <validators>
                <validator>
                    <validatorAddr> Addr </validatorAddr>
                    <active> _ => false </active>
                    ...
                </validator>
                ...
            </validators>
            ...
         </sui>
         removeValidator(Addr)

    // =========================================================================
    // BLS SIGNATURE VERIFICATION (ABSTRACT)
    // =========================================================================

    /**
     * Verify BLS signature (abstract - requires precompile)
     * In production, use EIP-2537 BLS precompiles
     */
    syntax Bool ::= verifyBLSSignature(Bytes, Bytes, Bytes) [function]
    // Abstract - actual verification depends on EVM precompiles

    /**
     * Verify aggregated BLS signature
     */
    syntax Bool ::= verifyAggregatedBLS(Bytes, List, Bytes) [function]
    // Abstract - requires BLS aggregation verification

    // =========================================================================
    // MESSAGE OPERATIONS
    // =========================================================================

    /**
     * Compute message ID
     */
    syntax Bytes ::= computeMessageId(Int, Int, Bytes, Bytes, Int, Bytes) [function, total]
    rule computeMessageId(SourceChain, TargetChain, Sender, Recipient, Nonce, Payload) =>
        blake2b256(
            Int2Bytes(SourceChain, 8, BE) +Bytes
            Int2Bytes(TargetChain, 8, BE) +Bytes
            Sender +Bytes
            Recipient +Bytes
            Int2Bytes(Nonce, 8, BE) +Bytes
            Payload
        )

    /**
     * Compute transfer ID
     */
    syntax Bytes ::= computeTransferId(Bytes, Bytes, Int, Bytes, Bytes, Int, Bytes) [function, total]
    rule computeTransferId(SourceObject, CoinType, Amount, Sender, Recipient, SourceEpoch, TxDigest) =>
        blake2b256(
            SourceObject +Bytes
            CoinType +Bytes
            Int2Bytes(Amount, 32, BE) +Bytes
            Sender +Bytes
            Recipient +Bytes
            Int2Bytes(SourceEpoch, 8, BE) +Bytes
            TxDigest
        )

    // =========================================================================
    // MERKLE TREE
    // =========================================================================

    /**
     * Compute Merkle root
     */
    syntax Bytes ::= computeMerkleRoot(List) [function]
    rule computeMerkleRoot(.List) => 0x0000000000000000000000000000000000000000000000000000000000000000
    rule computeMerkleRoot(ListItem(H:Bytes)) => H
    rule computeMerkleRoot(ListItem(H1:Bytes) ListItem(H2:Bytes)) => blake2b256Pair(H1, H2)
    rule computeMerkleRoot(ListItem(H1:Bytes) ListItem(H2:Bytes) REST) =>
        computeMerkleRoot(ListItem(blake2b256Pair(H1, H2)) REST)
        requires REST =/=K .List

    /**
     * Verify Merkle proof
     */
    syntax Bool ::= verifyMerkleProof(Bytes, List, List, Bytes) [function]
    
    rule verifyMerkleProof(Leaf, .List, .List, Root) => Leaf ==K Root
    
    rule verifyMerkleProof(Computed, ListItem(Sibling:Bytes) Proof, ListItem(0) Indices, Root) =>
        verifyMerkleProof(blake2b256Pair(Computed, Sibling), Proof, Indices, Root)
    
    rule verifyMerkleProof(Computed, ListItem(Sibling:Bytes) Proof, ListItem(1) Indices, Root) =>
        verifyMerkleProof(blake2b256Pair(Sibling, Computed), Proof, Indices, Root)

    // =========================================================================
    // CHAIN VALIDATION
    // =========================================================================

    /**
     * Sui chain IDs
     */
    syntax Int ::= "SUI_MAINNET" | "SUI_TESTNET" | "SUI_DEVNET"
    rule SUI_MAINNET => 1
    rule SUI_TESTNET => 2
    rule SUI_DEVNET => 3

    /**
     * Check if chain ID is valid Sui network
     */
    syntax Bool ::= isSuiChain(Int) [function, total]
    rule isSuiChain(ChainId) => ChainId ==Int SUI_MAINNET orBool
                                ChainId ==Int SUI_TESTNET orBool
                                ChainId ==Int SUI_DEVNET

    /**
     * Validate epoch
     */
    syntax Bool ::= isValidEpoch(Int, Int) [function, total]
    rule isValidEpoch(Epoch, CurrentEpoch) =>
        Epoch <=Int CurrentEpoch andBool Epoch >=Int CurrentEpoch -Int 1

    // =========================================================================
    // OBJECT VALIDATION
    // =========================================================================

    /**
     * Validate object ID (non-zero)
     */
    syntax Bool ::= isValidObjectId(Bytes) [function, total]
    rule isValidObjectId(ObjectId) => ObjectId =/=K 0x0000000000000000000000000000000000000000000000000000000000000000

    /**
     * Validate transaction digest
     */
    syntax Bool ::= isValidTxDigest(Bytes) [function, total]
    rule isValidTxDigest(Digest) => Digest =/=K 0x0000000000000000000000000000000000000000000000000000000000000000

    // =========================================================================
    // SECURITY THEOREMS
    // =========================================================================

    /**
     * Theorem: Nullifier uniqueness
     * A nullifier derived from an object can only be consumed once
     */
    // Proof: The consumeNullifier rule requires notBool NF in NFS
    // ensuring no duplicate consumption

    /**
     * Theorem: Cross-domain nullifier binding
     * For any Sui nullifier NF_sui, the PIL binding NF_pil is uniquely determined
     */
    // Proof: deriveCrossDomainNullifier is a deterministic function
    // NF_pil = Blake2b256(NF_sui || sourceChain || targetChain || "S2P")

    /**
     * Theorem: Checkpoint chain integrity
     * Each checkpoint must reference the correct previous checkpoint
     */
    // Proof: verifyCheckpointChain checks:
    // 1. CurrentPrevDigest == PreviousDigest
    // 2. CurrentSeqNum == PreviousSeqNum + 1

    /**
     * Theorem: Quorum security
     * A certificate is valid only if 2/3+ of stake signed
     */
    // Proof: hasQuorum requires SigningStake * 10000 >= TotalStake * 6667
    // This ensures >66.67% of stake participation

    /**
     * Theorem: Object ID derivation uniqueness
     * For different (txDigest, creationIndex) pairs, object IDs are unique
     * (with cryptographic probability)
     */
    // Proof: Collision resistance of Blake2b256

    /**
     * Theorem: Merkle proof soundness
     * A valid Merkle proof for leaf L with root R implies L was in the original set
     */
    // Proof: Collision resistance of Blake2b256 prevents forgery

endmodule
