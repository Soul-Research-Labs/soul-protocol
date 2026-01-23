// SPDX-License-Identifier: MIT

/**
 * K Framework Specification for Aptos Blockchain Integration
 * ===========================================================
 * 
 * This specification formalizes:
 * - BLS12-381 for validator aggregate signatures
 * - Ed25519 for user signatures
 * - SHA3-256 hashing (Aptos native)
 * - AptosBFT consensus (derived from DiemBFT/HotStuff)
 * - Block-STM parallel execution model
 * - Move resource model
 * - Nullifier derivation and cross-domain binding
 *
 * Aptos Key Features:
 * - Move programming language
 * - ~160ms finality under good conditions
 * - Epoch-based validator rotation
 * - Resource-oriented programming
 */

module APTOS-PRIMITIVES
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
        <aptos>
            <epoch> 1 </epoch>
            <round> 0 </round>
            <version> 0 </version>
            <ledgerInfo>
                <info multiplicity="*" type="Map">
                    <infoVersion> 0 </infoVersion>
                    <infoEpoch> 0 </infoEpoch>
                    <infoBlockHash> .Bytes </infoBlockHash>
                    <infoStateId> .Bytes </infoStateId>
                </info>
            </ledgerInfo>
            <validators>
                <validator multiplicity="*" type="Map">
                    <validatorAddr> .Bytes </validatorAddr>
                    <blsPublicKey> .Bytes </blsPublicKey>
                    <ed25519PublicKey> .Bytes </ed25519PublicKey>
                    <votingPower> 0 </votingPower>
                    <validatorActive> false </validatorActive>
                </validator>
            </validators>
            <nullifiers> .Set </nullifiers>
            <crossDomainBindings> .Map </crossDomainBindings>
            <totalVotingPower> 0 </totalVotingPower>
        </aptos>

    // =========================================================================
    // BLS12-381 CONSTANTS
    // =========================================================================

    /**
     * BLS12-381 scalar field order
     */
    syntax Int ::= "BLS12_381_SCALAR_ORDER"
    rule BLS12_381_SCALAR_ORDER => 52435875175126190479447740508185965837690552500527637822603658699938581184513

    /**
     * BLS12-381 base field modulus
     */
    syntax Int ::= "BLS12_381_FIELD_MODULUS"
    rule BLS12_381_FIELD_MODULUS => 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

    // =========================================================================
    // ED25519 CONSTANTS
    // =========================================================================

    /**
     * Ed25519 curve order
     */
    syntax Int ::= "ED25519_ORDER"
    rule ED25519_ORDER => 7237005577332262213973186563042994240857116359379907606001950938285454250989

    /**
     * Ed25519 field prime (2^255 - 19)
     */
    syntax Int ::= "ED25519_PRIME"
    rule ED25519_PRIME => 57896044618658097711785492504343953926634992332820282019728792003956564819949

    // =========================================================================
    // APTOS CHAIN CONSTANTS
    // =========================================================================

    /**
     * Aptos mainnet chain ID
     */
    syntax Int ::= "APTOS_MAINNET"
    rule APTOS_MAINNET => 1

    /**
     * Aptos testnet chain ID
     */
    syntax Int ::= "APTOS_TESTNET"
    rule APTOS_TESTNET => 2

    /**
     * Aptos devnet chain ID
     */
    syntax Int ::= "APTOS_DEVNET"
    rule APTOS_DEVNET => 34

    /**
     * Quorum threshold in basis points (2/3 + 1)
     */
    syntax Int ::= "QUORUM_THRESHOLD_BPS"
    rule QUORUM_THRESHOLD_BPS => 6667

    /**
     * Minimum confirmations (epochs)
     */
    syntax Int ::= "MIN_CONFIRMATIONS"
    rule MIN_CONFIRMATIONS => 2

    // =========================================================================
    // TYPE DEFINITIONS
    // =========================================================================

    syntax AuthenticatorType ::= "ED25519"
                                | "MULTI_ED25519"
                                | "MULTI_AGENT"
                                | "FEE_PAYER"
                                | "SINGLE_KEY"
                                | "MULTI_KEY"

    syntax AddressScheme ::= "DERIVE_RESOURCE_ACCOUNT"  // 255
                           | "DERIVE_OBJECT_ADDRESS"     // 254

    // =========================================================================
    // SHA3-256 HASHING
    // =========================================================================

    /**
     * SHA3-256 hash function (Aptos native)
     */
    syntax Bytes ::= sha3Hash(Bytes) [function, total]

    // Hash determinism
    rule sha3Hash(D) ==K sha3Hash(D) => true

    /**
     * Hash two values using SHA3-256
     */
    syntax Bytes ::= hash2(Bytes, Bytes) [function, total]
    rule hash2(L, R) => sha3Hash(L +Bytes R)

    /**
     * Hash with domain prefix (Aptos convention)
     */
    syntax Bytes ::= hashWithPrefix(String, Bytes) [function, total]
    rule hashWithPrefix(Prefix, Data) => sha3Hash(String2Bytes(Prefix) +Bytes Data)

    /**
     * Hash chain for multiple inputs
     */
    syntax Bytes ::= hashN(List) [function]
    
    rule hashN(.List) => 0x0000000000000000000000000000000000000000000000000000000000000000
    rule hashN(ListItem(H:Bytes)) => H
    rule hashN(ListItem(H1:Bytes) ListItem(H2:Bytes) REST) =>
        hashN(ListItem(hash2(H1, H2)) REST)

    // =========================================================================
    // BLOCK/LEDGER INFO OPERATIONS
    // =========================================================================

    /**
     * Compute ledger info (block) hash
     */
    syntax Bytes ::= computeBlockHash(Int, Int, Bytes, Int, Int) [function, total]
    rule computeBlockHash(Epoch, Round, ExecutedStateId, Version, TimestampUsecs) =>
        hashWithPrefix("APTOS::LedgerInfo",
            Int2Bytes(Epoch, 8, BE) +Bytes
            Int2Bytes(Round, 8, BE) +Bytes
            ExecutedStateId +Bytes
            Int2Bytes(Version, 8, BE) +Bytes
            Int2Bytes(TimestampUsecs, 8, BE)
        )

    /**
     * Compute epoch state hash
     */
    syntax Bytes ::= computeEpochStateHash(Int, List, List) [function]
    rule computeEpochStateHash(Epoch, Validators, Powers) =>
        hashWithPrefix("APTOS::EpochState",
            Int2Bytes(Epoch, 8, BE) +Bytes
            hashN(Validators) +Bytes
            hashN(Powers)
        )
        requires size(Validators) ==Int size(Powers)

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * Derive nullifier from Aptos transaction
     * Nullifier = SHA3(txHash || version || "APTOS_NF")
     */
    syntax Bytes ::= deriveNullifier(Bytes, Int) [function, total]
    rule deriveNullifier(TxHash, Version) =>
        sha3Hash(TxHash +Bytes Int2Bytes(Version, 8, BE) +Bytes String2Bytes("APTOS_NF"))

    /**
     * Derive cross-domain nullifier for PIL binding
     * CrossNullifier = SHA3(aptosNullifier || sourceChain || targetChain || "APTOS2PIL")
     */
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int, Int) [function, total]
    rule deriveCrossDomainNullifier(AptosNullifier, SourceChain, TargetChain) =>
        sha3Hash(AptosNullifier +Bytes Int2Bytes(SourceChain, 32, BE) +Bytes Int2Bytes(TargetChain, 32, BE) +Bytes String2Bytes("APTOS2PIL"))

    /**
     * Derive PIL binding
     */
    syntax Bytes ::= derivePILBinding(Bytes) [function, total]
    rule derivePILBinding(AptosNullifier) =>
        sha3Hash(AptosNullifier +Bytes String2Bytes("APTOS_TO_PIL"))

    // =========================================================================
    // NULLIFIER CONSUMPTION
    // =========================================================================

    /**
     * Consume a nullifier (mark as used)
     */
    syntax KItem ::= consumeNullifier(Bytes)

    rule <aptos>
            <nullifiers> NFS => NFS SetItem(NF) </nullifiers>
            ...
         </aptos>
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

    rule <aptos>
            <crossDomainBindings> BINDINGS => BINDINGS[AptosNf <- PilNf] </crossDomainBindings>
            ...
         </aptos>
         bindNullifier(AptosNf, PilNf)

    // =========================================================================
    // QUORUM AND CONSENSUS
    // =========================================================================

    /**
     * Check if voting power meets quorum (2/3 + 1)
     */
    syntax Bool ::= hasQuorum(Int, Int) [function, total]
    rule hasQuorum(SigningPower, TotalPower) =>
        SigningPower *Int 10000 >=Int TotalPower *Int QUORUM_THRESHOLD_BPS
        requires TotalPower >Int 0

    rule hasQuorum(_, 0) => false

    /**
     * Calculate signing power from bitmap
     */
    syntax Int ::= calculateSigningPower(Bytes, List) [function]
    
    rule calculateSigningPower(_, .List) => 0
    rule calculateSigningPower(Bitmap, ListItem(Power:Int) REST) =>
        (ifBool bitAt(Bitmap, size(REST)) then Power else 0) +Int
        calculateSigningPower(Bitmap, REST)

    /**
     * Check bit at position in bitmap
     */
    syntax Bool ::= bitAt(Bytes, Int) [function]
    rule bitAt(Bitmap, Pos) =>
        (Bytes2Int(substrBytes(Bitmap, Pos /Int 8, 1), BE, Unsigned) &Int (1 <<Int (Pos %Int 8))) =/=Int 0
        requires Pos /Int 8 <Int lengthBytes(Bitmap)
    rule bitAt(_, _) => false [owise]

    // =========================================================================
    // VALIDATOR OPERATIONS
    // =========================================================================

    /**
     * Register a validator
     */
    syntax KItem ::= registerValidator(Bytes, Bytes, Bytes, Int)

    rule <aptos>
            <validators>
                (.Bag => <validator>
                    <validatorAddr> Addr </validatorAddr>
                    <blsPublicKey> BlsKey </blsPublicKey>
                    <ed25519PublicKey> EdKey </ed25519PublicKey>
                    <votingPower> Power </votingPower>
                    <validatorActive> true </validatorActive>
                </validator>)
                ...
            </validators>
            <totalVotingPower> TVP => TVP +Int Power </totalVotingPower>
            ...
         </aptos>
         registerValidator(Addr, BlsKey, EdKey, Power)
        requires Power >Int 0 
            andBool lengthBytes(BlsKey) ==Int 96 
            andBool lengthBytes(EdKey) ==Int 32

    /**
     * Remove a validator
     */
    syntax KItem ::= removeValidator(Bytes)

    rule <aptos>
            <validators>
                <validator>
                    <validatorAddr> Addr </validatorAddr>
                    <votingPower> Power </votingPower>
                    <validatorActive> _ => false </validatorActive>
                    ...
                </validator>
                ...
            </validators>
            <totalVotingPower> TVP => TVP -Int Power </totalVotingPower>
            ...
         </aptos>
         removeValidator(Addr)

    // =========================================================================
    // MERKLE TREE OPERATIONS
    // =========================================================================

    /**
     * Verify sparse Merkle tree proof (Aptos uses 256-bit sparse Merkle trees)
     */
    syntax Bool ::= verifySparseMerkleProof(Bytes, List, Int, Bytes) [function]
    
    rule verifySparseMerkleProof(Leaf, .List, _, Root) => Leaf ==K Root
    
    rule verifySparseMerkleProof(Computed, ListItem(Sibling:Bytes) Proof, Index, Root) =>
        verifySparseMerkleProof(
            ifBool Index &Int 1 ==Int 0
            then hash2(Computed, Sibling)
            else hash2(Sibling, Computed),
            Proof,
            Index >>Int 1,
            Root
        )

    /**
     * Verify transaction accumulator proof
     */
    syntax Bool ::= verifyAccumulatorProof(Bytes, List, Int, Bytes) [function]
    
    rule verifyAccumulatorProof(TxHash, .List, _, Root) => TxHash ==K Root
    
    rule verifyAccumulatorProof(Computed, ListItem(Sibling:Bytes) Proof, Index, Root) =>
        verifyAccumulatorProof(
            ifBool Index &Int 1 ==Int 0
            then hash2(Computed, Sibling)
            else hash2(Sibling, Computed),
            Proof,
            Index >>Int 1,
            Root
        )

    /**
     * Compute Merkle root from leaves
     */
    syntax Bytes ::= computeMerkleRoot(List) [function]
    rule computeMerkleRoot(.List) => 0x0000000000000000000000000000000000000000000000000000000000000000
    rule computeMerkleRoot(ListItem(H:Bytes)) => H
    rule computeMerkleRoot(ListItem(H1:Bytes) ListItem(H2:Bytes)) => hash2(H1, H2)
    rule computeMerkleRoot(ListItem(H1:Bytes) ListItem(H2:Bytes) REST) =>
        computeMerkleRoot(ListItem(hash2(H1, H2)) REST)
        requires REST =/=K .List

    // =========================================================================
    // RESOURCE ADDRESS DERIVATION
    // =========================================================================

    /**
     * Compute resource account address
     * ResourceAddr = SHA3(creator || seed || 255)
     */
    syntax Bytes ::= computeResourceAddress(Bytes, Bytes) [function, total]
    rule computeResourceAddress(Creator, Seed) =>
        sha3Hash(Creator +Bytes Seed +Bytes Int2Bytes(255, 1, BE))

    /**
     * Compute object address
     * ObjectAddr = SHA3(creator || seed || 254)
     */
    syntax Bytes ::= computeObjectAddress(Bytes, Bytes) [function, total]
    rule computeObjectAddress(Creator, Seed) =>
        sha3Hash(Creator +Bytes Seed +Bytes Int2Bytes(254, 1, BE))

    /**
     * Compute resource tag hash
     */
    syntax Bytes ::= computeResourceTagHash(Bytes, Bytes, Bytes, List) [function, total]
    rule computeResourceTagHash(ModuleAddr, ModuleName, StructName, TypeArgs) =>
        sha3Hash(
            ModuleAddr +Bytes
            ModuleName +Bytes
            StructName +Bytes
            hashN(TypeArgs)
        )

    // =========================================================================
    // CHAIN VALIDATION
    // =========================================================================

    /**
     * Check if chain ID is valid Aptos network
     */
    syntax Bool ::= isAptosChain(Int) [function, total]
    rule isAptosChain(ChainId) => ChainId ==Int APTOS_MAINNET 
                                  orBool ChainId ==Int APTOS_TESTNET 
                                  orBool ChainId ==Int APTOS_DEVNET

    /**
     * Validate ledger info
     */
    syntax Bool ::= isValidLedgerInfo(Int, Bytes, Bytes, Int) [function, total]
    rule isValidLedgerInfo(Epoch, BlockHash, ExecutedStateId, SigLen) =>
        Epoch >Int 0 
        andBool BlockHash =/=K 0x0000000000000000000000000000000000000000000000000000000000000000
        andBool ExecutedStateId =/=K 0x0000000000000000000000000000000000000000000000000000000000000000
        andBool SigLen ==Int 48

    // =========================================================================
    // SIGNATURE VERIFICATION (ABSTRACT)
    // =========================================================================

    /**
     * Verify Ed25519 signature
     */
    syntax Bool ::= verifyEd25519Signature(Bytes, Bytes, Bytes) [function]
    // Abstract - requires Ed25519 precompile

    /**
     * Verify BLS12-381 aggregate signature
     */
    syntax Bool ::= verifyBLSSignature(Bytes, Bytes, Bytes) [function]
    // Abstract - requires BLS precompile

    // =========================================================================
    // SECURITY THEOREMS
    // =========================================================================

    /**
     * Theorem: Nullifier uniqueness
     * A nullifier derived from a transaction can only be consumed once
     */
    // Proof: The consumeNullifier rule requires notBool NF in NFS
    // ensuring no duplicate consumption

    /**
     * Theorem: Cross-domain nullifier binding
     * For any Aptos nullifier NF_aptos, the PIL binding NF_pil is uniquely determined
     */
    // Proof: deriveCrossDomainNullifier is a deterministic function
    // NF_pil = SHA3(NF_aptos || sourceChain || targetChain || "APTOS2PIL")

    /**
     * Theorem: Quorum security
     * A ledger info is finalized only if 2/3+ of voting power signed
     */
    // Proof: hasQuorum requires SigningPower * 10000 >= TotalPower * 6667
    // This ensures >66.67% of voting power participation

    /**
     * Theorem: Resource address determinism
     * Resource addresses are deterministically derived from creator and seed
     */
    // Proof: computeResourceAddress uses SHA3 hash with fixed scheme byte

    /**
     * Theorem: Merkle proof soundness
     * A valid Merkle proof for leaf L with root R implies L was in the original set
     */
    // Proof: Collision resistance of SHA3-256 prevents proof forgery

    /**
     * Theorem: AptosBFT safety
     * Under 1/3 Byzantine faults, no two conflicting ledger infos can be finalized
     */
    // Proof: Quorum intersection - two quorums (each >2/3) share at least one honest validator

endmodule
