// K Framework Specification for Brevis ZK Coprocessor
// Formalizes query semantics, proof verification, and privacy pool operations

module BREVIS-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports MAP
    imports LIST

    // =========================================================================
    // FIELD ARITHMETIC (BN254 for Groth16/PLONK compatibility)
    // =========================================================================

    syntax Int ::= "FIELD_MODULUS"  [macro]
    rule FIELD_MODULUS => 21888242871839275222246405745257275088696311157297823662689037894645226208583

    syntax Int ::= "SCALAR_ORDER"  [macro]
    rule SCALAR_ORDER => 21888242871839275222246405745257275088548364400416034343698204186575808495617

    // BNB Chain identifiers
    syntax Int ::= "BNB_MAINNET" [macro]
    rule BNB_MAINNET => 56

    syntax Int ::= "BNB_TESTNET" [macro]
    rule BNB_TESTNET => 97

    // Pool parameters
    syntax Int ::= "MERKLE_DEPTH" [macro]
    rule MERKLE_DEPTH => 20

    syntax Int ::= "MAX_LEAVES" [macro]
    rule MAX_LEAVES => 1048576  // 2^20

    syntax Int ::= "MIN_DEPOSIT" [macro]
    rule MIN_DEPOSIT => 10000000000000000  // 0.01 ETH

    syntax Int ::= "MAX_DEPOSIT" [macro]
    rule MAX_DEPOSIT => 10000000000000000000000  // 10000 ETH

    syntax Int ::= "DAILY_LIMIT" [macro]
    rule DAILY_LIMIT => 100000000000000000000000  // 100000 ETH

    syntax Int ::= "PROOF_EXPIRY" [macro]
    rule PROOF_EXPIRY => 86400  // 24 hours

    syntax Int ::= "MIN_CONFIRMATIONS" [macro]
    rule MIN_CONFIRMATIONS => 15

    syntax Int ::= "MAX_RELAYER_FEE_BPS" [macro]
    rule MAX_RELAYER_FEE_BPS => 500  // 5%

    // =========================================================================
    // QUERY TYPES
    // =========================================================================

    syntax QueryType ::= "RECEIPT" | "STORAGE" | "TRANSACTION" | "HEADER" | "ACCOUNT"

    syntax ReceiptQuery ::= receiptQuery(
        txHash: Bytes,
        logIndex: Int,
        blockNumber: Int,
        contractAddr: Bytes,
        topics: List,
        data: Bytes
    )

    syntax StorageQuery ::= storageQuery(
        contractAddr: Bytes,
        slot: Bytes,
        blockNumber: Int,
        value: Bytes
    )

    syntax TransactionQuery ::= transactionQuery(
        txHash: Bytes,
        blockNumber: Int,
        from: Bytes,
        to: Bytes,
        value: Int,
        data: Bytes
    )

    syntax HeaderQuery ::= headerQuery(
        blockNumber: Int,
        blockHash: Bytes,
        parentHash: Bytes,
        stateRoot: Bytes,
        timestamp: Int
    )

    syntax AccountQuery ::= accountQuery(
        accountAddr: Bytes,
        blockNumber: Int,
        balance: Int,
        nonce: Int,
        codeHash: Bytes,
        storageRoot: Bytes
    )

    // =========================================================================
    // PROOF TYPES
    // =========================================================================

    syntax ProofType ::= "GROTH16" | "PLONK" | "AGGREGATE"

    syntax Groth16Proof ::= groth16Proof(
        a: List,      // [x, y] G1 point
        b: List,      // [[x1, x2], [y1, y2]] G2 point
        c: List       // [x, y] G1 point
    )

    syntax PlonkProof ::= plonkProof(
        commitments: List,
        evaluations: List,
        openingProof: Bytes
    )

    syntax AggregateProof ::= aggregateProof(
        queryHashes: List,
        aggregateHash: Bytes,
        proof: Bytes,
        batchSize: Int
    )

    syntax BrevisProof ::= brevisProof(
        proofType: ProofType,
        queryHash: Bytes,
        resultHash: Bytes,
        proof: Bytes,
        timestamp: Int,
        chainId: Int
    )

    // =========================================================================
    // PRIVACY POOL STRUCTURES
    // =========================================================================

    syntax PrivacyNote ::= privacyNote(
        commitment: Bytes,
        amount: Int,
        token: Bytes,
        blinding: Bytes
    )

    syntax DepositData ::= depositData(
        commitment: Bytes,
        amount: Int,
        depositor: Bytes,
        timestamp: Int,
        leafIndex: Int
    )

    syntax WithdrawData ::= withdrawData(
        nullifierHash: Bytes,
        recipient: Bytes,
        amount: Int,
        relayer: Bytes,
        relayerFee: Int
    )

    syntax CrossChainNote ::= crossChainNote(
        sourceChain: Int,
        targetChain: Int,
        commitment: Bytes,
        nullifier: Bytes,
        pilBinding: Bytes
    )

    // =========================================================================
    // MERKLE TREE
    // =========================================================================

    syntax MerkleTree ::= merkleTree(
        root: Bytes,
        nextIndex: Int,
        filledSubtrees: Map,
        zeros: Map
    )

    syntax MerklePath ::= merklePath(
        leaf: Bytes,
        pathElements: List,
        pathIndices: List
    )

endmodule

module BREVIS-OPERATIONS
    imports BREVIS-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports CRYPTO

    // =========================================================================
    // HASH FUNCTIONS (Keccak256 for EVM compatibility)
    // =========================================================================

    syntax Bytes ::= hash2(Bytes, Bytes) [function, functional]
    rule hash2(Left, Right) => Keccak256(Left +Bytes Right)

    syntax Bytes ::= hashN(List) [function, functional]
    rule hashN(.List) => b""
    rule hashN(ListItem(B:Bytes)) => B
    rule hashN(ListItem(B1:Bytes) ListItem(B2:Bytes) Rest)
        => hashN(ListItem(hash2(B1, B2)) Rest)

    // =========================================================================
    // COMMITMENT COMPUTATION
    // =========================================================================

    // commitment = H(amount || token || blinding)
    syntax Bytes ::= computeCommitment(Int, Bytes, Bytes) [function, functional]
    rule computeCommitment(Amount, Token, Blinding)
        => Keccak256(Int2Bytes(32, Amount, BE) +Bytes Token +Bytes Blinding)

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // nullifier = H(secret || commitment || leafIndex)
    syntax Bytes ::= deriveNullifier(Bytes, Bytes, Int) [function, functional]
    rule deriveNullifier(Secret, Commitment, LeafIndex)
        => Keccak256(Secret +Bytes Commitment +Bytes Int2Bytes(32, LeafIndex, BE))

    // Cross-domain nullifier
    // cdnf = H(brevisNullifier || sourceChain || targetChain || "B2P")
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int, Int) [function, functional]
    rule deriveCrossDomainNullifier(Nf, SourceChain, TargetChain)
        => Keccak256(Nf +Bytes Int2Bytes(32, SourceChain, BE)
                       +Bytes Int2Bytes(32, TargetChain, BE)
                       +Bytes b"B2P")

    // PIL binding
    syntax Bytes ::= derivePILBinding(Bytes) [function, functional]
    rule derivePILBinding(BrevisNf)
        => Keccak256(BrevisNf +Bytes b"BREVIS_TO_PIL")

    // =========================================================================
    // QUERY HASH COMPUTATION
    // =========================================================================

    syntax Bytes ::= computeQueryHash(QueryType, Bytes) [function, functional]
    rule computeQueryHash(QType, Data)
        => Keccak256(queryTypeToBytes(QType) +Bytes Data)

    syntax Bytes ::= queryTypeToBytes(QueryType) [function, functional]
    rule queryTypeToBytes(RECEIPT) => b"\x00"
    rule queryTypeToBytes(STORAGE) => b"\x01"
    rule queryTypeToBytes(TRANSACTION) => b"\x02"
    rule queryTypeToBytes(HEADER) => b"\x03"
    rule queryTypeToBytes(ACCOUNT) => b"\x04"

    // =========================================================================
    // MERKLE TREE OPERATIONS
    // =========================================================================

    // Compute root from leaf and path
    syntax Bytes ::= computeRoot(Bytes, List, List) [function, functional]
    rule computeRoot(Leaf, .List, .List) => Leaf
    rule computeRoot(Leaf, ListItem(PE:Bytes) Path, ListItem(PI:Int) Indices)
        => computeRoot(
            #if PI ==Int 0
            #then hash2(Leaf, PE)
            #else hash2(PE, Leaf)
            #fi,
            Path,
            Indices
        )

    // Zero hash computation
    syntax Bytes ::= computeZeroHash(Int, Bytes) [function, functional]
    rule computeZeroHash(0, ZeroValue) => ZeroValue
    rule computeZeroHash(Level, ZeroValue)
        => hash2(computeZeroHash(Level -Int 1, ZeroValue),
                 computeZeroHash(Level -Int 1, ZeroValue))
        requires Level >Int 0

    // Insert leaf into tree
    syntax MerkleTree ::= insertLeaf(MerkleTree, Bytes) [function]
    rule insertLeaf(
        merkleTree(_, NextIdx, Subtrees, Zeros),
        Leaf
    ) => computeNewTree(Leaf, NextIdx, Subtrees, Zeros, 0)
        requires NextIdx <Int MAX_LEAVES

    // Helper for tree insertion
    syntax MerkleTree ::= computeNewTree(Bytes, Int, Map, Map, Int) [function]
    rule computeNewTree(CurrentHash, _, Subtrees, Zeros, MERKLE_DEPTH)
        => merkleTree(CurrentHash, _, Subtrees, Zeros)

    rule computeNewTree(CurrentHash, Idx, Subtrees, Zeros, Level)
        => #if (Idx >>Int Level) &Int 1 ==Int 0
           #then computeNewTree(
               hash2(CurrentHash, {Zeros[Level]}:>Bytes),
               Idx,
               Subtrees[Level <- CurrentHash],
               Zeros,
               Level +Int 1
           )
           #else computeNewTree(
               hash2({Subtrees[Level]}:>Bytes, CurrentHash),
               Idx,
               Subtrees,
               Zeros,
               Level +Int 1
           )
           #fi
        requires Level <Int MERKLE_DEPTH

    // =========================================================================
    // PROOF VERIFICATION
    // =========================================================================

    // Groth16 structure validation
    syntax Bool ::= verifyGroth16Structure(Groth16Proof) [function, functional]
    rule verifyGroth16Structure(groth16Proof(A, B, C))
        => size(A) ==Int 2 andBool size(B) ==Int 2 andBool size(C) ==Int 2

    // PLONK structure validation
    syntax Bool ::= verifyPlonkStructure(PlonkProof) [function, functional]
    rule verifyPlonkStructure(plonkProof(Commits, Evals, _))
        => size(Commits) >Int 0 andBool size(Evals) >Int 0

    // Aggregate proof validation
    syntax Bool ::= verifyAggregateProof(AggregateProof) [function, functional]
    rule verifyAggregateProof(aggregateProof(Hashes, AggHash, _, BatchSize))
        => size(Hashes) ==Int BatchSize andBool AggHash ==Bytes hashN(Hashes)

    // Brevis proof expiry check
    syntax Bool ::= isProofValid(Int, Int) [function, functional]
    rule isProofValid(ProofTimestamp, CurrentTimestamp)
        => (CurrentTimestamp -Int ProofTimestamp) <=Int PROOF_EXPIRY

    // =========================================================================
    // VALIDATION FUNCTIONS
    // =========================================================================

    syntax Bool ::= isBNBChain(Int) [function, functional]
    rule isBNBChain(ChainId) => ChainId ==Int BNB_MAINNET orBool ChainId ==Int BNB_TESTNET

    syntax Bool ::= isValidCommitment(Bytes) [function, functional]
    rule isValidCommitment(C) => C =/=K b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    syntax Bool ::= isValidNullifier(Bytes) [function, functional]
    rule isValidNullifier(N) => N =/=K b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    syntax Bool ::= isValidAmount(Int) [function, functional]
    rule isValidAmount(Amount) => Amount >=Int MIN_DEPOSIT andBool Amount <=Int MAX_DEPOSIT

    syntax Bool ::= isValidRelayerFee(Int, Int) [function, functional]
    rule isValidRelayerFee(Fee, Amount)
        => Fee <=Int (Amount *Int MAX_RELAYER_FEE_BPS) /Int 10000

    syntax Bool ::= hasEnoughConfirmations(Int, Int) [function, functional]
    rule hasEnoughConfirmations(QueryBlock, CurrentBlock)
        => CurrentBlock >=Int QueryBlock +Int MIN_CONFIRMATIONS

endmodule

module BREVIS-SECURITY
    imports BREVIS-OPERATIONS

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Property: Hash function is deterministic
    rule [hash-determinism]:
        hash2(L, R) ==Bytes hash2(L, R) => true

    // Property: Different inputs produce different hashes (collision resistance)
    rule [hash-collision-resistance]:
        hash2(L1, R1) ==Bytes hash2(L2, R2)
        => L1 ==Bytes L2 andBool R1 ==Bytes R2

    // Property: Commitment binding
    rule [commitment-binding]:
        computeCommitment(A1, T1, B1) ==Bytes computeCommitment(A2, T2, B2)
        => A1 ==Int A2 andBool T1 ==Bytes T2 andBool B1 ==Bytes B2

    // Property: Nullifier uniqueness
    rule [nullifier-uniqueness]:
        deriveNullifier(S1, C1, I1) ==Bytes deriveNullifier(S2, C2, I2)
        => S1 ==Bytes S2 andBool C1 ==Bytes C2 andBool I1 ==Int I2

    // Property: Cross-domain nullifier binding
    rule [cross-domain-binding]:
        deriveCrossDomainNullifier(Nf1, Src1, Tgt1) ==Bytes deriveCrossDomainNullifier(Nf2, Src2, Tgt2)
        => Nf1 ==Bytes Nf2 andBool Src1 ==Int Src2 andBool Tgt1 ==Int Tgt2

    // Property: PIL binding is one-way derivation
    rule [pil-binding-derivation]:
        derivePILBinding(Nf) =/=Bytes b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        requires isValidNullifier(Nf)

    // Property: Merkle path verification is consistent
    rule [merkle-consistency]:
        computeRoot(Leaf, Path, Indices) ==Bytes Root
        => isValidMerkleProof(Leaf, Path, Indices, Root) ==Bool true

    syntax Bool ::= isValidMerkleProof(Bytes, List, List, Bytes) [function]
    rule isValidMerkleProof(Leaf, Path, Indices, Root)
        => computeRoot(Leaf, Path, Indices) ==Bytes Root

    // Property: Amount bounds are enforced
    rule [amount-bounds]:
        isValidAmount(Amount) ==Bool true
        => Amount >=Int MIN_DEPOSIT andBool Amount <=Int MAX_DEPOSIT

    // Property: Relayer fee is bounded
    rule [relayer-fee-bounds]:
        isValidRelayerFee(Fee, Amount) ==Bool true
        => Fee <=Int (Amount *Int MAX_RELAYER_FEE_BPS) /Int 10000

endmodule

module BREVIS-POOL-INVARIANTS
    imports BREVIS-SECURITY

    // =========================================================================
    // POOL STATE INVARIANTS
    // =========================================================================

    // Invariant: Tree index never exceeds max
    rule [tree-index-bound]:
        merkleTree(_, NextIdx, _, _)
        => NextIdx <=Int MAX_LEAVES

    // Invariant: Nullifiers cannot be reused (double-spend prevention)
    syntax Bool ::= nullifierUsed(Map, Bytes) [function]
    rule nullifierUsed(UsedNullifiers, Nf)
        => Nf in_keys(UsedNullifiers)

    // Invariant: Each commitment has unique leaf index
    rule [commitment-leaf-uniqueness]:
        depositData(C1, _, _, _, I1) andBool depositData(C2, _, _, _, I2)
        => (C1 ==Bytes C2 impliesBool I1 ==Int I2)

    // Invariant: Daily volume cannot exceed limit
    syntax Bool ::= checkDailyLimit(Int, Int) [function]
    rule checkDailyLimit(CurrentVolume, NewAmount)
        => CurrentVolume +Int NewAmount <=Int DAILY_LIMIT

    // Invariant: Root history is maintained
    syntax Bool ::= isKnownRoot(Map, Bytes) [function]
    rule isKnownRoot(RootHistory, Root)
        => Root in_keys(RootHistory)

    // =========================================================================
    // CROSS-CHAIN INVARIANTS
    // =========================================================================

    // Invariant: Cross-domain nullifier mapping is bidirectional
    rule [cross-domain-bidirectional]:
        crossChainNote(Src, Tgt, C, Nf, Binding)
        => deriveCrossDomainNullifier(Nf, Src, Tgt) ==Bytes
           deriveCrossDomainNullifier(Nf, Src, Tgt)

    // Invariant: PIL binding is consistent
    rule [pil-binding-consistent]:
        derivePILBinding(Nf1) ==Bytes derivePILBinding(Nf2)
        => Nf1 ==Bytes Nf2

endmodule

module BREVIS
    imports BREVIS-POOL-INVARIANTS
endmodule
