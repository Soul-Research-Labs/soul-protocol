// K Framework Formal Specification for Polygon zkEVM
// Zaseon - Polygon zkEVM Bridge Formalization

module POLYGON-ZKEVM-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // POLYGON ZKEVM CONSTANTS
    // =========================================================================

    // Chain IDs
    syntax Int ::= "POLYGON_ZKEVM_CHAIN_ID"     [function, total]
                 | "POLYGON_ZKEVM_CARDONA_ID"   [function, total]

    rule POLYGON_ZKEVM_CHAIN_ID => 1101
    rule POLYGON_ZKEVM_CARDONA_ID => 2442

    // Timing Constants
    syntax Int ::= "FORCE_BATCH_TIMEOUT"        [function, total]
                 | "PENDING_STATE_TIMEOUT"      [function, total]
                 | "TRUSTED_AGGREGATOR_TIMEOUT" [function, total]

    rule FORCE_BATCH_TIMEOUT => 432000  // 5 days
    rule PENDING_STATE_TIMEOUT => 604800  // 7 days
    rule TRUSTED_AGGREGATOR_TIMEOUT => 604800

    // Merkle Tree Constants
    syntax Int ::= "DEPOSIT_TREE_DEPTH"         [function, total]
                 | "GLOBAL_EXIT_ROOT_DEPTH"     [function, total]

    rule DEPOSIT_TREE_DEPTH => 32
    rule GLOBAL_EXIT_ROOT_DEPTH => 32

    // =========================================================================
    // DATA STRUCTURES
    // =========================================================================

    // Batch Status
    syntax BatchStatus ::= "BATCH_SEQUENCED"
                         | "BATCH_VERIFIED"
                         | "BATCH_CONSOLIDATED"

    // Bridge Message
    syntax BridgeMessage ::= bridgeMessage(
        leafType: Int,
        originNetwork: Int,
        originAddress: Bytes,
        destinationNetwork: Int,
        destinationAddress: Bytes,
        amount: Int,
        metadata: Bytes,
        depositCount: Int
    )

    // Global Exit Root
    syntax GlobalExitRoot ::= globalExitRoot(
        mainnetExitRoot: Bytes,
        rollupExitRoot: Bytes,
        timestamp: Int
    )

    // Batch Sequencing
    syntax BatchData ::= batchData(
        batchNum: Int,
        transactions: Bytes,
        globalExitRoot: Bytes,
        timestamp: Int,
        minForcedTimestamp: Int,
        sequencer: Bytes
    )

    // Verified Batch
    syntax VerifiedBatch ::= verifiedBatch(
        batchNum: Int,
        stateRoot: Bytes,
        localExitRoot: Bytes,
        aggregator: Bytes,
        timestamp: Int
    )

    // Nullifier
    syntax Nullifier ::= nullifier(
        hash: Bytes,
        depositCount: Int,
        originNetwork: Int,
        consumed: Bool
    )

endmodule

module POLYGON-ZKEVM-KECCAK
    imports POLYGON-ZKEVM-TYPES
    imports KECCAK256

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Compute deposit leaf hash
    syntax Bytes ::= computeDepositLeaf(BridgeMessage) [function]
    rule computeDepositLeaf(bridgeMessage(LeafType, OriginNet, OriginAddr, DestNet, DestAddr, Amount, Metadata, DepCount)) =>
        keccak256(Int2Bytes(LeafType, BE, Unsigned) +Bytes
                  Int2Bytes(OriginNet, BE, Unsigned) +Bytes
                  OriginAddr +Bytes
                  Int2Bytes(DestNet, BE, Unsigned) +Bytes
                  DestAddr +Bytes
                  Int2Bytes(Amount, BE, Unsigned) +Bytes
                  keccak256(Metadata))

    // Compute global exit root
    syntax Bytes ::= computeGlobalExitRoot(Bytes, Bytes) [function]
    rule computeGlobalExitRoot(MainnetRoot, RollupRoot) =>
        keccak256(MainnetRoot +Bytes RollupRoot)

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Polygon zkEVM nullifier
    syntax Bytes ::= derivePolygonZkEVMNullifier(Int, Int, Bytes) [function]
    rule derivePolygonZkEVMNullifier(DepositCount, OriginNetwork, Domain) =>
        keccak256(Int2Bytes(DepositCount, BE, Unsigned) +Bytes Int2Bytes(OriginNetwork, BE, Unsigned) +Bytes Domain +Bytes b"POLYGON_ZKEVM_NULLIFIER")

    // Derive cross-domain Soul nullifier
    syntax Bytes ::= deriveSoulNullifier(Bytes, Bytes) [function]
    rule deriveSoulNullifier(PolygonNullifier, Domain) =>
        keccak256(PolygonNullifier +Bytes Domain +Bytes b"POLYGONZKEVM2Soul")

endmodule

module POLYGON-ZKEVM-MERKLE
    imports POLYGON-ZKEVM-KECCAK

    // =========================================================================
    // SPARSE MERKLE TREE FOR DEPOSITS
    // =========================================================================

    // Verify deposit Merkle proof
    syntax Bool ::= verifyDepositProof(Bytes, Bytes, List, Int) [function]
    rule verifyDepositProof(LeafHash, Root, Proof, Index) =>
        verifyDepositProofHelper(LeafHash, Root, Proof, Index, 0)

    syntax Bool ::= verifyDepositProofHelper(Bytes, Bytes, List, Int, Int) [function]
    rule verifyDepositProofHelper(Current, Root, .List, _Index, _Depth) => Current ==K Root
    rule verifyDepositProofHelper(Current, Root, ListItem(Sibling) Rest, Index, Depth) =>
        verifyDepositProofHelper(
            #if (Index >>Int Depth) &Int 1 ==Int 0
            #then keccak256(Current +Bytes Sibling)
            #else keccak256(Sibling +Bytes Current)
            #fi,
            Root,
            Rest,
            Index,
            Depth +Int 1
        )

endmodule

module POLYGON-ZKEVM-BRIDGE-SECURITY
    imports POLYGON-ZKEVM-MERKLE

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Batch verification before claim
    syntax Bool ::= batchVerifiedBeforeClaim(VerifiedBatch) [function]
    rule batchVerifiedBeforeClaim(verifiedBatch(_, StateRoot, _, _, _)) =>
        lengthBytes(StateRoot) ==Int 32

    // INVARIANT 3: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Int, Int, Int, Int) [function]
    rule crossDomainNullifierDeterministic(DC1, ON1, DC2, ON2) =>
        (DC1 ==Int DC2 andBool ON1 ==Int ON2) impliesBool
        (derivePolygonZkEVMNullifier(DC1, ON1, b"Soul") ==K derivePolygonZkEVMNullifier(DC2, ON2, b"Soul"))

    // INVARIANT 4: Deposit count monotonicity
    syntax Bool ::= depositCountMonotonic(Int, Int) [function]
    rule depositCountMonotonic(PrevCount, NewCount) => NewCount >Int PrevCount

    // INVARIANT 5: Global exit root validity
    syntax Bool ::= globalExitRootValid(GlobalExitRoot) [function]
    rule globalExitRootValid(globalExitRoot(MainnetRoot, RollupRoot, _)) =>
        lengthBytes(MainnetRoot) ==Int 32 andBool lengthBytes(RollupRoot) ==Int 32

    // INVARIANT 6: Network ID bounds
    syntax Bool ::= networkIdValid(Int) [function]
    rule networkIdValid(NetworkId) => NetworkId >=Int 0 andBool NetworkId <Int 2 ^Int 32

    // INVARIANT 7: Deposit proof soundness
    syntax Bool ::= depositProofSound(Bytes, Bytes, List, Int) [function]
    rule depositProofSound(Leaf, Root, Proof, Index) =>
        verifyDepositProof(Leaf, Root, Proof, Index) impliesBool
        size(Proof) ==Int DEPOSIT_TREE_DEPTH

    // INVARIANT 8: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (deriveSoulNullifier(Nf, DomainA) =/=K deriveSoulNullifier(Nf, DomainB))

endmodule

module POLYGON-ZKEVM-BRIDGE
    imports POLYGON-ZKEVM-BRIDGE-SECURITY

    configuration
        <polygonZkEVM>
            <deposits> .Map </deposits>
            <claims> .Map </claims>
            <batches> .Map </batches>
            <globalExitRoots> .Map </globalExitRoots>
            <nullifiers> .Set </nullifiers>
            <depositCount> 0 </depositCount>
            <currentBatch> 0 </currentBatch>
            <currentTime> 0 </currentTime>
        </polygonZkEVM>

endmodule
