// K Framework Formal Specification for Scroll zkEVM
// Zaseon - Scroll Bridge Formalization

module SCROLL-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // SCROLL CONSTANTS
    // =========================================================================

    // Chain IDs
    syntax Int ::= "SCROLL_MAINNET_CHAIN_ID"  [function, total]
                 | "SCROLL_SEPOLIA_CHAIN_ID"  [function, total]

    rule SCROLL_MAINNET_CHAIN_ID => 534352
    rule SCROLL_SEPOLIA_CHAIN_ID => 534351

    // Timing Constants
    syntax Int ::= "FINALIZATION_PERIOD"    [function, total]
                 | "BATCH_SUBMISSION_WINDOW" [function, total]
                 | "PROOF_GENERATION_WINDOW" [function, total]

    rule FINALIZATION_PERIOD => 3600  // 1 hour (ZK finality)
    rule BATCH_SUBMISSION_WINDOW => 1800  // 30 minutes
    rule PROOF_GENERATION_WINDOW => 7200  // 2 hours

    // Gas Constants
    syntax Int ::= "L1_GAS_ORACLE_OVERHEAD"  [function, total]
                 | "DEFAULT_L2_GAS_LIMIT"    [function, total]
                 | "L2_MESSAGE_GAS_LIMIT"    [function, total]

    rule L1_GAS_ORACLE_OVERHEAD => 5000
    rule DEFAULT_L2_GAS_LIMIT => 1000000
    rule L2_MESSAGE_GAS_LIMIT => 200000

    // =========================================================================
    // SCROLL DATA STRUCTURES
    // =========================================================================

    // Batch Status
    syntax BatchStatus ::= "BATCH_COMMITTED"
                         | "BATCH_FINALIZED"
                         | "BATCH_REVERTED"

    // Message Type
    syntax MessageType ::= "DEPOSIT"
                         | "WITHDRAWAL"
                         | "RELAY"
                         | "ENFORCE"

    // Cross-domain message
    syntax ScrollMessage ::= scrollMessage(
        messageId: Bytes,
        messageType: MessageType,
        sender: Bytes,
        target: Bytes,
        value: Int,
        gasLimit: Int,
        data: Bytes,
        nonce: Int,
        timestamp: Int,
        executed: Bool
    )

    // L1 -> L2 Deposit
    syntax Deposit ::= deposit(
        depositId: Bytes,
        sender: Bytes,
        recipient: Bytes,
        token: Bytes,
        amount: Int,
        gasLimit: Int,
        queueIndex: Int,
        timestamp: Int,
        status: Int
    )

    // L2 -> L1 Withdrawal
    syntax Withdrawal ::= withdrawal(
        withdrawalId: Bytes,
        sender: Bytes,
        recipient: Bytes,
        token: Bytes,
        amount: Int,
        batchIndex: Int,
        messageNonce: Int,
        timestamp: Int,
        finalized: Bool
    )

    // Batch data
    syntax ScrollBatch ::= scrollBatch(
        batchIndex: Int,
        batchHash: Bytes,
        stateRoot: Bytes,
        withdrawalRoot: Bytes,
        l1MessagePopped: Int,
        totalL1MessagePopped: Int,
        dataHash: Bytes,
        timestamp: Int,
        status: BatchStatus
    )

    // ZK Proof (zkEVM)
    syntax ZKEVMProof ::= zkevmProof(
        batchIndex: Int,
        proof: Bytes,
        instances: List,
        aggregatedProof: Bytes
    )

    // Nullifier
    syntax Nullifier ::= nullifier(
        hash: Bytes,
        messageId: Bytes,
        domain: Bytes,
        consumed: Bool
    )

endmodule

module SCROLL-KECCAK
    imports SCROLL-TYPES
    imports KECCAK256

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Compute message hash
    syntax Bytes ::= computeMessageHash(Bytes, Bytes, Int, Int, Bytes, Int) [function]
    rule computeMessageHash(Sender, Target, Value, GasLimit, Data, Nonce) =>
        keccak256(Sender +Bytes Target +Bytes Int2Bytes(Value, BE, Unsigned) +Bytes 
                  Int2Bytes(GasLimit, BE, Unsigned) +Bytes Data +Bytes Int2Bytes(Nonce, BE, Unsigned))

    // Compute deposit hash
    syntax Bytes ::= computeDepositHash(Bytes, Bytes, Bytes, Int, Int) [function]
    rule computeDepositHash(Sender, Recipient, Token, Amount, QueueIndex) =>
        keccak256(Sender +Bytes Recipient +Bytes Token +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes Int2Bytes(QueueIndex, BE, Unsigned))

    // Compute batch hash
    syntax Bytes ::= computeBatchHash(Bytes, Bytes, Bytes, Int) [function]
    rule computeBatchHash(StateRoot, WithdrawalRoot, DataHash, L1MsgPopped) =>
        keccak256(StateRoot +Bytes WithdrawalRoot +Bytes DataHash +Bytes Int2Bytes(L1MsgPopped, BE, Unsigned))

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Scroll nullifier
    syntax Bytes ::= deriveScrollNullifier(Bytes, Bytes, Int) [function]
    rule deriveScrollNullifier(MessageId, Domain, Timestamp) =>
        keccak256(MessageId +Bytes Domain +Bytes Int2Bytes(Timestamp, BE, Unsigned) +Bytes b"SCROLL_NULLIFIER")

    // Derive cross-domain Soul nullifier
    syntax Bytes ::= deriveSoulNullifier(Bytes, Bytes) [function]
    rule deriveSoulNullifier(ScrollNullifier, Domain) =>
        keccak256(ScrollNullifier +Bytes Domain +Bytes b"SCROLL2Soul")

endmodule

module SCROLL-ZKEVM
    imports SCROLL-KECCAK

    // =========================================================================
    // ZKEVM PROOF VERIFICATION
    // =========================================================================

    // Verify zkEVM proof structure
    syntax Bool ::= isValidProofStructure(ZKEVMProof) [function]
    rule isValidProofStructure(zkevmProof(BatchIndex, Proof, Instances, AggProof)) =>
        BatchIndex >Int 0 andBool
        lengthBytes(Proof) >Int 0 andBool
        size(Instances) >Int 0 andBool
        lengthBytes(AggProof) >Int 0

    // Verify batch proof (simplified)
    syntax Bool ::= verifyBatchProof(ScrollBatch, ZKEVMProof) [function]
    rule verifyBatchProof(scrollBatch(BatchIndex, _, StateRoot, _, _, _, _, _, _), zkevmProof(PBatchIndex, _, Instances, _)) =>
        BatchIndex ==Int PBatchIndex andBool
        #containsStateRoot(Instances, StateRoot)

    // Helper: check if instances contain state root
    syntax Bool ::= "#containsStateRoot" "(" List "," Bytes ")" [function]
    rule #containsStateRoot(.List, _) => false
    rule #containsStateRoot(ListItem(X) Rest, Root) => X ==K Root orBool #containsStateRoot(Rest, Root)

endmodule

module SCROLL-MERKLE
    imports SCROLL-ZKEVM

    // =========================================================================
    // WITHDRAWAL MERKLE TREE
    // =========================================================================

    // Withdrawal tree depth
    syntax Int ::= "WITHDRAWAL_TREE_DEPTH" [function, total]
    rule WITHDRAWAL_TREE_DEPTH => 32

    // Verify withdrawal Merkle proof
    syntax Bool ::= verifyWithdrawalProof(Bytes, Bytes, List, Int) [function]
    rule verifyWithdrawalProof(LeafHash, Root, Proof, Index) =>
        verifyWithdrawalProofHelper(LeafHash, Root, Proof, Index, 0)

    syntax Bool ::= verifyWithdrawalProofHelper(Bytes, Bytes, List, Int, Int) [function]
    rule verifyWithdrawalProofHelper(Current, Root, .List, _Index, _Depth) => Current ==K Root
    rule verifyWithdrawalProofHelper(Current, Root, ListItem(Sibling) Rest, Index, Depth) =>
        verifyWithdrawalProofHelper(
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

module SCROLL-BRIDGE-SECURITY
    imports SCROLL-MERKLE

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Batch is finalized
    syntax Bool ::= isBatchFinalized(ScrollBatch) [function]
    rule isBatchFinalized(scrollBatch(_, _, _, _, _, _, _, _, Status)) =>
        Status ==K BATCH_FINALIZED

    // Withdrawal is claimable
    syntax Bool ::= isWithdrawalClaimable(Withdrawal, ScrollBatch) [function]
    rule isWithdrawalClaimable(withdrawal(_, _, _, _, _, BatchIndex, _, _, Finalized), scrollBatch(BI, _, _, _, _, _, _, _, Status)) =>
        BatchIndex ==Int BI andBool Status ==K BATCH_FINALIZED andBool notBool Finalized

    // Message has valid gas
    syntax Bool ::= hasValidGas(ScrollMessage) [function]
    rule hasValidGas(scrollMessage(_, _, _, _, _, GasLimit, _, _, _, _)) =>
        GasLimit >Int 0 andBool GasLimit <=Int DEFAULT_L2_GAS_LIMIT

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Batch finalization before withdrawal
    syntax Bool ::= batchFinalizedBeforeWithdrawal(Withdrawal, ScrollBatch) [function]
    rule batchFinalizedBeforeWithdrawal(W, B) => isWithdrawalClaimable(W, B) impliesBool isBatchFinalized(B)

    // INVARIANT 3: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Bytes) [function]
    rule crossDomainNullifierDeterministic(MsgId1, MsgId2) =>
        (MsgId1 ==K MsgId2) impliesBool
        (deriveScrollNullifier(MsgId1, b"Soul", 0) ==K deriveScrollNullifier(MsgId2, b"Soul", 0))

    // INVARIANT 4: Different messages produce different nullifiers
    syntax Bool ::= differentMessagesUniqueNullifiers(Bytes, Bytes, Bytes) [function]
    rule differentMessagesUniqueNullifiers(MsgId1, MsgId2, Domain) =>
        (MsgId1 =/=K MsgId2) impliesBool
        (deriveScrollNullifier(MsgId1, Domain, 0) =/=K deriveScrollNullifier(MsgId2, Domain, 0))

    // INVARIANT 5: Batch index monotonicity
    syntax Bool ::= batchIndexMonotonic(Int, Int) [function]
    rule batchIndexMonotonic(PrevBatch, NewBatch) => NewBatch >Int PrevBatch

    // INVARIANT 6: ZK proof validity
    syntax Bool ::= zkProofValid(ZKEVMProof) [function]
    rule zkProofValid(P) => isValidProofStructure(P)

    // INVARIANT 7: L1 message queue ordering
    syntax Bool ::= l1MessageQueueOrdered(Int, Int) [function]
    rule l1MessageQueueOrdered(PrevPopped, TotalPopped) =>
        TotalPopped >=Int PrevPopped

    // INVARIANT 8: Gas limit bounds
    syntax Bool ::= gasLimitBounded(ScrollMessage) [function]
    rule gasLimitBounded(M) => hasValidGas(M)

    // INVARIANT 9: Withdrawal Merkle proof soundness
    syntax Bool ::= withdrawalProofSound(Bytes, Bytes, List, Int) [function]
    rule withdrawalProofSound(Leaf, Root, Proof, Index) =>
        verifyWithdrawalProof(Leaf, Root, Proof, Index) impliesBool
        size(Proof) <=Int WITHDRAWAL_TREE_DEPTH

    // INVARIANT 10: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (deriveSoulNullifier(Nf, DomainA) =/=K deriveSoulNullifier(Nf, DomainB))

endmodule

module SCROLL-BRIDGE
    imports SCROLL-BRIDGE-SECURITY

    // =========================================================================
    // MAIN SCROLL BRIDGE SPECIFICATION
    // =========================================================================

    configuration
        <scroll>
            <messages> .Map </messages>
            <deposits> .Map </deposits>
            <withdrawals> .Map </withdrawals>
            <batches> .Map </batches>
            <nullifiers> .Set </nullifiers>
            <messageNonce> 0 </messageNonce>
            <queueIndex> 0 </queueIndex>
            <currentBatchIndex> 0 </currentBatchIndex>
            <currentTime> 0 </currentTime>
            <totalDeposited> 0 </totalDeposited>
            <totalWithdrawn> 0 </totalWithdrawn>
        </scroll>

    // =========================================================================
    // STATE TRANSITIONS
    // =========================================================================

    // Queue L1 -> L2 Deposit
    rule <scroll>
            <deposits> D => D[DepositId <- NewDeposit] </deposits>
            <queueIndex> QI => QI +Int 1 </queueIndex>
            <currentTime> T </currentTime>
            <totalDeposited> Total => Total +Int Amount </totalDeposited>
            ...
         </scroll>
         requires notBool (DepositId in_keys(D))
         where DepositId = computeDepositHash(Sender, Recipient, Token, Amount, QI)
           and NewDeposit = deposit(DepositId, Sender, Recipient, Token, Amount, GasLimit, QI, T, 0)

    // Finalize Batch
    rule <scroll>
            <batches> B => B[BatchIndex <- finalizeBatch(B[BatchIndex])] </batches>
            ...
         </scroll>
         requires BatchIndex in_keys(B)
          andBool getStatus(B[BatchIndex]) ==K BATCH_COMMITTED

    // Claim Withdrawal
    rule <scroll>
            <withdrawals> W => W[WId <- markWithdrawalFinalized(W[WId])] </withdrawals>
            <batches> B </batches>
            <nullifiers> Nfs => Nfs |Set SetItem(NullifierHash) </nullifiers>
            <currentTime> T </currentTime>
            <totalWithdrawn> Total => Total +Int Amount </totalWithdrawn>
            ...
         </scroll>
         requires isWithdrawalClaimable(W[WId], B[getBatchIndex(W[WId])])
          andBool nullifierUnique(NullifierHash, Nfs)
         where NullifierHash = deriveScrollNullifier(WId, b"Soul", T)

    // Helper functions
    syntax BatchStatus ::= getStatus(ScrollBatch) [function]
    rule getStatus(scrollBatch(_, _, _, _, _, _, _, _, Status)) => Status

    syntax Int ::= getBatchIndex(Withdrawal) [function]
    rule getBatchIndex(withdrawal(_, _, _, _, _, BatchIndex, _, _, _)) => BatchIndex

    syntax ScrollBatch ::= finalizeBatch(ScrollBatch) [function]
    rule finalizeBatch(scrollBatch(BI, BH, SR, WR, L1MP, TL1MP, DH, TS, _)) =>
        scrollBatch(BI, BH, SR, WR, L1MP, TL1MP, DH, TS, BATCH_FINALIZED)

    syntax Withdrawal ::= markWithdrawalFinalized(Withdrawal) [function]
    rule markWithdrawalFinalized(withdrawal(Id, S, R, T, A, BI, MN, TS, _)) =>
        withdrawal(Id, S, R, T, A, BI, MN, TS, true)

endmodule
