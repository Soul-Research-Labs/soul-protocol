// K Framework Formal Specification for zkSync Era
// Zaseon - zkSync Bridge Formalization

module ZKSYNC-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // ZKSYNC ERA CONSTANTS
    // =========================================================================

    // Chain IDs
    syntax Int ::= "ZKSYNC_ERA_CHAIN_ID"    [function, total]
                 | "ZKSYNC_SEPOLIA_CHAIN_ID" [function, total]

    rule ZKSYNC_ERA_CHAIN_ID => 324
    rule ZKSYNC_SEPOLIA_CHAIN_ID => 300

    // Gas Constants (zkSync specific)
    syntax Int ::= "L2_GAS_PER_PUBDATA"     [function, total]
                 | "DEFAULT_L2_GAS_LIMIT"   [function, total]
                 | "PRIORITY_TX_MAX_GAS"    [function, total]
                 | "REQUIRED_L2_GAS_PRICE"  [function, total]

    rule L2_GAS_PER_PUBDATA => 800
    rule DEFAULT_L2_GAS_LIMIT => 2000000
    rule PRIORITY_TX_MAX_GAS => 72000000
    rule REQUIRED_L2_GAS_PRICE => 250000000  // 0.25 gwei

    // Timing Constants
    syntax Int ::= "BATCH_COMMIT_DELAY"     [function, total]
                 | "BATCH_EXECUTE_DELAY"    [function, total]
                 | "PRIORITY_EXPIRATION"    [function, total]

    rule BATCH_COMMIT_DELAY => 0  // ZK proofs enable instant commit
    rule BATCH_EXECUTE_DELAY => 3600  // 1 hour typical
    rule PRIORITY_EXPIRATION => 604800  // 7 days

    // =========================================================================
    // ZKSYNC DATA STRUCTURES
    // =========================================================================

    // Transfer Status
    syntax RequestStatus ::= "PENDING"
                            | "PROVED"
                            | "EXECUTED"
                            | "FAILED"

    // Proof Type
    syntax ProofType ::= "DEPOSIT_PROOF"
                       | "WITHDRAWAL_PROOF"
                       | "MESSAGE_PROOF"
                       | "BATCH_PROOF"

    // L1 -> L2 Deposit
    syntax L1ToL2Deposit ::= deposit(
        depositId: Bytes,
        sender: Bytes,
        l2Receiver: Bytes,
        l1Token: Bytes,
        l2Token: Bytes,
        amount: Int,
        l2GasLimit: Int,
        l2GasPerPubdata: Int,
        l2TxHash: Bytes,
        status: RequestStatus,
        priorityOpId: Int,
        initiatedAt: Int
    )

    // L2 -> L1 Withdrawal
    syntax L2ToL1Withdrawal ::= withdrawal(
        withdrawalId: Bytes,
        l2Sender: Bytes,
        l1Receiver: Bytes,
        l2Token: Bytes,
        l1Token: Bytes,
        amount: Int,
        l2BatchNumber: Int,
        l2MessageIndex: Int,
        l2TxNumberInBatch: Int,
        l2TxHash: Bytes,
        status: RequestStatus,
        initiatedAt: Int,
        finalizedAt: Int
    )

    // L2 Log (for withdrawal proof)
    syntax L2Log ::= l2Log(
        l2ShardId: Int,
        isService: Bool,
        txNumberInBatch: Int,
        sender: Bytes,
        key: Bytes,
        value: Bytes
    )

    // Batch Information
    syntax BatchInfo ::= batchInfo(
        batchNumber: Int,
        batchHash: Bytes,
        stateRoot: Bytes,
        timestamp: Int,
        commitment: Bytes,
        verified: Bool,
        executed: Bool
    )

    // ZK Proof (Boojum/PLONK)
    syntax ZKProof ::= zkProof(
        proof: Bytes,
        publicInputs: List,
        commitment: Bytes,
        proofType: ProofType
    )

    // Priority Operation
    syntax PriorityOp ::= priorityOp(
        opId: Int,
        opType: Int,        // 0: Deposit, 1: FullExit
        pubdata: Bytes,
        expirationBlock: Int,
        layer2Tip: Int
    )

    // Nullifier
    syntax Nullifier ::= nullifier(
        nullifierHash: Bytes,
        transferId: Bytes,
        domain: Bytes,
        consumed: Bool,
        timestamp: Int
    )

endmodule

module ZKSYNC-KECCAK
    imports ZKSYNC-TYPES
    imports KECCAK256

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Compute deposit hash
    syntax Bytes ::= computeDepositHash(Bytes, Bytes, Bytes, Int, Int) [function]
    rule computeDepositHash(Sender, L2Receiver, Token, Amount, Nonce) =>
        keccak256(Sender +Bytes L2Receiver +Bytes Token +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes Int2Bytes(Nonce, BE, Unsigned))

    // Compute withdrawal hash
    syntax Bytes ::= computeWithdrawalHash(Bytes, Bytes, Int, Int, Int) [function]
    rule computeWithdrawalHash(L2Sender, L1Receiver, Amount, BatchNum, MsgIndex) =>
        keccak256(L2Sender +Bytes L1Receiver +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes Int2Bytes(BatchNum, BE, Unsigned) +Bytes Int2Bytes(MsgIndex, BE, Unsigned))

    // Compute L2 log hash
    syntax Bytes ::= computeL2LogHash(L2Log) [function]
    rule computeL2LogHash(l2Log(ShardId, IsService, TxNum, Sender, Key, Value)) =>
        keccak256(Int2Bytes(ShardId, BE, Unsigned) +Bytes 
                  #if IsService #then b"\x01" #else b"\x00" #fi +Bytes
                  Int2Bytes(TxNum, BE, Unsigned) +Bytes
                  Sender +Bytes Key +Bytes Value)

    // Compute batch commitment
    syntax Bytes ::= computeBatchCommitment(Bytes, Bytes, Int) [function]
    rule computeBatchCommitment(StateRoot, BatchHash, Timestamp) =>
        keccak256(b"BATCH_COMMITMENT" +Bytes StateRoot +Bytes BatchHash +Bytes Int2Bytes(Timestamp, BE, Unsigned))

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive zkSync nullifier
    syntax Bytes ::= deriveZkSyncNullifier(Bytes, Bytes, Int) [function]
    rule deriveZkSyncNullifier(TransferId, Domain, Timestamp) =>
        keccak256(TransferId +Bytes Domain +Bytes Int2Bytes(Timestamp, BE, Unsigned) +Bytes b"ZKSYNC_NULLIFIER")

    // Derive cross-domain Soul nullifier
    syntax Bytes ::= deriveSoulNullifier(Bytes, Bytes) [function]
    rule deriveSoulNullifier(ZkSyncNullifier, Domain) =>
        keccak256(ZkSyncNullifier +Bytes Domain +Bytes b"ZKSYNC2Soul")

endmodule

module ZKSYNC-ZK-PROOFS
    imports ZKSYNC-KECCAK

    // =========================================================================
    // ZK PROOF VERIFICATION (BOOJUM/PLONK)
    // =========================================================================

    // Boojum proof structure constants
    syntax Int ::= "PROOF_SIZE_BYTES"       [function, total]
                 | "PUBLIC_INPUTS_SIZE"     [function, total]
                 | "VERIFICATION_KEY_SIZE"  [function, total]

    rule PROOF_SIZE_BYTES => 576  // 9 * 64 bytes for PLONK
    rule PUBLIC_INPUTS_SIZE => 32  // Single field element
    rule VERIFICATION_KEY_SIZE => 800

    // Verify ZK proof structure (simplified)
    syntax Bool ::= isValidProofStructure(ZKProof) [function]
    rule isValidProofStructure(zkProof(Proof, Inputs, Commitment, _)) =>
        lengthBytes(Proof) >=Int PROOF_SIZE_BYTES andBool
        size(Inputs) >Int 0 andBool
        lengthBytes(Commitment) ==Int 32

    // Verify batch proof
    syntax Bool ::= verifyBatchProof(BatchInfo, ZKProof) [function]
    rule verifyBatchProof(batchInfo(_, BatchHash, StateRoot, _, Commitment, _, _), zkProof(_, Inputs, ProofCommit, BATCH_PROOF)) =>
        ProofCommit ==K Commitment andBool
        #hasPublicInput(Inputs, BatchHash) andBool
        #hasPublicInput(Inputs, StateRoot)

    // Helper to check if list contains a bytes value
    syntax Bool ::= "#hasPublicInput" "(" List "," Bytes ")" [function]
    rule #hasPublicInput(.List, _) => false
    rule #hasPublicInput(ListItem(X) Rest, Target) => X ==K Target orBool #hasPublicInput(Rest, Target)

endmodule

module ZKSYNC-MERKLE
    imports ZKSYNC-ZK-PROOFS

    // =========================================================================
    // MERKLE PROOFS FOR L2 LOGS
    // =========================================================================

    // L2 log tree depth
    syntax Int ::= "L2_LOG_TREE_DEPTH" [function, total]
    rule L2_LOG_TREE_DEPTH => 10  // 1024 logs per batch

    // Verify L2 log Merkle proof
    syntax Bool ::= verifyL2LogProof(Bytes, Bytes, List, Int) [function]
    rule verifyL2LogProof(LogHash, Root, Proof, Index) =>
        verifyL2LogProofHelper(LogHash, Root, Proof, Index, 0)

    syntax Bool ::= verifyL2LogProofHelper(Bytes, Bytes, List, Int, Int) [function]
    rule verifyL2LogProofHelper(Current, Root, .List, _Index, _Depth) => Current ==K Root
    rule verifyL2LogProofHelper(Current, Root, ListItem(Sibling) Rest, Index, Depth) =>
        verifyL2LogProofHelper(
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

module ZKSYNC-BRIDGE-SECURITY
    imports ZKSYNC-MERKLE

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Withdrawal is finalizable
    syntax Bool ::= isWithdrawalFinalizable(L2ToL1Withdrawal, BatchInfo) [function]
    rule isWithdrawalFinalizable(withdrawal(_, _, _, _, _, _, BatchNum, _, _, _, Status, _, _), batchInfo(BN, _, _, _, _, Verified, Executed)) =>
        Status ==K PROVED andBool BatchNum ==Int BN andBool Verified andBool Executed

    // Deposit has valid gas
    syntax Bool ::= hasValidGas(L1ToL2Deposit) [function]
    rule hasValidGas(deposit(_, _, _, _, _, _, L2Gas, L2GasPerPubdata, _, _, _, _)) =>
        L2Gas >=Int 0 andBool L2Gas <=Int PRIORITY_TX_MAX_GAS andBool
        L2GasPerPubdata >=Int L2_GAS_PER_PUBDATA

    // Batch is verified
    syntax Bool ::= isBatchVerified(BatchInfo) [function]
    rule isBatchVerified(batchInfo(_, _, _, _, _, Verified, _)) => Verified

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Batch verification before execution
    syntax Bool ::= batchVerifiedBeforeExecution(BatchInfo) [function]
    rule batchVerifiedBeforeExecution(batchInfo(_, _, _, _, _, Verified, Executed)) =>
        Executed impliesBool Verified

    // INVARIANT 3: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Bytes) [function]
    rule crossDomainNullifierDeterministic(Id1, Id2) =>
        (Id1 ==K Id2) impliesBool
        (deriveZkSyncNullifier(Id1, b"Soul", 0) ==K deriveZkSyncNullifier(Id2, b"Soul", 0))

    // INVARIANT 4: Different transfers produce different nullifiers
    syntax Bool ::= differentTransfersUniqueNullifiers(Bytes, Bytes, Bytes) [function]
    rule differentTransfersUniqueNullifiers(Id1, Id2, Domain) =>
        (Id1 =/=K Id2) impliesBool
        (deriveZkSyncNullifier(Id1, Domain, 0) =/=K deriveZkSyncNullifier(Id2, Domain, 0))

    // INVARIANT 5: ZK proof structure validity
    syntax Bool ::= zkProofStructureValid(ZKProof) [function]
    rule zkProofStructureValid(P) => isValidProofStructure(P)

    // INVARIANT 6: Batch number monotonicity
    syntax Bool ::= batchMonotonic(Int, Int) [function]
    rule batchMonotonic(PrevBatch, NewBatch) => NewBatch >Int PrevBatch

    // INVARIANT 7: Gas bounds enforcement
    syntax Bool ::= gasBoundsEnforced(L1ToL2Deposit) [function]
    rule gasBoundsEnforced(D) => hasValidGas(D)

    // INVARIANT 8: Priority operation expiration
    syntax Bool ::= priorityOpNotExpired(PriorityOp, Int) [function]
    rule priorityOpNotExpired(priorityOp(_, _, _, ExpirationBlock, _), CurrentBlock) =>
        CurrentBlock <Int ExpirationBlock

    // INVARIANT 9: L2 log proof soundness
    syntax Bool ::= l2LogProofSound(Bytes, Bytes, List, Int) [function]
    rule l2LogProofSound(LogHash, Root, Proof, Index) =>
        verifyL2LogProof(LogHash, Root, Proof, Index) impliesBool
        size(Proof) ==Int L2_LOG_TREE_DEPTH

    // INVARIANT 10: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (deriveSoulNullifier(Nf, DomainA) =/=K deriveSoulNullifier(Nf, DomainB))

endmodule

module ZKSYNC-BRIDGE
    imports ZKSYNC-BRIDGE-SECURITY

    // =========================================================================
    // MAIN ZKSYNC BRIDGE SPECIFICATION
    // =========================================================================

    configuration
        <zksync>
            <deposits> .Map </deposits>
            <withdrawals> .Map </withdrawals>
            <batches> .Map </batches>
            <priorityOps> .Map </priorityOps>
            <nullifiers> .Set </nullifiers>
            <provedWithdrawals> .Set </provedWithdrawals>
            <priorityOpId> 0 </priorityOpId>
            <currentBatch> 0 </currentBatch>
            <currentBlock> 0 </currentBlock>
            <currentTime> 0 </currentTime>
            <totalDeposited> 0 </totalDeposited>
            <totalWithdrawn> 0 </totalWithdrawn>
        </zksync>

    // =========================================================================
    // STATE TRANSITIONS
    // =========================================================================

    // Initiate L1 -> L2 Deposit
    rule <zksync>
            <deposits> D => D[DepositId <- NewDeposit] </deposits>
            <priorityOps> PO => PO[OpId <- NewPriorityOp] </priorityOps>
            <priorityOpId> OpId => OpId +Int 1 </priorityOpId>
            <currentTime> T </currentTime>
            <currentBlock> B </currentBlock>
            <totalDeposited> Total => Total +Int Amount </totalDeposited>
            ...
         </zksync>
         requires notBool (DepositId in_keys(D))
          andBool hasValidGas(NewDeposit)
         where DepositId = computeDepositHash(Sender, L2Receiver, Token, Amount, OpId)
           and NewDeposit = deposit(DepositId, Sender, L2Receiver, Token, L2Token, Amount, L2Gas, L2GasPerPubdata, b"", PENDING, OpId, T)
           and NewPriorityOp = priorityOp(OpId, 0, Pubdata, B +Int 1000000, 0)

    // Prove Withdrawal (with ZK proof)
    rule <zksync>
            <withdrawals> W => W[WId <- updateWithdrawalStatus(W[WId], PROVED)] </withdrawals>
            <provedWithdrawals> PW => PW |Set SetItem(WId) </provedWithdrawals>
            <batches> B </batches>
            ...
         </zksync>
         requires WId in_keys(W)
          andBool isBatchVerified(B[getBatchNumber(W[WId])])
          andBool notBool (WId in PW)

    // Finalize Withdrawal
    rule <zksync>
            <withdrawals> W => W[WId <- updateWithdrawalStatus(W[WId], EXECUTED)] </withdrawals>
            <nullifiers> Nfs => Nfs |Set SetItem(NullifierHash) </nullifiers>
            <batches> B </batches>
            <currentTime> T </currentTime>
            <totalWithdrawn> Total => Total +Int Amount </totalWithdrawn>
            ...
         </zksync>
         requires isWithdrawalFinalizable(W[WId], B[getBatchNumber(W[WId])])
          andBool nullifierUnique(NullifierHash, Nfs)
         where NullifierHash = deriveZkSyncNullifier(WId, b"Soul", T)

    // Verify and Execute Batch
    rule <zksync>
            <batches> B => B[BatchNum <- markBatchExecuted(B[BatchNum])] </batches>
            ...
         </zksync>
         requires batchVerifiedBeforeExecution(B[BatchNum])

    // Helper functions
    syntax L2ToL1Withdrawal ::= updateWithdrawalStatus(L2ToL1Withdrawal, RequestStatus) [function]
    rule updateWithdrawalStatus(withdrawal(Id, L2S, L1R, L2T, L1T, A, BN, MI, TN, TxH, _, Init, _), NewStatus) =>
        withdrawal(Id, L2S, L1R, L2T, L1T, A, BN, MI, TN, TxH, NewStatus, Init, 0)

    syntax Int ::= getBatchNumber(L2ToL1Withdrawal) [function]
    rule getBatchNumber(withdrawal(_, _, _, _, _, _, BN, _, _, _, _, _, _)) => BN

    syntax BatchInfo ::= markBatchExecuted(BatchInfo) [function]
    rule markBatchExecuted(batchInfo(BN, BH, SR, TS, Commit, Verified, _)) =>
        batchInfo(BN, BH, SR, TS, Commit, Verified, true)

endmodule
