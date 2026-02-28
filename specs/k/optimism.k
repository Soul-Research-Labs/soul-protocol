// K Framework Formal Specification for Optimism OP Stack
// Zaseon - Optimism Bridge Formalization

module OPTIMISM-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // OPTIMISM OP STACK CONSTANTS
    // =========================================================================

    // Chain IDs
    syntax Int ::= "OP_MAINNET_CHAIN_ID"    [function, total]
                 | "OP_SEPOLIA_CHAIN_ID"    [function, total]
                 | "OP_GOERLI_CHAIN_ID"     [function, total]

    rule OP_MAINNET_CHAIN_ID => 10
    rule OP_SEPOLIA_CHAIN_ID => 11155420
    rule OP_GOERLI_CHAIN_ID => 420

    // Timing Constants
    syntax Int ::= "WITHDRAWAL_PERIOD"      [function, total]  // ~7 days
                 | "SEQUENCER_DRIFT"        [function, total]
                 | "OUTPUT_ROOT_PROOF_PERIOD" [function, total]
                 | "DISPUTE_GAME_DURATION"  [function, total]

    rule WITHDRAWAL_PERIOD => 604800  // 7 days in seconds
    rule SEQUENCER_DRIFT => 600       // 10 minutes
    rule OUTPUT_ROOT_PROOF_PERIOD => 7200  // 2 hours
    rule DISPUTE_GAME_DURATION => 604800   // 7 days

    // Gas Constants
    syntax Int ::= "MIN_GAS_LIMIT"          [function, total]
                 | "DEFAULT_L2_GAS_LIMIT"   [function, total]
                 | "GAS_PRICE_ORACLE_OVERHEAD" [function, total]

    rule MIN_GAS_LIMIT => 100000
    rule DEFAULT_L2_GAS_LIMIT => 1000000
    rule GAS_PRICE_ORACLE_OVERHEAD => 2100

    // =========================================================================
    // OP STACK DATA STRUCTURES
    // =========================================================================

    // Message Status
    syntax MessageStatus ::= "MSG_PENDING"
                           | "MSG_SENT"
                           | "MSG_RELAYED"
                           | "MSG_FAILED"
                           | "MSG_WITHDRAWN"

    // Message Type
    syntax MessageType ::= "PROOF_RELAY"
                         | "STATE_SYNC"
                         | "NULLIFIER_CHECK"
                         | "BATCH_VERIFY"
                         | "EMERGENCY"

    // Cross-Domain Message
    syntax CrossDomainMessage ::= cdMessage(
        messageId: Bytes,
        messageType: MessageType,
        payload: Bytes,
        sourceChainId: Int,
        targetChainId: Int,
        sender: Bytes,
        target: Bytes,
        value: Int,
        gasLimit: Int,
        timestamp: Int,
        status: MessageStatus
    )

    // Withdrawal Request (L2 -> L1)
    syntax WithdrawalRequest ::= withdrawalRequest(
        withdrawalId: Bytes,
        user: Bytes,
        proofHash: Bytes,
        amount: Int,
        requestedAt: Int,
        completableAt: Int,
        completed: Bool
    )

    // Output Root Proposal
    syntax OutputRootProposal ::= outputRoot(
        outputRoot: Bytes,
        l2BlockNumber: Int,
        l1Timestamp: Int,
        proposer: Bytes,
        finalized: Bool
    )

    // Fault Proof (Bedrock)
    syntax FaultProof ::= faultProof(
        proofId: Bytes,
        outputRoot: Bytes,
        challenger: Bytes,
        bond: Int,
        status: DisputeStatus,
        deadline: Int
    )

    // Dispute Status
    syntax DisputeStatus ::= "NO_DISPUTE"
                           | "CHALLENGED"
                           | "DEFENDER_WINS"
                           | "CHALLENGER_WINS"
                           | "TIMED_OUT"

    // Proof Relay Request
    syntax ProofRelayRequest ::= proofRelay(
        proofHash: Bytes,
        proof: Bytes,
        publicInputs: Bytes,
        stateRoot: Bytes,
        nonce: Int,
        deadline: Int
    )

    // Sequencer Batch
    syntax SequencerBatch ::= seqBatch(
        batchIndex: Int,
        batchRoot: Bytes,
        l1Origin: Int,
        timestamp: Int,
        txCount: Int,
        compressedData: Bytes
    )

    // Cross-domain nullifier
    syntax Nullifier ::= nullifier(
        nullifierHash: Bytes,
        messageId: Bytes,
        domain: Bytes,
        consumed: Bool,
        timestamp: Int
    )

endmodule

module OPTIMISM-KECCAK
    imports OPTIMISM-TYPES
    imports KECCAK256

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Compute message hash (cross-domain)
    syntax Bytes ::= computeMessageHash(Bytes, Bytes, Int, Int, Bytes) [function]
    rule computeMessageHash(Sender, Target, Value, GasLimit, Data) =>
        keccak256(Sender +Bytes Target +Bytes Int2Bytes(Value, BE, Unsigned) +Bytes Int2Bytes(GasLimit, BE, Unsigned) +Bytes Data)

    // Compute withdrawal hash
    syntax Bytes ::= computeWithdrawalHash(Bytes, Bytes, Int, Int, Int) [function]
    rule computeWithdrawalHash(User, ProofHash, Amount, RequestedAt, Nonce) =>
        keccak256(User +Bytes ProofHash +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes Int2Bytes(RequestedAt, BE, Unsigned) +Bytes Int2Bytes(Nonce, BE, Unsigned))

    // Compute output root
    syntax Bytes ::= computeOutputRoot(Bytes, Bytes, Bytes, Int) [function]
    rule computeOutputRoot(StateRoot, MessagePasserStorageRoot, BlockHash, L2BlockNumber) =>
        keccak256(b"\x00" +Bytes StateRoot +Bytes MessagePasserStorageRoot +Bytes BlockHash +Bytes Int2Bytes(L2BlockNumber, BE, Unsigned))

    // Compute batch root
    syntax Bytes ::= computeBatchRoot(Bytes, Int, Int) [function]
    rule computeBatchRoot(TxRoot, L1Origin, Timestamp) =>
        keccak256(TxRoot +Bytes Int2Bytes(L1Origin, BE, Unsigned) +Bytes Int2Bytes(Timestamp, BE, Unsigned))

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Optimism nullifier
    syntax Bytes ::= deriveOptimismNullifier(Bytes, Bytes, Int) [function]
    rule deriveOptimismNullifier(MessageId, Domain, Timestamp) =>
        keccak256(MessageId +Bytes Domain +Bytes Int2Bytes(Timestamp, BE, Unsigned) +Bytes b"OPTIMISM_NULLIFIER")

    // Derive cross-domain Soul nullifier
    syntax Bytes ::= deriveSoulNullifier(Bytes, Bytes) [function]
    rule deriveSoulNullifier(OptimismNullifier, Domain) =>
        keccak256(OptimismNullifier +Bytes Domain +Bytes b"OP2Soul")

endmodule

module OPTIMISM-MERKLE
    imports OPTIMISM-KECCAK

    // =========================================================================
    // MERKLE PATRICIA TRIE FOR STATE PROOFS
    // =========================================================================

    // Node types in MPT
    syntax MPTNode ::= emptyNode()
                     | leafNode(Bytes, Bytes)       // key suffix, value
                     | extensionNode(Bytes, MPTNode) // shared prefix, child
                     | branchNode(List, Bytes)       // 16 children + value

    // Verify MPT proof (simplified)
    syntax Bool ::= verifyMPTProof(Bytes, Bytes, Bytes, List) [function]
    rule verifyMPTProof(Root, Key, Value, Proof) => verifyMPTProofHelper(Root, Key, Value, Proof, 0)

    syntax Bool ::= verifyMPTProofHelper(Bytes, Bytes, Bytes, List, Int) [function]
    rule verifyMPTProofHelper(Root, _Key, Value, .List, _Depth) => Root ==K keccak256(Value)
    rule verifyMPTProofHelper(Root, Key, Value, ListItem(Node) Rest, Depth) =>
        keccak256(Node) ==K Root andBool verifyMPTProofHelper(extractChildHash(Node, Key, Depth), Key, Value, Rest, Depth +Int 1)

    // Extract child hash from node (placeholder)
    syntax Bytes ::= extractChildHash(Bytes, Bytes, Int) [function]
    // Implementation depends on node type and key nibble

    // =========================================================================
    // OUTPUT ROOT PROOFS
    // =========================================================================

    // Verify output root inclusion
    syntax Bool ::= verifyOutputRootProof(
        Bytes,  // claimed output root
        Bytes,  // state root
        Bytes,  // storage root
        Bytes,  // block hash
        Int     // L2 block number
    ) [function]
    rule verifyOutputRootProof(ClaimedRoot, StateRoot, StorageRoot, BlockHash, L2Block) =>
        ClaimedRoot ==K computeOutputRoot(StateRoot, StorageRoot, BlockHash, L2Block)

endmodule

module OPTIMISM-FAULT-PROOF
    imports OPTIMISM-MERKLE

    // =========================================================================
    // FAULT PROOF / DISPUTE GAME (BEDROCK)
    // =========================================================================

    // Fault proof game types
    syntax GameType ::= "CANNON"         // Standard fault proof
                      | "ALPHABET"       // Simplified for testing
                      | "ATTESTATION"    // Committee-based

    // Game state
    syntax GameState ::= gameState(
        gameType: GameType,
        rootClaim: Bytes,
        l2BlockNumber: Int,
        status: DisputeStatus,
        claimant: Bytes,
        challenger: Bytes,
        bond: Int,
        createdAt: Int,
        resolvedAt: Int
    )

    // Claim in dispute game
    syntax Claim ::= claim(
        position: Int,      // Position in game tree
        value: Bytes,       // State hash at position
        parent: Int,        // Parent claim index
        countered: Bool,    // Has been countered
        claimant: Bytes     // Who made this claim
    )

    // Check if game can be resolved
    syntax Bool ::= canResolveGame(GameState, Int) [function]
    rule canResolveGame(gameState(_, _, _, Status, _, _, _, CreatedAt, _), CurrentTime) =>
        (Status ==K NO_DISPUTE andBool CurrentTime >=Int CreatedAt +Int DISPUTE_GAME_DURATION) orBool
        Status ==K DEFENDER_WINS orBool
        Status ==K CHALLENGER_WINS

    // Check if challenge period has passed
    syntax Bool ::= challengePeriodPassed(Int, Int) [function]
    rule challengePeriodPassed(CreatedAt, CurrentTime) =>
        CurrentTime >=Int CreatedAt +Int WITHDRAWAL_PERIOD

endmodule

module OPTIMISM-CROSS-DOMAIN
    imports OPTIMISM-FAULT-PROOF

    // =========================================================================
    // CROSS-DOMAIN MESSENGER
    // =========================================================================

    // L1 -> L2 message encoding
    syntax Bytes ::= encodeL1ToL2Message(Bytes, Bytes, Int, Int, Bytes) [function]
    rule encodeL1ToL2Message(Sender, Target, Value, GasLimit, Data) =>
        b"\x00\x00\x00\x00" +Bytes // Version bytes
        computeMessageHash(Sender, Target, Value, GasLimit, Data) +Bytes
        Sender +Bytes Target +Bytes
        Int2Bytes(Value, BE, Unsigned) +Bytes
        Int2Bytes(GasLimit, BE, Unsigned) +Bytes
        Data

    // L2 -> L1 message encoding
    syntax Bytes ::= encodeL2ToL1Message(Bytes, Bytes, Int, Bytes) [function]
    rule encodeL2ToL1Message(Sender, Target, Value, Data) =>
        keccak256(
            b"\x01" +Bytes // Version
            Sender +Bytes Target +Bytes
            Int2Bytes(Value, BE, Unsigned) +Bytes
            Data
        )

    // Message nonce encoding (includes version)
    syntax Int ::= encodeMessageNonce(Int, Int) [function]
    rule encodeMessageNonce(Version, Nonce) =>
        (Version <<Int 240) |Int Nonce

    // Decode message version
    syntax Int ::= decodeMessageVersion(Int) [function]
    rule decodeMessageVersion(EncodedNonce) =>
        EncodedNonce >>Int 240

endmodule

module OPTIMISM-BRIDGE-SECURITY
    imports OPTIMISM-CROSS-DOMAIN

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Withdrawal is completable after period
    syntax Bool ::= isWithdrawalCompletable(WithdrawalRequest, Int) [function]
    rule isWithdrawalCompletable(withdrawalRequest(_, _, _, _, _, CompletableAt, Completed), CurrentTime) =>
        CurrentTime >=Int CompletableAt andBool notBool Completed

    // Message has valid gas limit
    syntax Bool ::= hasValidGasLimit(CrossDomainMessage) [function]
    rule hasValidGasLimit(cdMessage(_, _, _, _, _, _, _, _, GasLimit, _, _)) =>
        GasLimit >=Int MIN_GAS_LIMIT

    // Output root is finalized (no active disputes)
    syntax Bool ::= isOutputRootFinalized(OutputRootProposal, Int) [function]
    rule isOutputRootFinalized(outputRoot(_, _, L1Timestamp, _, Finalized), CurrentTime) =>
        Finalized orBool (CurrentTime >=Int L1Timestamp +Int DISPUTE_GAME_DURATION)

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Withdrawal period enforcement
    syntax Bool ::= withdrawalPeriodEnforced(WithdrawalRequest, Int) [function]
    rule withdrawalPeriodEnforced(withdrawalRequest(_, _, _, _, RequestedAt, CompletableAt, _), _) =>
        CompletableAt >=Int RequestedAt +Int WITHDRAWAL_PERIOD

    // INVARIANT 3: Message relay requires finalized output
    syntax Bool ::= messageRelayRequiresFinality(OutputRootProposal, Int) [function]
    rule messageRelayRequiresFinality(OR, CurrentTime) =>
        isOutputRootFinalized(OR, CurrentTime)

    // INVARIANT 4: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Bytes) [function]
    rule crossDomainNullifierDeterministic(MsgId1, MsgId2) =>
        (MsgId1 ==K MsgId2) impliesBool
        (deriveOptimismNullifier(MsgId1, b"Soul", 0) ==K deriveOptimismNullifier(MsgId2, b"Soul", 0))

    // INVARIANT 5: Different messages produce different nullifiers
    syntax Bool ::= differentMessagesUniqueNullifiers(Bytes, Bytes, Bytes) [function]
    rule differentMessagesUniqueNullifiers(MsgId1, MsgId2, Domain) =>
        (MsgId1 =/=K MsgId2) impliesBool
        (deriveOptimismNullifier(MsgId1, Domain, 0) =/=K deriveOptimismNullifier(MsgId2, Domain, 0))

    // INVARIANT 6: L2 block number monotonicity
    syntax Bool ::= l2BlockMonotonic(Int, Int) [function]
    rule l2BlockMonotonic(PrevBlock, NewBlock) => NewBlock >Int PrevBlock

    // INVARIANT 7: Output root proof soundness
    syntax Bool ::= outputRootProofSound(Bytes, Bytes, Bytes, Bytes, Int) [function]
    rule outputRootProofSound(ClaimedRoot, StateRoot, StorageRoot, BlockHash, L2Block) =>
        verifyOutputRootProof(ClaimedRoot, StateRoot, StorageRoot, BlockHash, L2Block)

    // INVARIANT 8: Gas limit minimum enforcement
    syntax Bool ::= gasLimitMinimumEnforced(Int) [function]
    rule gasLimitMinimumEnforced(GasLimit) => GasLimit >=Int MIN_GAS_LIMIT

    // INVARIANT 9: Dispute game resolution integrity
    syntax Bool ::= disputeResolutionIntegrity(GameState, Int) [function]
    rule disputeResolutionIntegrity(GS, CurrentTime) =>
        canResolveGame(GS, CurrentTime) impliesBool
        (getGameStatus(GS) =/=K NO_DISPUTE orBool challengePeriodPassed(getGameCreatedAt(GS), CurrentTime))

    // INVARIANT 10: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (deriveSoulNullifier(Nf, DomainA) =/=K deriveSoulNullifier(Nf, DomainB))

    // Helper functions
    syntax DisputeStatus ::= getGameStatus(GameState) [function]
    rule getGameStatus(gameState(_, _, _, Status, _, _, _, _, _)) => Status

    syntax Int ::= getGameCreatedAt(GameState) [function]
    rule getGameCreatedAt(gameState(_, _, _, _, _, _, _, CreatedAt, _)) => CreatedAt

endmodule

module OPTIMISM-BRIDGE
    imports OPTIMISM-BRIDGE-SECURITY

    // =========================================================================
    // MAIN OPTIMISM BRIDGE SPECIFICATION
    // =========================================================================

    configuration
        <optimism>
            <messages> .Map </messages>
            <withdrawals> .Map </withdrawals>
            <outputRoots> .Map </outputRoots>
            <disputeGames> .Map </disputeGames>
            <nullifiers> .Set </nullifiers>
            <relayedMessages> .Set </relayedMessages>
            <messageNonce> 0 </messageNonce>
            <currentL2Block> 0 </currentL2Block>
            <currentTime> 0 </currentTime>
            <totalDeposited> 0 </totalDeposited>
            <totalWithdrawn> 0 </totalWithdrawn>
        </optimism>

    // =========================================================================
    // STATE TRANSITIONS
    // =========================================================================

    // Send L1 -> L2 Message
    rule <optimism>
            <messages> M => M[MsgId <- NewMessage] </messages>
            <messageNonce> Nonce => Nonce +Int 1 </messageNonce>
            <currentTime> T </currentTime>
            <totalDeposited> Total => Total +Int Value </totalDeposited>
            ...
         </optimism>
         requires notBool (MsgId in_keys(M))
          andBool hasValidGasLimit(NewMessage)
         where MsgId = computeMessageHash(Sender, Target, Value, GasLimit, Data)
           and NewMessage = cdMessage(MsgId, PROOF_RELAY, Data, 1, OP_MAINNET_CHAIN_ID, Sender, Target, Value, GasLimit, T, MSG_SENT)

    // Relay L2 -> L1 Message (after finality)
    rule <optimism>
            <messages> M => M[MsgId <- updateMessageStatus(M[MsgId], MSG_RELAYED)] </messages>
            <outputRoots> OR </outputRoots>
            <relayedMessages> RM => RM |Set SetItem(MsgId) </relayedMessages>
            <currentTime> T </currentTime>
            ...
         </optimism>
         requires MsgId in_keys(M)
          andBool isOutputRootFinalized(OR[L2Block], T)
          andBool notBool (MsgId in RM)

    // Initiate Withdrawal
    rule <optimism>
            <withdrawals> W => W[WithdrawalId <- NewWithdrawal] </withdrawals>
            <currentTime> T </currentTime>
            ...
         </optimism>
         requires notBool (WithdrawalId in_keys(W))
         where NewWithdrawal = withdrawalRequest(WithdrawalId, User, ProofHash, Amount, T, T +Int WITHDRAWAL_PERIOD, false)

    // Complete Withdrawal (after period)
    rule <optimism>
            <withdrawals> W => W[WithdrawalId <- markWithdrawalComplete(W[WithdrawalId])] </withdrawals>
            <nullifiers> Nfs => Nfs |Set SetItem(NullifierHash) </nullifiers>
            <currentTime> T </currentTime>
            <totalWithdrawn> Total => Total +Int Amount </totalWithdrawn>
            ...
         </optimism>
         requires isWithdrawalCompletable(W[WithdrawalId], T)
          andBool nullifierUnique(NullifierHash, Nfs)
         where NullifierHash = deriveOptimismNullifier(WithdrawalId, b"Soul", T)

    // Propose Output Root
    rule <optimism>
            <outputRoots> OR => OR[L2Block <- NewOutputRoot] </outputRoots>
            <currentL2Block> _ => L2Block </currentL2Block>
            <currentTime> T </currentTime>
            ...
         </optimism>
         requires L2Block >Int currentL2Block
         where NewOutputRoot = outputRoot(Root, L2Block, T, Proposer, false)

    // Helper functions
    syntax CrossDomainMessage ::= updateMessageStatus(CrossDomainMessage, MessageStatus) [function]
    rule updateMessageStatus(cdMessage(Id, Type, Payload, Src, Tgt, S, T, V, G, Ts, _), NewStatus) =>
        cdMessage(Id, Type, Payload, Src, Tgt, S, T, V, G, Ts, NewStatus)

    syntax WithdrawalRequest ::= markWithdrawalComplete(WithdrawalRequest) [function]
    rule markWithdrawalComplete(withdrawalRequest(Id, User, PH, Amount, ReqAt, CompAt, _)) =>
        withdrawalRequest(Id, User, PH, Amount, ReqAt, CompAt, true)

endmodule
