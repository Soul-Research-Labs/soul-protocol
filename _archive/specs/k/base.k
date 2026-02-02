// K Framework Formal Specification for Base (OP Stack L2)
// Soul Protocol (Soul) - Base Bridge Formalization

module BASE-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // BASE CHAIN CONSTANTS (OP STACK BASED)
    // =========================================================================

    // Chain IDs
    syntax Int ::= "BASE_MAINNET_CHAIN_ID"  [function, total]
                 | "BASE_SEPOLIA_CHAIN_ID"  [function, total]
                 | "BASE_GOERLI_CHAIN_ID"   [function, total]

    rule BASE_MAINNET_CHAIN_ID => 8453
    rule BASE_SEPOLIA_CHAIN_ID => 84532
    rule BASE_GOERLI_CHAIN_ID => 84531

    // Timing Constants (OP Stack inherited)
    syntax Int ::= "WITHDRAWAL_PERIOD"      [function, total]  // 7 days
                 | "SEQUENCER_WINDOW"       [function, total]
                 | "FINALIZATION_PERIOD"    [function, total]

    rule WITHDRAWAL_PERIOD => 604800  // 7 days
    rule SEQUENCER_WINDOW => 43200    // 12 hours
    rule FINALIZATION_PERIOD => 604800

    // Gas Constants
    syntax Int ::= "MIN_GAS_LIMIT"          [function, total]
                 | "DEFAULT_L2_GAS_LIMIT"   [function, total]
                 | "L1_GAS_OVERHEAD"        [function, total]

    rule MIN_GAS_LIMIT => 100000
    rule DEFAULT_L2_GAS_LIMIT => 1000000
    rule L1_GAS_OVERHEAD => 2100

    // =========================================================================
    // BASE DATA STRUCTURES
    // =========================================================================

    // Message Status (OP Stack compatible)
    syntax MessageStatus ::= "MSG_PENDING"
                           | "MSG_SENT"
                           | "MSG_RELAYED"
                           | "MSG_FAILED"
                           | "MSG_WITHDRAWN"

    // Cross-Domain Message
    syntax CrossDomainMessage ::= baseMessage(
        messageId: Bytes,
        sender: Bytes,
        target: Bytes,
        value: Int,
        gasLimit: Int,
        data: Bytes,
        nonce: Int,
        timestamp: Int,
        status: MessageStatus
    )

    // Withdrawal Request
    syntax WithdrawalRequest ::= baseWithdrawal(
        withdrawalId: Bytes,
        user: Bytes,
        amount: Int,
        l2Token: Bytes,
        l1Token: Bytes,
        requestedAt: Int,
        completableAt: Int,
        outputIndex: Int,
        completed: Bool
    )

    // Output Root (OP Stack)
    syntax OutputRoot ::= outputRoot(
        root: Bytes,
        l2BlockNumber: Int,
        l1Timestamp: Int,
        outputIndex: Int,
        finalized: Bool
    )

    // CCTP (Circle Cross-Chain Transfer Protocol) for USDC
    syntax CCTPTransfer ::= cctpTransfer(
        nonce: Int,
        sourceDomain: Int,
        destinationDomain: Int,
        sender: Bytes,
        recipient: Bytes,
        amount: Int,
        burnToken: Bytes,
        attestation: Bytes,
        completed: Bool
    )

    // Base-specific nullifier
    syntax Nullifier ::= nullifier(
        nullifierHash: Bytes,
        messageId: Bytes,
        domain: Bytes,
        consumed: Bool,
        timestamp: Int
    )

endmodule

module BASE-KECCAK
    imports BASE-TYPES
    imports KECCAK256

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Compute message hash
    syntax Bytes ::= computeMessageHash(Bytes, Bytes, Int, Int, Bytes, Int) [function]
    rule computeMessageHash(Sender, Target, Value, GasLimit, Data, Nonce) =>
        keccak256(Sender +Bytes Target +Bytes Int2Bytes(Value, BE, Unsigned) +Bytes 
                  Int2Bytes(GasLimit, BE, Unsigned) +Bytes Data +Bytes Int2Bytes(Nonce, BE, Unsigned))

    // Compute withdrawal hash
    syntax Bytes ::= computeWithdrawalHash(Bytes, Int, Bytes, Bytes, Int) [function]
    rule computeWithdrawalHash(User, Amount, L2Token, L1Token, Nonce) =>
        keccak256(User +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes L2Token +Bytes L1Token +Bytes Int2Bytes(Nonce, BE, Unsigned))

    // Compute output root
    syntax Bytes ::= computeOutputRoot(Bytes, Bytes, Bytes, Int) [function]
    rule computeOutputRoot(StateRoot, StorageRoot, BlockHash, L2Block) =>
        keccak256(b"\x00" +Bytes StateRoot +Bytes StorageRoot +Bytes BlockHash +Bytes Int2Bytes(L2Block, BE, Unsigned))

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Base nullifier
    syntax Bytes ::= deriveBaseNullifier(Bytes, Bytes, Int) [function]
    rule deriveBaseNullifier(MessageId, Domain, Timestamp) =>
        keccak256(MessageId +Bytes Domain +Bytes Int2Bytes(Timestamp, BE, Unsigned) +Bytes b"BASE_NULLIFIER")

    // Derive cross-domain Soul nullifier
    syntax Bytes ::= deriveSoulNullifier(Bytes, Bytes) [function]
    rule deriveSoulNullifier(BaseNullifier, Domain) =>
        keccak256(BaseNullifier +Bytes Domain +Bytes b"BASE2Soul")

endmodule

module BASE-CCTP
    imports BASE-KECCAK

    // =========================================================================
    // CIRCLE CCTP INTEGRATION (USDC NATIVE BRIDGING)
    // =========================================================================

    // CCTP Domain IDs
    syntax Int ::= "CCTP_ETHEREUM_DOMAIN"   [function, total]
                 | "CCTP_BASE_DOMAIN"       [function, total]
                 | "CCTP_ARBITRUM_DOMAIN"   [function, total]
                 | "CCTP_OPTIMISM_DOMAIN"   [function, total]

    rule CCTP_ETHEREUM_DOMAIN => 0
    rule CCTP_BASE_DOMAIN => 6
    rule CCTP_ARBITRUM_DOMAIN => 3
    rule CCTP_OPTIMISM_DOMAIN => 2

    // Compute CCTP message hash
    syntax Bytes ::= computeCCTPMessageHash(Int, Int, Int, Bytes, Bytes, Int) [function]
    rule computeCCTPMessageHash(Nonce, SrcDomain, DstDomain, Sender, Recipient, Amount) =>
        keccak256(Int2Bytes(Nonce, BE, Unsigned) +Bytes Int2Bytes(SrcDomain, BE, Unsigned) +Bytes 
                  Int2Bytes(DstDomain, BE, Unsigned) +Bytes Sender +Bytes Recipient +Bytes Int2Bytes(Amount, BE, Unsigned))

    // Verify CCTP attestation (simplified)
    syntax Bool ::= verifyCCTPAttestation(Bytes, Bytes) [function]
    rule verifyCCTPAttestation(MessageHash, Attestation) =>
        lengthBytes(Attestation) >=Int 65  // At least one signature

    // Check if CCTP transfer is valid
    syntax Bool ::= isValidCCTPTransfer(CCTPTransfer) [function]
    rule isValidCCTPTransfer(cctpTransfer(Nonce, Src, Dst, _, _, Amount, _, _, _)) =>
        Nonce >Int 0 andBool Amount >Int 0 andBool Src =/=K Dst

endmodule

module BASE-BRIDGE-SECURITY
    imports BASE-CCTP

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Withdrawal is completable
    syntax Bool ::= isWithdrawalCompletable(WithdrawalRequest, Int) [function]
    rule isWithdrawalCompletable(baseWithdrawal(_, _, _, _, _, _, CompletableAt, _, Completed), CurrentTime) =>
        CurrentTime >=Int CompletableAt andBool notBool Completed

    // Message has valid gas limit
    syntax Bool ::= hasValidGasLimit(CrossDomainMessage) [function]
    rule hasValidGasLimit(baseMessage(_, _, _, _, GasLimit, _, _, _, _)) =>
        GasLimit >=Int MIN_GAS_LIMIT

    // Output root is finalized
    syntax Bool ::= isOutputFinalized(OutputRoot, Int) [function]
    rule isOutputFinalized(outputRoot(_, _, L1Timestamp, _, Finalized), CurrentTime) =>
        Finalized orBool (CurrentTime >=Int L1Timestamp +Int FINALIZATION_PERIOD)

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Withdrawal period enforcement
    syntax Bool ::= withdrawalPeriodEnforced(WithdrawalRequest) [function]
    rule withdrawalPeriodEnforced(baseWithdrawal(_, _, _, _, _, RequestedAt, CompletableAt, _, _)) =>
        CompletableAt >=Int RequestedAt +Int WITHDRAWAL_PERIOD

    // INVARIANT 3: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Bytes) [function]
    rule crossDomainNullifierDeterministic(MsgId1, MsgId2) =>
        (MsgId1 ==K MsgId2) impliesBool
        (deriveBaseNullifier(MsgId1, b"Soul", 0) ==K deriveBaseNullifier(MsgId2, b"Soul", 0))

    // INVARIANT 4: Different messages produce different nullifiers
    syntax Bool ::= differentMessagesUniqueNullifiers(Bytes, Bytes, Bytes) [function]
    rule differentMessagesUniqueNullifiers(MsgId1, MsgId2, Domain) =>
        (MsgId1 =/=K MsgId2) impliesBool
        (deriveBaseNullifier(MsgId1, Domain, 0) =/=K deriveBaseNullifier(MsgId2, Domain, 0))

    // INVARIANT 5: CCTP transfer validity
    syntax Bool ::= cctpTransferValid(CCTPTransfer) [function]
    rule cctpTransferValid(T) => isValidCCTPTransfer(T)

    // INVARIANT 6: Output index monotonicity
    syntax Bool ::= outputIndexMonotonic(Int, Int) [function]
    rule outputIndexMonotonic(PrevIndex, NewIndex) => NewIndex >Int PrevIndex

    // INVARIANT 7: Gas limit minimum enforcement
    syntax Bool ::= gasLimitEnforced(CrossDomainMessage) [function]
    rule gasLimitEnforced(M) => hasValidGasLimit(M)

    // INVARIANT 8: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (deriveSoulNullifier(Nf, DomainA) =/=K deriveSoulNullifier(Nf, DomainB))

    // INVARIANT 9: CCTP domain validity
    syntax Bool ::= cctpDomainValid(Int) [function]
    rule cctpDomainValid(Domain) =>
        Domain ==Int CCTP_ETHEREUM_DOMAIN orBool
        Domain ==Int CCTP_BASE_DOMAIN orBool
        Domain ==Int CCTP_ARBITRUM_DOMAIN orBool
        Domain ==Int CCTP_OPTIMISM_DOMAIN

    // INVARIANT 10: Amount bounds enforcement
    syntax Bool ::= amountBoundsEnforced(Int, Int, Int) [function]
    rule amountBoundsEnforced(Amount, MinAmount, MaxAmount) =>
        Amount >=Int MinAmount andBool Amount <=Int MaxAmount

endmodule

module BASE-BRIDGE
    imports BASE-BRIDGE-SECURITY

    // =========================================================================
    // MAIN BASE BRIDGE SPECIFICATION
    // =========================================================================

    configuration
        <base>
            <messages> .Map </messages>
            <withdrawals> .Map </withdrawals>
            <outputRoots> .Map </outputRoots>
            <cctpTransfers> .Map </cctpTransfers>
            <nullifiers> .Set </nullifiers>
            <relayedMessages> .Set </relayedMessages>
            <messageNonce> 0 </messageNonce>
            <cctpNonce> 0 </cctpNonce>
            <currentOutputIndex> 0 </currentOutputIndex>
            <currentTime> 0 </currentTime>
            <totalDeposited> 0 </totalDeposited>
            <totalWithdrawn> 0 </totalWithdrawn>
        </base>

    // =========================================================================
    // STATE TRANSITIONS
    // =========================================================================

    // Send L1 -> L2 Message
    rule <base>
            <messages> M => M[MsgId <- NewMessage] </messages>
            <messageNonce> Nonce => Nonce +Int 1 </messageNonce>
            <currentTime> T </currentTime>
            <totalDeposited> Total => Total +Int Value </totalDeposited>
            ...
         </base>
         requires notBool (MsgId in_keys(M))
          andBool hasValidGasLimit(NewMessage)
         where MsgId = computeMessageHash(Sender, Target, Value, GasLimit, Data, Nonce)
           and NewMessage = baseMessage(MsgId, Sender, Target, Value, GasLimit, Data, Nonce, T, MSG_SENT)

    // Complete Withdrawal
    rule <base>
            <withdrawals> W => W[WId <- markWithdrawalComplete(W[WId])] </withdrawals>
            <nullifiers> Nfs => Nfs |Set SetItem(NullifierHash) </nullifiers>
            <currentTime> T </currentTime>
            <totalWithdrawn> Total => Total +Int Amount </totalWithdrawn>
            ...
         </base>
         requires isWithdrawalCompletable(W[WId], T)
          andBool nullifierUnique(NullifierHash, Nfs)
         where NullifierHash = deriveBaseNullifier(WId, b"Soul", T)

    // CCTP Transfer (USDC)
    rule <base>
            <cctpTransfers> C => C[Nonce <- NewTransfer] </cctpTransfers>
            <cctpNonce> Nonce => Nonce +Int 1 </cctpNonce>
            ...
         </base>
         requires isValidCCTPTransfer(NewTransfer)
         where NewTransfer = cctpTransfer(Nonce, SrcDomain, DstDomain, Sender, Recipient, Amount, BurnToken, b"", false)

    // Helper function
    syntax WithdrawalRequest ::= markWithdrawalComplete(WithdrawalRequest) [function]
    rule markWithdrawalComplete(baseWithdrawal(Id, User, Amount, L2T, L1T, ReqAt, CompAt, OutIdx, _)) =>
        baseWithdrawal(Id, User, Amount, L2T, L1T, ReqAt, CompAt, OutIdx, true)

endmodule
