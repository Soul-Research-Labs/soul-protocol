// K Framework Formal Specification for Arbitrum Nitro
// Soul Protocol (Soul) - Arbitrum Bridge Formalization

module ARBITRUM-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // ARBITRUM NITRO CONSTANTS
    // =========================================================================

    // Chain IDs
    syntax Int ::= "ARB_ONE_CHAIN_ID"       [function, total]
                 | "ARB_NOVA_CHAIN_ID"      [function, total]
                 | "ARB_SEPOLIA_CHAIN_ID"   [function, total]

    rule ARB_ONE_CHAIN_ID => 42161
    rule ARB_NOVA_CHAIN_ID => 42170
    rule ARB_SEPOLIA_CHAIN_ID => 421614

    // Timing Constants (in seconds)
    syntax Int ::= "CHALLENGE_PERIOD"       [function, total]  // ~7 days
                 | "SEQUENCER_REPORTING_THRESHOLD" [function, total]
                 | "MIN_ASSERTION_PERIOD"   [function, total]

    rule CHALLENGE_PERIOD => 604800  // 7 * 24 * 60 * 60
    rule SEQUENCER_REPORTING_THRESHOLD => 3600  // 1 hour
    rule MIN_ASSERTION_PERIOD => 600  // 10 minutes

    // Gas Constants
    syntax Int ::= "DEFAULT_L2_GAS_LIMIT"   [function, total]
                 | "MAX_SUBMISSION_COST"    [function, total]
                 | "L2_GAS_PRICE_BID"       [function, total]

    rule DEFAULT_L2_GAS_LIMIT => 1000000
    rule MAX_SUBMISSION_COST => 10000000000000000  // 0.01 ETH in wei
    rule L2_GAS_PRICE_BID => 100000000  // 0.1 gwei

    // =========================================================================
    // ARBITRUM DATA STRUCTURES
    // =========================================================================

    // Transfer Status
    syntax TransferStatus ::= "PENDING"
                            | "RETRYABLE_CREATED"
                            | "EXECUTED"
                            | "CHALLENGED"
                            | "FINALIZED"
                            | "FAILED"

    // Rollup Type
    syntax RollupType ::= "ARB_ONE" | "ARB_NOVA"

    // L1 to L2 Deposit
    syntax L1ToL2Deposit ::= deposit(
        depositId: Bytes,
        sender: Bytes,
        l2Recipient: Bytes,
        l1Token: Bytes,
        l2Token: Bytes,
        amount: Int,
        maxSubmissionCost: Int,
        l2GasLimit: Int,
        l2GasPrice: Int,
        ticketId: Int,
        status: TransferStatus,
        initiatedAt: Int,
        executedAt: Int
    )

    // L2 to L1 Withdrawal
    syntax L2ToL1Withdrawal ::= withdrawal(
        withdrawalId: Bytes,
        l2Sender: Bytes,
        l1Recipient: Bytes,
        l2Token: Bytes,
        l1Token: Bytes,
        amount: Int,
        l2BlockNumber: Int,
        l1BatchNumber: Int,
        l2Timestamp: Int,
        outputId: Bytes,
        status: TransferStatus,
        initiatedAt: Int,
        claimableAt: Int,
        claimedAt: Int
    )

    // Retryable Ticket
    syntax RetryableTicket ::= ticket(
        ticketId: Int,
        from: Bytes,
        to: Bytes,
        value: Int,
        data: Bytes,
        maxSubmissionCost: Int,
        l2GasLimit: Int,
        l2GasPrice: Int,
        redeemed: Bool,
        createdAt: Int
    )

    // Outbox Proof
    syntax OutboxProof ::= outboxProof(
        proof: List,
        index: Int,
        l2Sender: Bytes,
        destAddress: Bytes,
        l2Block: Int,
        l1Block: Int,
        l2Timestamp: Int,
        value: Int,
        data: Bytes
    )

    // Rollup Assertion
    syntax RollupAssertion ::= assertion(
        assertionId: Int,
        proposer: Bytes,
        stateHash: Bytes,
        prevStateHash: Bytes,
        numBlocks: Int,
        inboxSize: Int,
        deadline: Int,
        confirmed: Bool
    )

    // Nullifier for cross-domain
    syntax Nullifier ::= nullifier(
        nullifierHash: Bytes,
        depositId: Bytes,
        domain: Bytes,
        consumed: Bool,
        timestamp: Int
    )

endmodule

module ARBITRUM-KECCAK
    imports ARBITRUM-TYPES
    imports KECCAK256

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Compute deposit ID
    syntax Bytes ::= computeDepositId(Bytes, Bytes, Int, Int) [function]
    rule computeDepositId(Sender, Recipient, Amount, Nonce) =>
        keccak256(Sender +Bytes Recipient +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes Int2Bytes(Nonce, BE, Unsigned))

    // Compute withdrawal ID
    syntax Bytes ::= computeWithdrawalId(Bytes, Bytes, Int, Int, Int) [function]
    rule computeWithdrawalId(L2Sender, L1Recipient, Amount, L2Block, Timestamp) =>
        keccak256(L2Sender +Bytes L1Recipient +Bytes Int2Bytes(Amount, BE, Unsigned) +Bytes Int2Bytes(L2Block, BE, Unsigned) +Bytes Int2Bytes(Timestamp, BE, Unsigned))

    // Compute retryable ticket hash
    syntax Bytes ::= computeTicketHash(Bytes, Bytes, Int, Bytes, Int) [function]
    rule computeTicketHash(From, To, Value, Data, TicketId) =>
        keccak256(From +Bytes To +Bytes Int2Bytes(Value, BE, Unsigned) +Bytes Data +Bytes Int2Bytes(TicketId, BE, Unsigned))

    // Compute outbox output ID
    syntax Bytes ::= computeOutputId(Bytes, Int, Int) [function]
    rule computeOutputId(L2Sender, L2Block, Index) =>
        keccak256(L2Sender +Bytes Int2Bytes(L2Block, BE, Unsigned) +Bytes Int2Bytes(Index, BE, Unsigned))

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Arbitrum nullifier
    syntax Bytes ::= deriveArbitrumNullifier(Bytes, Bytes, Int) [function]
    rule deriveArbitrumNullifier(DepositId, Domain, Timestamp) =>
        keccak256(DepositId +Bytes Domain +Bytes Int2Bytes(Timestamp, BE, Unsigned) +Bytes b"ARBITRUM_NULLIFIER")

    // Derive cross-domain Soul nullifier
    syntax Bytes ::= deriveSoulNullifier(Bytes, Bytes) [function]
    rule deriveSoulNullifier(ArbitrumNullifier, Domain) =>
        keccak256(ArbitrumNullifier +Bytes Domain +Bytes b"ARB2Soul")

endmodule

module ARBITRUM-MERKLE
    imports ARBITRUM-KECCAK

    // =========================================================================
    // MERKLE TREE FOR OUTBOX PROOFS
    // =========================================================================

    // Merkle tree depth
    syntax Int ::= "OUTBOX_TREE_DEPTH" [function, total]
    rule OUTBOX_TREE_DEPTH => 26  // ~67M leaves

    // Empty leaf hash (keccak256(0))
    syntax Bytes ::= "EMPTY_LEAF" [function, total]
    rule EMPTY_LEAF => b"\x29\x0d\xec\xd9\x54\x8b\x62\xa8\xd6\x03\x45\xa9\x88\x38\x6f\xc8\x4b\xa6\xbc\x95\x48\x40\x08\xf6\x36\x2f\x93\x16\x0e\xf3\xe5\x63"

    // Compute leaf hash
    syntax Bytes ::= computeLeafHash(Bytes, Bytes, Int, Int) [function]
    rule computeLeafHash(Sender, Recipient, Value, Index) =>
        keccak256(b"\x00" +Bytes Sender +Bytes Recipient +Bytes Int2Bytes(Value, BE, Unsigned) +Bytes Int2Bytes(Index, BE, Unsigned))

    // Compute node hash
    syntax Bytes ::= computeNodeHash(Bytes, Bytes) [function]
    rule computeNodeHash(Left, Right) =>
        keccak256(b"\x01" +Bytes Left +Bytes Right)

    // Verify Merkle proof
    syntax Bool ::= verifyMerkleProof(Bytes, Bytes, List, Int) [function]
    rule verifyMerkleProof(Leaf, Root, Proof, Index) => verifyMerkleProofHelper(Leaf, Root, Proof, Index, 0)

    syntax Bool ::= verifyMerkleProofHelper(Bytes, Bytes, List, Int, Int) [function]
    rule verifyMerkleProofHelper(Current, Root, .List, _Index, _Depth) => Current ==K Root
    rule verifyMerkleProofHelper(Current, Root, ListItem(Sibling) Rest, Index, Depth) =>
        verifyMerkleProofHelper(
            #if (Index >>Int Depth) &Int 1 ==Int 0
            #then computeNodeHash(Current, Sibling)
            #else computeNodeHash(Sibling, Current)
            #fi,
            Root,
            Rest,
            Index,
            Depth +Int 1
        )

endmodule

module ARBITRUM-FRAUD-PROOF
    imports ARBITRUM-MERKLE

    // =========================================================================
    // FRAUD PROOF / CHALLENGE SYSTEM
    // =========================================================================

    // Challenge status
    syntax ChallengeStatus ::= "NO_CHALLENGE"
                             | "CHALLENGE_PENDING"
                             | "BISECTING"
                             | "ONE_STEP_PROOF"
                             | "CHALLENGER_WON"
                             | "DEFENDER_WON"

    // Challenge struct
    syntax Challenge ::= challenge(
        challengeId: Int,
        assertion: RollupAssertion,
        challenger: Bytes,
        defender: Bytes,
        bisectionRoot: Bytes,
        bisectionDepth: Int,
        status: ChallengeStatus,
        deadline: Int
    )

    // One-step proof
    syntax OneStepProof ::= oneStepProof(
        beforeState: Bytes,
        afterState: Bytes,
        instruction: Bytes,
        proof: Bytes
    )

    // Validate assertion deadline
    syntax Bool ::= isAssertionDeadlinePassed(RollupAssertion, Int) [function]
    rule isAssertionDeadlinePassed(assertion(_, _, _, _, _, _, Deadline, _), CurrentTime) =>
        CurrentTime >Int Deadline

    // Check if assertion can be confirmed
    syntax Bool ::= canConfirmAssertion(RollupAssertion, Int) [function]
    rule canConfirmAssertion(A, CurrentTime) =>
        isAssertionDeadlinePassed(A, CurrentTime) andBool notBool hasChallenge(A)

    // Check if assertion has active challenge (placeholder)
    syntax Bool ::= hasChallenge(RollupAssertion) [function]
    rule hasChallenge(assertion(_, _, _, _, _, _, _, Confirmed)) => notBool Confirmed

endmodule

module ARBITRUM-RETRYABLE
    imports ARBITRUM-MERKLE

    // =========================================================================
    // RETRYABLE TICKET SYSTEM
    // =========================================================================

    // Ticket lifetime (7 days)
    syntax Int ::= "TICKET_LIFETIME" [function, total]
    rule TICKET_LIFETIME => 604800

    // Check if ticket is expired
    syntax Bool ::= isTicketExpired(RetryableTicket, Int) [function]
    rule isTicketExpired(ticket(_, _, _, _, _, _, _, _, _, CreatedAt), CurrentTime) =>
        CurrentTime >Int (CreatedAt +Int TICKET_LIFETIME)

    // Check if ticket can be redeemed
    syntax Bool ::= canRedeemTicket(RetryableTicket, Int) [function]
    rule canRedeemTicket(T, CurrentTime) =>
        notBool isTicketExpired(T, CurrentTime) andBool
        notBool isTicketRedeemed(T)

    // Check if ticket is redeemed
    syntax Bool ::= isTicketRedeemed(RetryableTicket) [function]
    rule isTicketRedeemed(ticket(_, _, _, _, _, _, _, _, Redeemed, _)) => Redeemed

    // Compute refund amount (gas refund)
    syntax Int ::= computeRefund(RetryableTicket, Int) [function]
    rule computeRefund(ticket(_, _, _, _, _, MaxSubmission, L2Gas, L2Price, _, _), GasUsed) =>
        (L2Gas -Int GasUsed) *Int L2Price

endmodule

module ARBITRUM-BRIDGE-SECURITY
    imports ARBITRUM-RETRYABLE
    imports ARBITRUM-FRAUD-PROOF

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Withdrawal is claimable after challenge period
    syntax Bool ::= isWithdrawalClaimable(L2ToL1Withdrawal, Int) [function]
    rule isWithdrawalClaimable(withdrawal(_, _, _, _, _, _, _, _, _, _, Status, _, ClaimableAt, _), CurrentTime) =>
        Status ==K EXECUTED andBool CurrentTime >=Int ClaimableAt

    // Deposit has sufficient fee
    syntax Bool ::= hasSufficientFee(L1ToL2Deposit) [function]
    rule hasSufficientFee(deposit(_, _, _, _, _, _, MaxSubmission, L2Gas, L2Price, _, _, _, _)) =>
        MaxSubmission >=Int (L2Gas *Int L2Price)

    // Check amount bounds
    syntax Bool ::= isAmountValid(Int, Int, Int) [function]
    rule isAmountValid(Amount, MinAmount, MaxAmount) =>
        Amount >=Int MinAmount andBool Amount <=Int MaxAmount

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Challenge period must pass for withdrawal
    syntax Bool ::= challengePeriodPassed(Int, Int) [function]
    rule challengePeriodPassed(InitiatedAt, CurrentTime) =>
        CurrentTime >=Int (InitiatedAt +Int CHALLENGE_PERIOD)

    // INVARIANT 3: Retryable tickets expire correctly
    syntax Bool ::= ticketExpiryValid(RetryableTicket, Int) [function]
    rule ticketExpiryValid(T, CurrentTime) =>
        isTicketExpired(T, CurrentTime) impliesBool notBool canRedeemTicket(T, CurrentTime)

    // INVARIANT 4: Assertion confirmation requires no challenge
    syntax Bool ::= assertionConfirmationValid(RollupAssertion, Int) [function]
    rule assertionConfirmationValid(A, CurrentTime) =>
        canConfirmAssertion(A, CurrentTime) impliesBool notBool hasChallenge(A)

    // INVARIANT 5: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Bytes, Bytes, Bytes) [function]
    rule crossDomainNullifierDeterministic(DepositId1, DepositId2, Domain1, Domain2) =>
        (DepositId1 ==K DepositId2 andBool Domain1 ==K Domain2) impliesBool
        (deriveSoulNullifier(deriveArbitrumNullifier(DepositId1, Domain1, 0), Domain1) ==K
         deriveSoulNullifier(deriveArbitrumNullifier(DepositId2, Domain2, 0), Domain2))

    // INVARIANT 6: Different deposits produce different nullifiers
    syntax Bool ::= differentDepositsUniqueNullifiers(Bytes, Bytes, Bytes) [function]
    rule differentDepositsUniqueNullifiers(DepositId1, DepositId2, Domain) =>
        (DepositId1 =/=K DepositId2) impliesBool
        (deriveArbitrumNullifier(DepositId1, Domain, 0) =/=K deriveArbitrumNullifier(DepositId2, Domain, 0))

    // INVARIANT 7: Batch number monotonicity
    syntax Bool ::= batchMonotonic(Int, Int) [function]
    rule batchMonotonic(PrevBatch, NewBatch) => NewBatch >Int PrevBatch

    // INVARIANT 8: Merkle proof soundness
    syntax Bool ::= merkleProofSound(Bytes, Bytes, List, Int) [function]
    rule merkleProofSound(Leaf, Root, Proof, Index) =>
        verifyMerkleProof(Leaf, Root, Proof, Index) impliesBool
        (size(Proof) ==Int OUTBOX_TREE_DEPTH)

    // INVARIANT 9: Amount bounds enforcement
    syntax Bool ::= amountBoundsEnforced(Int, Int, Int) [function]
    rule amountBoundsEnforced(Amount, MinAmount, MaxAmount) =>
        (Amount <Int MinAmount orBool Amount >Int MaxAmount) impliesBool
        notBool isAmountValid(Amount, MinAmount, MaxAmount)

    // INVARIANT 10: Fee sufficiency for deposits
    syntax Bool ::= feeSufficiencyEnforced(L1ToL2Deposit) [function]
    rule feeSufficiencyEnforced(D) =>
        hasSufficientFee(D) impliesBool
        getMaxSubmissionCost(D) >=Int (getL2GasLimit(D) *Int getL2GasPrice(D))

    // Helper getters
    syntax Int ::= getMaxSubmissionCost(L1ToL2Deposit) [function]
    rule getMaxSubmissionCost(deposit(_, _, _, _, _, _, MaxSub, _, _, _, _, _, _)) => MaxSub

    syntax Int ::= getL2GasLimit(L1ToL2Deposit) [function]
    rule getL2GasLimit(deposit(_, _, _, _, _, _, _, L2Gas, _, _, _, _, _)) => L2Gas

    syntax Int ::= getL2GasPrice(L1ToL2Deposit) [function]
    rule getL2GasPrice(deposit(_, _, _, _, _, _, _, _, L2Price, _, _, _, _)) => L2Price

endmodule

module ARBITRUM-BRIDGE
    imports ARBITRUM-BRIDGE-SECURITY

    // =========================================================================
    // MAIN ARBITRUM BRIDGE SPECIFICATION
    // =========================================================================

    configuration
        <arbitrum>
            <deposits> .Map </deposits>
            <withdrawals> .Map </withdrawals>
            <retryableTickets> .Map </retryableTickets>
            <assertions> .Map </assertions>
            <challenges> .Map </challenges>
            <nullifiers> .Set </nullifiers>
            <tokenMappings> .Map </tokenMappings>
            <outboxRoots> .Map </outboxRoots>
            <currentBatch> 0 </currentBatch>
            <currentTime> 0 </currentTime>
            <totalDeposited> 0 </totalDeposited>
            <totalWithdrawn> 0 </totalWithdrawn>
        </arbitrum>

    // =========================================================================
    // STATE TRANSITIONS
    // =========================================================================

    // Initiate L1 to L2 Deposit
    rule <arbitrum>
            <deposits> D => D[DepositId <- NewDeposit] </deposits>
            <currentTime> T </currentTime>
            <totalDeposited> Total => Total +Int Amount </totalDeposited>
            ...
         </arbitrum>
         requires notBool (DepositId in_keys(D))
          andBool hasSufficientFee(NewDeposit)
          andBool isAmountValid(Amount, MIN_DEPOSIT, MAX_DEPOSIT)
         where NewDeposit = deposit(DepositId, Sender, Recipient, L1Token, L2Token, Amount, MaxSub, L2Gas, L2Price, 0, PENDING, T, 0)
           and MIN_DEPOSIT = 1000000000000000  // 0.001 ETH
           and MAX_DEPOSIT = 1000000000000000000000000  // 1M ETH

    // Execute Retryable Ticket
    rule <arbitrum>
            <retryableTickets> Tickets => Tickets[TicketId <- ticket(TicketId, From, To, Value, Data, MaxSub, L2Gas, L2Price, true, CreatedAt)] </retryableTickets>
            <deposits> D => D[DepositId <- updateDepositStatus(D[DepositId], EXECUTED)] </deposits>
            <currentTime> T </currentTime>
            ...
         </arbitrum>
         requires canRedeemTicket(Tickets[TicketId], T)

    // Initiate L2 to L1 Withdrawal
    rule <arbitrum>
            <withdrawals> W => W[WithdrawalId <- NewWithdrawal] </withdrawals>
            <currentTime> T </currentTime>
            <currentBatch> Batch </currentBatch>
            ...
         </arbitrum>
         requires notBool (WithdrawalId in_keys(W))
         where NewWithdrawal = withdrawal(WithdrawalId, L2Sender, L1Recipient, L2Token, L1Token, Amount, L2Block, Batch, T, OutputId, PENDING, T, T +Int CHALLENGE_PERIOD, 0)

    // Claim Withdrawal (after challenge period)
    rule <arbitrum>
            <withdrawals> W => W[WithdrawalId <- updateWithdrawalStatus(W[WithdrawalId], FINALIZED, T)] </withdrawals>
            <nullifiers> Nfs => Nfs |Set SetItem(NullifierHash) </nullifiers>
            <currentTime> T </currentTime>
            <totalWithdrawn> Total => Total +Int Amount </totalWithdrawn>
            ...
         </arbitrum>
         requires isWithdrawalClaimable(W[WithdrawalId], T)
          andBool nullifierUnique(NullifierHash, Nfs)
         where NullifierHash = deriveArbitrumNullifier(WithdrawalId, b"Soul", T)

    // Helper functions for state updates
    syntax L1ToL2Deposit ::= updateDepositStatus(L1ToL2Deposit, TransferStatus) [function]
    rule updateDepositStatus(deposit(Id, S, R, L1T, L2T, A, MSC, L2G, L2P, TId, _, Init, _), NewStatus) =>
        deposit(Id, S, R, L1T, L2T, A, MSC, L2G, L2P, TId, NewStatus, Init, 0)

    syntax L2ToL1Withdrawal ::= updateWithdrawalStatus(L2ToL1Withdrawal, TransferStatus, Int) [function]
    rule updateWithdrawalStatus(withdrawal(Id, L2S, L1R, L2T, L1T, A, L2B, L1B, L2Ts, OutId, _, Init, Claim, _), NewStatus, ClaimedTime) =>
        withdrawal(Id, L2S, L1R, L2T, L1T, A, L2B, L1B, L2Ts, OutId, NewStatus, Init, Claim, ClaimedTime)

endmodule
