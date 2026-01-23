// K Framework Specification for Canton Network
// Formalizes Daml contracts, sub-transaction privacy, and domain synchronization

module CANTON-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports MAP
    imports LIST

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    // P-256 (secp256r1) curve parameters for X.509 compatibility
    syntax Int ::= "P256_ORDER"  [macro]
    rule P256_ORDER => 115792089210356248762697446949407573529996955224135760342422259061068512044369

    syntax Int ::= "P256_PRIME"  [macro]
    rule P256_PRIME => 115792089210356248762697446949407573530086143415290314195533631308867097853951

    // Canton protocol parameters
    syntax Int ::= "MAX_PARTICIPANTS" [macro]
    rule MAX_PARTICIPANTS => 100

    syntax Int ::= "MAX_SUB_TRANSACTIONS" [macro]
    rule MAX_SUB_TRANSACTIONS => 50

    syntax Int ::= "MAX_COMMITTEE_SIZE" [macro]
    rule MAX_COMMITTEE_SIZE => 21

    syntax Int ::= "BFT_THRESHOLD" [macro]
    rule BFT_THRESHOLD => 14  // 2/3 + 1

    syntax Int ::= "MAX_CLOCK_SKEW" [macro]
    rule MAX_CLOCK_SKEW => 300  // 5 minutes

    syntax Int ::= "FINALITY_DELAY" [macro]
    rule FINALITY_DELAY => 30  // seconds

    // =========================================================================
    // ENUMS
    // =========================================================================

    syntax ActionType ::= "CREATE" | "EXERCISE" | "FETCH" | "LOOKUP_BY_KEY" | "ROLLBACK"

    syntax DomainStatus ::= "INACTIVE" | "ACTIVE" | "SUSPENDED" | "DEPRECATED"

    syntax ParticipantStatus ::= "DISCONNECTED" | "CONNECTING" | "CONNECTED" 
                               | "PARTICIPANT_ACTIVE" | "PARTICIPANT_SUSPENDED"

    syntax Visibility ::= "FULL" | "BLINDED" | "DIVULGED" | "HIDDEN"

    // =========================================================================
    // IDENTITY STRUCTURES
    // =========================================================================

    syntax PartyId ::= partyId(
        fingerprint: Bytes,
        namespace: Bytes
    )

    syntax X509Certificate ::= x509Cert(
        subjectKeyId: Bytes,
        issuerKeyId: Bytes,
        validFrom: Int,
        validUntil: Int,
        publicKey: Bytes,
        signature: Bytes
    )

    syntax ParticipantNode ::= participantNode(
        nodeId: Bytes,
        hostedParties: List,
        connectedDomains: List,
        status: ParticipantStatus,
        registeredAt: Int
    )

    // =========================================================================
    // DOMAIN STRUCTURES
    // =========================================================================

    syntax DomainConfig ::= domainConfig(
        domainId: Bytes,
        domainAlias: String,
        sequencerThreshold: Int,
        mediatorThreshold: Int,
        maxRequestSize: Int,
        participantResponseTimeout: Int,
        reconciliationInterval: Int,
        status: DomainStatus
    )

    syntax DomainTopology ::= domainTopology(
        domainId: Bytes,
        sequencers: List,
        mediators: List,
        participants: List,
        timestamp: Int,
        topologyHash: Bytes
    )

    // =========================================================================
    // TRANSACTION STRUCTURES
    // =========================================================================

    syntax ContractInstance ::= contractInstance(
        contractId: Bytes,
        templateId: Bytes,
        signatories: List,
        observers: List,
        argumentHash: Bytes,
        keyHash: Bytes,
        createdAt: Int
    )

    syntax TransactionAction ::= txAction(
        actionType: ActionType,
        contractId: Bytes,
        templateId: Bytes,
        choiceId: Bytes,
        argumentHash: Bytes,
        actingParties: List,
        childViews: List
    )

    syntax SubTransaction ::= subTx(
        viewHash: Bytes,
        parentViewHash: Bytes,
        actions: List,
        informees: List,
        visibility: Visibility,
        salt: Bytes
    )

    syntax CantonTransaction ::= cantonTx(
        transactionId: Bytes,
        domainId: Bytes,
        ledgerTime: Int,
        submissionTime: Int,
        subTransactions: List,
        submitter: PartyId,
        commandId: Bytes,
        deduplicationPeriod: Int
    )

    syntax TransactionConfirmation ::= txConfirmation(
        transactionId: Bytes,
        domainId: Bytes,
        rootHash: Bytes,
        recordTime: Int,
        participantAcks: List,
        isAccepted: Bool
    )

    // =========================================================================
    // CROSS-DOMAIN STRUCTURES
    // =========================================================================

    syntax DomainTransfer ::= domainTransfer(
        transferId: Bytes,
        sourceDomain: Bytes,
        targetDomain: Bytes,
        contractId: Bytes,
        submitter: PartyId,
        initiatedAt: Int,
        completedAt: Int,
        isComplete: Bool
    )

    syntax BlindedView ::= blindedView(
        commitment: Bytes,
        participantId: Bytes,
        epoch: Int
    )

    syntax CantonNullifier ::= cantonNullifier(
        contractId: Bytes,
        domainId: Bytes,
        actionHash: Bytes,
        pilBinding: Bytes
    )

endmodule

module CANTON-OPERATIONS
    imports CANTON-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports CRYPTO

    // =========================================================================
    // HASH FUNCTIONS (Canton uses SHA-256)
    // =========================================================================

    syntax Bytes ::= hash2(Bytes, Bytes) [function, functional]
    rule hash2(Left, Right) => SHA256(Left +Bytes Right)

    syntax Bytes ::= hashN(List) [function, functional]
    rule hashN(.List) => b""
    rule hashN(ListItem(B:Bytes)) => B
    rule hashN(ListItem(B1:Bytes) ListItem(B2:Bytes) Rest)
        => hashN(ListItem(hash2(B1, B2)) Rest)

    // =========================================================================
    // PARTY ID FUNCTIONS
    // =========================================================================

    // Compute party fingerprint from public key
    syntax Bytes ::= computePartyFingerprint(Bytes) [function, functional]
    rule computePartyFingerprint(PublicKey) => SHA256(PublicKey)

    // Compute party ID
    syntax PartyId ::= computePartyId(Bytes, Bytes) [function, functional]
    rule computePartyId(PublicKey, Namespace)
        => partyId(computePartyFingerprint(PublicKey), Namespace)

    // Encode party ID to bytes
    syntax Bytes ::= encodePartyId(PartyId) [function, functional]
    rule encodePartyId(partyId(Fp, Ns)) => Fp +Bytes Ns

    // Hash party ID
    syntax Bytes ::= hashPartyId(PartyId) [function, functional]
    rule hashPartyId(P) => SHA256(encodePartyId(P))

    // Hash party list
    syntax Bytes ::= hashPartyList(List) [function, functional]
    rule hashPartyList(.List) => b""
    rule hashPartyList(ListItem(P:PartyId) Rest)
        => hashN(ListItem(hashPartyId(P)) hashPartyListToHashes(Rest))

    syntax List ::= hashPartyListToHashes(List) [function]
    rule hashPartyListToHashes(.List) => .List
    rule hashPartyListToHashes(ListItem(P:PartyId) Rest)
        => ListItem(hashPartyId(P)) hashPartyListToHashes(Rest)

    // =========================================================================
    // CONTRACT ID FUNCTIONS
    // =========================================================================

    // Compute contract ID
    syntax Bytes ::= computeContractId(Bytes, Bytes) [function, functional]
    rule computeContractId(Discriminator, Suffix)
        => SHA256(Discriminator +Bytes Suffix)

    // =========================================================================
    // VIEW HASH FUNCTIONS
    // =========================================================================

    // Compute action hash
    syntax Bytes ::= computeActionHash(TransactionAction) [function, functional]
    rule computeActionHash(txAction(Type, ContractId, TemplateId, ChoiceId, ArgHash, Parties, Children))
        => SHA256(
            actionTypeToBytes(Type) +Bytes
            ContractId +Bytes
            TemplateId +Bytes
            ChoiceId +Bytes
            ArgHash +Bytes
            hashPartyList(Parties) +Bytes
            hashN(Children)
        )

    syntax Bytes ::= actionTypeToBytes(ActionType) [function, functional]
    rule actionTypeToBytes(CREATE) => b"\x00"
    rule actionTypeToBytes(EXERCISE) => b"\x01"
    rule actionTypeToBytes(FETCH) => b"\x02"
    rule actionTypeToBytes(LOOKUP_BY_KEY) => b"\x03"
    rule actionTypeToBytes(ROLLBACK) => b"\x04"

    // Compute view hash
    syntax Bytes ::= computeViewHash(SubTransaction) [function, functional]
    rule computeViewHash(subTx(_, ParentHash, Actions, Informees, Vis, Salt))
        => SHA256(
            ParentHash +Bytes
            hashActionList(Actions) +Bytes
            hashPartyList(Informees) +Bytes
            visibilityToBytes(Vis) +Bytes
            Salt
        )

    syntax Bytes ::= hashActionList(List) [function]
    rule hashActionList(.List) => b""
    rule hashActionList(ListItem(A:TransactionAction) Rest)
        => hashN(ListItem(computeActionHash(A)) actionListToHashes(Rest))

    syntax List ::= actionListToHashes(List) [function]
    rule actionListToHashes(.List) => .List
    rule actionListToHashes(ListItem(A:TransactionAction) Rest)
        => ListItem(computeActionHash(A)) actionListToHashes(Rest)

    syntax Bytes ::= visibilityToBytes(Visibility) [function, functional]
    rule visibilityToBytes(FULL) => b"\x00"
    rule visibilityToBytes(BLINDED) => b"\x01"
    rule visibilityToBytes(DIVULGED) => b"\x02"
    rule visibilityToBytes(HIDDEN) => b"\x03"

    // =========================================================================
    // BLINDED COMMITMENT FUNCTIONS
    // =========================================================================

    // Compute blinded commitment
    syntax Bytes ::= computeBlindedCommitment(Bytes, Bytes) [function, functional]
    rule computeBlindedCommitment(ViewHash, Salt)
        => SHA256(ViewHash +Bytes Salt)

    // Verify blinded opening
    syntax Bool ::= verifyBlindedOpening(Bytes, Bytes, Bytes) [function, functional]
    rule verifyBlindedOpening(Commitment, ViewHash, Salt)
        => Commitment ==Bytes computeBlindedCommitment(ViewHash, Salt)

    // =========================================================================
    // MERKLE TREE FUNCTIONS
    // =========================================================================

    // Compute Merkle root
    syntax Bytes ::= computeMerkleRoot(List) [function, functional]
    rule computeMerkleRoot(.List) => b""
    rule computeMerkleRoot(ListItem(L:Bytes)) => L
    rule computeMerkleRoot(Leaves) => merkleLevel(Leaves)
        requires size(Leaves) >Int 1

    syntax Bytes ::= merkleLevel(List) [function]
    rule merkleLevel(ListItem(L:Bytes)) => L
    rule merkleLevel(ListItem(L1:Bytes) ListItem(L2:Bytes) Rest)
        => merkleLevel(ListItem(hash2(L1, L2)) pairRest(Rest))
    rule merkleLevel(ListItem(L:Bytes) .List) => L

    syntax List ::= pairRest(List) [function]
    rule pairRest(.List) => .List
    rule pairRest(ListItem(L:Bytes)) => ListItem(L)
    rule pairRest(ListItem(L1:Bytes) ListItem(L2:Bytes) Rest)
        => ListItem(hash2(L1, L2)) pairRest(Rest)

    // Verify Merkle proof
    syntax Bytes ::= computeRootFromProof(Bytes, List, List) [function, functional]
    rule computeRootFromProof(Leaf, .List, .List) => Leaf
    rule computeRootFromProof(Leaf, ListItem(PE:Bytes) Path, ListItem(0) Indices)
        => computeRootFromProof(hash2(Leaf, PE), Path, Indices)
    rule computeRootFromProof(Leaf, ListItem(PE:Bytes) Path, ListItem(1) Indices)
        => computeRootFromProof(hash2(PE, Leaf), Path, Indices)

    syntax Bool ::= verifyMerkleProof(Bytes, List, List, Bytes) [function, functional]
    rule verifyMerkleProof(Leaf, Path, Indices, Root)
        => computeRootFromProof(Leaf, Path, Indices) ==Bytes Root

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    // Derive nullifier from archived contract
    syntax Bytes ::= deriveNullifier(Bytes, Bytes, Bytes) [function, functional]
    rule deriveNullifier(ContractId, DomainId, ActionHash)
        => SHA256(ContractId +Bytes DomainId +Bytes ActionHash +Bytes b"CANTON_NF")

    // Derive cross-domain nullifier for PIL binding
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int, Int) [function, functional]
    rule deriveCrossDomainNullifier(CantonNf, SourceChain, TargetChain)
        => SHA256(CantonNf +Bytes Int2Bytes(32, SourceChain, BE)
                          +Bytes Int2Bytes(32, TargetChain, BE)
                          +Bytes b"C2P")

    // Derive PIL binding
    syntax Bytes ::= derivePILBinding(Bytes) [function, functional]
    rule derivePILBinding(CantonNf)
        => SHA256(CantonNf +Bytes b"CANTON_TO_PIL")

    // =========================================================================
    // VALIDATION FUNCTIONS
    // =========================================================================

    // Validate domain configuration
    syntax Bool ::= isValidDomainConfig(DomainConfig) [function, functional]
    rule isValidDomainConfig(domainConfig(DomainId, _, SeqThresh, MedThresh, MaxSize, Timeout, _, _))
        => DomainId =/=Bytes b"" andBool
           SeqThresh >Int 0 andBool
           MedThresh >Int 0 andBool
           MaxSize >Int 0 andBool
           Timeout >Int 0

    // Check if domain is active
    syntax Bool ::= isDomainActive(DomainConfig) [function, functional]
    rule isDomainActive(domainConfig(_, _, _, _, _, _, _, Status))
        => Status ==K ACTIVE

    // Check if participant is active
    syntax Bool ::= isParticipantActive(ParticipantNode) [function, functional]
    rule isParticipantActive(participantNode(_, _, _, Status, _))
        => Status ==K PARTICIPANT_ACTIVE orBool Status ==K CONNECTED

    // Validate certificate timing
    syntax Bool ::= isCertificateValid(X509Certificate, Int) [function, functional]
    rule isCertificateValid(x509Cert(SubjectId, _, ValidFrom, ValidUntil, _, _), CurrentTime)
        => CurrentTime >=Int ValidFrom andBool
           CurrentTime <=Int ValidUntil andBool
           SubjectId =/=Bytes b""

    // Validate transaction structure
    syntax Bool ::= isValidTransaction(CantonTransaction) [function, functional]
    rule isValidTransaction(cantonTx(TxId, DomainId, _, _, SubTxs, Submitter, _, _))
        => TxId =/=Bytes b"" andBool
           DomainId =/=Bytes b"" andBool
           size(SubTxs) >Int 0 andBool
           size(SubTxs) <=Int MAX_SUB_TRANSACTIONS andBool
           fingerprint(Submitter) =/=Bytes b""

    syntax Bytes ::= fingerprint(PartyId) [function]
    rule fingerprint(partyId(Fp, _)) => Fp

    // Validate timing
    syntax Bool ::= isTimingValid(CantonTransaction, Int) [function, functional]
    rule isTimingValid(cantonTx(_, _, LedgerTime, SubmitTime, _, _, _, _), CurrentTime)
        => LedgerTime <=Int CurrentTime +Int MAX_CLOCK_SKEW andBool
           SubmitTime <=Int LedgerTime

endmodule

module CANTON-SECURITY
    imports CANTON-OPERATIONS

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Property: Hash function is deterministic
    rule [hash-determinism]:
        hash2(L, R) ==Bytes hash2(L, R) => true

    // Property: Different inputs produce different hashes
    rule [hash-collision-resistance]:
        hash2(L1, R1) ==Bytes hash2(L2, R2)
        => L1 ==Bytes L2 andBool R1 ==Bytes R2

    // Property: Party ID is deterministic
    rule [party-id-determinism]:
        computePartyId(PK, NS) ==K computePartyId(PK, NS) => true

    // Property: Contract ID is unique per discriminator
    rule [contract-id-uniqueness]:
        computeContractId(D1, S1) ==Bytes computeContractId(D2, S2)
        => D1 ==Bytes D2 andBool S1 ==Bytes S2

    // Property: Blinded commitment hiding
    rule [commitment-hiding]:
        computeBlindedCommitment(V1, S1) ==Bytes computeBlindedCommitment(V2, S2)
        => V1 ==Bytes V2 andBool S1 ==Bytes S2

    // Property: Blinded commitment can be verified
    rule [commitment-opening]:
        verifyBlindedOpening(computeBlindedCommitment(V, S), V, S) => true

    // Property: Nullifier is deterministic
    rule [nullifier-determinism]:
        deriveNullifier(C, D, A) ==Bytes deriveNullifier(C, D, A) => true

    // Property: Nullifier uniqueness
    rule [nullifier-uniqueness]:
        deriveNullifier(C1, D1, A1) ==Bytes deriveNullifier(C2, D2, A2)
        => C1 ==Bytes C2 andBool D1 ==Bytes D2 andBool A1 ==Bytes A2

    // Property: Cross-domain nullifier binding
    rule [cross-domain-binding]:
        deriveCrossDomainNullifier(Nf1, Src1, Tgt1) ==Bytes deriveCrossDomainNullifier(Nf2, Src2, Tgt2)
        => Nf1 ==Bytes Nf2 andBool Src1 ==Int Src2 andBool Tgt1 ==Int Tgt2

    // Property: PIL binding is unique
    rule [pil-binding-uniqueness]:
        derivePILBinding(Nf1) ==Bytes derivePILBinding(Nf2)
        => Nf1 ==Bytes Nf2

    // Property: Merkle proof verification is consistent
    rule [merkle-consistency]:
        verifyMerkleProof(Leaf, Path, Indices, computeRootFromProof(Leaf, Path, Indices)) => true

endmodule

module CANTON-PRIVACY
    imports CANTON-SECURITY

    // =========================================================================
    // SUB-TRANSACTION PRIVACY PROPERTIES
    // =========================================================================

    // Property: Only informees can see view content
    syntax Bool ::= canSeeView(PartyId, SubTransaction) [function]
    rule canSeeView(Party, subTx(_, _, _, Informees, Vis, _))
        => partyInList(Party, Informees) andBool Vis =/=K HIDDEN

    syntax Bool ::= partyInList(PartyId, List) [function]
    rule partyInList(_, .List) => false
    rule partyInList(P, ListItem(Q:PartyId) Rest)
        => P ==K Q orBool partyInList(P, Rest)

    // Property: Blinded views reveal nothing about content
    rule [blinded-privacy]:
        computeBlindedCommitment(V1, S1) ==Bytes computeBlindedCommitment(V2, S2)
        => (V1 ==Bytes V2 andBool S1 ==Bytes S2)
           // Cannot determine V from commitment alone

    // Property: Hidden views are completely private
    rule [hidden-privacy]:
        canSeeView(P, subTx(_, _, _, _, HIDDEN, _)) => false

    // =========================================================================
    // DOMAIN ISOLATION PROPERTIES
    // =========================================================================

    // Property: Transactions are domain-scoped
    syntax Bool ::= sameDomain(CantonTransaction, CantonTransaction) [function]
    rule sameDomain(cantonTx(_, D1, _, _, _, _, _, _), cantonTx(_, D2, _, _, _, _, _, _))
        => D1 ==Bytes D2

    // Property: Cross-domain transfers require explicit transfer protocol
    syntax Bool ::= validCrossDomainTransfer(DomainTransfer) [function]
    rule validCrossDomainTransfer(domainTransfer(TxId, Src, Tgt, ContractId, _, _, _, _))
        => TxId =/=Bytes b"" andBool
           Src =/=Bytes b"" andBool
           Tgt =/=Bytes b"" andBool
           Src =/=Bytes Tgt andBool
           ContractId =/=Bytes b""

endmodule

module CANTON-BFT
    imports CANTON-PRIVACY

    // =========================================================================
    // BFT CONSENSUS PROPERTIES
    // =========================================================================

    // Property: BFT threshold is respected
    syntax Bool ::= hasQuorum(Int, Int) [function, functional]
    rule hasQuorum(Acks, Total)
        => Acks >=Int (2 *Int Total) /Int 3 +Int 1

    // Property: Transaction accepted with sufficient acks
    syntax Bool ::= canAcceptTransaction(TransactionConfirmation, DomainConfig) [function]
    rule canAcceptTransaction(
        txConfirmation(_, _, _, _, Acks, _),
        domainConfig(_, _, _, MedThresh, _, _, _, _)
    ) => size(Acks) >=Int MedThresh

    // Property: Finality is achieved after confirmation
    rule [finality]:
        canAcceptTransaction(Conf, Config) ==Bool true
        => isAccepted(Conf) ==Bool true

    syntax Bool ::= isAccepted(TransactionConfirmation) [function]
    rule isAccepted(txConfirmation(_, _, _, _, _, Accepted)) => Accepted

endmodule

module CANTON
    imports CANTON-BFT
endmodule
