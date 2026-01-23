// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CantonPrimitives
 * @notice Core cryptographic primitives for Canton Network integration
 * @dev Canton Network is an enterprise blockchain built on Daml with:
 *      - Sub-transaction privacy (only participants see their parts)
 *      - Synchronization domains for multi-party coordination
 *      - X.509 certificate-based identity
 *      - BFT consensus within domains
 *      - Atomic multi-domain transactions
 */
library CantonPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice secp256r1 (P-256) curve order for Canton signatures
    uint256 internal constant P256_ORDER =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /// @notice secp256r1 field prime
    uint256 internal constant P256_PRIME =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;

    /// @notice Canton protocol version
    uint8 internal constant PROTOCOL_VERSION = 5;

    /// @notice Maximum participants per transaction
    uint256 internal constant MAX_PARTICIPANTS = 100;

    /// @notice Maximum sub-transactions in a transaction
    uint256 internal constant MAX_SUB_TRANSACTIONS = 50;

    /// @notice Domain ID length (32 bytes)
    uint256 internal constant DOMAIN_ID_LENGTH = 32;

    /// @notice Party ID length (typically 64 bytes for fingerprint + namespace)
    uint256 internal constant PARTY_ID_LENGTH = 64;

    /// @notice Contract ID length (66 bytes - discriminator + suffix)
    uint256 internal constant CONTRACT_ID_LENGTH = 66;

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Canton transaction action types
    enum ActionType {
        CREATE, // Create a new contract
        EXERCISE, // Exercise a choice on a contract
        FETCH, // Fetch contract data
        LOOKUP_BY_KEY, // Lookup contract by key
        ROLLBACK // Rollback sub-transaction
    }

    /// @notice Synchronization domain status
    enum DomainStatus {
        INACTIVE,
        ACTIVE,
        SUSPENDED,
        DEPRECATED
    }

    /// @notice Participant connection status
    enum ParticipantStatus {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        ACTIVE,
        SUSPENDED
    }

    /// @notice Transaction view visibility
    enum Visibility {
        FULL, // Full transaction visible
        BLINDED, // Only commitment visible
        DIVULGED, // Divulged to non-stakeholder
        HIDDEN // Completely hidden
    }

    // =========================================================================
    // STRUCTS - IDENTITY
    // =========================================================================

    /// @notice Canton party identifier
    struct PartyId {
        bytes32 fingerprint; // SHA-256 of public key
        bytes32 namespace; // Namespace identifier
    }

    /// @notice X.509 certificate data
    struct X509Certificate {
        bytes32 subjectKeyId; // Subject key identifier
        bytes32 issuerKeyId; // Issuer key identifier
        uint256 validFrom; // Not before timestamp
        uint256 validUntil; // Not after timestamp
        bytes publicKey; // DER-encoded public key
        bytes signature; // Certificate signature
    }

    /// @notice Participant node identity
    struct ParticipantNode {
        bytes32 nodeId; // Unique node identifier
        PartyId[] hostedParties; // Parties hosted on this node
        bytes32[] connectedDomains; // Connected domain IDs
        ParticipantStatus status;
        uint256 registeredAt;
    }

    // =========================================================================
    // STRUCTS - DOMAIN
    // =========================================================================

    /// @notice Synchronization domain configuration
    struct DomainConfig {
        bytes32 domainId; // Unique domain identifier
        string domainAlias; // Human-readable alias
        uint256 sequencerThreshold; // BFT threshold for sequencers
        uint256 mediatorThreshold; // BFT threshold for mediators
        uint256 maxRequestSize; // Maximum request size in bytes
        uint256 participantResponseTimeout; // Timeout for participant responses
        uint256 reconciliationInterval; // ACS reconciliation interval
        DomainStatus status;
    }

    /// @notice Domain topology snapshot
    struct DomainTopology {
        bytes32 domainId;
        bytes32[] sequencers; // Sequencer node IDs
        bytes32[] mediators; // Mediator node IDs
        bytes32[] participants; // Participant node IDs
        uint256 timestamp;
        bytes32 topologyHash; // Hash of full topology
    }

    // =========================================================================
    // STRUCTS - TRANSACTIONS
    // =========================================================================

    /// @notice Daml contract instance
    struct ContractInstance {
        bytes32 contractId; // Unique contract ID
        bytes32 templateId; // Daml template hash
        PartyId[] signatories; // Contract signatories
        PartyId[] observers; // Contract observers
        bytes32 argumentHash; // Hash of contract arguments
        bytes32 keyHash; // Contract key hash (if keyed)
        uint256 createdAt; // Ledger effective time
    }

    /// @notice Transaction action (view)
    struct TransactionAction {
        ActionType actionType;
        bytes32 contractId; // Target contract (for exercise/fetch)
        bytes32 templateId; // Template ID
        bytes32 choiceId; // Choice name hash (for exercise)
        bytes32 argumentHash; // Action argument hash
        PartyId[] actingParties; // Parties performing action
        bytes32[] childViews; // Child view hashes (for exercise)
    }

    /// @notice Sub-transaction (view) for privacy
    struct SubTransaction {
        bytes32 viewHash; // Hash of this view
        bytes32 parentViewHash; // Parent view (0 if root)
        TransactionAction[] actions;
        PartyId[] informees; // Parties who can see this view
        Visibility visibility;
        bytes32 salt; // Randomness for blinding
    }

    /// @notice Full Canton transaction
    struct CantonTransaction {
        bytes32 transactionId; // Global transaction ID
        bytes32 domainId; // Domain where submitted
        uint256 ledgerTime; // Ledger effective time
        uint256 submissionTime; // Submission timestamp
        SubTransaction[] subTransactions;
        PartyId submitter; // Submitting party
        bytes32 commandId; // Original command ID
        uint256 deduplicationPeriod;
    }

    /// @notice Transaction confirmation
    struct TransactionConfirmation {
        bytes32 transactionId;
        bytes32 domainId;
        bytes32 rootHash; // Merkle root of views
        uint256 recordTime; // Domain record time
        bytes32[] participantAcks; // Participant acknowledgments
        bool isAccepted;
    }

    // =========================================================================
    // STRUCTS - CROSS-DOMAIN
    // =========================================================================

    /// @notice Cross-domain transfer request
    struct DomainTransfer {
        bytes32 transferId;
        bytes32 sourceDomain;
        bytes32 targetDomain;
        bytes32 contractId;
        PartyId submitter;
        uint256 initiatedAt;
        uint256 completedAt;
        bool isComplete;
    }

    /// @notice Contract stakeholder set
    struct Stakeholders {
        PartyId[] signatories;
        PartyId[] observers;
        PartyId[] choiceObservers;
    }

    // =========================================================================
    // STRUCTS - PRIVACY
    // =========================================================================

    /// @notice Blinded view commitment
    struct BlindedView {
        bytes32 commitment; // H(viewHash || salt)
        bytes32 participantId; // Participant who can unblind
        uint256 epoch; // Validity epoch
    }

    /// @notice Privacy envelope for selective disclosure
    struct PrivacyEnvelope {
        bytes32 envelopeId;
        bytes32[] blindedViews; // Blinded view commitments
        bytes encryptedPayload; // Encrypted view data
        bytes32 recipientFingerprint; // Recipient public key fingerprint
        bytes32 senderFingerprint; // Sender public key fingerprint
    }

    /// @notice Cross-domain nullifier for PIL binding
    struct CantonNullifier {
        bytes32 contractId; // Source contract ID
        bytes32 domainId; // Source domain
        bytes32 actionHash; // Action that archived contract
        bytes32 pilBinding; // PIL nullifier binding
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /// @notice Hash two values (Canton uses SHA-256)
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
    }

    /// @notice Hash multiple values
    function hashN(bytes32[] memory inputs) internal pure returns (bytes32) {
        if (inputs.length == 0) return bytes32(0);
        if (inputs.length == 1) return inputs[0];

        bytes32 result = inputs[0];
        for (uint256 i = 1; i < inputs.length; i++) {
            result = hash2(result, inputs[i]);
        }
        return result;
    }

    /// @notice Compute party ID from public key
    function computePartyId(
        bytes memory publicKey,
        bytes32 namespace
    ) internal pure returns (PartyId memory) {
        bytes32 fingerprint = sha256(publicKey);
        return PartyId({fingerprint: fingerprint, namespace: namespace});
    }

    /// @notice Compute contract ID
    function computeContractId(
        bytes32 discriminator,
        bytes32 suffix
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(discriminator, suffix));
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Compute view hash for sub-transaction
    function computeViewHash(
        SubTransaction memory subTx
    ) internal pure returns (bytes32) {
        bytes32[] memory actionHashes = new bytes32[](subTx.actions.length);
        for (uint256 i = 0; i < subTx.actions.length; i++) {
            actionHashes[i] = computeActionHash(subTx.actions[i]);
        }

        bytes32 actionsRoot = hashN(actionHashes);
        bytes32 informeesHash = computePartyListHash(subTx.informees);

        return
            sha256(
                abi.encodePacked(
                    subTx.parentViewHash,
                    actionsRoot,
                    informeesHash,
                    uint8(subTx.visibility),
                    subTx.salt
                )
            );
    }

    /// @notice Compute action hash
    function computeActionHash(
        TransactionAction memory action
    ) internal pure returns (bytes32) {
        bytes32 actingPartiesHash = computePartyListHash(action.actingParties);
        bytes32 childViewsHash = hashN(action.childViews);

        return
            sha256(
                abi.encodePacked(
                    uint8(action.actionType),
                    action.contractId,
                    action.templateId,
                    action.choiceId,
                    action.argumentHash,
                    actingPartiesHash,
                    childViewsHash
                )
            );
    }

    /// @notice Compute party list hash
    function computePartyListHash(
        PartyId[] memory parties
    ) internal pure returns (bytes32) {
        if (parties.length == 0) return bytes32(0);

        bytes32[] memory partyHashes = new bytes32[](parties.length);
        for (uint256 i = 0; i < parties.length; i++) {
            partyHashes[i] = sha256(
                abi.encodePacked(parties[i].fingerprint, parties[i].namespace)
            );
        }
        return hashN(partyHashes);
    }

    // =========================================================================
    // COMMITMENT FUNCTIONS
    // =========================================================================

    /// @notice Compute blinded view commitment
    function computeBlindedCommitment(
        bytes32 viewHash,
        bytes32 salt
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(viewHash, salt));
    }

    /// @notice Verify blinded view opening
    function verifyBlindedOpening(
        bytes32 commitment,
        bytes32 viewHash,
        bytes32 salt
    ) internal pure returns (bool) {
        return commitment == computeBlindedCommitment(viewHash, salt);
    }

    /// @notice Compute transaction root hash
    function computeTransactionRoot(
        CantonTransaction memory cantonTx
    ) internal pure returns (bytes32) {
        bytes32[] memory viewHashes = new bytes32[](
            cantonTx.subTransactions.length
        );
        for (uint256 i = 0; i < cantonTx.subTransactions.length; i++) {
            viewHashes[i] = cantonTx.subTransactions[i].viewHash;
        }
        return computeMerkleRoot(viewHashes);
    }

    // =========================================================================
    // MERKLE TREE FUNCTIONS
    // =========================================================================

    /// @notice Compute Merkle root from leaves
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        uint256 n = leaves.length;
        bytes32[] memory nodes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            nodes[i] = leaves[i];
        }

        while (n > 1) {
            uint256 newN = (n + 1) / 2;
            for (uint256 i = 0; i < newN; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1;
                if (right < n) {
                    nodes[i] = hash2(nodes[left], nodes[right]);
                } else {
                    nodes[i] = nodes[left];
                }
            }
            n = newN;
        }

        return nodes[0];
    }

    /// @notice Verify Merkle proof
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] memory proof,
        uint256[] memory indices,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (indices[i] == 0) {
                computed = hash2(computed, proof[i]);
            } else {
                computed = hash2(proof[i], computed);
            }
        }
        return computed == root;
    }

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    /// @notice Derive nullifier from archived contract
    function deriveNullifier(
        bytes32 contractId,
        bytes32 domainId,
        bytes32 actionHash
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(contractId, domainId, actionHash, "CANTON_NF")
            );
    }

    /// @notice Derive cross-domain nullifier for PIL binding
    function deriveCrossDomainNullifier(
        bytes32 cantonNullifier,
        uint256 sourceChainId,
        uint256 targetChainId
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    cantonNullifier,
                    sourceChainId,
                    targetChainId,
                    "C2P"
                )
            );
    }

    /// @notice Derive PIL binding from Canton nullifier
    function derivePILBinding(
        bytes32 cantonNullifier
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(cantonNullifier, "CANTON_TO_PIL"));
    }

    // =========================================================================
    // SIGNATURE VERIFICATION (P-256)
    // =========================================================================

    /// @notice Verify P-256 signature (stub - requires precompile or library)
    /// @dev Canton typically uses P-256 (secp256r1) for X.509 compatibility
    function verifyP256Signature(
        bytes32 /* messageHash */,
        bytes memory signature,
        bytes memory publicKey
    ) internal pure returns (bool) {
        // In production, use EIP-7212 precompile or external library
        // This is a placeholder that validates structure
        require(signature.length == 64, "Invalid signature length");
        require(
            publicKey.length == 64 || publicKey.length == 65,
            "Invalid public key"
        );

        // Extract r, s from signature
        uint256 r;
        uint256 s;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
        }

        // Basic validity checks
        return r > 0 && r < P256_ORDER && s > 0 && s < P256_ORDER;
    }

    // =========================================================================
    // DOMAIN VALIDATION
    // =========================================================================

    /// @notice Validate domain configuration
    function isValidDomainConfig(
        DomainConfig memory config
    ) internal pure returns (bool) {
        return
            config.domainId != bytes32(0) &&
            config.sequencerThreshold > 0 &&
            config.mediatorThreshold > 0 &&
            config.maxRequestSize > 0 &&
            config.participantResponseTimeout > 0;
    }

    /// @notice Check if domain is active
    function isDomainActive(
        DomainConfig memory config
    ) internal pure returns (bool) {
        return config.status == DomainStatus.ACTIVE;
    }

    /// @notice Validate participant status
    function isParticipantActive(
        ParticipantNode memory node
    ) internal pure returns (bool) {
        return
            node.status == ParticipantStatus.ACTIVE ||
            node.status == ParticipantStatus.CONNECTED;
    }

    // =========================================================================
    // TRANSACTION VALIDATION
    // =========================================================================

    /// @notice Validate transaction structure
    function isValidTransaction(
        CantonTransaction memory cantonTx
    ) internal pure returns (bool) {
        return
            cantonTx.transactionId != bytes32(0) &&
            cantonTx.domainId != bytes32(0) &&
            cantonTx.subTransactions.length > 0 &&
            cantonTx.subTransactions.length <= MAX_SUB_TRANSACTIONS &&
            cantonTx.submitter.fingerprint != bytes32(0);
    }

    /// @notice Validate sub-transaction visibility
    function isValidSubTransaction(
        SubTransaction memory subTx
    ) internal pure returns (bool) {
        return
            subTx.viewHash != bytes32(0) &&
            subTx.actions.length > 0 &&
            subTx.informees.length > 0 &&
            subTx.informees.length <= MAX_PARTICIPANTS;
    }

    // =========================================================================
    // TIME VALIDATION
    // =========================================================================

    /// @notice Check if certificate is valid
    function isCertificateValid(
        X509Certificate memory cert,
        uint256 currentTime
    ) internal pure returns (bool) {
        return
            currentTime >= cert.validFrom &&
            currentTime <= cert.validUntil &&
            cert.subjectKeyId != bytes32(0);
    }

    /// @notice Check transaction timing validity
    function isTimingValid(
        CantonTransaction memory cantonTx,
        uint256 currentTime,
        uint256 maxClockSkew
    ) internal pure returns (bool) {
        // Ledger time should be close to current time
        if (cantonTx.ledgerTime > currentTime + maxClockSkew) return false;
        if (cantonTx.ledgerTime + maxClockSkew < currentTime) return false;

        // Submission time should be before or at ledger time
        return cantonTx.submissionTime <= cantonTx.ledgerTime;
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /// @notice Encode party ID to bytes
    function encodePartyId(
        PartyId memory party
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(party.fingerprint, party.namespace);
    }

    /// @notice Check if party is in list
    function isPartyInList(
        PartyId memory party,
        PartyId[] memory list
    ) internal pure returns (bool) {
        bytes32 partyHash = sha256(encodePartyId(party));
        for (uint256 i = 0; i < list.length; i++) {
            if (sha256(encodePartyId(list[i])) == partyHash) {
                return true;
            }
        }
        return false;
    }

    /// @notice Get stakeholder union
    function getStakeholderUnion(
        Stakeholders memory s
    ) internal pure returns (bytes32) {
        uint256 totalLen = s.signatories.length +
            s.observers.length +
            s.choiceObservers.length;
        bytes32[] memory allHashes = new bytes32[](totalLen);

        uint256 idx = 0;
        for (uint256 i = 0; i < s.signatories.length; i++) {
            allHashes[idx++] = sha256(encodePartyId(s.signatories[i]));
        }
        for (uint256 i = 0; i < s.observers.length; i++) {
            allHashes[idx++] = sha256(encodePartyId(s.observers[i]));
        }
        for (uint256 i = 0; i < s.choiceObservers.length; i++) {
            allHashes[idx++] = sha256(encodePartyId(s.choiceObservers[i]));
        }

        return hashN(allHashes);
    }
}
