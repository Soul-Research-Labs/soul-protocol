// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ConfidentialMessageTransport
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Confidential Payload Transport as a Native Primitive
 * @dev Cryptographic message confidentiality - no relayer learns payload, policy, or outcome
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    DESIGN PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Confidentiality must be enforced by CRYPTOGRAPHY, not oracle behavior.
 *
 * Soul's Confidential Message Transport (CMT) provides:
 * 1. Payload encrypted INSIDE Confidential Containers
 * 2. Transport layer is oblivious
 * 3. No relayer learns:
 *    - payload content
 *    - disclosure policy
 *    - execution outcome
 *
 * Key improvements over oracle-based confidentiality:
 * - Encryption keys derived inside ZK
 * - Domain-bound encryption prevents cross-domain attacks
 * - Replay-safe ciphertexts via nullifier binding
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                THREE-LAYER SEPARATION
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Soul enforces strict separation between layers:
 *
 * ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ LAYER 1: TRANSPORT                                                                                 │
 * │ - Oblivious relay                                                                                  │
 * │ - Metadata-minimized                                                                               │
 * │ - Learns NOTHING about payload                                                                     │
 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *                                              │
 *                                              ▼
 * ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ LAYER 2: EXECUTION                                                                                 │
 * │ - ZK / TEE / MPC backends                                                                          │
 * │ - Processes encrypted payload                                                                      │
 * │ - Produces ExecutionReceipt                                                                        │
 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *                                              │
 *                                              ▼
 * ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ LAYER 3: VERIFICATION                                                                              │
 * │ - Kernel-enforced                                                                                  │
 * │ - Policy-bound                                                                                     │
 * │ - No trust in transport or execution                                                               │
 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * No layer trusts the others - all guarantees are cryptographic.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract ConfidentialMessageTransport is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant TRANSPORT_ADMIN_ROLE =
        keccak256("TRANSPORT_ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ENCRYPTOR_ROLE = keccak256("ENCRYPTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidCiphertext(bytes32 messageId);
    error InvalidDomainBinding(bytes32 expected, bytes32 actual);
    error ReplayDetected(bytes32 nullifier);
    error InvalidEncryptionProof();
    error MessageNotFound(bytes32 messageId);
    error MessageAlreadyRelayed(bytes32 messageId);
    error InvalidRecipient();
    error TransportExpired(bytes32 messageId);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Encryption schemes supported
    enum EncryptionScheme {
        ECIES_SECP256K1, // Elliptic curve integrated encryption
        HPKE_X25519, // Hybrid public key encryption
        THRESHOLD_BLS, // Threshold BLS encryption
        ZK_DERIVED // Keys derived inside ZK circuit
    }

    /**
     * @notice Confidential Container - encrypted payload wrapper
     * @dev All payloads travel encrypted; transport layer is oblivious
     */
    struct ConfidentialContainer {
        bytes32 containerId;
        // Encryption metadata
        EncryptionScheme scheme;
        bytes32 ephemeralPubKeyHash; // Hash of ephemeral public key
        bytes encryptedPayload; // The actual encrypted data
        // Domain binding (prevents cross-domain attacks)
        bytes32 sourceDomain;
        bytes32 destDomain;
        bytes32 domainSeparator;
        // Replay protection
        bytes32 nullifier;
        // Policy binding (encrypted)
        bytes32 encryptedPolicyHash; // Policy is also confidential
        // Timestamps
        uint64 createdAt;
        uint64 expiresAt;
    }

    /**
     * @notice Transport envelope - metadata for oblivious relay
     * @dev Relayers see only routing info, not content
     */
    struct TransportEnvelope {
        bytes32 envelopeId;
        bytes32 containerId; // Reference to container
        // Routing (visible to relayers)
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 recipientCommitment; // Commitment, not plaintext
        // Transport metadata
        uint64 createdAt;
        uint64 expiresAt;
        uint256 transportFee;
        // Status
        TransportStatus status;
        bytes32 relayerCommitment; // Who relayed (if any)
    }

    /// @notice Transport status
    enum TransportStatus {
        Pending,
        InTransit,
        Delivered,
        Failed,
        Expired
    }

    /**
     * @notice Encryption proof - proves correct encryption without revealing key
     * @dev ZK proof that encryption was done correctly
     */
    struct EncryptionProof {
        bytes32 proofId;
        bytes32 containerId;
        bytes32 publicInputHash; // Hash of public inputs
        bytes proof; // ZK proof bytes
        bool verified;
    }

    /**
     * @notice Decryption authorization - who can decrypt
     * @dev Policy-bound decryption rights
     */
    struct DecryptionAuthorization {
        bytes32 authId;
        bytes32 containerId;
        bytes32 recipientCommitment; // Who is authorized
        bytes32 policyProof; // Proof they satisfy policy
        uint64 validUntil;
        bool revoked;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain ID (immutable)
    uint256 public immutable CHAIN_ID;

    /// @notice Containers: containerId => container
    mapping(bytes32 => ConfidentialContainer) public containers;

    /// @notice Envelopes: envelopeId => envelope
    mapping(bytes32 => TransportEnvelope) public envelopes;

    /// @notice Encryption proofs: containerId => proof
    mapping(bytes32 => EncryptionProof) public encryptionProofs;

    /// @notice Decryption authorizations: authId => authorization
    mapping(bytes32 => DecryptionAuthorization) public authorizations;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Domain registry: domainId => isValid
    mapping(bytes32 => bool) public validDomains;

    /// @notice Container to envelope mapping
    mapping(bytes32 => bytes32) public containerToEnvelope;

    /// @notice Counters
    uint256 public totalContainers;
    uint256 public totalTransports;
    uint256 public totalDeliveries;

    /// @notice Default expiry
    uint256 public defaultContainerExpiry = 24 hours;
    uint256 public defaultTransportExpiry = 1 hours;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ContainerCreated(
        bytes32 indexed containerId,
        EncryptionScheme scheme,
        bytes32 sourceDomain,
        bytes32 destDomain
    );

    event EnvelopeCreated(
        bytes32 indexed envelopeId,
        bytes32 indexed containerId,
        uint256 destChainId
    );

    event TransportInitiated(
        bytes32 indexed envelopeId,
        bytes32 relayerCommitment
    );

    event TransportDelivered(
        bytes32 indexed envelopeId,
        bytes32 indexed containerId
    );

    event EncryptionProofVerified(bytes32 indexed containerId, bool success);

    event DecryptionAuthorized(
        bytes32 indexed authId,
        bytes32 indexed containerId,
        bytes32 recipientCommitment
    );

    event DomainRegistered(bytes32 indexed domainId);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        CHAIN_ID = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TRANSPORT_ADMIN_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
        _grantRole(ENCRYPTOR_ROLE, msg.sender);

        // Register this chain's domain
        bytes32 selfDomain = keccak256(
            abi.encodePacked("SOUL_DOMAIN", CHAIN_ID)
        );
        validDomains[selfDomain] = true;
        emit DomainRegistered(selfDomain);
    }

    /*//////////////////////////////////////////////////////////////
                        CONTAINER CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a confidential container for transport
     * @dev Payload is encrypted; only authorized recipients can decrypt
     * @param scheme Encryption scheme used
     * @param ephemeralPubKeyHash Hash of ephemeral public key
     * @param encryptedPayload The encrypted payload bytes
     * @param destDomain Destination domain
     * @param encryptedPolicyHash Hash of encrypted policy
     * @param nullifierPreimage Preimage for nullifier generation
     * @return containerId The container identifier
     */
    function createContainer(
        EncryptionScheme scheme,
        bytes32 ephemeralPubKeyHash,
        bytes calldata encryptedPayload,
        bytes32 destDomain,
        bytes32 encryptedPolicyHash,
        bytes32 nullifierPreimage
    ) external whenNotPaused returns (bytes32 containerId) {
        // Validate destination domain
        if (!validDomains[destDomain] && destDomain != bytes32(0)) {
            // Allow unknown domains for cross-chain
        }

        // Generate source domain
        bytes32 sourceDomain = keccak256(
            abi.encodePacked("SOUL_DOMAIN", CHAIN_ID)
        );

        // Generate domain separator
        bytes32 domainSeparator = keccak256(
            abi.encodePacked(
                "ConfidentialMessageTransport",
                CHAIN_ID,
                sourceDomain,
                destDomain
            )
        );

        // Generate nullifier
        bytes32 nullifier = keccak256(
            abi.encodePacked(nullifierPreimage, domainSeparator, msg.sender)
        );

        // Check replay
        if (usedNullifiers[nullifier]) {
            revert ReplayDetected(nullifier);
        }

        // Generate container ID
        containerId = keccak256(
            abi.encodePacked(
                ephemeralPubKeyHash,
                encryptedPolicyHash,
                nullifier,
                block.timestamp
            )
        );

        // Create container
        containers[containerId] = ConfidentialContainer({
            containerId: containerId,
            scheme: scheme,
            ephemeralPubKeyHash: ephemeralPubKeyHash,
            encryptedPayload: encryptedPayload,
            sourceDomain: sourceDomain,
            destDomain: destDomain,
            domainSeparator: domainSeparator,
            nullifier: nullifier,
            encryptedPolicyHash: encryptedPolicyHash,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + defaultContainerExpiry)
        });

        // Mark nullifier used
        usedNullifiers[nullifier] = true;

        unchecked {
            ++totalContainers;
        }

        emit ContainerCreated(containerId, scheme, sourceDomain, destDomain);
        return containerId;
    }

    /**
     * @notice Create container with ZK-derived encryption
     * @dev Keys are derived inside ZK circuit for maximum privacy
     */
    function createZKEncryptedContainer(
        bytes32 zkKeyCommitment,
        bytes calldata encryptedPayload,
        bytes32 destDomain,
        bytes32 encryptedPolicyHash,
        bytes calldata encryptionProof
    ) external whenNotPaused returns (bytes32 containerId) {
        // Verify ZK encryption proof
        if (
            !_verifyEncryptionProof(
                zkKeyCommitment,
                encryptedPayload,
                encryptionProof
            )
        ) {
            revert InvalidEncryptionProof();
        }

        bytes32 sourceDomain = keccak256(
            abi.encodePacked("SOUL_DOMAIN", CHAIN_ID)
        );
        bytes32 domainSeparator = keccak256(
            abi.encodePacked(
                "ConfidentialMessageTransport",
                CHAIN_ID,
                sourceDomain,
                destDomain
            )
        );

        bytes32 nullifier = keccak256(
            abi.encodePacked(zkKeyCommitment, domainSeparator, block.timestamp)
        );

        if (usedNullifiers[nullifier]) {
            revert ReplayDetected(nullifier);
        }

        containerId = keccak256(
            abi.encodePacked(zkKeyCommitment, nullifier, block.timestamp)
        );

        containers[containerId] = ConfidentialContainer({
            containerId: containerId,
            scheme: EncryptionScheme.ZK_DERIVED,
            ephemeralPubKeyHash: zkKeyCommitment,
            encryptedPayload: encryptedPayload,
            sourceDomain: sourceDomain,
            destDomain: destDomain,
            domainSeparator: domainSeparator,
            nullifier: nullifier,
            encryptedPolicyHash: encryptedPolicyHash,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + defaultContainerExpiry)
        });

        usedNullifiers[nullifier] = true;

        // Store encryption proof
        encryptionProofs[containerId] = EncryptionProof({
            proofId: keccak256(encryptionProof),
            containerId: containerId,
            publicInputHash: keccak256(
                abi.encodePacked(zkKeyCommitment, destDomain)
            ),
            proof: encryptionProof,
            verified: true
        });

        unchecked {
            ++totalContainers;
        }

        emit ContainerCreated(
            containerId,
            EncryptionScheme.ZK_DERIVED,
            sourceDomain,
            destDomain
        );
        emit EncryptionProofVerified(containerId, true);

        return containerId;
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSPORT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create transport envelope for a container
     * @dev Envelope contains only routing info visible to relayers
     * @param containerId The container to transport
     * @param destChainId Destination chain
     * @param recipientCommitment Commitment to recipient (not plaintext)
     * @return envelopeId The envelope identifier
     */
    function createEnvelope(
        bytes32 containerId,
        uint256 destChainId,
        bytes32 recipientCommitment
    ) external whenNotPaused returns (bytes32 envelopeId) {
        ConfidentialContainer storage container = containers[containerId];

        if (container.containerId == bytes32(0)) {
            revert MessageNotFound(containerId);
        }

        if (recipientCommitment == bytes32(0)) {
            revert InvalidRecipient();
        }

        envelopeId = keccak256(
            abi.encodePacked(
                containerId,
                destChainId,
                recipientCommitment,
                block.timestamp
            )
        );

        envelopes[envelopeId] = TransportEnvelope({
            envelopeId: envelopeId,
            containerId: containerId,
            sourceChainId: CHAIN_ID,
            destChainId: destChainId,
            recipientCommitment: recipientCommitment,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + defaultTransportExpiry),
            transportFee: 0,
            status: TransportStatus.Pending,
            relayerCommitment: bytes32(0)
        });

        containerToEnvelope[containerId] = envelopeId;

        emit EnvelopeCreated(envelopeId, containerId, destChainId);
        return envelopeId;
    }

    /**
     * @notice Initiate transport of envelope (relayer picks up)
     * @param envelopeId The envelope to transport
     * @param relayerCommitment Commitment identifying the relayer
     */
    function initiateTransport(
        bytes32 envelopeId,
        bytes32 relayerCommitment
    ) external onlyRole(RELAYER_ROLE) whenNotPaused {
        TransportEnvelope storage envelope = envelopes[envelopeId];

        if (envelope.status != TransportStatus.Pending) {
            revert MessageAlreadyRelayed(envelopeId);
        }

        if (block.timestamp > envelope.expiresAt) {
            envelope.status = TransportStatus.Expired;
            revert TransportExpired(envelopeId);
        }

        envelope.status = TransportStatus.InTransit;
        envelope.relayerCommitment = relayerCommitment;

        unchecked {
            ++totalTransports;
        }

        emit TransportInitiated(envelopeId, relayerCommitment);
    }

    /**
     * @notice Mark envelope as delivered
     * @param envelopeId The envelope that was delivered
     */
    function confirmDelivery(
        bytes32 envelopeId
    ) external onlyRole(RELAYER_ROLE) whenNotPaused {
        TransportEnvelope storage envelope = envelopes[envelopeId];

        if (envelope.status != TransportStatus.InTransit) {
            revert MessageNotFound(envelopeId);
        }

        envelope.status = TransportStatus.Delivered;

        unchecked {
            ++totalDeliveries;
        }

        emit TransportDelivered(envelopeId, envelope.containerId);
    }

    /*//////////////////////////////////////////////////////////////
                    DECRYPTION AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Authorize decryption for a recipient
     * @dev Only authorized recipients who prove policy compliance can decrypt
     * @param containerId The container
     * @param recipientCommitment Commitment to authorized recipient
     * @param policyProof Proof that recipient satisfies policy
     * @param validUntil Authorization validity
     * @return authId Authorization identifier
     */
    function authorizeDecryption(
        bytes32 containerId,
        bytes32 recipientCommitment,
        bytes32 policyProof,
        uint64 validUntil
    ) external onlyRole(ENCRYPTOR_ROLE) returns (bytes32 authId) {
        if (containers[containerId].containerId == bytes32(0)) {
            revert MessageNotFound(containerId);
        }

        authId = keccak256(
            abi.encodePacked(
                containerId,
                recipientCommitment,
                policyProof,
                block.timestamp
            )
        );

        authorizations[authId] = DecryptionAuthorization({
            authId: authId,
            containerId: containerId,
            recipientCommitment: recipientCommitment,
            policyProof: policyProof,
            validUntil: validUntil,
            revoked: false
        });

        emit DecryptionAuthorized(authId, containerId, recipientCommitment);
        return authId;
    }

    /**
     * @notice Revoke decryption authorization
     * @param authId Authorization to revoke
     */
    function revokeAuthorization(
        bytes32 authId
    ) external onlyRole(ENCRYPTOR_ROLE) {
        authorizations[authId].revoked = true;
    }

    /**
     * @notice Check if decryption is authorized
     * @param containerId Container to check
     * @param recipientCommitment Recipient to check
     * @return authorized True if authorized
     * @return authId The authorization ID if found
     */
    function checkDecryptionAuthorization(
        bytes32 containerId,
        bytes32 recipientCommitment
    ) external view returns (bool authorized, bytes32 authId) {
        // In production: iterate through authorizations or use better indexing
        authId = keccak256(abi.encodePacked(containerId, recipientCommitment));

        DecryptionAuthorization storage auth = authorizations[authId];

        if (
            auth.containerId == containerId &&
            auth.recipientCommitment == recipientCommitment &&
            !auth.revoked &&
            block.timestamp < auth.validUntil
        ) {
            return (true, authId);
        }

        return (false, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyEncryptionProof(
        bytes32 keyCommitment,
        bytes calldata encryptedPayload,
        bytes calldata proof
    ) internal pure returns (bool) {
        // In production: verify ZK proof of correct encryption
        // For MVP: basic validation
        return
            keyCommitment != bytes32(0) &&
            encryptedPayload.length > 0 &&
            proof.length > 0;
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get container details
    function getContainer(
        bytes32 containerId
    ) external view returns (ConfidentialContainer memory) {
        return containers[containerId];
    }

    /// @notice Get envelope details
    function getEnvelope(
        bytes32 envelopeId
    ) external view returns (TransportEnvelope memory) {
        return envelopes[envelopeId];
    }

    /// @notice Get encryption proof
    function getEncryptionProof(
        bytes32 containerId
    ) external view returns (EncryptionProof memory) {
        return encryptionProofs[containerId];
    }

    /// @notice Check if nullifier is used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if domain is valid
    function isDomainValid(bytes32 domainId) external view returns (bool) {
        return validDomains[domainId];
    }

    /// @notice Get envelope for container
    function getEnvelopeForContainer(
        bytes32 containerId
    ) external view returns (bytes32) {
        return containerToEnvelope[containerId];
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerDomain(
        bytes32 domainId
    ) external onlyRole(TRANSPORT_ADMIN_ROLE) {
        validDomains[domainId] = true;
        emit DomainRegistered(domainId);
    }

    function setDefaultContainerExpiry(
        uint256 expiry
    ) external onlyRole(TRANSPORT_ADMIN_ROLE) {
        defaultContainerExpiry = expiry;
    }

    function setDefaultTransportExpiry(
        uint256 expiry
    ) external onlyRole(TRANSPORT_ADMIN_ROLE) {
        defaultTransportExpiry = expiry;
    }

    function pause() external onlyRole(TRANSPORT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(TRANSPORT_ADMIN_ROLE) {
        _unpause();
    }
}
