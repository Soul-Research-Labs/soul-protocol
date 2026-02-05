// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {MPCLib} from "../libraries/MPCLib.sol";

/**
 * @title MPCKeyRegistry
 * @author Soul Protocol
 * @notice Distributed Key Generation (DKG) and key management for MPC
 * @dev Implements Feldman and Pedersen DKG protocols for threshold key generation
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                   Distributed Key Generation (DKG)                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  Feldman's DKG (Verifiable):                                                │
 * │  1. Each party i chooses random polynomial f_i(x) of degree t-1            │
 * │  2. Party i broadcasts commitments: C_ij = g^{a_ij} for coefficients       │
 * │  3. Party i sends share f_i(j) to party j (encrypted)                      │
 * │  4. Party j verifies: g^{f_i(j)} = ∏ C_ik^{j^k}                            │
 * │  5. Final share: s_j = Σ f_i(j), Public key: PK = ∏ C_i0                   │
 * │                                                                              │
 * │  Pedersen's DKG (Information-theoretic hiding):                             │
 * │  - Adds second generator h for commitments: C = g^a * h^r                  │
 * │  - Provides unconditional hiding of shares                                  │
 * │                                                                              │
 * │  Key Types:                                                                  │
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
 * │  │  Signing    │  │  Encryption │  │   Custom    │                         │
 * │  │    Key      │  │     Key     │  │    Key      │                         │
 * │  │  (ECDSA)    │  │   (ECIES)   │  │  (Generic)  │                         │
 * │  └─────────────┘  └─────────────┘  └─────────────┘                         │
 * │                                                                              │
 * │  Security: t-1 corrupted parties learn nothing about secret key            │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract MPCKeyRegistry is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant KEY_ADMIN_ROLE = keccak256("KEY_ADMIN_ROLE");
    bytes32 public constant DKG_PARTICIPANT_ROLE =
        keccak256("DKG_PARTICIPANT_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum key holders
    uint256 public constant MAX_KEY_HOLDERS = 256;

    /// @notice DKG phase timeout
    uint256 public constant DKG_PHASE_TIMEOUT = 3600; // 1 hour

    /// @notice Key validity period
    uint256 public constant DEFAULT_KEY_VALIDITY = 365 days;

    /// @notice Domain separator
    bytes32 public constant DOMAIN_SEPARATOR =
        keccak256("SoulMPCKeyRegistry_v1");

    // ============================================
    // ENUMS
    // ============================================

    /**
     * @notice Key purpose
     */
    enum KeyPurpose {
        None, // 0: Invalid
        Signing, // 1: For threshold signatures
        Encryption, // 2: For threshold encryption
        KeyExchange, // 3: For key exchange (Kyber, ECDH)
        Custom // 4: Custom purpose
    }

    /**
     * @notice DKG protocol phase
     */
    enum DKGPhase {
        Inactive, // 0: Not started
        Setup, // 1: Participants registering
        Commitment, // 2: Broadcasting commitments
        ShareDistribution, // 3: Sending encrypted shares
        Verification, // 4: Verifying received shares
        Complaint, // 5: Raising complaints about invalid shares
        Complete, // 6: Successfully completed
        Failed // 7: Failed (too many complaints)
    }

    // ============================================
    // EVENTS
    // ============================================

    event DKGSessionCreated(
        bytes32 indexed sessionId,
        MPCLib.ProtocolType protocol,
        uint8 threshold,
        uint8 totalParticipants
    );

    event DKGParticipantRegistered(
        bytes32 indexed sessionId,
        address indexed participant,
        uint8 participantIndex
    );

    event DKGPhaseAdvanced(
        bytes32 indexed sessionId,
        DKGPhase oldPhase,
        DKGPhase newPhase
    );

    event CommitmentSubmitted(
        bytes32 indexed sessionId,
        address indexed participant,
        bytes32 commitmentHash
    );

    event ShareDistributed(
        bytes32 indexed sessionId,
        address indexed from,
        address indexed to
    );

    event ShareVerified(
        bytes32 indexed sessionId,
        address indexed verifier,
        address indexed dealer,
        bool valid
    );

    event ComplaintRaised(
        bytes32 indexed sessionId,
        address indexed complainant,
        address indexed accused,
        string reason
    );

    event DKGCompleted(
        bytes32 indexed sessionId,
        bytes32 indexed keyId,
        bytes32 publicKeyHash
    );

    event DKGFailed(bytes32 indexed sessionId, string reason);

    event KeyRegistered(
        bytes32 indexed keyId,
        KeyPurpose purpose,
        bytes32 publicKeyHash,
        uint8 threshold
    );

    event KeyRevoked(bytes32 indexed keyId);
    event KeyRotated(bytes32 indexed oldKeyId, bytes32 indexed newKeyId);
    event KeyHolderAdded(bytes32 indexed keyId, address indexed holder);
    event KeyHolderRemoved(bytes32 indexed keyId, address indexed holder);

    // ============================================
    // ERRORS
    // ============================================

    error SessionNotFound(bytes32 sessionId);
    error SessionAlreadyExists(bytes32 sessionId);
    error InvalidDKGPhase(DKGPhase current, DKGPhase expected);
    error SessionExpired(bytes32 sessionId);
    error ParticipantNotFound(address participant);
    error ParticipantAlreadyRegistered(address participant);
    error MaxParticipantsReached();
    error InvalidThreshold();
    error KeyNotFound(bytes32 keyId);
    error KeyAlreadyExists(bytes32 keyId);
    error KeyIsRevoked(bytes32 keyId);
    error InvalidCommitment();
    error ShareVerificationFailed();
    error TooManyComplaints();
    error PhaseTimeout();
    error NotKeyHolder(address caller);

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice DKG Session
     */
    struct DKGSession {
        bytes32 sessionId;
        MPCLib.ProtocolType protocol;
        KeyPurpose keyPurpose;
        uint8 threshold;
        uint8 totalParticipants;
        uint8 registeredCount;
        uint8 committedCount;
        uint8 verifiedCount;
        uint8 complaintCount;
        DKGPhase phase;
        uint256 createdAt;
        uint256 phaseDeadline;
        bytes32 resultingKeyId;
        address coordinator;
    }

    /**
     * @notice DKG Participant
     */
    struct DKGParticipant {
        address participantAddress;
        uint8 participantIndex;
        bytes32 publicKeyCommitment; // Commitment to this participant's public contribution
        bytes32[] coefficientCommitments; // C_ij = g^{a_ij}
        MPCLib.ParticipantStatus status;
        uint256 sharesDistributed;
        uint256 sharesReceived;
        uint256 complaintsReceived;
        bool disqualified;
    }

    /**
     * @notice Distributed Key
     */
    struct DistributedKey {
        bytes32 keyId;
        bytes32 dkgSessionId; // DKG session that created this key
        KeyPurpose purpose;
        bytes32 publicKeyHash;
        bytes publicKeyData; // Serialized public key
        uint8 threshold;
        uint8 totalHolders;
        uint256 createdAt;
        uint256 expiresAt;
        uint256 lastUsedAt;
        uint256 usageCount;
        bool active;
        bool revoked;
    }

    /**
     * @notice Key holder information
     */
    struct KeyHolder {
        address holderAddress;
        uint8 holderIndex;
        bytes32 shareCommitment; // Commitment to key share
        bool active;
        uint256 addedAt;
    }

    /**
     * @notice Encrypted share for distribution
     */
    struct EncryptedShare {
        bytes32 sessionId;
        address sender;
        address recipient;
        bytes32 encryptedValue; // Encrypted with recipient's public key
        bytes32 commitment; // VSS commitment for verification
        bool distributed;
        bool verified;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Session nonce
    uint256 public sessionNonce;

    /// @notice Key nonce
    uint256 public keyNonce;

    /// @notice Total keys registered
    uint256 public totalKeys;

    /// @notice DKG Sessions: sessionId => session
    mapping(bytes32 => DKGSession) public dkgSessions;

    /// @notice DKG Participants: sessionId => address => participant
    mapping(bytes32 => mapping(address => DKGParticipant))
        public dkgParticipants;

    /// @notice Participant by index: sessionId => index => address
    mapping(bytes32 => mapping(uint8 => address)) public participantByIndex;

    /// @notice Encrypted shares: sessionId => sender => recipient => share
    mapping(bytes32 => mapping(address => mapping(address => EncryptedShare)))
        public encryptedShares;

    /// @notice Distributed keys: keyId => key
    mapping(bytes32 => DistributedKey) public keys;

    /// @notice Key holders: keyId => address => holder
    mapping(bytes32 => mapping(address => KeyHolder)) public keyHolders;

    /// @notice Holder by index: keyId => index => address
    mapping(bytes32 => mapping(uint8 => address)) public holderByIndex;

    /// @notice Keys by purpose: purpose => keyId[]
    mapping(KeyPurpose => bytes32[]) public keysByPurpose;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(KEY_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ============================================
    // DKG SESSION MANAGEMENT
    // ============================================

    /**
     * @notice Create a new DKG session
     * @param protocol DKG protocol (Feldman or Pedersen)
     * @param keyPurpose Purpose of the key being generated
     * @param threshold t in t-of-n
     * @param totalParticipants n
     * @return sessionId Unique session identifier
     */
    function createDKGSession(
        MPCLib.ProtocolType protocol,
        KeyPurpose keyPurpose,
        uint8 threshold,
        uint8 totalParticipants
    )
        external
        whenNotPaused
        onlyRole(KEY_ADMIN_ROLE)
        returns (bytes32 sessionId)
    {
        if (
            protocol != MPCLib.ProtocolType.DKGFeldman &&
            protocol != MPCLib.ProtocolType.DKGPedersen
        ) {
            revert InvalidThreshold();
        }
        if (!MPCLib.validateThreshold(threshold, totalParticipants)) {
            revert InvalidThreshold();
        }

        sessionId = MPCLib.generateSessionId(
            protocol,
            msg.sender,
            sessionNonce++
        );

        if (dkgSessions[sessionId].createdAt != 0) {
            revert SessionAlreadyExists(sessionId);
        }

        dkgSessions[sessionId] = DKGSession({
            sessionId: sessionId,
            protocol: protocol,
            keyPurpose: keyPurpose,
            threshold: threshold,
            totalParticipants: totalParticipants,
            registeredCount: 0,
            committedCount: 0,
            verifiedCount: 0,
            complaintCount: 0,
            phase: DKGPhase.Setup,
            createdAt: block.timestamp,
            phaseDeadline: block.timestamp + DKG_PHASE_TIMEOUT,
            resultingKeyId: bytes32(0),
            coordinator: msg.sender
        });

        emit DKGSessionCreated(
            sessionId,
            protocol,
            threshold,
            totalParticipants
        );
    }

    /**
     * @notice Register as DKG participant
     * @param sessionId DKG session to join
     * @param publicKeyCommitment Commitment to participant's contribution
     * @return participantIndex Assigned index (1-based)
     */
    function registerForDKG(
        bytes32 sessionId,
        bytes32 publicKeyCommitment
    ) external whenNotPaused nonReentrant returns (uint8 participantIndex) {
        DKGSession storage session = dkgSessions[sessionId];

        if (session.createdAt == 0) {
            revert SessionNotFound(sessionId);
        }
        if (session.phase != DKGPhase.Setup) {
            revert InvalidDKGPhase(session.phase, DKGPhase.Setup);
        }
        if (block.timestamp > session.phaseDeadline) {
            revert PhaseTimeout();
        }
        if (dkgParticipants[sessionId][msg.sender].participantIndex != 0) {
            revert ParticipantAlreadyRegistered(msg.sender);
        }
        if (session.registeredCount >= session.totalParticipants) {
            revert MaxParticipantsReached();
        }

        participantIndex = session.registeredCount + 1;
        session.registeredCount++;

        dkgParticipants[sessionId][msg.sender] = DKGParticipant({
            participantAddress: msg.sender,
            participantIndex: participantIndex,
            publicKeyCommitment: publicKeyCommitment,
            coefficientCommitments: new bytes32[](0),
            status: MPCLib.ParticipantStatus.Registered,
            sharesDistributed: 0,
            sharesReceived: 0,
            complaintsReceived: 0,
            disqualified: false
        });

        participantByIndex[sessionId][participantIndex] = msg.sender;
        _grantRole(DKG_PARTICIPANT_ROLE, msg.sender);

        emit DKGParticipantRegistered(sessionId, msg.sender, participantIndex);

        // If all registered, advance to commitment phase
        if (session.registeredCount == session.totalParticipants) {
            _advanceDKGPhase(sessionId, DKGPhase.Commitment);
        }
    }

    /**
     * @notice Submit coefficient commitments
     * @param sessionId DKG session
     * @param coeffCommitments Array of g^{a_j} for polynomial coefficients
     */
    function submitCommitments(
        bytes32 sessionId,
        bytes32[] calldata coeffCommitments
    ) external whenNotPaused nonReentrant {
        DKGSession storage session = dkgSessions[sessionId];
        DKGParticipant storage participant = dkgParticipants[sessionId][
            msg.sender
        ];

        if (session.phase != DKGPhase.Commitment) {
            revert InvalidDKGPhase(session.phase, DKGPhase.Commitment);
        }
        if (participant.participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }
        if (coeffCommitments.length != session.threshold) {
            revert InvalidCommitment();
        }

        // Store commitments
        delete participant.coefficientCommitments;
        for (uint256 i = 0; i < coeffCommitments.length; i++) {
            participant.coefficientCommitments.push(coeffCommitments[i]);
        }

        participant.status = MPCLib.ParticipantStatus.Committed;
        session.committedCount++;

        bytes32 commitmentHash = keccak256(abi.encodePacked(coeffCommitments));
        emit CommitmentSubmitted(sessionId, msg.sender, commitmentHash);

        // If all committed, advance to share distribution
        if (session.committedCount == session.registeredCount) {
            _advanceDKGPhase(sessionId, DKGPhase.ShareDistribution);
        }
    }

    /**
     * @notice Distribute encrypted share to another participant
     * @param sessionId DKG session
     * @param recipient Recipient address
     * @param encryptedShare Share encrypted with recipient's public key
     * @param commitment VSS commitment for verification
     */
    function distributeShare(
        bytes32 sessionId,
        address recipient,
        bytes32 encryptedShare,
        bytes32 commitment
    ) external whenNotPaused nonReentrant {
        DKGSession storage session = dkgSessions[sessionId];
        DKGParticipant storage sender = dkgParticipants[sessionId][msg.sender];
        DKGParticipant storage recipientP = dkgParticipants[sessionId][
            recipient
        ];

        if (session.phase != DKGPhase.ShareDistribution) {
            revert InvalidDKGPhase(session.phase, DKGPhase.ShareDistribution);
        }
        if (sender.participantIndex == 0 || recipientP.participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }

        encryptedShares[sessionId][msg.sender][recipient] = EncryptedShare({
            sessionId: sessionId,
            sender: msg.sender,
            recipient: recipient,
            encryptedValue: encryptedShare,
            commitment: commitment,
            distributed: true,
            verified: false
        });

        sender.sharesDistributed++;
        recipientP.sharesReceived++;

        emit ShareDistributed(sessionId, msg.sender, recipient);

        // Check if all shares distributed
        _checkShareDistributionComplete(sessionId);
    }

    /**
     * @notice Verify received share
     * @param sessionId DKG session
     * @param sender Address that sent the share
     * @param shareValue Decrypted share value
     * @param valid Whether the share verified correctly
     */
    function verifyReceivedShare(
        bytes32 sessionId,
        address sender,
        bytes32 shareValue,
        bool valid
    ) external whenNotPaused nonReentrant {
        DKGSession storage session = dkgSessions[sessionId];
        EncryptedShare storage share = encryptedShares[sessionId][sender][
            msg.sender
        ];
        DKGParticipant storage senderP = dkgParticipants[sessionId][sender];

        if (session.phase != DKGPhase.Verification) {
            revert InvalidDKGPhase(session.phase, DKGPhase.Verification);
        }
        if (!share.distributed) {
            revert ParticipantNotFound(sender);
        }

        // Verify against VSS commitments
        bool vssValid = MPCLib.verifyVSSShare(
            shareValue,
            dkgParticipants[sessionId][msg.sender].participantIndex,
            senderP.coefficientCommitments
        );

        share.verified = valid && vssValid;

        if (!share.verified) {
            // Raise implicit complaint
            session.complaintCount++;
            senderP.complaintsReceived++;

            if (senderP.complaintsReceived > session.threshold) {
                senderP.disqualified = true;
            }
        } else {
            session.verifiedCount++;
        }

        emit ShareVerified(sessionId, msg.sender, sender, share.verified);

        // Check if verification complete
        _checkVerificationComplete(sessionId);
    }

    /**
     * @notice Raise formal complaint against a participant
     * @param sessionId DKG session
     * @param accused Accused participant
     * @param reason Complaint reason
     */
    function raiseComplaint(
        bytes32 sessionId,
        address accused,
        string calldata reason
    ) external whenNotPaused {
        DKGSession storage session = dkgSessions[sessionId];
        DKGParticipant storage accusedP = dkgParticipants[sessionId][accused];

        if (session.phase != DKGPhase.Complaint) {
            revert InvalidDKGPhase(session.phase, DKGPhase.Complaint);
        }
        if (dkgParticipants[sessionId][msg.sender].participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }

        accusedP.complaintsReceived++;
        session.complaintCount++;

        if (accusedP.complaintsReceived > session.totalParticipants / 2) {
            accusedP.disqualified = true;
        }

        emit ComplaintRaised(sessionId, msg.sender, accused, reason);

        // Check if too many disqualifications
        _checkComplaintsResolution(sessionId);
    }

    // ============================================
    // INTERNAL DKG HELPERS
    // ============================================

    function _advanceDKGPhase(bytes32 sessionId, DKGPhase newPhase) internal {
        DKGSession storage session = dkgSessions[sessionId];
        DKGPhase oldPhase = session.phase;

        session.phase = newPhase;
        session.phaseDeadline = block.timestamp + DKG_PHASE_TIMEOUT;

        emit DKGPhaseAdvanced(sessionId, oldPhase, newPhase);
    }

    function _checkShareDistributionComplete(bytes32 sessionId) internal {
        DKGSession storage session = dkgSessions[sessionId];

        // Check if all participants have distributed to all others
        bool allDistributed = true;
        for (uint8 i = 1; i <= session.registeredCount && allDistributed; i++) {
            address participant = participantByIndex[sessionId][i];
            DKGParticipant storage p = dkgParticipants[sessionId][participant];
            // Each participant should distribute to n-1 others
            if (p.sharesDistributed < session.registeredCount - 1) {
                allDistributed = false;
            }
        }

        if (allDistributed) {
            _advanceDKGPhase(sessionId, DKGPhase.Verification);
        }
    }

    function _checkVerificationComplete(bytes32 sessionId) internal {
        DKGSession storage session = dkgSessions[sessionId];

        // Expected verifications: n * (n-1)
        uint256 expectedVerifications = uint256(session.registeredCount) *
            (session.registeredCount - 1);

        if (
            session.verifiedCount + session.complaintCount >=
            expectedVerifications
        ) {
            if (session.complaintCount > 0) {
                _advanceDKGPhase(sessionId, DKGPhase.Complaint);
            } else {
                _completeDKG(sessionId);
            }
        }
    }

    function _checkComplaintsResolution(bytes32 sessionId) internal {
        DKGSession storage session = dkgSessions[sessionId];

        // Count disqualified participants
        uint8 disqualifiedCount = 0;
        for (uint8 i = 1; i <= session.registeredCount; i++) {
            address participant = participantByIndex[sessionId][i];
            if (dkgParticipants[sessionId][participant].disqualified) {
                disqualifiedCount++;
            }
        }

        // If too many disqualified, DKG fails
        if (session.registeredCount - disqualifiedCount < session.threshold) {
            session.phase = DKGPhase.Failed;
            emit DKGFailed(sessionId, "Too many disqualified participants");
        } else {
            _completeDKG(sessionId);
        }
    }

    function _completeDKG(bytes32 sessionId) internal {
        DKGSession storage session = dkgSessions[sessionId];

        // Generate key ID
        bytes32 keyId = keccak256(
            abi.encodePacked(
                DOMAIN_SEPARATOR,
                sessionId,
                keyNonce++,
                block.timestamp
            )
        );

        // Aggregate public key (simplified - XOR of all contributions)
        bytes32 aggregatedPK = bytes32(0);
        uint8 qualifiedCount = 0;

        for (uint8 i = 1; i <= session.registeredCount; i++) {
            address participant = participantByIndex[sessionId][i];
            DKGParticipant storage p = dkgParticipants[sessionId][participant];

            if (!p.disqualified && p.coefficientCommitments.length > 0) {
                // First commitment is g^{a_i0} (contribution to public key)
                aggregatedPK = bytes32(
                    uint256(aggregatedPK) ^ uint256(p.coefficientCommitments[0])
                );
                qualifiedCount++;
            }
        }

        // Register the key
        keys[keyId] = DistributedKey({
            keyId: keyId,
            dkgSessionId: sessionId,
            purpose: session.keyPurpose,
            publicKeyHash: keccak256(abi.encodePacked(aggregatedPK)),
            publicKeyData: abi.encodePacked(aggregatedPK),
            threshold: session.threshold,
            totalHolders: qualifiedCount,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + DEFAULT_KEY_VALIDITY,
            lastUsedAt: 0,
            usageCount: 0,
            active: true,
            revoked: false
        });

        // Register key holders
        uint8 holderIndex = 0;
        for (uint8 i = 1; i <= session.registeredCount; i++) {
            address participant = participantByIndex[sessionId][i];
            DKGParticipant storage p = dkgParticipants[sessionId][participant];

            if (!p.disqualified) {
                holderIndex++;
                keyHolders[keyId][participant] = KeyHolder({
                    holderAddress: participant,
                    holderIndex: holderIndex,
                    shareCommitment: p.publicKeyCommitment,
                    active: true,
                    addedAt: block.timestamp
                });
                holderByIndex[keyId][holderIndex] = participant;

                emit KeyHolderAdded(keyId, participant);
            }
        }

        session.phase = DKGPhase.Complete;
        session.resultingKeyId = keyId;
        totalKeys++;
        keysByPurpose[session.keyPurpose].push(keyId);

        emit DKGCompleted(sessionId, keyId, keys[keyId].publicKeyHash);
        emit KeyRegistered(
            keyId,
            session.keyPurpose,
            keys[keyId].publicKeyHash,
            session.threshold
        );
    }

    // ============================================
    // KEY MANAGEMENT
    // ============================================

    /**
     * @notice Revoke a distributed key
     * @param keyId Key to revoke
     */
    function revokeKey(bytes32 keyId) external onlyRole(KEY_ADMIN_ROLE) {
        DistributedKey storage key = keys[keyId];

        if (key.createdAt == 0) {
            revert KeyNotFound(keyId);
        }

        key.revoked = true;
        key.active = false;

        emit KeyRevoked(keyId);
    }

    /**
     * @notice Initiate key rotation
     * @param oldKeyId Key to rotate
     * @return newSessionId DKG session for new key
     */
    function initiateKeyRotation(
        bytes32 oldKeyId
    ) external onlyRole(KEY_ADMIN_ROLE) returns (bytes32 newSessionId) {
        DistributedKey storage oldKey = keys[oldKeyId];

        if (oldKey.createdAt == 0) {
            revert KeyNotFound(oldKeyId);
        }

        // Create new DKG session with same parameters
        DKGSession storage oldSession = dkgSessions[oldKey.dkgSessionId];

        newSessionId = MPCLib.generateSessionId(
            oldSession.protocol,
            msg.sender,
            sessionNonce++
        );

        dkgSessions[newSessionId] = DKGSession({
            sessionId: newSessionId,
            protocol: oldSession.protocol,
            keyPurpose: oldKey.purpose,
            threshold: oldKey.threshold,
            totalParticipants: oldKey.totalHolders,
            registeredCount: 0,
            committedCount: 0,
            verifiedCount: 0,
            complaintCount: 0,
            phase: DKGPhase.Setup,
            createdAt: block.timestamp,
            phaseDeadline: block.timestamp + DKG_PHASE_TIMEOUT,
            resultingKeyId: bytes32(0),
            coordinator: msg.sender
        });

        emit DKGSessionCreated(
            newSessionId,
            oldSession.protocol,
            oldKey.threshold,
            oldKey.totalHolders
        );
        emit KeyRotated(oldKeyId, newSessionId);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get DKG session details
     * @param sessionId Session identifier
     * @return session Session data
     */
    function getDKGSession(
        bytes32 sessionId
    ) external view returns (DKGSession memory session) {
        session = dkgSessions[sessionId];
    }

    /**
     * @notice Get DKG participant info
     * @param sessionId Session identifier
     * @param participant Participant address
     * @return info Participant data
     */
    function getDKGParticipant(
        bytes32 sessionId,
        address participant
    ) external view returns (DKGParticipant memory info) {
        info = dkgParticipants[sessionId][participant];
    }

    /**
     * @notice Get distributed key details
     * @param keyId Key identifier
     * @return key Key data
     */
    function getKey(
        bytes32 keyId
    ) external view returns (DistributedKey memory key) {
        key = keys[keyId];
    }

    /**
     * @notice Get key holder info
     * @param keyId Key identifier
     * @param holder Holder address
     * @return info Holder data
     */
    function getKeyHolder(
        bytes32 keyId,
        address holder
    ) external view returns (KeyHolder memory info) {
        info = keyHolders[keyId][holder];
    }

    /**
     * @notice Check if address is a key holder
     * @param keyId Key identifier
     * @param holder Address to check
     * @return isHolder True if address holds this key
     */
    function isKeyHolder(
        bytes32 keyId,
        address holder
    ) external view returns (bool isHolder) {
        isHolder = keyHolders[keyId][holder].active;
    }

    /**
     * @notice Get keys by purpose
     * @param purpose Key purpose
     * @return keyIds Array of key IDs
     */
    function getKeysByPurpose(
        KeyPurpose purpose
    ) external view returns (bytes32[] memory keyIds) {
        keyIds = keysByPurpose[purpose];
    }

    /**
     * @notice Get active key for a purpose
     * @param purpose Key purpose
     * @return keyId Most recent active key, or bytes32(0) if none
     */
    function getActiveKeyForPurpose(
        KeyPurpose purpose
    ) external view returns (bytes32 keyId) {
        bytes32[] storage purposeKeys = keysByPurpose[purpose];

        for (uint256 i = purposeKeys.length; i > 0; i--) {
            bytes32 k = purposeKeys[i - 1];
            if (
                keys[k].active &&
                !keys[k].revoked &&
                keys[k].expiresAt > block.timestamp
            ) {
                return k;
            }
        }

        return bytes32(0);
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Handle DKG timeout
     * @param sessionId Session that timed out
     */
    function handleDKGTimeout(bytes32 sessionId) external {
        DKGSession storage session = dkgSessions[sessionId];

        if (block.timestamp <= session.phaseDeadline) {
            revert InvalidDKGPhase(session.phase, DKGPhase.Failed);
        }

        session.phase = DKGPhase.Failed;
        emit DKGFailed(sessionId, "Phase timeout");
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
