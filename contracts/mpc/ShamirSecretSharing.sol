// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {MPCLib} from "../libraries/MPCLib.sol";

/**
 * @title ShamirSecretSharing
 * @author Soul Protocol
 * @notice Implementation of Shamir's Secret Sharing Scheme with VSS
 * @dev Supports t-of-n threshold secret sharing with verifiable shares
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    Shamir Secret Sharing (t-of-n)                           │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  Secret s is encoded as polynomial f(x) = s + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹  │
 * │                                                                              │
 * │  Share generation: share_i = f(i) for i ∈ {1, 2, ..., n}                    │
 * │                                                                              │
 * │  Reconstruction: Use Lagrange interpolation on any t shares                 │
 * │                  s = Σ share_i × L_i(0)                                      │
 * │                                                                              │
 * │  VSS (Verifiable): Dealer commits to coefficients                           │
 * │                    C_j = g^{a_j} for j ∈ {0, ..., t-1}                       │
 * │                    Verify: g^{f(i)} = ∏ C_j^{i^j}                            │
 * │                                                                              │
 * │  Security Properties:                                                        │
 * │  - Information-theoretic: t-1 shares reveal nothing about secret            │
 * │  - Computational: VSS prevents malicious dealer                              │
 * │  - Proactive: Shares can be refreshed without changing secret               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract ShamirSecretSharing is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant DEALER_ROLE = keccak256("DEALER_ROLE");
    bytes32 public constant PARTICIPANT_ROLE = keccak256("PARTICIPANT_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // EVENTS
    // ============================================

    event SharingSessionCreated(
        bytes32 indexed sessionId,
        address indexed dealer,
        uint8 threshold,
        uint8 totalParticipants
    );

    event ParticipantRegistered(
        bytes32 indexed sessionId,
        address indexed participant,
        uint8 participantIndex
    );

    event CommitmentsPublished(
        bytes32 indexed sessionId,
        address indexed dealer,
        uint256 numCommitments
    );

    event ShareDistributed(
        bytes32 indexed sessionId,
        address indexed recipient,
        uint8 shareIndex
    );

    event ShareVerified(
        bytes32 indexed sessionId,
        address indexed participant,
        bool valid
    );

    event SecretReconstructed(
        bytes32 indexed sessionId,
        bytes32 indexed resultHash,
        uint8 numShares
    );

    event ShareRefreshed(
        bytes32 indexed sessionId,
        address indexed participant,
        uint8 shareIndex
    );

    event ParticipantExcluded(
        bytes32 indexed sessionId,
        address indexed participant,
        string reason
    );

    event SessionCompleted(bytes32 indexed sessionId);
    event SessionFailed(bytes32 indexed sessionId, string reason);

    // ============================================
    // ERRORS
    // ============================================

    error InvalidThreshold(uint8 threshold, uint8 totalParticipants);
    error SessionNotFound(bytes32 sessionId);
    error SessionAlreadyExists(bytes32 sessionId);
    error SessionNotInPhase(bytes32 sessionId, MPCLib.SessionStatus expected);
    error ParticipantNotRegistered(address participant);
    error ParticipantAlreadyRegistered(address participant);
    error MaxParticipantsReached(bytes32 sessionId);
    error NotDealer(address caller);
    error InvalidShareIndex(uint8 index);
    error ShareVerificationFailed();
    error InsufficientShares(uint256 provided, uint256 required);
    error SessionExpired(bytes32 sessionId);
    error InvalidCommitmentCount();
    error ShareAlreadySubmitted(address participant);

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice Sharing session state
     */
    struct SharingSession {
        bytes32 sessionId;
        address dealer;
        uint8 threshold;
        uint8 totalParticipants;
        uint8 registeredCount;
        uint8 distributedCount;
        uint8 verifiedCount;
        MPCLib.SessionStatus status;
        uint256 createdAt;
        uint256 deadline;
        bytes32 secretCommitment;      // Commitment to original secret
        bytes32 reconstructedHash;     // Hash of reconstructed secret
    }

    /**
     * @notice Participant's share data
     */
    struct ParticipantShare {
        uint8 shareIndex;
        bytes32 encryptedShare;        // Encrypted with participant's public key
        bytes32 shareCommitment;
        MPCLib.VerificationStatus status;
        uint256 receivedAt;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Prime field for Shamir (BN254 order)
    uint256 public immutable FIELD_PRIME = MPCLib.BN254_ORDER;

    /// @notice Session nonce
    uint256 public sessionNonce;

    /// @notice Sessions: sessionId => session
    mapping(bytes32 => SharingSession) public sessions;

    /// @notice VSS commitments: sessionId => commitment array
    mapping(bytes32 => bytes32[]) public vssCommitments;

    /// @notice Participants: sessionId => address => participant info
    mapping(bytes32 => mapping(address => MPCLib.Participant)) public participants;

    /// @notice Participant addresses: sessionId => index => address
    mapping(bytes32 => mapping(uint8 => address)) public participantByIndex;

    /// @notice Shares: sessionId => participant => share data
    mapping(bytes32 => mapping(address => ParticipantShare)) public shares;

    /// @notice Reconstruction shares: sessionId => shares array
    mapping(bytes32 => uint256[]) internal reconstructionShares;
    mapping(bytes32 => uint256[]) internal reconstructionIndices;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ============================================
    // SESSION MANAGEMENT
    // ============================================

    /**
     * @notice Create a new secret sharing session
     * @param threshold Minimum shares needed (t)
     * @param totalParticipants Total shares to create (n)
     * @param secretCommitment Commitment to the secret being shared
     * @param duration Session duration in seconds
     * @return sessionId Unique session identifier
     */
    function createSession(
        uint8 threshold,
        uint8 totalParticipants,
        bytes32 secretCommitment,
        uint256 duration
    ) external whenNotPaused nonReentrant returns (bytes32 sessionId) {
        // Validate threshold
        if (!MPCLib.validateThreshold(threshold, totalParticipants)) {
            revert InvalidThreshold(threshold, totalParticipants);
        }

        // Generate session ID
        sessionId = MPCLib.generateSessionId(
            MPCLib.ProtocolType.ShamirSS,
            msg.sender,
            sessionNonce++
        );

        if (sessions[sessionId].createdAt != 0) {
            revert SessionAlreadyExists(sessionId);
        }

        // Create session
        sessions[sessionId] = SharingSession({
            sessionId: sessionId,
            dealer: msg.sender,
            threshold: threshold,
            totalParticipants: totalParticipants,
            registeredCount: 0,
            distributedCount: 0,
            verifiedCount: 0,
            status: MPCLib.SessionStatus.Created,
            createdAt: block.timestamp,
            deadline: block.timestamp + duration,
            secretCommitment: secretCommitment,
            reconstructedHash: bytes32(0)
        });

        // Grant dealer role
        _grantRole(DEALER_ROLE, msg.sender);

        emit SharingSessionCreated(sessionId, msg.sender, threshold, totalParticipants);
    }

    /**
     * @notice Register as a participant in a session
     * @param sessionId Session to join
     * @param publicKeyCommitment Commitment to participant's public key
     * @return participantIndex Assigned index (1-based)
     */
    function registerParticipant(
        bytes32 sessionId,
        bytes32 publicKeyCommitment
    ) external whenNotPaused nonReentrant returns (uint8 participantIndex) {
        SharingSession storage session = sessions[sessionId];
        
        if (session.createdAt == 0) {
            revert SessionNotFound(sessionId);
        }
        if (session.status != MPCLib.SessionStatus.Created) {
            revert SessionNotInPhase(sessionId, MPCLib.SessionStatus.Created);
        }
        if (block.timestamp > session.deadline) {
            revert SessionExpired(sessionId);
        }
        if (participants[sessionId][msg.sender].status != MPCLib.ParticipantStatus.None) {
            revert ParticipantAlreadyRegistered(msg.sender);
        }
        if (session.registeredCount >= session.totalParticipants) {
            revert MaxParticipantsReached(sessionId);
        }

        // Assign index (1-based)
        participantIndex = session.registeredCount + 1;
        session.registeredCount++;

        // Register participant
        participants[sessionId][msg.sender] = MPCLib.Participant({
            participantAddress: msg.sender,
            publicKeyCommitment: publicKeyCommitment,
            shareCommitment: bytes32(0),
            participantIndex: participantIndex,
            status: MPCLib.ParticipantStatus.Registered,
            stake: 0,
            joinedAt: block.timestamp,
            hasSubmittedResult: false
        });

        participantByIndex[sessionId][participantIndex] = msg.sender;

        emit ParticipantRegistered(sessionId, msg.sender, participantIndex);

        // If all participants registered, move to commitment phase
        if (session.registeredCount == session.totalParticipants) {
            session.status = MPCLib.SessionStatus.CommitmentPhase;
        }
    }

    // ============================================
    // VSS COMMITMENTS
    // ============================================

    /**
     * @notice Dealer publishes VSS commitments
     * @dev Commitments C_j = g^{a_j} for each polynomial coefficient
     * @param sessionId Session identifier
     * @param coefficientCommitments Array of commitments (length = threshold)
     */
    function publishCommitments(
        bytes32 sessionId,
        bytes32[] calldata coefficientCommitments
    ) external whenNotPaused nonReentrant {
        SharingSession storage session = sessions[sessionId];
        
        if (session.dealer != msg.sender) {
            revert NotDealer(msg.sender);
        }
        if (session.status != MPCLib.SessionStatus.CommitmentPhase) {
            revert SessionNotInPhase(sessionId, MPCLib.SessionStatus.CommitmentPhase);
        }
        if (coefficientCommitments.length != session.threshold) {
            revert InvalidCommitmentCount();
        }

        // Store commitments
        delete vssCommitments[sessionId];
        for (uint256 i = 0; i < coefficientCommitments.length; i++) {
            vssCommitments[sessionId].push(coefficientCommitments[i]);
        }

        session.status = MPCLib.SessionStatus.ShareDistribution;

        emit CommitmentsPublished(sessionId, msg.sender, coefficientCommitments.length);
    }

    // ============================================
    // SHARE DISTRIBUTION
    // ============================================

    /**
     * @notice Dealer distributes shares to participants
     * @param sessionId Session identifier
     * @param participantIndex Recipient's index
     * @param encryptedShare Share encrypted with participant's public key
     * @param shareCommitment Commitment to the share value
     */
    function distributeShare(
        bytes32 sessionId,
        uint8 participantIndex,
        bytes32 encryptedShare,
        bytes32 shareCommitment
    ) external whenNotPaused nonReentrant {
        SharingSession storage session = sessions[sessionId];
        
        if (session.dealer != msg.sender) {
            revert NotDealer(msg.sender);
        }
        if (session.status != MPCLib.SessionStatus.ShareDistribution) {
            revert SessionNotInPhase(sessionId, MPCLib.SessionStatus.ShareDistribution);
        }
        if (!MPCLib.isValidParticipantIndex(participantIndex, session.totalParticipants)) {
            revert InvalidShareIndex(participantIndex);
        }

        address participant = participantByIndex[sessionId][participantIndex];
        if (participant == address(0)) {
            revert ParticipantNotRegistered(participant);
        }

        // Check if share already distributed
        if (shares[sessionId][participant].receivedAt != 0) {
            revert ShareAlreadySubmitted(participant);
        }

        // Store encrypted share
        shares[sessionId][participant] = ParticipantShare({
            shareIndex: participantIndex,
            encryptedShare: encryptedShare,
            shareCommitment: shareCommitment,
            status: MPCLib.VerificationStatus.Pending,
            receivedAt: block.timestamp
        });

        session.distributedCount++;

        emit ShareDistributed(sessionId, participant, participantIndex);

        // If all shares distributed, update status
        if (session.distributedCount == session.totalParticipants) {
            session.status = MPCLib.SessionStatus.Computation;
        }
    }

    /**
     * @notice Participant verifies their share against VSS commitments
     * @param sessionId Session identifier
     * @param shareValue Decrypted share value
     * @param valid Whether the share verified correctly
     */
    function verifyShare(
        bytes32 sessionId,
        bytes32 shareValue,
        bool valid
    ) external whenNotPaused nonReentrant {
        SharingSession storage session = sessions[sessionId];
        ParticipantShare storage share = shares[sessionId][msg.sender];
        
        if (share.receivedAt == 0) {
            revert ParticipantNotRegistered(msg.sender);
        }
        if (share.status != MPCLib.VerificationStatus.Pending) {
            revert ShareAlreadySubmitted(msg.sender);
        }

        // Verify share against VSS commitments
        bytes32[] memory commitments = vssCommitments[sessionId];
        bool vssValid = MPCLib.verifyVSSShare(shareValue, share.shareIndex, commitments);

        if (valid && vssValid) {
            share.status = MPCLib.VerificationStatus.Valid;
            participants[sessionId][msg.sender].shareCommitment = share.shareCommitment;
            participants[sessionId][msg.sender].status = MPCLib.ParticipantStatus.Ready;
            session.verifiedCount++;
        } else {
            share.status = MPCLib.VerificationStatus.Invalid;
            participants[sessionId][msg.sender].status = MPCLib.ParticipantStatus.Malicious;
            emit ParticipantExcluded(sessionId, msg.sender, "Share verification failed");
        }

        emit ShareVerified(sessionId, msg.sender, valid && vssValid);
    }

    // ============================================
    // SECRET RECONSTRUCTION
    // ============================================

    /**
     * @notice Submit share for reconstruction
     * @param sessionId Session identifier
     * @param shareValue The share value f(i)
     */
    function submitShareForReconstruction(
        bytes32 sessionId,
        uint256 shareValue
    ) external whenNotPaused nonReentrant {
        SharingSession storage session = sessions[sessionId];
        MPCLib.Participant storage participant = participants[sessionId][msg.sender];
        
        if (participant.status != MPCLib.ParticipantStatus.Ready) {
            revert ParticipantNotRegistered(msg.sender);
        }
        if (participant.hasSubmittedResult) {
            revert ShareAlreadySubmitted(msg.sender);
        }

        participant.hasSubmittedResult = true;
        participant.status = MPCLib.ParticipantStatus.Computed;

        // Store for reconstruction
        reconstructionShares[sessionId].push(shareValue);
        reconstructionIndices[sessionId].push(participant.participantIndex);

        // Check if we have enough shares
        if (reconstructionShares[sessionId].length >= session.threshold) {
            _reconstructSecret(sessionId);
        }
    }

    /**
     * @notice Reconstruct secret from submitted shares
     * @param sessionId Session identifier
     */
    function _reconstructSecret(bytes32 sessionId) internal {
        SharingSession storage session = sessions[sessionId];
        
        uint256[] memory shareValues = reconstructionShares[sessionId];
        uint256[] memory indices = reconstructionIndices[sessionId];

        // Reconstruct using Lagrange interpolation
        uint256 secret = MPCLib.reconstructSecret(
            shareValues,
            indices,
            FIELD_PRIME
        );

        // Store hash of reconstructed secret
        session.reconstructedHash = keccak256(abi.encodePacked(secret));
        session.status = MPCLib.SessionStatus.Completed;

        emit SecretReconstructed(
            sessionId,
            session.reconstructedHash,
            uint8(shareValues.length)
        );
        emit SessionCompleted(sessionId);
    }

    // ============================================
    // SHARE REFRESH (PROACTIVE SECURITY)
    // ============================================

    /**
     * @notice Initiate share refresh for proactive security
     * @dev Generates new shares for the same secret
     * @param sessionId Session to refresh
     * @return refreshSessionId New session for refreshed shares
     */
    function initiateShareRefresh(
        bytes32 sessionId
    ) external whenNotPaused returns (bytes32 refreshSessionId) {
        SharingSession storage session = sessions[sessionId];
        
        if (session.dealer != msg.sender) {
            revert NotDealer(msg.sender);
        }
        if (session.status != MPCLib.SessionStatus.Completed) {
            revert SessionNotInPhase(sessionId, MPCLib.SessionStatus.Completed);
        }

        // Create new session for refresh
        refreshSessionId = MPCLib.generateSessionId(
            MPCLib.ProtocolType.ShamirSS,
            msg.sender,
            sessionNonce++
        );

        sessions[refreshSessionId] = SharingSession({
            sessionId: refreshSessionId,
            dealer: msg.sender,
            threshold: session.threshold,
            totalParticipants: session.totalParticipants,
            registeredCount: 0,
            distributedCount: 0,
            verifiedCount: 0,
            status: MPCLib.SessionStatus.Created,
            createdAt: block.timestamp,
            deadline: block.timestamp + MPCLib.SESSION_TIMEOUT,
            secretCommitment: session.secretCommitment,
            reconstructedHash: bytes32(0)
        });

        // Participants need to re-register
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get session details
     * @param sessionId Session identifier
     * @return session Session data
     */
    function getSession(bytes32 sessionId) external view returns (SharingSession memory session) {
        session = sessions[sessionId];
    }

    /**
     * @notice Get participant info
     * @param sessionId Session identifier
     * @param participant Participant address
     * @return info Participant data
     */
    function getParticipant(
        bytes32 sessionId,
        address participant
    ) external view returns (MPCLib.Participant memory info) {
        info = participants[sessionId][participant];
    }

    /**
     * @notice Get VSS commitments for a session
     * @param sessionId Session identifier
     * @return commitments Array of coefficient commitments
     */
    function getVSSCommitments(bytes32 sessionId) external view returns (bytes32[] memory commitments) {
        commitments = vssCommitments[sessionId];
    }

    /**
     * @notice Get share info for a participant
     * @param sessionId Session identifier
     * @param participant Participant address
     * @return share Share data
     */
    function getShare(
        bytes32 sessionId,
        address participant
    ) external view returns (ParticipantShare memory share) {
        share = shares[sessionId][participant];
    }

    /**
     * @notice Check if session has enough verified shares
     * @param sessionId Session identifier
     * @return ready True if reconstruction is possible
     */
    function isReconstructionReady(bytes32 sessionId) external view returns (bool ready) {
        SharingSession storage session = sessions[sessionId];
        ready = reconstructionShares[sessionId].length >= session.threshold;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Cancel a session (dealer or admin only)
     * @param sessionId Session to cancel
     */
    function cancelSession(bytes32 sessionId) external {
        SharingSession storage session = sessions[sessionId];
        
        if (session.dealer != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotDealer(msg.sender);
        }

        session.status = MPCLib.SessionStatus.Cancelled;
        emit SessionFailed(sessionId, "Cancelled by dealer");
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
