// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MPCLib} from "../../libraries/MPCLib.sol";

/**
 * @title IShamirSecretSharing
 * @author Soul Protocol
 * @notice Interface for Shamir Secret Sharing with VSS
 */
interface IShamirSecretSharing {
    // ============================================
    // STRUCTS
    // ============================================

    struct SharingSession {
        bytes32 sessionId;
        MPCLib.ProtocolType protocol;
        uint8 threshold;
        uint8 totalParticipants;
        uint8 registeredCount;
        uint8 sharesDistributed;
        uint8 sharesSubmitted;
        uint8 status;
        uint256 createdAt;
        uint256 deadline;
        bytes32 secretCommitment;
        address dealer;
        bool vssVerified;
        bool reconstructed;
        bytes32 reconstructedSecret;
    }

    // ============================================
    // EVENTS
    // ============================================

    event SessionCreated(
        bytes32 indexed sessionId,
        MPCLib.ProtocolType protocol,
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
        bytes32 commitmentRoot
    );

    event ShareDistributed(
        bytes32 indexed sessionId,
        address indexed recipient,
        uint8 shareIndex
    );

    event ShareVerified(
        bytes32 indexed sessionId,
        address indexed verifier,
        bool valid
    );

    event ShareSubmitted(
        bytes32 indexed sessionId,
        address indexed participant,
        uint8 shareIndex
    );

    event SecretReconstructed(
        bytes32 indexed sessionId,
        bytes32 secretHash
    );

    event ShareRefreshInitiated(bytes32 indexed sessionId, bytes32 indexed newSessionId);

    // ============================================
    // FUNCTIONS
    // ============================================

    /**
     * @notice Create a new secret sharing session
     * @param protocol Secret sharing protocol
     * @param threshold t in t-of-n
     * @param totalParticipants n
     * @param deadline Session deadline
     * @param secretCommitment Commitment to the secret
     * @return sessionId Unique session identifier
     */
    function createSession(
        MPCLib.ProtocolType protocol,
        uint8 threshold,
        uint8 totalParticipants,
        uint256 deadline,
        bytes32 secretCommitment
    ) external returns (bytes32 sessionId);

    /**
     * @notice Register as a participant in a session
     * @param sessionId Session to join
     * @return participantIndex Assigned index
     */
    function registerParticipant(bytes32 sessionId) external returns (uint8 participantIndex);

    /**
     * @notice Publish VSS commitments
     * @param sessionId Session ID
     * @param commitments Array of coefficient commitments
     */
    function publishCommitments(
        bytes32 sessionId,
        bytes32[] calldata commitments
    ) external;

    /**
     * @notice Distribute a share to a participant
     * @param sessionId Session ID
     * @param recipient Recipient address
     * @param encryptedShare Encrypted share value
     * @param shareCommitment Commitment for verification
     */
    function distributeShare(
        bytes32 sessionId,
        address recipient,
        bytes32 encryptedShare,
        bytes32 shareCommitment
    ) external;

    /**
     * @notice Verify received share using VSS
     * @param sessionId Session ID
     * @param share Decrypted share value
     * @return valid True if share is valid
     */
    function verifyShare(
        bytes32 sessionId,
        bytes32 share
    ) external returns (bool valid);

    /**
     * @notice Submit share for secret reconstruction
     * @param sessionId Session ID
     * @param share Share value
     */
    function submitShareForReconstruction(
        bytes32 sessionId,
        bytes32 share
    ) external;

    /**
     * @notice Initiate share refresh
     * @param sessionId Original session ID
     * @return newSessionId New session for refreshed shares
     */
    function initiateShareRefresh(bytes32 sessionId) external returns (bytes32 newSessionId);

    /**
     * @notice Get session details
     * @param sessionId Session identifier
     * @return session Session data
     */
    function getSession(bytes32 sessionId) external view returns (SharingSession memory session);

    /**
     * @notice Check if session is complete
     * @param sessionId Session identifier
     * @return complete True if reconstruction is complete
     */
    function isComplete(bytes32 sessionId) external view returns (bool complete);
}
