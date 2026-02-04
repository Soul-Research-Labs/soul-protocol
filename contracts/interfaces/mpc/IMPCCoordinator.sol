// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MPCLib} from "../../libraries/MPCLib.sol";

/**
 * @title IMPCCoordinator
 * @author Soul Protocol
 * @notice Interface for MPC session coordination
 */
interface IMPCCoordinator {
    // ============================================
    // STRUCTS
    // ============================================

    struct Session {
        bytes32 sessionId;
        MPCLib.ProtocolType protocol;
        uint8 threshold;
        uint8 totalParticipants;
        uint8 joinedCount;
        uint8 committedCount;
        uint8 resultsSubmitted;
        uint8 status;
        uint256 createdAt;
        uint256 deadline;
        uint256 phaseDeadline;
        bytes32 inputCommitment;
        bytes32 resultHash;
        address coordinator;
    }

    struct StakeInfo {
        uint256 amount;
        uint256 lockedUntil;
        uint256 slashedAmount;
        bool isLocked;
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

    event ParticipantJoined(
        bytes32 indexed sessionId,
        address indexed participant,
        uint8 participantIndex
    );

    event ParticipantLeft(
        bytes32 indexed sessionId,
        address indexed participant
    );

    event InputCommitted(
        bytes32 indexed sessionId,
        address indexed participant,
        bytes32 commitmentHash
    );

    event ResultSubmitted(
        bytes32 indexed sessionId,
        address indexed participant,
        bytes32 resultHash
    );

    event SessionCompleted(
        bytes32 indexed sessionId,
        bytes32 resultHash
    );

    event SessionFailed(bytes32 indexed sessionId, string reason);

    event PhaseAdvanced(
        bytes32 indexed sessionId,
        uint8 oldPhase,
        uint8 newPhase
    );

    event StakeDeposited(address indexed participant, uint256 amount);
    event StakeWithdrawn(address indexed participant, uint256 amount);
    event StakeSlashed(
        bytes32 indexed sessionId,
        address indexed participant,
        uint256 amount
    );

    // ============================================
    // FUNCTIONS
    // ============================================

    /**
     * @notice Deposit stake to participate in MPC
     */
    function depositStake() external payable;

    /**
     * @notice Withdraw stake
     * @param amount Amount to withdraw
     */
    function withdrawStake(uint256 amount) external;

    /**
     * @notice Create a new MPC session
     * @param protocol MPC protocol to use
     * @param threshold t in t-of-n
     * @param totalParticipants n
     * @param deadline Session deadline
     * @param inputCommitment Commitment to computation inputs
     * @return sessionId Unique session identifier
     */
    function createSession(
        MPCLib.ProtocolType protocol,
        uint8 threshold,
        uint8 totalParticipants,
        uint256 deadline,
        bytes32 inputCommitment
    ) external returns (bytes32 sessionId);

    /**
     * @notice Join an MPC session
     * @param sessionId Session to join
     * @return participantIndex Assigned index
     */
    function joinSession(bytes32 sessionId) external returns (uint8 participantIndex);

    /**
     * @notice Leave an MPC session
     * @param sessionId Session to leave
     */
    function leaveSession(bytes32 sessionId) external;

    /**
     * @notice Commit input for computation
     * @param sessionId Session ID
     * @param inputCommitment Commitment to private input
     */
    function commitInput(bytes32 sessionId, bytes32 inputCommitment) external;

    /**
     * @notice Submit computation result
     * @param sessionId Session ID
     * @param resultHash Hash of result
     * @param proof Proof of correct computation
     */
    function submitResult(
        bytes32 sessionId,
        bytes32 resultHash,
        bytes calldata proof
    ) external;

    /**
     * @notice Slash a misbehaving participant
     * @param sessionId Session ID
     * @param participant Participant to slash
     * @param proof Proof of misbehavior
     */
    function slashParticipant(
        bytes32 sessionId,
        address participant,
        bytes calldata proof
    ) external;

    /**
     * @notice Handle session timeout
     * @param sessionId Session that timed out
     */
    function handleTimeout(bytes32 sessionId) external;

    /**
     * @notice Get session details
     * @param sessionId Session identifier
     * @return session Session data
     */
    function getSession(bytes32 sessionId) external view returns (Session memory session);

    /**
     * @notice Get stake info for a participant
     * @param participant Participant address
     * @return info Stake information
     */
    function getStakeInfo(address participant) external view returns (StakeInfo memory info);

    /**
     * @notice Check if participant can join sessions
     * @param participant Participant address
     * @return canJoin True if participant has sufficient stake
     */
    function canParticipate(address participant) external view returns (bool canJoin);
}
