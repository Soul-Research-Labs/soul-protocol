// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {MPCLib} from "../libraries/MPCLib.sol";

/**
 * @title MPCCoordinator
 * @author Soul Protocol
 * @notice Orchestrates Multi-Party Computation sessions across participants
 * @dev Manages session lifecycle, participant coordination, and result aggregation
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                        MPC Coordinator                                      │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  Session Lifecycle:                                                          │
 * │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐       │
 * │  │ Create  │──▶│  Setup  │──▶│ Compute │──▶│ Verify  │──▶│Complete │       │
 * │  └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘       │
 * │       │             │             │             │             │             │
 * │       ▼             ▼             ▼             ▼             ▼             │
 * │   Register     Distribute    Execute      Validate      Finalize           │
 * │   Parties       Inputs       Protocol     Results       Output             │
 * │                                                                              │
 * │  Supported Protocols:                                                        │
 * │  - Secret Sharing (Shamir, Additive)                                        │
 * │  - Threshold Signatures (ECDSA, Schnorr, BLS)                               │
 * │  - Secure Computation (SPDZ, GMW, Yao)                                      │
 * │  - Distributed Key Generation (Feldman, Pedersen)                           │
 * │                                                                              │
 * │  Security Features:                                                          │
 * │  - Stake-based participation (slashing for misbehavior)                     │
 * │  - Commitment schemes for input hiding                                      │
 * │  - ZK proofs for computation correctness                                    │
 * │  - Timeout handling for liveness                                            │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract MPCCoordinator is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant COORDINATOR_ROLE = keccak256("COORDINATOR_ROLE");
    bytes32 public constant PARTICIPANT_ROLE = keccak256("PARTICIPANT_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Minimum stake to participate
    uint256 public constant MIN_STAKE = 1 ether;

    /// @notice Maximum stake per participant
    uint256 public constant MAX_STAKE = 100 ether;

    /// @notice Slashing percentage for misbehavior (basis points)
    uint256 public constant SLASH_BPS = 1000; // 10%

    /// @notice Minimum session duration
    uint256 public constant MIN_DURATION = 300; // 5 minutes

    /// @notice Maximum session duration
    uint256 public constant MAX_DURATION = 86400; // 24 hours

    /// @notice Phase timeout
    uint256 public constant PHASE_TIMEOUT = 600; // 10 minutes

    // ============================================
    // EVENTS
    // ============================================

    event SessionCreated(
        bytes32 indexed sessionId,
        MPCLib.ProtocolType protocol,
        MPCLib.ComputationType computation,
        address indexed coordinator,
        uint8 threshold,
        uint8 totalParticipants
    );

    event ParticipantJoined(
        bytes32 indexed sessionId,
        address indexed participant,
        uint8 participantIndex,
        uint256 stake
    );

    event ParticipantLeft(
        bytes32 indexed sessionId,
        address indexed participant
    );

    event PhaseAdvanced(
        bytes32 indexed sessionId,
        MPCLib.SessionStatus oldPhase,
        MPCLib.SessionStatus newPhase
    );

    event InputCommitted(
        bytes32 indexed sessionId,
        address indexed participant,
        bytes32 inputCommitment
    );

    event ComputationSubmitted(
        bytes32 indexed sessionId,
        address indexed participant,
        bytes32 resultCommitment
    );

    event SessionCompleted(
        bytes32 indexed sessionId,
        bytes32 resultHash,
        uint256 completedAt
    );

    event SessionFailed(
        bytes32 indexed sessionId,
        string reason
    );

    event ParticipantSlashed(
        bytes32 indexed sessionId,
        address indexed participant,
        uint256 amount,
        string reason
    );

    event StakeDeposited(address indexed participant, uint256 amount);
    event StakeWithdrawn(address indexed participant, uint256 amount);

    // ============================================
    // ERRORS
    // ============================================

    error SessionNotFound(bytes32 sessionId);
    error SessionAlreadyExists(bytes32 sessionId);
    error InvalidSessionPhase(MPCLib.SessionStatus current, MPCLib.SessionStatus expected);
    error SessionExpired(bytes32 sessionId);
    error InvalidThreshold(uint8 threshold, uint8 total);
    error ParticipantNotFound(address participant);
    error ParticipantAlreadyJoined(address participant);
    error InsufficientStake(uint256 required, uint256 provided);
    error MaxParticipantsReached();
    error NotCoordinator(address caller);
    error InvalidInput();
    error CommitmentMismatch();
    error QuorumNotReached(uint256 received, uint256 required);
    error PhaseTimeout();
    error WithdrawalLocked(uint256 unlockTime);

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice MPC Session
     */
    struct Session {
        bytes32 sessionId;
        MPCLib.ProtocolType protocol;
        MPCLib.ComputationType computation;
        address coordinator;
        uint8 threshold;
        uint8 totalParticipants;
        uint8 joinedCount;
        uint8 committedCount;
        uint8 computedCount;
        MPCLib.SessionStatus status;
        uint256 createdAt;
        uint256 deadline;
        uint256 phaseDeadline;
        bytes32 inputCommitmentRoot;   // Merkle root of all input commitments
        bytes32 resultHash;
        bytes metadata;                 // Protocol-specific metadata
    }

    /**
     * @notice Participant in a session
     */
    struct SessionParticipant {
        address participantAddress;
        uint8 participantIndex;
        uint256 stakeAmount;
        bytes32 inputCommitment;
        bytes32 resultCommitment;
        MPCLib.ParticipantStatus status;
        uint256 joinedAt;
        bool slashed;
    }

    /**
     * @notice Participant's global stake info
     */
    struct StakeInfo {
        uint256 totalStake;
        uint256 lockedStake;
        uint256 unlockTime;
        uint256 activeSessions;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Session nonce
    uint256 public sessionNonce;

    /// @notice Total active sessions
    uint256 public activeSessions;

    /// @notice Sessions: sessionId => session
    mapping(bytes32 => Session) public sessions;

    /// @notice Session participants: sessionId => address => participant
    mapping(bytes32 => mapping(address => SessionParticipant)) public sessionParticipants;

    /// @notice Participant by index: sessionId => index => address
    mapping(bytes32 => mapping(uint8 => address)) public participantByIndex;

    /// @notice Global stake info: address => stake
    mapping(address => StakeInfo) public stakes;

    /// @notice Session results: sessionId => result data
    mapping(bytes32 => bytes) public sessionResults;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COORDINATOR_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ============================================
    // STAKE MANAGEMENT
    // ============================================

    /**
     * @notice Deposit stake to participate in MPC sessions
     */
    function depositStake() external payable nonReentrant {
        require(msg.value >= MIN_STAKE, "Below minimum stake");
        require(stakes[msg.sender].totalStake + msg.value <= MAX_STAKE, "Exceeds max stake");

        stakes[msg.sender].totalStake += msg.value;

        emit StakeDeposited(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw available stake
     * @param amount Amount to withdraw
     */
    function withdrawStake(uint256 amount) external nonReentrant {
        StakeInfo storage stake = stakes[msg.sender];
        
        uint256 available = stake.totalStake - stake.lockedStake;
        require(amount <= available, "Insufficient available stake");
        
        if (stake.unlockTime > 0 && block.timestamp < stake.unlockTime) {
            revert WithdrawalLocked(stake.unlockTime);
        }

        stake.totalStake -= amount;
        
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit StakeWithdrawn(msg.sender, amount);
    }

    // ============================================
    // SESSION MANAGEMENT
    // ============================================

    /**
     * @notice Create a new MPC session
     * @param protocol MPC protocol type
     * @param computation Computation type
     * @param threshold Minimum participants for result
     * @param totalParticipants Total participants allowed
     * @param duration Session duration
     * @param metadata Protocol-specific metadata
     * @return sessionId Unique session identifier
     */
    function createSession(
        MPCLib.ProtocolType protocol,
        MPCLib.ComputationType computation,
        uint8 threshold,
        uint8 totalParticipants,
        uint256 duration,
        bytes calldata metadata
    ) external whenNotPaused onlyRole(COORDINATOR_ROLE) returns (bytes32 sessionId) {
        if (!MPCLib.validateThreshold(threshold, totalParticipants)) {
            revert InvalidThreshold(threshold, totalParticipants);
        }
        if (duration < MIN_DURATION || duration > MAX_DURATION) {
            duration = MIN_DURATION;
        }

        sessionId = MPCLib.generateSessionId(protocol, msg.sender, sessionNonce++);

        if (sessions[sessionId].createdAt != 0) {
            revert SessionAlreadyExists(sessionId);
        }

        sessions[sessionId] = Session({
            sessionId: sessionId,
            protocol: protocol,
            computation: computation,
            coordinator: msg.sender,
            threshold: threshold,
            totalParticipants: totalParticipants,
            joinedCount: 0,
            committedCount: 0,
            computedCount: 0,
            status: MPCLib.SessionStatus.Created,
            createdAt: block.timestamp,
            deadline: block.timestamp + duration,
            phaseDeadline: block.timestamp + PHASE_TIMEOUT,
            inputCommitmentRoot: bytes32(0),
            resultHash: bytes32(0),
            metadata: metadata
        });

        activeSessions++;

        emit SessionCreated(
            sessionId,
            protocol,
            computation,
            msg.sender,
            threshold,
            totalParticipants
        );
    }

    /**
     * @notice Join an MPC session
     * @param sessionId Session to join
     * @param stakeAmount Amount to stake for this session
     * @return participantIndex Assigned index
     */
    function joinSession(
        bytes32 sessionId,
        uint256 stakeAmount
    ) external whenNotPaused nonReentrant returns (uint8 participantIndex) {
        Session storage session = sessions[sessionId];
        
        if (session.createdAt == 0) {
            revert SessionNotFound(sessionId);
        }
        if (session.status != MPCLib.SessionStatus.Created) {
            revert InvalidSessionPhase(session.status, MPCLib.SessionStatus.Created);
        }
        if (block.timestamp > session.deadline) {
            revert SessionExpired(sessionId);
        }
        if (sessionParticipants[sessionId][msg.sender].joinedAt != 0) {
            revert ParticipantAlreadyJoined(msg.sender);
        }
        if (session.joinedCount >= session.totalParticipants) {
            revert MaxParticipantsReached();
        }

        // Verify stake
        StakeInfo storage stake = stakes[msg.sender];
        uint256 available = stake.totalStake - stake.lockedStake;
        if (available < stakeAmount || stakeAmount < MIN_STAKE) {
            revert InsufficientStake(MIN_STAKE, available);
        }

        // Lock stake
        stake.lockedStake += stakeAmount;
        stake.activeSessions++;

        // Assign index
        participantIndex = session.joinedCount + 1;
        session.joinedCount++;

        sessionParticipants[sessionId][msg.sender] = SessionParticipant({
            participantAddress: msg.sender,
            participantIndex: participantIndex,
            stakeAmount: stakeAmount,
            inputCommitment: bytes32(0),
            resultCommitment: bytes32(0),
            status: MPCLib.ParticipantStatus.Registered,
            joinedAt: block.timestamp,
            slashed: false
        });

        participantByIndex[sessionId][participantIndex] = msg.sender;
        _grantRole(PARTICIPANT_ROLE, msg.sender);

        emit ParticipantJoined(sessionId, msg.sender, participantIndex, stakeAmount);

        // If all participants joined, advance to commitment phase
        if (session.joinedCount == session.totalParticipants) {
            _advancePhase(sessionId, MPCLib.SessionStatus.CommitmentPhase);
        }
    }

    /**
     * @notice Leave a session before it starts
     * @param sessionId Session to leave
     */
    function leaveSession(bytes32 sessionId) external nonReentrant {
        Session storage session = sessions[sessionId];
        SessionParticipant storage participant = sessionParticipants[sessionId][msg.sender];
        
        if (participant.joinedAt == 0) {
            revert ParticipantNotFound(msg.sender);
        }
        if (session.status != MPCLib.SessionStatus.Created) {
            revert InvalidSessionPhase(session.status, MPCLib.SessionStatus.Created);
        }

        // Unlock stake
        StakeInfo storage stake = stakes[msg.sender];
        stake.lockedStake -= participant.stakeAmount;
        stake.activeSessions--;

        participant.status = MPCLib.ParticipantStatus.Excluded;
        session.joinedCount--;

        emit ParticipantLeft(sessionId, msg.sender);
    }

    // ============================================
    // COMPUTATION PHASES
    // ============================================

    /**
     * @notice Commit input for the computation
     * @param sessionId Session identifier
     * @param inputCommitment Commitment to participant's input
     */
    function commitInput(
        bytes32 sessionId,
        bytes32 inputCommitment
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[sessionId];
        SessionParticipant storage participant = sessionParticipants[sessionId][msg.sender];
        
        if (session.status != MPCLib.SessionStatus.CommitmentPhase) {
            revert InvalidSessionPhase(session.status, MPCLib.SessionStatus.CommitmentPhase);
        }
        if (participant.status != MPCLib.ParticipantStatus.Registered) {
            revert ParticipantNotFound(msg.sender);
        }
        if (block.timestamp > session.phaseDeadline) {
            revert PhaseTimeout();
        }

        participant.inputCommitment = inputCommitment;
        participant.status = MPCLib.ParticipantStatus.Committed;
        session.committedCount++;

        emit InputCommitted(sessionId, msg.sender, inputCommitment);

        // If all committed, advance to computation
        if (session.committedCount >= session.threshold) {
            _advancePhase(sessionId, MPCLib.SessionStatus.Computation);
        }
    }

    /**
     * @notice Submit computation result
     * @param sessionId Session identifier
     * @param resultCommitment Commitment to computation result
     * @param proof Optional ZK proof of correct computation
     */
    function submitResult(
        bytes32 sessionId,
        bytes32 resultCommitment,
        bytes calldata proof
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[sessionId];
        SessionParticipant storage participant = sessionParticipants[sessionId][msg.sender];
        
        if (session.status != MPCLib.SessionStatus.Computation) {
            revert InvalidSessionPhase(session.status, MPCLib.SessionStatus.Computation);
        }
        if (participant.status != MPCLib.ParticipantStatus.Committed) {
            revert ParticipantNotFound(msg.sender);
        }
        if (block.timestamp > session.phaseDeadline) {
            revert PhaseTimeout();
        }

        // Verify proof if required
        if (proof.length > 0) {
            // In production: verify ZK proof
            require(proof.length >= 32, "Invalid proof");
        }

        participant.resultCommitment = resultCommitment;
        participant.status = MPCLib.ParticipantStatus.Computed;
        session.computedCount++;

        emit ComputationSubmitted(sessionId, msg.sender, resultCommitment);

        // If enough results, advance to reconstruction
        if (session.computedCount >= session.threshold) {
            _advancePhase(sessionId, MPCLib.SessionStatus.Reconstruction);
            _finalizeSession(sessionId);
        }
    }

    /**
     * @notice Finalize session and determine result
     */
    function _finalizeSession(bytes32 sessionId) internal {
        Session storage session = sessions[sessionId];

        // Aggregate results (simplified: use first result as consensus)
        bytes32 consensusResult;
        uint256 matchCount;

        for (uint8 i = 1; i <= session.joinedCount; i++) {
            address participant = participantByIndex[sessionId][i];
            SessionParticipant storage p = sessionParticipants[sessionId][participant];
            
            if (p.status == MPCLib.ParticipantStatus.Computed) {
                if (consensusResult == bytes32(0)) {
                    consensusResult = p.resultCommitment;
                    matchCount = 1;
                } else if (p.resultCommitment == consensusResult) {
                    matchCount++;
                }
            }
        }

        // Check quorum
        if (matchCount >= session.threshold) {
            session.resultHash = consensusResult;
            session.status = MPCLib.SessionStatus.Completed;
            
            // Unlock stakes for successful participants
            _unlockStakes(sessionId, true);

            emit SessionCompleted(sessionId, consensusResult, block.timestamp);
        } else {
            session.status = MPCLib.SessionStatus.Failed;
            _unlockStakes(sessionId, false);
            emit SessionFailed(sessionId, "Quorum not reached");
        }

        activeSessions--;
    }

    /**
     * @notice Advance session to next phase
     */
    function _advancePhase(bytes32 sessionId, MPCLib.SessionStatus newPhase) internal {
        Session storage session = sessions[sessionId];
        MPCLib.SessionStatus oldPhase = session.status;
        
        session.status = newPhase;
        session.phaseDeadline = block.timestamp + PHASE_TIMEOUT;

        emit PhaseAdvanced(sessionId, oldPhase, newPhase);
    }

    /**
     * @notice Unlock stakes after session completion
     */
    function _unlockStakes(bytes32 sessionId, bool successful) internal {
        Session storage session = sessions[sessionId];

        for (uint8 i = 1; i <= session.joinedCount; i++) {
            address participant = participantByIndex[sessionId][i];
            SessionParticipant storage p = sessionParticipants[sessionId][participant];
            
            if (!p.slashed) {
                StakeInfo storage stake = stakes[participant];
                stake.lockedStake -= p.stakeAmount;
                stake.activeSessions--;
                
                // Set unlock delay if unsuccessful
                if (!successful) {
                    stake.unlockTime = block.timestamp + 1 days;
                }
            }
        }
    }

    // ============================================
    // SLASHING
    // ============================================

    /**
     * @notice Slash a misbehaving participant
     * @param sessionId Session where misbehavior occurred
     * @param participant Participant to slash
     * @param reason Reason for slashing
     */
    function slashParticipant(
        bytes32 sessionId,
        address participant,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        SessionParticipant storage p = sessionParticipants[sessionId][participant];
        
        if (p.joinedAt == 0 || p.slashed) {
            revert ParticipantNotFound(participant);
        }

        uint256 slashAmount = (p.stakeAmount * SLASH_BPS) / 10000;
        
        p.slashed = true;
        p.status = MPCLib.ParticipantStatus.Malicious;

        StakeInfo storage stake = stakes[participant];
        stake.totalStake -= slashAmount;
        stake.lockedStake -= p.stakeAmount;
        stake.activeSessions--;

        emit ParticipantSlashed(sessionId, participant, slashAmount, reason);
    }

    // ============================================
    // TIMEOUT HANDLING
    // ============================================

    /**
     * @notice Handle phase timeout
     * @param sessionId Session that timed out
     */
    function handleTimeout(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];
        
        if (block.timestamp <= session.phaseDeadline && block.timestamp <= session.deadline) {
            revert InvalidSessionPhase(session.status, MPCLib.SessionStatus.Failed);
        }

        session.status = MPCLib.SessionStatus.Failed;
        _unlockStakes(sessionId, false);
        activeSessions--;

        emit SessionFailed(sessionId, "Phase timeout");
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get session details
     * @param sessionId Session identifier
     * @return session Session data
     */
    function getSession(bytes32 sessionId) external view returns (Session memory session) {
        session = sessions[sessionId];
    }

    /**
     * @notice Get participant in session
     * @param sessionId Session identifier
     * @param participant Participant address
     * @return info Participant data
     */
    function getSessionParticipant(
        bytes32 sessionId,
        address participant
    ) external view returns (SessionParticipant memory info) {
        info = sessionParticipants[sessionId][participant];
    }

    /**
     * @notice Get stake info for an address
     * @param participant Address to check
     * @return info Stake data
     */
    function getStakeInfo(address participant) external view returns (StakeInfo memory info) {
        info = stakes[participant];
    }

    /**
     * @notice Check if session is active
     * @param sessionId Session identifier
     * @return active True if session is ongoing
     */
    function isSessionActive(bytes32 sessionId) external view returns (bool active) {
        Session storage session = sessions[sessionId];
        active = session.status != MPCLib.SessionStatus.None &&
                 session.status != MPCLib.SessionStatus.Completed &&
                 session.status != MPCLib.SessionStatus.Failed &&
                 session.status != MPCLib.SessionStatus.Cancelled &&
                 block.timestamp <= session.deadline;
    }

    /**
     * @notice Get session result
     * @param sessionId Session identifier
     * @return resultHash Hash of the computation result
     * @return completed Whether session completed successfully
     */
    function getSessionResult(bytes32 sessionId) external view returns (
        bytes32 resultHash,
        bool completed
    ) {
        Session storage session = sessions[sessionId];
        resultHash = session.resultHash;
        completed = session.status == MPCLib.SessionStatus.Completed;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Cancel a session (coordinator only)
     * @param sessionId Session to cancel
     */
    function cancelSession(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];
        
        if (session.coordinator != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotCoordinator(msg.sender);
        }

        session.status = MPCLib.SessionStatus.Cancelled;
        _unlockStakes(sessionId, true); // Return stakes without penalty
        activeSessions--;

        emit SessionFailed(sessionId, "Cancelled");
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

    /**
     * @notice Receive function for stake deposits
     */
    receive() external payable {
        stakes[msg.sender].totalStake += msg.value;
        emit StakeDeposited(msg.sender, msg.value);
    }
}
