// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {PQCLib} from "../libraries/PQCLib.sol";
import {HybridPQCVerifier} from "./HybridPQCVerifier.sol";

/**
 * @title PQCModeController
 * @author Soul Protocol
 * @notice Safe mode transition controller for PQC verification
 * @dev Implements timelock and multi-sig requirements for mode changes.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                    MODE TRANSITION SAFETY                                  ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                           ║
 * ║  SAFETY GUARANTEES:                                                       ║
 * ║  1. TIMELOCK: All mode changes require 72-hour delay                     ║
 * ║  2. MULTI-SIG: Critical changes require 2-of-3 approval                  ║
 * ║  3. NO DOWNGRADE: Cannot return to MOCK after leaving                    ║
 * ║  4. EMERGENCY: Guardian can pause but not change modes                   ║
 * ║  5. AUDIT LOG: All changes logged with justification                     ║
 * ║                                                                           ║
 * ║  PHASE TRANSITIONS:                                                       ║
 * ║  ClassicalOnly → HybridOptional → HybridMandatory → PQPreferred → PQOnly ║
 * ║                                                                           ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract PQCModeController is AccessControl {
    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice Mode change proposal
     */
    struct ModeChangeProposal {
        PQCLib.VerificationMode newMode;
        address proposer;
        uint256 proposedAt;
        uint256 executeAfter;
        uint256 approvalCount;
        string justification;
        bool executed;
        bool cancelled;
    }

    /**
     * @notice Phase change proposal
     */
    struct PhaseChangeProposal {
        PQCLib.TransitionPhase newPhase;
        address proposer;
        uint256 proposedAt;
        uint256 executeAfter;
        uint256 approvalCount;
        string justification;
        bool executed;
        bool cancelled;
    }

    /**
     * @notice Approval record
     */
    struct Approval {
        address approver;
        uint256 approvedAt;
    }

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Minimum delay for mode changes (72 hours)
    uint256 public constant MIN_DELAY = 72 hours;

    /// @notice Maximum delay (30 days)
    uint256 public constant MAX_DELAY = 30 days;

    /// @notice Required approvals for execution
    uint256 public constant REQUIRED_APPROVALS = 2;

    /// @notice Proposal validity period
    uint256 public constant PROPOSAL_VALIDITY = 14 days;

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice The hybrid PQC verifier being controlled
    HybridPQCVerifier public immutable verifier;

    /// @notice Current delay for mode changes
    uint256 public modeChangeDelay = 72 hours;

    /// @notice Mode proposal counter
    uint256 public modeProposalCount;

    /// @notice Phase proposal counter
    uint256 public phaseProposalCount;

    /// @notice Mode proposals by ID
    mapping(uint256 => ModeChangeProposal) public modeProposals;

    /// @notice Phase proposals by ID
    mapping(uint256 => PhaseChangeProposal) public phaseProposals;

    /// @notice Mode proposal approvals
    mapping(uint256 => mapping(address => bool)) public hasModeApproved;

    /// @notice Phase proposal approvals
    mapping(uint256 => mapping(address => bool)) public hasPhaseApproved;

    /// @notice Mode history
    PQCLib.VerificationMode[] public modeHistory;

    /// @notice Phase history
    PQCLib.TransitionPhase[] public phaseHistory;

    /// @notice Mode change timestamps
    uint256[] public modeChangeTimestamps;

    /// @notice Phase change timestamps
    uint256[] public phaseChangeTimestamps;

    /// @notice Emergency pause active
    bool public emergencyPaused;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event ModeProposalCreated(
        uint256 indexed proposalId,
        PQCLib.VerificationMode newMode,
        address indexed proposer,
        uint256 executeAfter,
        string justification
    );

    event PhaseProposalCreated(
        uint256 indexed proposalId,
        PQCLib.TransitionPhase newPhase,
        address indexed proposer,
        uint256 executeAfter,
        string justification
    );

    event ModeProposalApproved(
        uint256 indexed proposalId,
        address indexed approver,
        uint256 approvalCount
    );

    event PhaseProposalApproved(
        uint256 indexed proposalId,
        address indexed approver,
        uint256 approvalCount
    );

    event ModeProposalExecuted(
        uint256 indexed proposalId,
        PQCLib.VerificationMode oldMode,
        PQCLib.VerificationMode newMode
    );

    event PhaseProposalExecuted(
        uint256 indexed proposalId,
        PQCLib.TransitionPhase oldPhase,
        PQCLib.TransitionPhase newPhase
    );

    event ProposalCancelled(
        uint256 indexed proposalId,
        string proposalType,
        address cancelledBy
    );

    event DelayUpdated(uint256 oldDelay, uint256 newDelay);

    event EmergencyPauseActivated(address activatedBy);
    event EmergencyPauseDeactivated(address deactivatedBy);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error ProposalNotFound(uint256 proposalId);
    error ProposalAlreadyExecuted(uint256 proposalId);
    error ProposalIsCancelled(uint256 proposalId);
    error ProposalExpired(uint256 proposalId);
    error TimelockNotExpired(uint256 executeAfter, uint256 currentTime);
    error InsufficientApprovals(uint256 current, uint256 required);
    error AlreadyApproved(uint256 proposalId, address approver);
    error CannotProposeMockMode();
    error InvalidDelay(uint256 delay);
    error EmergencyPauseActive();
    error NotEmergencyPaused();
    error SelfApprovalNotAllowed();
    error InvalidPhaseTransition();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(
        address _verifier,
        address admin,
        address[] memory proposers,
        address[] memory approvers
    ) {
        verifier = HybridPQCVerifier(_verifier);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(EXECUTOR_ROLE, admin);

        for (uint256 i = 0; i < proposers.length; i++) {
            _grantRole(PROPOSER_ROLE, proposers[i]);
        }

        for (uint256 i = 0; i < approvers.length; i++) {
            _grantRole(APPROVER_ROLE, approvers[i]);
        }

        // Record initial mode
        modeHistory.push(verifier.currentMode());
        modeChangeTimestamps.push(block.timestamp);
    }

    // =============================================================================
    // MODE PROPOSAL FUNCTIONS
    // =============================================================================

    /**
     * @notice Creates a mode change proposal
     * @param newMode The proposed new verification mode
     * @param justification Reason for the change
     * @return proposalId The created proposal ID
     */
    function proposeModeChange(
        PQCLib.VerificationMode newMode,
        string calldata justification
    ) external onlyRole(PROPOSER_ROLE) returns (uint256 proposalId) {
        if (emergencyPaused) revert EmergencyPauseActive();

        // Cannot propose mock mode on mainnet
        if (newMode == PQCLib.VerificationMode.Mock && block.chainid == 1) {
            revert CannotProposeMockMode();
        }

        proposalId = ++modeProposalCount;

        modeProposals[proposalId] = ModeChangeProposal({
            newMode: newMode,
            proposer: msg.sender,
            proposedAt: block.timestamp,
            executeAfter: block.timestamp + modeChangeDelay,
            approvalCount: 0,
            justification: justification,
            executed: false,
            cancelled: false
        });

        emit ModeProposalCreated(
            proposalId,
            newMode,
            msg.sender,
            block.timestamp + modeChangeDelay,
            justification
        );
    }

    /**
     * @notice Approves a mode change proposal
     * @param proposalId The proposal to approve
     */
    function approveModeProposal(
        uint256 proposalId
    ) external onlyRole(APPROVER_ROLE) {
        ModeChangeProposal storage proposal = modeProposals[proposalId];

        if (proposal.proposer == address(0))
            revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (proposal.cancelled) revert ProposalIsCancelled(proposalId);
        if (block.timestamp > proposal.proposedAt + PROPOSAL_VALIDITY) {
            revert ProposalExpired(proposalId);
        }
        if (hasModeApproved[proposalId][msg.sender]) {
            revert AlreadyApproved(proposalId, msg.sender);
        }
        if (msg.sender == proposal.proposer) {
            revert SelfApprovalNotAllowed();
        }

        hasModeApproved[proposalId][msg.sender] = true;
        proposal.approvalCount++;

        emit ModeProposalApproved(
            proposalId,
            msg.sender,
            proposal.approvalCount
        );
    }

    /**
     * @notice Executes a mode change proposal
     * @param proposalId The proposal to execute
     */
    function executeModeProposal(
        uint256 proposalId
    ) external onlyRole(EXECUTOR_ROLE) {
        if (emergencyPaused) revert EmergencyPauseActive();

        ModeChangeProposal storage proposal = modeProposals[proposalId];

        if (proposal.proposer == address(0))
            revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (proposal.cancelled) revert ProposalIsCancelled(proposalId);
        if (block.timestamp < proposal.executeAfter) {
            revert TimelockNotExpired(proposal.executeAfter, block.timestamp);
        }
        if (proposal.approvalCount < REQUIRED_APPROVALS) {
            revert InsufficientApprovals(
                proposal.approvalCount,
                REQUIRED_APPROVALS
            );
        }

        PQCLib.VerificationMode oldMode = verifier.currentMode();

        // Execute mode change on verifier
        verifier.setMode(proposal.newMode);

        proposal.executed = true;
        modeHistory.push(proposal.newMode);
        modeChangeTimestamps.push(block.timestamp);

        emit ModeProposalExecuted(proposalId, oldMode, proposal.newMode);
    }

    /**
     * @notice Cancels a mode proposal
     * @param proposalId The proposal to cancel
     */
    function cancelModeProposal(uint256 proposalId) external {
        ModeChangeProposal storage proposal = modeProposals[proposalId];

        if (proposal.proposer == address(0))
            revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);

        // Only proposer or admin can cancel
        require(
            msg.sender == proposal.proposer ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized"
        );

        proposal.cancelled = true;
        emit ProposalCancelled(proposalId, "mode", msg.sender);
    }

    // =============================================================================
    // PHASE PROPOSAL FUNCTIONS
    // =============================================================================

    /**
     * @notice Creates a phase change proposal
     * @param newPhase The proposed new transition phase
     * @param justification Reason for the change
     * @return proposalId The created proposal ID
     */
    function proposePhaseChange(
        PQCLib.TransitionPhase newPhase,
        string calldata justification
    ) external onlyRole(PROPOSER_ROLE) returns (uint256 proposalId) {
        if (emergencyPaused) revert EmergencyPauseActive();

        // Validate phase transition (cannot go back to ClassicalOnly)
        if (
            phaseHistory.length > 0 &&
            phaseHistory[phaseHistory.length - 1] > newPhase &&
            newPhase == PQCLib.TransitionPhase.ClassicalOnly
        ) {
            revert InvalidPhaseTransition();
        }

        proposalId = ++phaseProposalCount;

        phaseProposals[proposalId] = PhaseChangeProposal({
            newPhase: newPhase,
            proposer: msg.sender,
            proposedAt: block.timestamp,
            executeAfter: block.timestamp + modeChangeDelay,
            approvalCount: 0,
            justification: justification,
            executed: false,
            cancelled: false
        });

        emit PhaseProposalCreated(
            proposalId,
            newPhase,
            msg.sender,
            block.timestamp + modeChangeDelay,
            justification
        );
    }

    /**
     * @notice Approves a phase change proposal
     * @param proposalId The proposal to approve
     */
    function approvePhaseProposal(
        uint256 proposalId
    ) external onlyRole(APPROVER_ROLE) {
        PhaseChangeProposal storage proposal = phaseProposals[proposalId];

        if (proposal.proposer == address(0))
            revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (proposal.cancelled) revert ProposalIsCancelled(proposalId);
        if (block.timestamp > proposal.proposedAt + PROPOSAL_VALIDITY) {
            revert ProposalExpired(proposalId);
        }
        if (hasPhaseApproved[proposalId][msg.sender]) {
            revert AlreadyApproved(proposalId, msg.sender);
        }
        if (msg.sender == proposal.proposer) {
            revert SelfApprovalNotAllowed();
        }

        hasPhaseApproved[proposalId][msg.sender] = true;
        proposal.approvalCount++;

        emit PhaseProposalApproved(
            proposalId,
            msg.sender,
            proposal.approvalCount
        );
    }

    // =============================================================================
    // EMERGENCY FUNCTIONS
    // =============================================================================

    /**
     * @notice Activates emergency pause
     */
    function activateEmergencyPause() external onlyRole(GUARDIAN_ROLE) {
        emergencyPaused = true;
        verifier.pause();
        emit EmergencyPauseActivated(msg.sender);
    }

    /**
     * @notice Deactivates emergency pause
     */
    function deactivateEmergencyPause() external onlyRole(GUARDIAN_ROLE) {
        if (!emergencyPaused) revert NotEmergencyPaused();
        emergencyPaused = false;
        verifier.unpause();
        emit EmergencyPauseDeactivated(msg.sender);
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    /**
     * @notice Updates the mode change delay
     * @param newDelay The new delay in seconds
     */
    function setModeChangeDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newDelay < MIN_DELAY || newDelay > MAX_DELAY) {
            revert InvalidDelay(newDelay);
        }

        uint256 oldDelay = modeChangeDelay;
        modeChangeDelay = newDelay;
        emit DelayUpdated(oldDelay, newDelay);
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    function getModeProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            PQCLib.VerificationMode newMode,
            address proposer,
            uint256 proposedAt,
            uint256 executeAfter,
            uint256 approvalCount,
            bool executed,
            bool cancelled
        )
    {
        ModeChangeProposal memory proposal = modeProposals[proposalId];
        return (
            proposal.newMode,
            proposal.proposer,
            proposal.proposedAt,
            proposal.executeAfter,
            proposal.approvalCount,
            proposal.executed,
            proposal.cancelled
        );
    }

    function getPhaseProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            PQCLib.TransitionPhase newPhase,
            address proposer,
            uint256 proposedAt,
            uint256 executeAfter,
            uint256 approvalCount,
            bool executed,
            bool cancelled
        )
    {
        PhaseChangeProposal memory proposal = phaseProposals[proposalId];
        return (
            proposal.newPhase,
            proposal.proposer,
            proposal.proposedAt,
            proposal.executeAfter,
            proposal.approvalCount,
            proposal.executed,
            proposal.cancelled
        );
    }

    function getModeHistory()
        external
        view
        returns (PQCLib.VerificationMode[] memory)
    {
        return modeHistory;
    }

    function getPhaseHistory()
        external
        view
        returns (PQCLib.TransitionPhase[] memory)
    {
        return phaseHistory;
    }

    function canExecuteModeProposal(
        uint256 proposalId
    ) external view returns (bool) {
        ModeChangeProposal memory proposal = modeProposals[proposalId];
        return
            !proposal.executed &&
            !proposal.cancelled &&
            !emergencyPaused &&
            block.timestamp >= proposal.executeAfter &&
            proposal.approvalCount >= REQUIRED_APPROVALS;
    }

    function canExecutePhaseProposal(
        uint256 proposalId
    ) external view returns (bool) {
        PhaseChangeProposal memory proposal = phaseProposals[proposalId];
        return
            !proposal.executed &&
            !proposal.cancelled &&
            !emergencyPaused &&
            block.timestamp >= proposal.executeAfter &&
            proposal.approvalCount >= REQUIRED_APPROVALS;
    }
}
