// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {HybridPQCVerifier} from "./HybridPQCVerifier.sol";

/**
 * @title PQCModeController
 * @author Soul Protocol
 * @notice Safe mode transition controller for PQC verification
 * @dev Implements timelock and multi-sig requirements for mode changes.
 *      Prevents accidental or malicious downgrades to insecure modes.
 *
 * SAFETY GUARANTEES:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Mode Transition Safety                                │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  1. TIMELOCK: All mode changes require 72-hour delay                   │
 * │  2. MULTI-SIG: Critical changes require 2-of-3 approval               │
 * │  3. NO DOWNGRADE: Cannot return to MOCK after leaving                  │
 * │  4. EMERGENCY: Guardian can pause but not change modes                 │
 * │  5. AUDIT LOG: All changes logged with justification                   │
 * │                                                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@soul.network
 */
contract PQCModeController is AccessControl {
    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mode change proposal
    struct ModeChangeProposal {
        HybridPQCVerifier.VerificationMode newMode;
        address proposer;
        uint256 proposedAt;
        uint256 executeAfter;
        uint256 approvalCount;
        string justification;
        bool executed;
        bool cancelled;
    }

    /// @notice Approval record
    struct Approval {
        address approver;
        uint256 approvedAt;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The PQC verifier being controlled
    HybridPQCVerifier public immutable verifier;

    /// @notice Current delay for mode changes
    uint256 public modeChangeDelay = 72 hours;

    /// @notice Proposal counter
    uint256 public proposalCount;

    /// @notice Proposals by ID
    mapping(uint256 => ModeChangeProposal) public proposals;

    /// @notice Approvals for proposals
    mapping(uint256 => mapping(address => bool)) public hasApproved;

    /// @notice Approval list for proposals
    mapping(uint256 => Approval[]) public approvalList;

    /// @notice Mode change history
    HybridPQCVerifier.VerificationMode[] public modeHistory;

    /// @notice Timestamp of each mode change
    uint256[] public modeChangeTimestamps;

    /// @notice Emergency pause active
    bool public emergencyPaused;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProposalCreated(
        uint256 indexed proposalId,
        HybridPQCVerifier.VerificationMode newMode,
        address indexed proposer,
        uint256 executeAfter,
        string justification
    );

    event ProposalApproved(
        uint256 indexed proposalId,
        address indexed approver,
        uint256 approvalCount
    );

    event ProposalExecuted(
        uint256 indexed proposalId,
        HybridPQCVerifier.VerificationMode oldMode,
        HybridPQCVerifier.VerificationMode newMode
    );

    event ProposalCancelled(uint256 indexed proposalId, address cancelledBy);

    event DelayUpdated(uint256 oldDelay, uint256 newDelay);

    event EmergencyPauseActivated(address activatedBy);
    event EmergencyPauseDeactivated(address deactivatedBy);

    /*//////////////////////////////////////////////////////////////
                             CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes the mode controller
     * @param _verifier The HybridPQCVerifier to control
     * @param admin Admin address
     * @param proposers Initial proposer addresses
     * @param approvers Initial approver addresses
     */
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

    /*//////////////////////////////////////////////////////////////
                          PROPOSAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a mode change proposal
     * @param newMode The proposed new verification mode
     * @param justification Reason for the change
     * @return proposalId The created proposal ID
     */
    function proposeMode(
        HybridPQCVerifier.VerificationMode newMode,
        string calldata justification
    ) external onlyRole(PROPOSER_ROLE) returns (uint256 proposalId) {
        if (emergencyPaused) revert EmergencyPauseActive();

        // Cannot propose mock mode (security critical)
        if (newMode == HybridPQCVerifier.VerificationMode.MOCK) {
            revert CannotProposeMockMode();
        }

        proposalId = ++proposalCount;

        proposals[proposalId] = ModeChangeProposal({
            newMode: newMode,
            proposer: msg.sender,
            proposedAt: block.timestamp,
            executeAfter: block.timestamp + modeChangeDelay,
            approvalCount: 0,
            justification: justification,
            executed: false,
            cancelled: false
        });

        emit ProposalCreated(
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
    function approveProposal(
        uint256 proposalId
    ) external onlyRole(APPROVER_ROLE) {
        ModeChangeProposal storage proposal = proposals[proposalId];

        if (proposal.proposer == address(0))
            revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (proposal.cancelled) revert ProposalIsCancelled(proposalId);
        if (block.timestamp > proposal.proposedAt + PROPOSAL_VALIDITY) {
            revert ProposalExpired(proposalId);
        }
        if (hasApproved[proposalId][msg.sender]) {
            revert AlreadyApproved(proposalId, msg.sender);
        }
        if (msg.sender == proposal.proposer) {
            revert SelfApprovalNotAllowed();
        }

        hasApproved[proposalId][msg.sender] = true;
        proposal.approvalCount++;

        approvalList[proposalId].push(
            Approval({approver: msg.sender, approvedAt: block.timestamp})
        );

        emit ProposalApproved(proposalId, msg.sender, proposal.approvalCount);
    }

    /**
     * @notice Executes an approved proposal
     * @param proposalId The proposal to execute
     */
    function executeProposal(
        uint256 proposalId
    ) external onlyRole(EXECUTOR_ROLE) {
        if (emergencyPaused) revert EmergencyPauseActive();

        ModeChangeProposal storage proposal = proposals[proposalId];

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

        HybridPQCVerifier.VerificationMode oldMode = verifier.currentMode();

        // Execute mode change on verifier
        verifier.setMode(proposal.newMode);

        proposal.executed = true;

        // Record in history
        modeHistory.push(proposal.newMode);
        modeChangeTimestamps.push(block.timestamp);

        emit ProposalExecuted(proposalId, oldMode, proposal.newMode);
    }

    /**
     * @notice Cancels a proposal
     * @param proposalId The proposal to cancel
     */
    function cancelProposal(uint256 proposalId) external {
        ModeChangeProposal storage proposal = proposals[proposalId];

        if (proposal.proposer == address(0))
            revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);

        // Proposer can cancel their own, or guardian can cancel any
        require(
            msg.sender == proposal.proposer ||
                hasRole(GUARDIAN_ROLE, msg.sender),
            "Not authorized to cancel"
        );

        proposal.cancelled = true;

        emit ProposalCancelled(proposalId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Activates emergency pause
     * @dev Prevents proposal execution but not creation
     */
    function activateEmergencyPause() external onlyRole(GUARDIAN_ROLE) {
        require(!emergencyPaused, "Already paused");
        emergencyPaused = true;
        emit EmergencyPauseActivated(msg.sender);
    }

    /**
     * @notice Deactivates emergency pause
     */
    function deactivateEmergencyPause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!emergencyPaused) revert NotEmergencyPaused();
        emergencyPaused = false;
        emit EmergencyPauseDeactivated(msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Updates the mode change delay
     * @param newDelay New delay in seconds
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

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gets proposal details
     * @param proposalId Proposal ID
     * @return proposal The proposal struct
     */
    function getProposal(
        uint256 proposalId
    ) external view returns (ModeChangeProposal memory) {
        return proposals[proposalId];
    }

    /**
     * @notice Gets approval list for a proposal
     * @param proposalId Proposal ID
     * @return approvals Array of approvals
     */
    function getApprovals(
        uint256 proposalId
    ) external view returns (Approval[] memory) {
        return approvalList[proposalId];
    }

    /**
     * @notice Gets mode change history
     * @return modes Array of historical modes
     * @return timestamps Array of change timestamps
     */
    function getModeHistory()
        external
        view
        returns (
            HybridPQCVerifier.VerificationMode[] memory modes,
            uint256[] memory timestamps
        )
    {
        return (modeHistory, modeChangeTimestamps);
    }

    /**
     * @notice Checks if a proposal can be executed
     * @param proposalId Proposal ID
     * @return isExecutable True if executable
     * @return reason Reason if not executable
     */
    function canExecute(
        uint256 proposalId
    ) external view returns (bool isExecutable, string memory reason) {
        ModeChangeProposal storage proposal = proposals[proposalId];

        if (proposal.proposer == address(0)) {
            return (false, "Proposal not found");
        }
        if (proposal.executed) {
            return (false, "Already executed");
        }
        if (proposal.cancelled) {
            return (false, "Cancelled");
        }
        if (emergencyPaused) {
            return (false, "Emergency pause active");
        }
        if (block.timestamp < proposal.executeAfter) {
            return (false, "Timelock not expired");
        }
        if (proposal.approvalCount < REQUIRED_APPROVALS) {
            return (false, "Insufficient approvals");
        }
        if (block.timestamp > proposal.proposedAt + PROPOSAL_VALIDITY) {
            return (false, "Proposal expired");
        }

        return (true, "");
    }

    /**
     * @notice Gets the current verification mode from the verifier
     * @return mode Current mode
     */
    function currentMode()
        external
        view
        returns (HybridPQCVerifier.VerificationMode)
    {
        return verifier.currentMode();
    }
}
