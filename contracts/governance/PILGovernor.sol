// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";

/**
 * @title PILGovernor
 * @notice Governance contract for the Privacy Interoperability Layer
 * @dev OpenZeppelin Governor 5.x with timelock, quorum, and voting extensions
 *
 * Governance Parameters:
 * - Voting delay: 1 day (after proposal creation)
 * - Voting period: 7 days
 * - Proposal threshold: 100,000 PIL tokens
 * - Quorum: 4% of total supply
 * - Timelock: 2 days
 *
 * Proposal Types:
 * - Parameter updates (fees, thresholds)
 * - Bridge adapter additions/removals
 * - Protocol upgrades
 * - Treasury allocations
 * - Emergency actions
 */
contract PILGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl
{
    // Proposal categories
    enum ProposalCategory {
        PARAMETER_UPDATE,
        BRIDGE_MANAGEMENT,
        PROTOCOL_UPGRADE,
        TREASURY_ALLOCATION,
        EMERGENCY_ACTION
    }

    // Extended proposal info
    struct ProposalMetadata {
        ProposalCategory category;
        string title;
        string description;
        address proposer;
        uint256 createdAt;
    }

    mapping(uint256 => ProposalMetadata) public proposalMetadata;

    // Events
    event ProposalCreatedWithMetadata(
        uint256 indexed proposalId,
        ProposalCategory category,
        string title,
        address indexed proposer
    );

    constructor(
        IVotes _token,
        TimelockController _timelock
    )
        Governor("PIL Governor")
        GovernorSettings(
            1 days, // Voting delay
            7 days, // Voting period
            100_000e18 // Proposal threshold: 100,000 PIL
        )
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(4) // 4% quorum
        GovernorTimelockControl(_timelock)
    {}

    /**
     * @notice Create a proposal with metadata
     * @param targets Target addresses
     * @param values ETH values
     * @param calldatas Function call data
     * @param category Proposal category
     * @param title Proposal title
     * @param description Full description
     */
    function proposeWithMetadata(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        ProposalCategory category,
        string memory title,
        string memory description
    ) external returns (uint256) {
        uint256 proposalId = propose(targets, values, calldatas, description);

        proposalMetadata[proposalId] = ProposalMetadata({
            category: category,
            title: title,
            description: description,
            proposer: msg.sender,
            createdAt: block.timestamp
        });

        emit ProposalCreatedWithMetadata(
            proposalId,
            category,
            title,
            msg.sender
        );

        return proposalId;
    }

    /**
     * @notice Get proposal details with metadata
     * @param proposalId Proposal ID
     */
    function getProposalDetails(
        uint256 proposalId
    )
        external
        view
        returns (
            ProposalCategory category,
            string memory title,
            string memory description,
            address proposer,
            uint256 createdAt,
            ProposalState currentState,
            uint256 forVotes,
            uint256 againstVotes,
            uint256 abstainVotes
        )
    {
        ProposalMetadata storage meta = proposalMetadata[proposalId];
        (forVotes, againstVotes, abstainVotes) = proposalVotes(proposalId);

        return (
            meta.category,
            meta.title,
            meta.description,
            meta.proposer,
            meta.createdAt,
            state(proposalId),
            forVotes,
            againstVotes,
            abstainVotes
        );
    }

    // Required overrides for OpenZeppelin 5.x

    function votingDelay()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingDelay();
    }

    function votingPeriod()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingPeriod();
    }

    function quorum(
        uint256 timepoint
    )
        public
        view
        override(Governor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(timepoint);
    }

    function state(
        uint256 proposalId
    )
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (ProposalState)
    {
        return super.state(proposalId);
    }

    function proposalNeedsQueuing(
        uint256 proposalId
    ) public view override(Governor, GovernorTimelockControl) returns (bool) {
        return super.proposalNeedsQueuing(proposalId);
    }

    function proposalThreshold()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.proposalThreshold();
    }

    function _queueOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint48) {
        return
            super._queueOperations(
                proposalId,
                targets,
                values,
                calldatas,
                descriptionHash
            );
    }

    function _executeOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) {
        super._executeOperations(
            proposalId,
            targets,
            values,
            calldatas,
            descriptionHash
        );
    }

    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    function _executor()
        internal
        view
        override(Governor, GovernorTimelockControl)
        returns (address)
    {
        return super._executor();
    }
}
