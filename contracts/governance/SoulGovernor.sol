// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";

/**
 * @title SoulGovernor
 * @author Soul Protocol
 * @notice On-chain governance for the Soul Protocol, using token-weighted voting
 *         and the existing SoulUpgradeTimelock for execution.
 *
 * @dev Composed from OpenZeppelin 5.x Governor extensions:
 *      - GovernorSettings: configurable votingDelay, votingPeriod, proposalThreshold
 *      - GovernorCountingSimple: For/Against/Abstain counting
 *      - GovernorVotes: ERC-5805 (IVotes) token integration
 *      - GovernorVotesQuorumFraction: quorum as % of total supply
 *      - GovernorTimelockControl: proposals queue through SoulUpgradeTimelock
 *
 * GOVERNANCE FLOW:
 * ┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌─────────┐
 * │ Propose  │────►│  Vote    │────►│ Queue in     │────►│ Execute │
 * │ (token   │     │ (1-5 day │     │ Timelock     │     │ (after  │
 * │ holders) │     │  period) │     │ (48-72h)     │     │  delay) │
 * └──────────┘     └──────────┘     └──────────────┘     └─────────┘
 *      │                                                       │
 *      │              ┌─────────────┐                         │
 *      └─────────────►│ Cancel by   │◄────────────────────────┘
 *                     │ proposer or │
 *                     │ guardian    │
 *                     └─────────────┘
 */
contract SoulGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl
{
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Default voting delay: 1 day (in seconds for timestamp mode)
    uint48 public constant DEFAULT_VOTING_DELAY = 1 days;

    /// @notice Default voting period: 5 days
    uint32 public constant DEFAULT_VOTING_PERIOD = 5 days;

    /// @notice Default proposal threshold: 100,000 tokens (18 decimals)
    uint256 public constant DEFAULT_PROPOSAL_THRESHOLD = 100_000e18;

    /// @notice Default quorum: 4% of total supply
    uint256 public constant DEFAULT_QUORUM_PERCENTAGE = 4;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _token The ERC-5805 compatible voting token
     * @param _timelock The SoulUpgradeTimelock contract for queuing and executing proposals
     * @param _votingDelay Delay before voting starts (in seconds). Use 0 for DEFAULT_VOTING_DELAY.
     * @param _votingPeriod Duration of voting (in seconds). Use 0 for DEFAULT_VOTING_PERIOD.
     * @param _proposalThreshold Minimum tokens required to create a proposal. Use 0 for DEFAULT_PROPOSAL_THRESHOLD.
     * @param _quorumPercentage Quorum as percentage of total supply (1-100). Use 0 for DEFAULT_QUORUM_PERCENTAGE.
     */
    constructor(
        IVotes _token,
        TimelockController _timelock,
        uint48 _votingDelay,
        uint32 _votingPeriod,
        uint256 _proposalThreshold,
        uint256 _quorumPercentage
    )
        Governor("SoulGovernor")
        GovernorSettings(
            _votingDelay == 0 ? DEFAULT_VOTING_DELAY : _votingDelay,
            _votingPeriod == 0 ? DEFAULT_VOTING_PERIOD : _votingPeriod,
            _proposalThreshold == 0
                ? DEFAULT_PROPOSAL_THRESHOLD
                : _proposalThreshold
        )
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(
            _quorumPercentage == 0
                ? DEFAULT_QUORUM_PERCENTAGE
                : _quorumPercentage
        )
        GovernorTimelockControl(_timelock)
    {}

    /*//////////////////////////////////////////////////////////////
                           CLOCK MODE
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Use block.timestamp for voting clock — required for L2 compatibility
     *      where block numbers are unreliable across chains.
     */
    function clock() public view override(Governor, GovernorVotes) returns (uint48) {
        return uint48(block.timestamp);
    }

    /**
     * @dev Machine-readable description of the clock mode.
     */
    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE()
        public
        pure
        override(Governor, GovernorVotes)
        returns (string memory)
    {
        return "mode=timestamp&from=default";
    }

    /*//////////////////////////////////////////////////////////////
                      REQUIRED OVERRIDES
    //////////////////////////////////////////////////////////////*/

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
    )
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (bool)
    {
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
    )
        internal
        override(Governor, GovernorTimelockControl)
        returns (uint48)
    {
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
    )
        internal
        override(Governor, GovernorTimelockControl)
        returns (uint256)
    {
        return
            super._cancel(targets, values, calldatas, descriptionHash);
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
