// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";
import {IZaseonGovernor} from "../interfaces/IZaseonGovernor.sol";

/**
 * @title ZaseonGovernor
 * @author ZASEON
 * @notice On-chain governance for the ZASEON, using token-weighted voting
 *         and the existing ZaseonUpgradeTimelock for execution.
 *
 * @dev Composed from OpenZeppelin 5.x Governor extensions:
 *      - GovernorSettings: configurable votingDelay, votingPeriod, proposalThreshold
 *      - GovernorCountingSimple: For/Against/Abstain counting
 *      - GovernorVotes: ERC-5805 (IVotes) token integration
 *      - GovernorVotesQuorumFraction: quorum as % of total supply
 *      - GovernorTimelockControl: proposals queue through ZaseonUpgradeTimelock
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
contract ZaseonGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl,
    IZaseonGovernor
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
     * @param _timelock The ZaseonUpgradeTimelock contract for queuing and executing proposals
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
        Governor("ZaseonGovernor")
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
        /**
     * @notice Clock
     * @return The result value
     */
function clock()
        public
        view
        override(Governor, GovernorVotes, IERC6372)
        returns (uint48)
    {
        return uint48(block.timestamp);
    }

    /**
     * @dev Machine-readable description of the clock mode.
     */
    // solhint-disable-next-line func-name-mixedcase
        /**
     * @notice C l o c k_ m o d e
     * @return The result value
     */
function CLOCK_MODE()
        public
        pure
        override(Governor, GovernorVotes, IERC6372)
        returns (string memory)
    {
        return "mode=timestamp&from=default";
    }

    /*//////////////////////////////////////////////////////////////
                      REQUIRED OVERRIDES
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc GovernorSettings
        /**
     * @notice Voting delay
     * @return The result value
     */
function votingDelay()
        public
        view
        override(Governor, GovernorSettings, IGovernor)
        returns (uint256)
    {
        return super.votingDelay();
    }

    /// @inheritdoc GovernorSettings
        /**
     * @notice Voting period
     * @return The result value
     */
function votingPeriod()
        public
        view
        override(Governor, GovernorSettings, IGovernor)
        returns (uint256)
    {
        return super.votingPeriod();
    }

    /// @inheritdoc GovernorVotesQuorumFraction
        /**
     * @notice Quorum
     * @param timepoint The timepoint timestamp
     * @return The result value
     */
function quorum(
        uint256 timepoint
    )
        public
        view
        override(Governor, GovernorVotesQuorumFraction, IGovernor)
        returns (uint256)
    {
        return super.quorum(timepoint);
    }

    /// @inheritdoc GovernorTimelockControl
        /**
     * @notice State
     * @param proposalId The proposalId identifier
     * @return The result value
     */
function state(
        uint256 proposalId
    )
        public
        view
        override(Governor, GovernorTimelockControl, IGovernor)
        returns (ProposalState)
    {
        return super.state(proposalId);
    }

    /// @inheritdoc GovernorTimelockControl
        /**
     * @notice Proposal needs queuing
     * @param proposalId The proposalId identifier
     * @return The result value
     */
function proposalNeedsQueuing(
        uint256 proposalId
    )
        public
        view
        override(Governor, GovernorTimelockControl, IGovernor)
        returns (bool)
    {
        return super.proposalNeedsQueuing(proposalId);
    }

    /// @inheritdoc GovernorSettings
        /**
     * @notice Proposal threshold
     * @return The result value
     */
function proposalThreshold()
        public
        view
        override(Governor, GovernorSettings, IGovernor)
        returns (uint256)
    {
        return super.proposalThreshold();
    }

    /// @inheritdoc GovernorTimelockControl
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

    /// @inheritdoc GovernorTimelockControl
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

    /// @inheritdoc GovernorTimelockControl
    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    /// @inheritdoc GovernorTimelockControl
    function _executor()
        internal
        view
        override(Governor, GovernorTimelockControl)
        returns (address)
    {
        return super._executor();
    }
}
