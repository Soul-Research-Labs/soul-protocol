// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISoulGovernor
 * @author Soul Protocol
 * @notice Interface for Soul Protocol governance operations
 * @dev Defines the standard interface for governance proposals and execution
 */
interface ISoulGovernor {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Proposal states
    enum ProposalState {
        Pending,
        Active,
        Canceled,
        Defeated,
        Succeeded,
        Queued,
        Expired,
        Executed
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a proposal is created
     * @param proposalId Unique identifier for the proposal
     * @param proposer Address that created the proposal
     * @param targets Target addresses for proposal calls
     * @param values ETH values for each call
     * @param calldatas Encoded function calls
     * @param startBlock Block when voting starts
     * @param endBlock Block when voting ends
     * @param description Human-readable description
     */
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address[] targets,
        uint256[] values,
        bytes[] calldatas,
        uint256 startBlock,
        uint256 endBlock,
        string description
    );

    /**
     * @notice Emitted when a proposal is executed
     * @param proposalId The executed proposal ID
     */
    event ProposalExecuted(uint256 indexed proposalId);

    /**
     * @notice Emitted when a proposal is canceled
     * @param proposalId The canceled proposal ID
     */
    event ProposalCanceled(uint256 indexed proposalId);

    /*//////////////////////////////////////////////////////////////
                            PROPOSAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a new governance proposal
     * @param targets Contract addresses to call
     * @param values ETH amounts to send with each call
     * @param calldatas Encoded function calls
     * @param description Human-readable proposal description
     * @return proposalId Unique identifier for the created proposal
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256 proposalId);

    /**
     * @notice Queues a successful proposal for execution
     * @param targets Contract addresses to call
     * @param values ETH amounts to send
     * @param calldatas Encoded function calls
     * @param descriptionHash Hash of proposal description
     * @return proposalId The queued proposal ID
     */
    function queue(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external returns (uint256 proposalId);

    /**
     * @notice Executes a queued proposal
     * @param targets Contract addresses to call
     * @param values ETH amounts to send
     * @param calldatas Encoded function calls
     * @param descriptionHash Hash of proposal description
     * @return proposalId The executed proposal ID
     */
    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external payable returns (uint256 proposalId);

    /**
     * @notice Cancels a proposal
     * @param targets Contract addresses from proposal
     * @param values ETH amounts from proposal
     * @param calldatas Encoded calls from proposal
     * @param descriptionHash Hash of proposal description
     * @return proposalId The canceled proposal ID
     */
    function cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external returns (uint256 proposalId);

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the current state of a proposal
     * @param proposalId The proposal to check
     * @return state Current proposal state
     */
    function state(
        uint256 proposalId
    ) external view returns (ProposalState state);

    /**
     * @notice Returns the voting delay in blocks
     * @return delay Number of blocks between proposal creation and voting start
     */
    function votingDelay() external view returns (uint256 delay);

    /**
     * @notice Returns the voting period in blocks
     * @return period Number of blocks voting remains open
     */
    function votingPeriod() external view returns (uint256 period);

    /**
     * @notice Returns the proposal threshold
     * @return threshold Minimum votes needed to create a proposal
     */
    function proposalThreshold() external view returns (uint256 threshold);

    /**
     * @notice Generates a proposal ID from its parameters
     * @param targets Contract addresses
     * @param values ETH amounts
     * @param calldatas Encoded function calls
     * @param descriptionHash Hash of description
     * @return proposalId The computed proposal ID
     */
    function hashProposal(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external pure returns (uint256 proposalId);
}
