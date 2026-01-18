// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PILGovernance
 * @notice On-chain governance for PIL protocol parameters and upgrades
 * @dev Implements proposal-based governance with voting and timelock
 */
contract PILGovernance is AccessControl, ReentrancyGuard {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

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

    struct Proposal {
        uint256 id;
        address proposer;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        string description;
        uint256 startBlock;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        bool canceled;
        bool executed;
        uint256 eta; // Execution time after success
    }

    struct Vote {
        bool hasVoted;
        uint8 support; // 0=against, 1=for, 2=abstain
        uint256 weight;
    }

    // Governance parameters
    uint256 public votingDelay = 1; // 1 block
    uint256 public votingPeriod = 45818; // ~1 week at 13s blocks
    uint256 public proposalThreshold = 100000e18; // 100k tokens to propose
    uint256 public quorumVotes = 4000000e18; // 4M tokens quorum
    uint256 public timelockDelay = 2 days;

    // State
    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => Vote)) public proposalVotes;
    mapping(address => uint256) public latestProposalIds;

    // Governance token
    address public governanceToken;

    // Events
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address[] targets,
        uint256[] values,
        bytes[] calldatas,
        string description
    );
    event ProposalCanceled(uint256 indexed proposalId);
    event ProposalExecuted(uint256 indexed proposalId);
    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        uint8 support,
        uint256 weight,
        string reason
    );
    event ProposalQueued(uint256 indexed proposalId, uint256 eta);

    // Errors
    error InvalidProposalLength();
    error ProposalAlreadyExists();
    error ProposalNotActive();
    error ProposalNotSucceeded();
    error ProposalNotQueued();
    error TimelockNotMet();
    error AlreadyVoted();
    error InvalidVoteType();
    error InsufficientVotingPower();

    constructor(address _governanceToken) {
        governanceToken = _governanceToken;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROPOSER_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(CANCELLER_ROLE, msg.sender);
    }

    /// @notice Create a new proposal
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external onlyRole(PROPOSER_ROLE) returns (uint256) {
        if (
            targets.length != values.length ||
            targets.length != calldatas.length
        ) {
            revert InvalidProposalLength();
        }
        if (targets.length == 0) {
            revert InvalidProposalLength();
        }

        uint256 proposalId = hashProposal(
            targets,
            values,
            calldatas,
            keccak256(bytes(description))
        );

        if (proposals[proposalId].startBlock != 0) {
            revert ProposalAlreadyExists();
        }

        uint256 startBlock = block.number + votingDelay;
        uint256 endBlock = startBlock + votingPeriod;

        proposalCount++;

        Proposal storage proposal = proposals[proposalId];
        proposal.id = proposalId;
        proposal.proposer = msg.sender;
        proposal.targets = targets;
        proposal.values = values;
        proposal.calldatas = calldatas;
        proposal.description = description;
        proposal.startBlock = startBlock;
        proposal.endBlock = endBlock;

        latestProposalIds[msg.sender] = proposalId;

        emit ProposalCreated(
            proposalId,
            msg.sender,
            targets,
            values,
            calldatas,
            description
        );

        return proposalId;
    }

    /// @notice Cast a vote on a proposal
    function castVote(uint256 proposalId, uint8 support) external {
        _castVote(msg.sender, proposalId, support, "");
    }

    /// @notice Cast a vote with reason
    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external {
        _castVote(msg.sender, proposalId, support, reason);
    }

    function _castVote(
        address voter,
        uint256 proposalId,
        uint8 support,
        string memory reason
    ) internal {
        Proposal storage proposal = proposals[proposalId];

        if (state(proposalId) != ProposalState.Active) {
            revert ProposalNotActive();
        }

        Vote storage vote = proposalVotes[proposalId][voter];
        if (vote.hasVoted) {
            revert AlreadyVoted();
        }

        if (support > 2) {
            revert InvalidVoteType();
        }

        uint256 weight = getVotingPower(voter, proposal.startBlock);

        vote.hasVoted = true;
        vote.support = support;
        vote.weight = weight;

        if (support == 0) {
            proposal.againstVotes += weight;
        } else if (support == 1) {
            proposal.forVotes += weight;
        } else {
            proposal.abstainVotes += weight;
        }

        emit VoteCast(voter, proposalId, support, weight, reason);
    }

    /// @notice Queue a successful proposal for execution
    function queue(uint256 proposalId) external {
        if (state(proposalId) != ProposalState.Succeeded) {
            revert ProposalNotSucceeded();
        }

        Proposal storage proposal = proposals[proposalId];
        uint256 eta = block.timestamp + timelockDelay;
        proposal.eta = eta;

        emit ProposalQueued(proposalId, eta);
    }

    /// @notice Execute a queued proposal
    function execute(
        uint256 proposalId
    ) external payable nonReentrant onlyRole(EXECUTOR_ROLE) {
        if (state(proposalId) != ProposalState.Queued) {
            revert ProposalNotQueued();
        }

        Proposal storage proposal = proposals[proposalId];

        if (block.timestamp < proposal.eta) {
            revert TimelockNotMet();
        }

        proposal.executed = true;

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            (bool success, ) = proposal.targets[i].call{
                value: proposal.values[i]
            }(proposal.calldatas[i]);
            require(success, "Execution failed");
        }

        emit ProposalExecuted(proposalId);
    }

    /// @notice Cancel a proposal
    function cancel(uint256 proposalId) external onlyRole(CANCELLER_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        proposal.canceled = true;
        emit ProposalCanceled(proposalId);
    }

    /// @notice Get the current state of a proposal
    function state(uint256 proposalId) public view returns (ProposalState) {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) {
            return ProposalState.Canceled;
        }

        if (proposal.executed) {
            return ProposalState.Executed;
        }

        if (block.number <= proposal.startBlock) {
            return ProposalState.Pending;
        }

        if (block.number <= proposal.endBlock) {
            return ProposalState.Active;
        }

        if (
            proposal.forVotes <= proposal.againstVotes ||
            proposal.forVotes < quorumVotes
        ) {
            return ProposalState.Defeated;
        }

        if (proposal.eta == 0) {
            return ProposalState.Succeeded;
        }

        if (block.timestamp >= proposal.eta + 14 days) {
            return ProposalState.Expired;
        }

        return ProposalState.Queued;
    }

    /// @notice Get voting power at a specific block
    function getVotingPower(
        address account,
        uint256 blockNumber
    ) public view returns (uint256) {
        // In production, query the governance token's getPastVotes
        // For now, return a placeholder
        blockNumber; // silence warning
        account;
        return 1000000e18; // Placeholder: 1M tokens
    }

    /// @notice Hash proposal parameters
    function hashProposal(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) public pure returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encode(targets, values, calldatas, descriptionHash)
                )
            );
    }

    /// @notice Update governance parameters
    function setVotingDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        votingDelay = newDelay;
    }

    function setVotingPeriod(
        uint256 newPeriod
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        votingPeriod = newPeriod;
    }

    function setProposalThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proposalThreshold = newThreshold;
    }

    function setQuorumVotes(
        uint256 newQuorum
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        quorumVotes = newQuorum;
    }
}
