// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC8004ReputationRegistry
 * @author Soul Protocol
 * @notice Interface for ERC-8004 Trustless Agents - Reputation Registry
 * @dev On-chain feedback system for agent reputation with composable signals
 *
 * ERC-8004 REPUTATION REGISTRY:
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                  Reputation Registry                        │
 *   │  ┌───────────────────────────────────────────────────────┐  │
 *   │  │  Feedback Signals                                     │  │
 *   │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │  │
 *   │  │  │ Client A  │  │ Client B  │  │ Client N  │           │  │
 *   │  │  │ → Agent 1 │  │ → Agent 1 │  │ → Agent M │           │  │
 *   │  │  │ value=87  │  │ value=95  │  │ value=-3  │           │  │
 *   │  │  │ tag=qual  │  │ tag=speed │  │ tag=yield │           │  │
 *   │  │  └──────────┘  └──────────┘  └──────────┘           │  │
 *   │  │                                                       │  │
 *   │  │  Responses: agent refunds, spam tags, auditor notes    │  │
 *   │  │  Revocations: clients can revoke their own feedback    │  │
 *   │  │  Summaries: on-chain aggregation by client + tag       │  │
 *   │  └───────────────────────────────────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * Feedback value: int128 with uint8 valueDecimals (0-18)
 * Stored on-chain: value, valueDecimals, tag1, tag2, isRevoked
 * Emitted only: endpoint, feedbackURI, feedbackHash
 */
interface IERC8004ReputationRegistry {
    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when new feedback is given
    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        int128 value,
        uint8 valueDecimals,
        string indexed indexedTag1,
        string tag1,
        string tag2,
        string endpoint,
        string feedbackURI,
        bytes32 feedbackHash
    );

    /// @notice Emitted when feedback is revoked
    event FeedbackRevoked(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 indexed feedbackIndex
    );

    /// @notice Emitted when a response is appended to feedback
    event ResponseAppended(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        address indexed responder,
        string responseURI,
        bytes32 responseHash
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error AgentNotRegistered(uint256 agentId);
    error InvalidValueDecimals(uint8 decimals);
    error CannotReviewOwnAgent(uint256 agentId, address caller);
    error FeedbackNotFound(uint256 agentId, address client, uint64 index);
    error FeedbackAlreadyRevoked(uint256 agentId, address client, uint64 index);
    error NotFeedbackOwner(address caller, address expected);
    error EmptyClientList();

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the identity registry address
    function getIdentityRegistry() external view returns (address);

    /// @notice Give feedback to an agent
    /// @param agentId The registered agent ID
    /// @param value Signed fixed-point feedback value
    /// @param valueDecimals Number of decimal places (0-18)
    /// @param tag1 Optional primary tag for categorization
    /// @param tag2 Optional secondary tag
    /// @param endpoint Optional endpoint being reviewed
    /// @param feedbackURI Optional URI to off-chain feedback details
    /// @param feedbackHash Optional keccak256 hash of feedbackURI content
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external;

    /// @notice Revoke previously given feedback
    /// @param agentId The agent ID
    /// @param feedbackIndex The 1-indexed feedback counter
    function revokeFeedback(
        uint256 agentId,
        uint64 feedbackIndex
    ) external;

    /// @notice Append a response to existing feedback
    /// @param agentId The agent ID
    /// @param clientAddress The original feedback giver
    /// @param feedbackIndex The feedback entry index
    /// @param responseURI URI to response content
    /// @param responseHash keccak256 hash of responseURI content
    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        string calldata responseURI,
        bytes32 responseHash
    ) external;

    /// @notice Get aggregated summary for an agent filtered by clients and tags
    /// @param agentId The agent ID
    /// @param clientAddresses Array of client addresses to filter by (required)
    /// @param tag1 Optional tag1 filter
    /// @param tag2 Optional tag2 filter
    /// @return count Number of matching feedback entries
    /// @return summaryValue Sum of feedback values
    /// @return summaryValueDecimals Maximum decimals across entries
    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals);

    /// @notice Read a specific feedback entry
    function readFeedback(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex
    ) external view returns (
        int128 value,
        uint8 valueDecimals,
        string memory tag1,
        string memory tag2,
        bool isRevoked
    );

    /// @notice Get the number of responses for a feedback entry
    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata responders
    ) external view returns (uint64 count);

    /// @notice Get all client addresses that have given feedback to an agent
    function getClients(
        uint256 agentId
    ) external view returns (address[] memory);

    /// @notice Get the last feedback index for a client → agent pair
    function getLastIndex(
        uint256 agentId,
        address clientAddress
    ) external view returns (uint64);
}
