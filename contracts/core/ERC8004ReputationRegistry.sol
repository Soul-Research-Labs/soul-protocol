// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC8004ReputationRegistry} from "../interfaces/IERC8004ReputationRegistry.sol";

/**
 * @title ERC8004ReputationRegistry
 * @author Soul Protocol
 * @notice ERC-8004 Trustless Agents - Reputation Registry implementation
 * @dev On-chain feedback system for agent reputation with composable signals.
 *
 * Feedback consists of:
 * - value (int128): Signed fixed-point feedback value
 * - valueDecimals (uint8): 0-18 decimal places
 * - tag1, tag2: Optional string tags for categorization
 * - endpoint, feedbackURI, feedbackHash: Emitted in events, not stored
 *
 * Key properties:
 * - Feedback submitter MUST NOT be the agent owner or operator
 * - feedbackIndex is 1-indexed per (agentId, clientAddress) pair
 * - On-chain summary supports filtering by client list + tags
 * - Responses can be appended by anyone (agent, auditor, etc.)
 * - Clients can revoke their own feedback
 */
contract ERC8004ReputationRegistry is
    IERC8004ReputationRegistry,
    ReentrancyGuard
{
    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Stored feedback entry
    struct FeedbackEntry {
        int128 value;
        uint8 valueDecimals;
        string tag1;
        string tag2;
        bool isRevoked;
    }

    /// @dev Response tracking
    struct ResponseInfo {
        uint64 count;
        mapping(address => bool) hasResponded;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Identity registry reference
    address public identityRegistry;

    /// @notice Whether the registry has been initialized
    bool public initialized;

    /// @notice Contract deployer
    address private immutable _deployer;

    /// @notice Feedback storage: agentId → client → feedbackIndex → entry
    mapping(uint256 => mapping(address => mapping(uint64 => FeedbackEntry)))
        private _feedback;

    /// @notice Last feedback index per (agentId, client) pair
    mapping(uint256 => mapping(address => uint64)) private _lastIndex;

    /// @notice Client list per agent
    mapping(uint256 => address[]) private _agentClients;

    /// @notice Whether a client has given feedback to an agent
    mapping(uint256 => mapping(address => bool)) private _isClient;

    /// @notice Response tracking: agentId → client → index → responses
    mapping(uint256 => mapping(address => mapping(uint64 => ResponseInfo)))
        private _responses;

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _deployer = msg.sender;
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize with identity registry address
    function initialize(address identityRegistry_) external {
        require(msg.sender == _deployer, "Only deployer");
        require(!initialized, "Already initialized");
        require(identityRegistry_ != address(0), "Zero address");
        identityRegistry = identityRegistry_;
        initialized = true;
    }

    /// @inheritdoc IERC8004ReputationRegistry
    function getIdentityRegistry() external view returns (address) {
        return identityRegistry;
    }

    /*//////////////////////////////////////////////////////////////
                          GIVE FEEDBACK
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ReputationRegistry
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external nonReentrant {
        _requireRegisteredAgent(agentId);
        if (valueDecimals > 18) revert InvalidValueDecimals(valueDecimals);

        // Feedback submitter must not be the agent owner or operator
        address agentOwner = IERC721(identityRegistry).ownerOf(agentId);
        if (msg.sender == agentOwner)
            revert CannotReviewOwnAgent(agentId, msg.sender);

        // Check if approved operator
        try
            IERC721(identityRegistry).isApprovedForAll(agentOwner, msg.sender)
        returns (bool isOperator) {
            if (isOperator) revert CannotReviewOwnAgent(agentId, msg.sender);
        } catch {}

        // Increment feedback index (1-indexed)
        uint64 feedbackIndex = ++_lastIndex[agentId][msg.sender];

        // Store feedback on-chain
        _feedback[agentId][msg.sender][feedbackIndex] = FeedbackEntry({
            value: value,
            valueDecimals: valueDecimals,
            tag1: tag1,
            tag2: tag2,
            isRevoked: false
        });

        // Track client
        if (!_isClient[agentId][msg.sender]) {
            _isClient[agentId][msg.sender] = true;
            _agentClients[agentId].push(msg.sender);
        }

        emit NewFeedback(
            agentId,
            msg.sender,
            feedbackIndex,
            value,
            valueDecimals,
            tag1,
            tag1,
            tag2,
            endpoint,
            feedbackURI,
            feedbackHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                         REVOKE FEEDBACK
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ReputationRegistry
    function revokeFeedback(
        uint256 agentId,
        uint64 feedbackIndex
    ) external nonReentrant {
        if (
            feedbackIndex == 0 ||
            feedbackIndex > _lastIndex[agentId][msg.sender]
        ) revert FeedbackNotFound(agentId, msg.sender, feedbackIndex);

        FeedbackEntry storage entry = _feedback[agentId][msg.sender][
            feedbackIndex
        ];
        if (entry.isRevoked)
            revert FeedbackAlreadyRevoked(agentId, msg.sender, feedbackIndex);

        entry.isRevoked = true;

        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    /*//////////////////////////////////////////////////////////////
                        APPEND RESPONSE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ReputationRegistry
    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        string calldata responseURI,
        bytes32 responseHash
    ) external nonReentrant {
        if (
            feedbackIndex == 0 ||
            feedbackIndex > _lastIndex[agentId][clientAddress]
        ) revert FeedbackNotFound(agentId, clientAddress, feedbackIndex);

        ResponseInfo storage ri = _responses[agentId][clientAddress][
            feedbackIndex
        ];
        if (!ri.hasResponded[msg.sender]) {
            ri.hasResponded[msg.sender] = true;
            ri.count++;
        }

        emit ResponseAppended(
            agentId,
            clientAddress,
            feedbackIndex,
            msg.sender,
            responseURI,
            responseHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                          READ FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ReputationRegistry
    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    )
        external
        view
        returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)
    {
        if (clientAddresses.length == 0) revert EmptyClientList();

        bytes32 tag1Hash = bytes(tag1).length > 0
            ? keccak256(abi.encodePacked(tag1))
            : bytes32(0);
        bytes32 tag2Hash = bytes(tag2).length > 0
            ? keccak256(abi.encodePacked(tag2))
            : bytes32(0);

        for (uint256 c = 0; c < clientAddresses.length; c++) {
            address client = clientAddresses[c];
            uint64 lastIdx = _lastIndex[agentId][client];

            for (uint64 i = 1; i <= lastIdx; i++) {
                FeedbackEntry storage entry = _feedback[agentId][client][i];
                if (entry.isRevoked) continue;

                // Apply tag filters
                if (
                    tag1Hash != bytes32(0) &&
                    keccak256(abi.encodePacked(entry.tag1)) != tag1Hash
                ) continue;
                if (
                    tag2Hash != bytes32(0) &&
                    keccak256(abi.encodePacked(entry.tag2)) != tag2Hash
                ) continue;

                count++;
                summaryValue += entry.value;
                if (entry.valueDecimals > summaryValueDecimals) {
                    summaryValueDecimals = entry.valueDecimals;
                }
            }
        }
    }

    /// @inheritdoc IERC8004ReputationRegistry
    function readFeedback(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex
    )
        external
        view
        returns (
            int128 value,
            uint8 valueDecimals,
            string memory tag1,
            string memory tag2,
            bool isRevoked
        )
    {
        FeedbackEntry storage entry = _feedback[agentId][clientAddress][
            feedbackIndex
        ];
        return (
            entry.value,
            entry.valueDecimals,
            entry.tag1,
            entry.tag2,
            entry.isRevoked
        );
    }

    /// @inheritdoc IERC8004ReputationRegistry
    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata /* responders */
    ) external view returns (uint64 count) {
        return _responses[agentId][clientAddress][feedbackIndex].count;
    }

    /// @inheritdoc IERC8004ReputationRegistry
    function getClients(
        uint256 agentId
    ) external view returns (address[] memory) {
        return _agentClients[agentId];
    }

    /// @inheritdoc IERC8004ReputationRegistry
    function getLastIndex(
        uint256 agentId,
        address clientAddress
    ) external view returns (uint64) {
        return _lastIndex[agentId][clientAddress];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _requireRegisteredAgent(uint256 agentId) internal view {
        try IERC721(identityRegistry).ownerOf(agentId) returns (address) {
            // Agent exists
        } catch {
            revert AgentNotRegistered(agentId);
        }
    }
}
