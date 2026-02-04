// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MPCLib} from "../../libraries/MPCLib.sol";

/**
 * @title IMPCGateway
 * @author Soul Protocol
 * @notice Interface for the MPC Gateway - unified entry point for MPC operations
 */
interface IMPCGateway {
    // ============================================
    // ENUMS
    // ============================================

    enum RequestType {
        None,
        ThresholdSign,
        SecretShare,
        SecretReconstruct,
        DKGInitiate,
        KeyRotation,
        ComputePrivate,
        CrossChainRelay
    }

    enum RequestStatus {
        None,
        Pending,
        Processing,
        Completed,
        Failed,
        Expired,
        Cancelled
    }

    // ============================================
    // STRUCTS
    // ============================================

    struct MPCRequest {
        bytes32 requestId;
        RequestType requestType;
        address requester;
        bytes32 keyId;
        bytes data;
        bytes32 dataHash;
        uint256 fee;
        uint256 deadline;
        uint256 submittedAt;
        uint256 processedAt;
        RequestStatus status;
        bytes32 resultHash;
        bytes result;
    }

    struct CrossChainRequest {
        bytes32 requestId;
        uint256 sourceChainId;
        uint256 targetChainId;
        bytes32 originalRequestId;
        bytes payload;
        bytes32 payloadHash;
        bool executed;
        uint256 receivedAt;
    }

    struct FeeConfig {
        uint256 baseFee;
        uint256 perParticipantFee;
        uint256 crossChainFee;
        uint256 computeFee;
    }

    // ============================================
    // EVENTS
    // ============================================

    event RequestSubmitted(
        bytes32 indexed requestId,
        RequestType requestType,
        address indexed requester,
        bytes32 indexed keyId
    );

    event RequestProcessed(
        bytes32 indexed requestId,
        RequestStatus status,
        bytes32 resultHash
    );

    event RequestCancelled(bytes32 indexed requestId, address indexed canceller);
    event RequestExpired(bytes32 indexed requestId);

    event ModuleUpdated(string moduleName, address indexed oldAddress, address indexed newAddress);

    event CrossChainRequestSent(
        bytes32 indexed requestId,
        uint256 indexed targetChainId,
        bytes32 messageHash
    );

    event CrossChainRequestReceived(
        bytes32 indexed requestId,
        uint256 indexed sourceChainId,
        bytes32 messageHash
    );

    event FeeCollected(bytes32 indexed requestId, uint256 amount);
    event FeeWithdrawn(address indexed recipient, uint256 amount);

    // ============================================
    // FUNCTIONS
    // ============================================

    /**
     * @notice Submit a threshold signing request
     * @param keyId Threshold key to use
     * @param messageHash Hash of message to sign
     * @param deadline Request deadline
     * @return requestId Unique request identifier
     */
    function requestThresholdSign(
        bytes32 keyId,
        bytes32 messageHash,
        uint256 deadline
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Submit a secret sharing request
     * @param secret Secret value to share
     * @param threshold t in t-of-n
     * @param participants Number of participants
     * @param deadline Request deadline
     * @return requestId Unique request identifier
     */
    function requestSecretShare(
        bytes32 secret,
        uint8 threshold,
        uint8 participants,
        uint256 deadline
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Submit a DKG initiation request
     * @param protocol DKG protocol (Feldman or Pedersen)
     * @param keyPurpose Purpose of the key
     * @param threshold t in t-of-n
     * @param participants Number of participants
     * @param deadline Request deadline
     * @return requestId Unique request identifier
     */
    function requestDKGInitiate(
        MPCLib.ProtocolType protocol,
        uint8 keyPurpose,
        uint8 threshold,
        uint8 participants,
        uint256 deadline
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Submit a privacy-preserving computation request
     * @param computationType Type of computation
     * @param inputCommitments Commitments to private inputs
     * @param program Computation program identifier
     * @param deadline Request deadline
     * @return requestId Unique request identifier
     */
    function requestPrivateCompute(
        MPCLib.ComputationType computationType,
        bytes32[] calldata inputCommitments,
        bytes32 program,
        uint256 deadline
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Send cross-chain MPC request
     * @param targetChainId Destination chain ID
     * @param requestType Type of MPC request
     * @param keyId Associated key
     * @param data Request-specific data
     * @param deadline Request deadline
     * @return requestId Local request identifier
     */
    function sendCrossChainRequest(
        uint256 targetChainId,
        RequestType requestType,
        bytes32 keyId,
        bytes calldata data,
        uint256 deadline
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Receive cross-chain MPC request
     * @param sourceChainId Source chain ID
     * @param originalRequestId Request ID on source chain
     * @param payload Encoded request data
     */
    function receiveCrossChainRequest(
        uint256 sourceChainId,
        bytes32 originalRequestId,
        bytes calldata payload
    ) external;

    /**
     * @notice Cancel a pending request
     * @param requestId Request to cancel
     */
    function cancelRequest(bytes32 requestId) external;

    /**
     * @notice Mark expired requests
     * @param requestId Request to check
     */
    function markExpired(bytes32 requestId) external;

    /**
     * @notice Complete a request
     * @param requestId Request to complete
     * @param resultHash Hash of the result
     * @param result Result data
     */
    function completeRequest(
        bytes32 requestId,
        bytes32 resultHash,
        bytes calldata result
    ) external;

    /**
     * @notice Mark request as failed
     * @param requestId Request to mark
     * @param reason Failure reason
     */
    function failRequest(bytes32 requestId, bytes calldata reason) external;

    /**
     * @notice Get request details
     * @param requestId Request identifier
     * @return request Request data
     */
    function getRequest(bytes32 requestId) external view returns (MPCRequest memory request);

    /**
     * @notice Get user's requests
     * @param user User address
     * @return requestIds Array of request IDs
     */
    function getUserRequests(address user) external view returns (bytes32[] memory requestIds);

    /**
     * @notice Get cross-chain request details
     * @param requestId Request identifier
     * @return ccRequest Cross-chain request data
     */
    function getCrossChainRequest(
        bytes32 requestId
    ) external view returns (CrossChainRequest memory ccRequest);

    /**
     * @notice Estimate fee for a request
     * @param requestType Type of request
     * @param numParticipants Number of participants
     * @param isCrossChain Whether it's a cross-chain request
     * @return fee Estimated fee in wei
     */
    function estimateFee(
        RequestType requestType,
        uint8 numParticipants,
        bool isCrossChain
    ) external view returns (uint256 fee);
}
