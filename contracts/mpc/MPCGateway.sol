// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MPCLib} from "../libraries/MPCLib.sol";
import {ShamirSecretSharing} from "./ShamirSecretSharing.sol";
import {ThresholdSignature} from "./ThresholdSignature.sol";
import {MPCCoordinator} from "./MPCCoordinator.sol";
import {MPCKeyRegistry} from "./MPCKeyRegistry.sol";

/**
 * @title MPCGateway
 * @author Soul Protocol
 * @notice Unified entry point for all MPC operations in Soul Protocol
 * @dev Routes requests to appropriate MPC modules and handles cross-chain coordination
 *
 * Architecture Overview:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          MPC Gateway                                         │
 * │                     (Unified Entry Point)                                   │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
 * │  │   Secret    │  │  Threshold  │  │    MPC      │  │    Key      │        │
 * │  │  Sharing    │  │ Signatures  │  │ Coordinator │  │  Registry   │        │
 * │  │  Module     │  │   Module    │  │   Module    │  │   Module    │        │
 * │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
 * │         │                │                │                │                │
 * │         └────────────────┴────────────────┴────────────────┘                │
 * │                                   │                                          │
 * │                          ┌────────┴────────┐                                │
 * │                          │  Request Router │                                │
 * │                          └────────┬────────┘                                │
 * │                                   │                                          │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    Cross-Chain Messaging Layer                       │   │
 * │  │  (Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM)  │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │  Supported Operations:                                                       │
 * │  • Threshold Signing (ECDSA, Schnorr, BLS)                                  │
 * │  • Secret Sharing (Shamir's with VSS)                                       │
 * │  • Distributed Key Generation (Feldman, Pedersen)                           │
 * │  • Privacy-Preserving Computation (SPDZ, GMW)                               │
 * │  • Cross-Chain MPC Coordination                                             │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract MPCGateway is AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant GATEWAY_ADMIN_ROLE = keccak256("GATEWAY_ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice EIP-712 Domain separator
    bytes32 public constant DOMAIN_SEPARATOR = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice Request typehash for EIP-712
    bytes32 public constant REQUEST_TYPEHASH = keccak256(
        "MPCRequest(bytes32 requestId,uint8 requestType,bytes32 keyId,bytes data,uint256 deadline,uint256 nonce)"
    );

    /// @notice Maximum request lifetime
    uint256 public constant MAX_REQUEST_LIFETIME = 1 hours;

    /// @notice Minimum request lifetime
    uint256 public constant MIN_REQUEST_LIFETIME = 5 minutes;

    // ============================================
    // ENUMS
    // ============================================

    /**
     * @notice Type of MPC request
     */
    enum RequestType {
        None,              // 0: Invalid
        ThresholdSign,     // 1: Request threshold signature
        SecretShare,       // 2: Create secret sharing session
        SecretReconstruct, // 3: Reconstruct shared secret
        DKGInitiate,       // 4: Start DKG protocol
        KeyRotation,       // 5: Rotate existing key
        ComputePrivate,    // 6: Privacy-preserving computation
        CrossChainRelay    // 7: Cross-chain MPC coordination
    }

    /**
     * @notice Request status
     */
    enum RequestStatus {
        None,       // 0: Not submitted
        Pending,    // 1: Awaiting processing
        Processing, // 2: Being processed
        Completed,  // 3: Successfully completed
        Failed,     // 4: Failed
        Expired,    // 5: Deadline passed
        Cancelled   // 6: Cancelled by requester
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
    // ERRORS
    // ============================================

    error InvalidRequestType();
    error RequestNotFound(bytes32 requestId);
    error RequestAlreadyExists(bytes32 requestId);
    error InvalidDeadline();
    error RequestExpiredError(bytes32 requestId);
    error NotRequester(address caller);
    error InvalidSignature();
    error ModuleNotSet(string moduleName);
    error InvalidKeyId(bytes32 keyId);
    error InsufficientFee();
    error TransferFailed();
    error InvalidChainId();
    error ZeroAddress();

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice MPC Request
     */
    struct MPCRequest {
        bytes32 requestId;
        RequestType requestType;
        address requester;
        bytes32 keyId;              // Associated key (if applicable)
        bytes data;                 // Request-specific data
        bytes32 dataHash;           // Hash of data for verification
        uint256 fee;                // Fee paid
        uint256 deadline;
        uint256 submittedAt;
        uint256 processedAt;
        RequestStatus status;
        bytes32 resultHash;         // Hash of result (if completed)
        bytes result;               // Result data (if applicable)
    }

    /**
     * @notice Cross-chain request
     */
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

    /**
     * @notice Fee configuration
     */
    struct FeeConfig {
        uint256 baseFee;
        uint256 perParticipantFee;
        uint256 crossChainFee;
        uint256 computeFee;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Request nonce
    uint256 public requestNonce;

    /// @notice Total requests processed
    uint256 public totalRequests;

    /// @notice Total fees collected
    uint256 public totalFeesCollected;

    /// @notice Fee configuration
    FeeConfig public feeConfig;

    /// @notice Shamir Secret Sharing module
    ShamirSecretSharing public shamirModule;

    /// @notice Threshold Signature module
    ThresholdSignature public thresholdSigModule;

    /// @notice MPC Coordinator module
    MPCCoordinator public coordinatorModule;

    /// @notice Key Registry module
    MPCKeyRegistry public keyRegistryModule;

    /// @notice Requests: requestId => request
    mapping(bytes32 => MPCRequest) public requests;

    /// @notice User requests: user => requestId[]
    mapping(address => bytes32[]) public userRequests;

    /// @notice Cross-chain requests: requestId => crossChainRequest
    mapping(bytes32 => CrossChainRequest) public crossChainRequests;

    /// @notice Used nonces for EIP-712: user => nonce => used
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    /// @notice Supported chains: chainId => supported
    mapping(uint256 => bool) public supportedChains;

    /// @notice Chain messengers: chainId => messenger address
    mapping(uint256 => address) public chainMessengers;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GATEWAY_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(ROUTER_ROLE, msg.sender);

        // Default fee configuration
        feeConfig = FeeConfig({
            baseFee: 0.001 ether,
            perParticipantFee: 0.0001 ether,
            crossChainFee: 0.01 ether,
            computeFee: 0.005 ether
        });

        // Support current chain
        supportedChains[block.chainid] = true;
    }

    // ============================================
    // REQUEST SUBMISSION
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
    ) external payable whenNotPaused nonReentrant returns (bytes32 requestId) {
        if (address(thresholdSigModule) == address(0)) {
            revert ModuleNotSet("ThresholdSignature");
        }
        
        _validateDeadline(deadline);
        _validateFee(RequestType.ThresholdSign);

        requestId = _generateRequestId(RequestType.ThresholdSign);

        bytes memory data = abi.encode(messageHash);

        requests[requestId] = MPCRequest({
            requestId: requestId,
            requestType: RequestType.ThresholdSign,
            requester: msg.sender,
            keyId: keyId,
            data: data,
            dataHash: keccak256(data),
            fee: msg.value,
            deadline: deadline,
            submittedAt: block.timestamp,
            processedAt: 0,
            status: RequestStatus.Pending,
            resultHash: bytes32(0),
            result: ""
        });

        userRequests[msg.sender].push(requestId);
        totalRequests++;
        totalFeesCollected += msg.value;

        // Create signing request in threshold module
        // Note: deadline will be handled by the gateway
        thresholdSigModule.createSigningRequest(keyId, messageHash, deadline);

        emit RequestSubmitted(requestId, RequestType.ThresholdSign, msg.sender, keyId);
        emit FeeCollected(requestId, msg.value);
    }

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
    ) external payable whenNotPaused nonReentrant returns (bytes32 requestId) {
        if (address(shamirModule) == address(0)) {
            revert ModuleNotSet("ShamirSecretSharing");
        }
        
        _validateDeadline(deadline);
        _validateFee(RequestType.SecretShare);

        requestId = _generateRequestId(RequestType.SecretShare);

        bytes memory data = abi.encode(secret, threshold, participants);

        requests[requestId] = MPCRequest({
            requestId: requestId,
            requestType: RequestType.SecretShare,
            requester: msg.sender,
            keyId: bytes32(0),
            data: data,
            dataHash: keccak256(data),
            fee: msg.value,
            deadline: deadline,
            submittedAt: block.timestamp,
            processedAt: 0,
            status: RequestStatus.Pending,
            resultHash: bytes32(0),
            result: ""
        });

        userRequests[msg.sender].push(requestId);
        totalRequests++;
        totalFeesCollected += msg.value;

        // Create sharing session in Shamir module
        // Duration is deadline - now
        uint256 duration = deadline - block.timestamp;
        bytes32 sessionId = shamirModule.createSession(
            threshold,
            participants,
            keccak256(abi.encodePacked(requestId)), // secretCommitment
            duration
        );
        requests[requestId].result = abi.encode(sessionId);

        emit RequestSubmitted(requestId, RequestType.SecretShare, msg.sender, bytes32(0));
        emit FeeCollected(requestId, msg.value);
    }

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
        MPCKeyRegistry.KeyPurpose keyPurpose,
        uint8 threshold,
        uint8 participants,
        uint256 deadline
    ) external payable whenNotPaused nonReentrant returns (bytes32 requestId) {
        if (address(keyRegistryModule) == address(0)) {
            revert ModuleNotSet("MPCKeyRegistry");
        }
        
        _validateDeadline(deadline);
        _validateFee(RequestType.DKGInitiate);

        requestId = _generateRequestId(RequestType.DKGInitiate);

        bytes memory data = abi.encode(protocol, keyPurpose, threshold, participants);

        requests[requestId] = MPCRequest({
            requestId: requestId,
            requestType: RequestType.DKGInitiate,
            requester: msg.sender,
            keyId: bytes32(0),
            data: data,
            dataHash: keccak256(data),
            fee: msg.value,
            deadline: deadline,
            submittedAt: block.timestamp,
            processedAt: 0,
            status: RequestStatus.Pending,
            resultHash: bytes32(0),
            result: ""
        });

        userRequests[msg.sender].push(requestId);
        totalRequests++;
        totalFeesCollected += msg.value;

        // Create DKG session in key registry
        bytes32 sessionId = keyRegistryModule.createDKGSession(
            protocol,
            keyPurpose,
            threshold,
            participants
        );

        // Store session ID in result
        requests[requestId].result = abi.encode(sessionId);

        emit RequestSubmitted(requestId, RequestType.DKGInitiate, msg.sender, sessionId);
        emit FeeCollected(requestId, msg.value);
    }

    /**
     * @notice Submit a privacy-preserving computation request
     * @param computationType Type of computation
     * @param inputCommitments Commitments to private inputs
     * @param program Computation program/circuit identifier
     * @param deadline Request deadline
     * @return requestId Unique request identifier
     */
    function requestPrivateCompute(
        MPCLib.ComputationType computationType,
        bytes32[] calldata inputCommitments,
        bytes32 program,
        uint256 deadline
    ) external payable whenNotPaused nonReentrant returns (bytes32 requestId) {
        if (address(coordinatorModule) == address(0)) {
            revert ModuleNotSet("MPCCoordinator");
        }
        
        _validateDeadline(deadline);
        _validateFee(RequestType.ComputePrivate);

        requestId = _generateRequestId(RequestType.ComputePrivate);

        bytes memory data = abi.encode(computationType, inputCommitments, program);

        requests[requestId] = MPCRequest({
            requestId: requestId,
            requestType: RequestType.ComputePrivate,
            requester: msg.sender,
            keyId: program,
            data: data,
            dataHash: keccak256(data),
            fee: msg.value,
            deadline: deadline,
            submittedAt: block.timestamp,
            processedAt: 0,
            status: RequestStatus.Pending,
            resultHash: bytes32(0),
            result: ""
        });

        userRequests[msg.sender].push(requestId);
        totalRequests++;
        totalFeesCollected += msg.value;

        // Determine MPC protocol based on computation type
        MPCLib.ProtocolType protocol;
        if (computationType == MPCLib.ComputationType.Addition || 
            computationType == MPCLib.ComputationType.Multiplication) {
            protocol = MPCLib.ProtocolType.SPDZ;
        } else if (computationType == MPCLib.ComputationType.Comparison) {
            protocol = MPCLib.ProtocolType.GMW;
        } else {
            protocol = MPCLib.ProtocolType.Yao;
        }

        // Create MPC session
        // Duration is deadline - now
        uint256 duration = deadline - block.timestamp;
        bytes32 sessionId = coordinatorModule.createSession(
            protocol,
            computationType,
            uint8(inputCommitments.length), // threshold
            uint8(inputCommitments.length), // participants
            duration,
            data // metadata
        );
        requests[requestId].result = abi.encode(sessionId);

        emit RequestSubmitted(requestId, RequestType.ComputePrivate, msg.sender, program);
        emit FeeCollected(requestId, msg.value);
    }

    // ============================================
    // CROSS-CHAIN OPERATIONS
    // ============================================

    /**
     * @notice Send cross-chain MPC request
     * @param targetChainId Destination chain ID
     * @param requestType Type of MPC request
     * @param keyId Associated key (if applicable)
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
    ) external payable whenNotPaused nonReentrant returns (bytes32 requestId) {
        if (!supportedChains[targetChainId]) {
            revert InvalidChainId();
        }
        if (chainMessengers[targetChainId] == address(0)) {
            revert ModuleNotSet("ChainMessenger");
        }
        
        _validateDeadline(deadline);
        if (msg.value < feeConfig.crossChainFee) {
            revert InsufficientFee();
        }

        requestId = _generateRequestId(requestType);

        // Create local request record
        requests[requestId] = MPCRequest({
            requestId: requestId,
            requestType: requestType,
            requester: msg.sender,
            keyId: keyId,
            data: data,
            dataHash: keccak256(data),
            fee: msg.value,
            deadline: deadline,
            submittedAt: block.timestamp,
            processedAt: 0,
            status: RequestStatus.Pending,
            resultHash: bytes32(0),
            result: ""
        });

        // Create cross-chain record
        bytes memory payload = abi.encode(
            requestId,
            requestType,
            msg.sender,
            keyId,
            data,
            deadline
        );

        crossChainRequests[requestId] = CrossChainRequest({
            requestId: requestId,
            sourceChainId: block.chainid,
            targetChainId: targetChainId,
            originalRequestId: requestId,
            payload: payload,
            payloadHash: keccak256(payload),
            executed: false,
            receivedAt: 0
        });

        userRequests[msg.sender].push(requestId);
        totalRequests++;
        totalFeesCollected += msg.value;

        emit RequestSubmitted(requestId, requestType, msg.sender, keyId);
        emit CrossChainRequestSent(requestId, targetChainId, keccak256(payload));
        emit FeeCollected(requestId, msg.value);
    }

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
    ) external onlyRole(RELAYER_ROLE) whenNotPaused nonReentrant {
        if (!supportedChains[sourceChainId]) {
            revert InvalidChainId();
        }

        // Decode payload
        (
            ,
            RequestType requestType,
            address requester,
            bytes32 keyId,
            bytes memory data,
            uint256 deadline
        ) = abi.decode(payload, (bytes32, RequestType, address, bytes32, bytes, uint256));

        bytes32 localRequestId = keccak256(abi.encodePacked(
            sourceChainId,
            originalRequestId,
            block.timestamp
        ));

        // Store cross-chain request
        crossChainRequests[localRequestId] = CrossChainRequest({
            requestId: localRequestId,
            sourceChainId: sourceChainId,
            targetChainId: block.chainid,
            originalRequestId: originalRequestId,
            payload: payload,
            payloadHash: keccak256(payload),
            executed: false,
            receivedAt: block.timestamp
        });

        // Create local request
        requests[localRequestId] = MPCRequest({
            requestId: localRequestId,
            requestType: requestType,
            requester: requester,
            keyId: keyId,
            data: data,
            dataHash: keccak256(data),
            fee: 0, // Fee was paid on source chain
            deadline: deadline,
            submittedAt: block.timestamp,
            processedAt: 0,
            status: RequestStatus.Pending,
            resultHash: bytes32(0),
            result: ""
        });

        emit CrossChainRequestReceived(localRequestId, sourceChainId, keccak256(payload));
    }

    // ============================================
    // REQUEST MANAGEMENT
    // ============================================

    /**
     * @notice Cancel a pending request
     * @param requestId Request to cancel
     */
    function cancelRequest(bytes32 requestId) external nonReentrant {
        MPCRequest storage request = requests[requestId];
        
        if (request.submittedAt == 0) {
            revert RequestNotFound(requestId);
        }
        if (request.requester != msg.sender) {
            revert NotRequester(msg.sender);
        }
        if (request.status != RequestStatus.Pending) {
            revert RequestNotFound(requestId);
        }

        request.status = RequestStatus.Cancelled;
        
        // Refund fee (minus gas cost)
        if (request.fee > 0) {
            uint256 refund = (request.fee * 90) / 100; // 10% cancellation fee
            (bool success, ) = msg.sender.call{value: refund}("");
            if (!success) {
                revert TransferFailed();
            }
        }

        emit RequestCancelled(requestId, msg.sender);
    }

    /**
     * @notice Mark expired requests
     * @param requestId Request to check
     */
    function markExpired(bytes32 requestId) external {
        MPCRequest storage request = requests[requestId];
        
        if (request.submittedAt == 0) {
            revert RequestNotFound(requestId);
        }
        if (request.status != RequestStatus.Pending && request.status != RequestStatus.Processing) {
            return;
        }
        if (block.timestamp <= request.deadline) {
            return;
        }

        request.status = RequestStatus.Expired;
        emit RequestExpired(requestId);
    }

    /**
     * @notice Complete a request (called by modules)
     * @param requestId Request to complete
     * @param resultHash Hash of the result
     * @param result Result data
     */
    function completeRequest(
        bytes32 requestId,
        bytes32 resultHash,
        bytes calldata result
    ) external onlyRole(ROUTER_ROLE) {
        MPCRequest storage request = requests[requestId];
        
        if (request.submittedAt == 0) {
            revert RequestNotFound(requestId);
        }

        request.status = RequestStatus.Completed;
        request.processedAt = block.timestamp;
        request.resultHash = resultHash;
        request.result = result;

        emit RequestProcessed(requestId, RequestStatus.Completed, resultHash);
    }

    /**
     * @notice Mark request as failed
     * @param requestId Request to mark
     * @param reason Failure reason (encoded)
     */
    function failRequest(
        bytes32 requestId,
        bytes calldata reason
    ) external onlyRole(ROUTER_ROLE) {
        MPCRequest storage request = requests[requestId];
        
        if (request.submittedAt == 0) {
            revert RequestNotFound(requestId);
        }

        request.status = RequestStatus.Failed;
        request.processedAt = block.timestamp;
        request.result = reason;

        emit RequestProcessed(requestId, RequestStatus.Failed, keccak256(reason));
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    function _generateRequestId(RequestType requestType) internal returns (bytes32) {
        return keccak256(abi.encodePacked(
            block.chainid,
            address(this),
            requestType,
            msg.sender,
            requestNonce++,
            block.timestamp
        ));
    }

    function _validateDeadline(uint256 deadline) internal view {
        if (deadline <= block.timestamp) {
            revert InvalidDeadline();
        }
        if (deadline > block.timestamp + MAX_REQUEST_LIFETIME) {
            revert InvalidDeadline();
        }
        if (deadline < block.timestamp + MIN_REQUEST_LIFETIME) {
            revert InvalidDeadline();
        }
    }

    function _validateFee(RequestType requestType) internal view {
        uint256 requiredFee = feeConfig.baseFee;
        
        if (requestType == RequestType.ComputePrivate) {
            requiredFee += feeConfig.computeFee;
        }
        
        if (msg.value < requiredFee) {
            revert InsufficientFee();
        }
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get request details
     * @param requestId Request identifier
     * @return request Request data
     */
    function getRequest(bytes32 requestId) external view returns (MPCRequest memory request) {
        request = requests[requestId];
    }

    /**
     * @notice Get user's requests
     * @param user User address
     * @return requestIds Array of request IDs
     */
    function getUserRequests(address user) external view returns (bytes32[] memory requestIds) {
        requestIds = userRequests[user];
    }

    /**
     * @notice Get cross-chain request details
     * @param requestId Request identifier
     * @return ccRequest Cross-chain request data
     */
    function getCrossChainRequest(
        bytes32 requestId
    ) external view returns (CrossChainRequest memory ccRequest) {
        ccRequest = crossChainRequests[requestId];
    }

    /**
     * @notice Estimate fee for a request
     * @param requestType Type of request
     * @param numParticipants Number of participants (for applicable requests)
     * @param isCrossChain Whether it's a cross-chain request
     * @return fee Estimated fee in wei
     */
    function estimateFee(
        RequestType requestType,
        uint8 numParticipants,
        bool isCrossChain
    ) external view returns (uint256 fee) {
        fee = feeConfig.baseFee;
        fee += uint256(numParticipants) * feeConfig.perParticipantFee;
        
        if (requestType == RequestType.ComputePrivate) {
            fee += feeConfig.computeFee;
        }
        
        if (isCrossChain) {
            fee += feeConfig.crossChainFee;
        }
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Set Shamir module
     * @param module Module address
     */
    function setShamirModule(address module) external onlyRole(GATEWAY_ADMIN_ROLE) {
        if (module == address(0)) revert ZeroAddress();
        address old = address(shamirModule);
        shamirModule = ShamirSecretSharing(module);
        emit ModuleUpdated("ShamirSecretSharing", old, module);
    }

    /**
     * @notice Set Threshold Signature module
     * @param module Module address
     */
    function setThresholdSigModule(address module) external onlyRole(GATEWAY_ADMIN_ROLE) {
        if (module == address(0)) revert ZeroAddress();
        address old = address(thresholdSigModule);
        thresholdSigModule = ThresholdSignature(module);
        emit ModuleUpdated("ThresholdSignature", old, module);
    }

    /**
     * @notice Set Coordinator module
     * @param module Module address
     */
    function setCoordinatorModule(address payable module) external onlyRole(GATEWAY_ADMIN_ROLE) {
        if (module == address(0)) revert ZeroAddress();
        address old = address(coordinatorModule);
        coordinatorModule = MPCCoordinator(module);
        emit ModuleUpdated("MPCCoordinator", old, module);
    }

    /**
     * @notice Set Key Registry module
     * @param module Module address
     */
    function setKeyRegistryModule(address module) external onlyRole(GATEWAY_ADMIN_ROLE) {
        if (module == address(0)) revert ZeroAddress();
        address old = address(keyRegistryModule);
        keyRegistryModule = MPCKeyRegistry(module);
        emit ModuleUpdated("MPCKeyRegistry", old, module);
    }

    /**
     * @notice Add supported chain
     * @param chainId Chain to support
     * @param messenger Messenger contract on that chain
     */
    function addSupportedChain(
        uint256 chainId,
        address messenger
    ) external onlyRole(GATEWAY_ADMIN_ROLE) {
        supportedChains[chainId] = true;
        chainMessengers[chainId] = messenger;
    }

    /**
     * @notice Remove supported chain
     * @param chainId Chain to remove
     */
    function removeSupportedChain(uint256 chainId) external onlyRole(GATEWAY_ADMIN_ROLE) {
        supportedChains[chainId] = false;
        chainMessengers[chainId] = address(0);
    }

    /**
     * @notice Update fee configuration
     * @param newConfig New fee configuration
     */
    function updateFeeConfig(FeeConfig calldata newConfig) external onlyRole(GATEWAY_ADMIN_ROLE) {
        feeConfig = newConfig;
    }

    /**
     * @notice Withdraw collected fees
     * @param recipient Recipient address
     * @param amount Amount to withdraw
     */
    function withdrawFees(
        address recipient,
        uint256 amount
    ) external onlyRole(GATEWAY_ADMIN_ROLE) {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount > address(this).balance) {
            amount = address(this).balance;
        }
        
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }
        
        emit FeeWithdrawn(recipient, amount);
    }

    /**
     * @notice Pause the gateway
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the gateway
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive function for ETH
     */
    receive() external payable {}
}
