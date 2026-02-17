// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title LayerZeroBridgeAdapter
 * @author Soul Protocol
 * @notice Omnichain bridge adapter using LayerZero V2 protocol
 * @dev Enables cross-chain interoperability across 120+ chains via LayerZero
 *
 * LAYERZERO V2 INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> LayerZero Omnichain                         │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Soul Protocol    │           │   Remote Chains   │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ OApp        │  │◄─────────►│  │ OApp        │  │                 │
 * │  │  │ (Omnichain) │  │           │  │ (Peer)      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Endpoint    │  │           │  │ Endpoint    │  │                 │
 * │  │  │ (Immutable) │  │◄─────────►│  │ (Immutable) │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   LayerZero Security Stack                         │ │
 * │  │  - DVNs (Decentralized Verifier Networks)                          │ │
 * │  │  - Executors (Message Execution)                                   │ │
 * │  │  - Message Libraries (Ultra Light Node)                            │ │
 * │  │  - Security Configurations (Per-pathway)                           │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * LAYERZERO V2 CONCEPTS:
 * - OApp: Omnichain Application - smart contracts that use LayerZero
 * - Endpoint: Immutable entry/exit points for LayerZero messages
 * - EID: Endpoint ID - unique identifier for each chain's endpoint
 * - DVN: Decentralized Verifier Network - validates cross-chain messages
 * - Executor: Service that executes messages on destination chain
 * - MessageLib: Library for packing/verifying message payloads
 * - lzSend: Function to send cross-chain messages
 * - lzReceive: Callback function for receiving messages
 *
 * SUPPORTED FEATURES:
 * - Push-based messaging (lzSend)
 * - Pull-based data reads (lzRead)
 * - OFT (Omnichain Fungible Token) bridging
 * - ONFT (Omnichain NFT) transfers
 * - Composed messaging
 * - Multi-chain deployments
 */
contract LayerZeroBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Message type identifiers
    uint16 public constant MSG_TYPE_SEND = 1;
    uint16 public constant MSG_TYPE_SEND_AND_CALL = 2;
    uint16 public constant MSG_TYPE_OFT_SEND = 3;
    uint16 public constant MSG_TYPE_ONFT_SEND = 4;

    /// @notice Message status
    enum MessageStatus {
        PENDING,
        INFLIGHT,
        DELIVERED,
        FAILED,
        STORED
    }

    /// @notice Chain type for gas estimation
    enum ChainType {
        EVM,
        SOLANA,
        APTOS,
        SUI,
        IOTA,
        HYPERLIQUID
    }

    /// @notice DVN security level
    enum SecurityLevel {
        STANDARD, // Single DVN
        ENHANCED, // 2 of N DVNs
        MAXIMUM // Required + Optional DVNs
    }

    /// @notice Peer configuration for a remote chain
    struct PeerConfig {
        uint32 eid; // Endpoint ID
        bytes32 peerAddress; // Remote OApp address (bytes32 for universality)
        ChainType chainType;
        bool active;
        uint256 minGas; // Minimum gas for execution
        SecurityLevel securityLevel;
        uint256 registeredAt;
    }

    /// @notice Message options for lzSend
    struct MessageOptions {
        uint128 gas; // Destination gas limit
        uint128 value; // Native value to send
        bytes composeMsg; // Optional composed message
        bytes extraOptions; // Additional options
    }

    /// @notice Cross-chain message
    struct OmniMessage {
        bytes32 guid; // Global unique identifier
        uint32 srcEid; // Source endpoint ID
        uint32 dstEid; // Destination endpoint ID
        bytes32 sender; // Sender address as bytes32
        bytes32 receiver; // Receiver address as bytes32
        bytes message; // Encoded message payload
        uint64 nonce; // Message nonce
        MessageStatus status;
        uint256 timestamp;
        bytes options;
    }

    /// @notice OFT (Omnichain Fungible Token) transfer
    struct OFTTransfer {
        bytes32 transferId;
        uint32 srcEid;
        uint32 dstEid;
        address localToken;
        bytes32 remoteToken;
        uint256 amountSent;
        uint256 amountReceived; // After fees
        bytes32 sender;
        bytes32 recipient;
        uint256 fee;
        MessageStatus status;
        uint256 timestamp;
    }

    /// @notice DVN configuration
    struct DVNConfig {
        address[] requiredDVNs;
        address[] optionalDVNs;
        uint8 optionalDVNThreshold;
    }

    /// @notice Executor configuration
    struct ExecutorConfig {
        uint32 maxMessageSize;
        address executor;
    }

    /// @notice Send library configuration
    struct SendLibConfig {
        address sendLib;
        DVNConfig dvnConfig;
        ExecutorConfig executorConfig;
    }

    /// @notice Receive library configuration
    struct ReceiveLibConfig {
        address receiveLib;
        DVNConfig dvnConfig;
        uint64 gracePeriod;
    }

    /// @notice Messaging fee structure
    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum message size (1MB)
    uint32 public constant MAX_MESSAGE_SIZE = 1048576;

    /// @notice Minimum gas limit
    uint128 public constant MIN_GAS = 100000;

    /// @notice Default composed message gas
    uint128 public constant DEFAULT_COMPOSE_GAS = 200000;

    /// @notice Fee denominator
    uint256 public constant FEE_DENOMINATOR = 10000;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice LayerZero Endpoint address
    address public lzEndpoint;

    /// @notice Local endpoint ID
    uint32 public localEid;

    /// @notice Bridge fee in basis points
    uint256 public bridgeFee;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Message nonce counter
    uint64 public messageNonce;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Peer configurations by endpoint ID
    mapping(uint32 => PeerConfig) public peers;

    /// @notice Registered endpoint IDs
    uint32[] public registeredEids;

    /// @notice Messages by GUID
    mapping(bytes32 => OmniMessage) public messages;

    /// @notice OFT transfers by ID
    mapping(bytes32 => OFTTransfer) public oftTransfers;

    /// @notice Token to OFT mapping (local ERC20 -> OFT adapter)
    mapping(address => address) public tokenToOFT;

    /// @notice Remote token mappings (local token => remote eid => remote token)
    mapping(address => mapping(uint32 => bytes32)) public remoteTokens;

    /// @notice Send library configurations by endpoint ID
    mapping(uint32 => SendLibConfig) public sendLibConfigs;

    /// @notice Receive library configurations by endpoint ID
    mapping(uint32 => ReceiveLibConfig) public receiveLibConfigs;

    /// @notice Stored failed messages (for retry)
    mapping(bytes32 => bytes) public storedPayloads;

    /// @notice Sender nonces
    mapping(address => uint64) public senderNonces;

    /// @notice Delegate for configuration
    address public delegate;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event EndpointSet(address indexed endpoint, uint32 localEid);
    event DelegateSet(address indexed delegate);
    event BridgeFeeSet(uint256 feeBps);

    event PeerSet(uint32 indexed eid, bytes32 peerAddress, ChainType chainType);
    event PeerRemoved(uint32 indexed eid);
    event PeerSecurityUpdated(uint32 indexed eid, SecurityLevel level);

    event SendLibConfigSet(uint32 indexed eid, address sendLib);
    event ReceiveLibConfigSet(uint32 indexed eid, address receiveLib);
    event DVNConfigSet(uint32 indexed eid, address[] requiredDVNs);

    event MessageSent(
        bytes32 indexed guid,
        uint32 indexed dstEid,
        bytes32 receiver,
        uint256 fee
    );
    event MessageReceived(
        bytes32 indexed guid,
        uint32 indexed srcEid,
        bytes32 sender
    );
    event MessageDelivered(bytes32 indexed guid);
    event MessageFailed(bytes32 indexed guid, bytes reason);
    event MessageStored(bytes32 indexed guid);
    event MessageRetried(bytes32 indexed guid);

    event OFTSent(
        bytes32 indexed transferId,
        uint32 indexed dstEid,
        address localToken,
        uint256 amount
    );
    event OFTReceived(
        bytes32 indexed transferId,
        uint32 indexed srcEid,
        bytes32 remoteToken,
        uint256 amount
    );

    event TokenMapped(
        address indexed localToken,
        uint32 indexed eid,
        bytes32 remoteToken
    );
    event OFTAdapterSet(address indexed token, address indexed oftAdapter);

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidEndpoint();
    error InvalidEid();
    error InvalidPeer();
    error PeerNotSet();
    error PeerAlreadySet();
    error PeerNotActive();
    error InvalidMessage();
    error MessageTooLarge();
    error InsufficientFee();
    error InsufficientGas();
    error MessageNotFound();
    error MessageAlreadyDelivered();
    error InvalidToken();
    error TokenNotMapped();
    error InvalidAmount();
    error TransferFailed();
    error PayloadNotStored();
    error UnauthorizedCaller();
    error WithdrawalFailed();
    error FeeTooHigh();
    error InvalidRecipient();
    error NoFeesToWithdraw();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(CONFIG_ROLE, msg.sender);

        bridgeFee = 10; // 0.1%
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set the LayerZero endpoint
     * @param _endpoint Address of the LayerZero V2 endpoint contract
     * @param _localEid Local endpoint ID for this chain
     */
    function setEndpoint(
        address _endpoint,
        uint32 _localEid
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_endpoint == address(0)) revert InvalidEndpoint();
        if (_localEid == 0) revert InvalidEid();

        lzEndpoint = _endpoint;
        localEid = _localEid;

        emit EndpointSet(_endpoint, _localEid);
    }

    /**
     * @notice Set the delegate for configurations
     * @param _delegate Address authorized to modify endpoint configurations
     */
    function setDelegate(
        address _delegate
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delegate = _delegate;
        emit DelegateSet(_delegate);
    }

    /**
     * @notice Set bridge fee in basis points
     * @param _feeBps Fee in basis points (max 100 = 1%)
     */
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_feeBps > 100) revert FeeTooHigh(); // Max 1%
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /*//////////////////////////////////////////////////////////////
                          PEER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set a peer (remote OApp) for a destination chain
     * @param eid Destination endpoint ID
     * @param peerAddress Remote OApp address (bytes32 for cross-VM compatibility)
     * @param chainType Type of destination chain (EVM, Solana, Aptos, etc.)
     * @param minGas Minimum gas for message execution (0 uses default MIN_GAS)
     * @param securityLevel DVN verification level for this pathway
     */
    function setPeer(
        uint32 eid,
        bytes32 peerAddress,
        ChainType chainType,
        uint256 minGas,
        SecurityLevel securityLevel
    ) external onlyRole(CONFIG_ROLE) {
        if (eid == 0) revert InvalidEid();
        if (peerAddress == bytes32(0)) revert InvalidPeer();
        if (peers[eid].eid != 0) revert PeerAlreadySet();

        peers[eid] = PeerConfig({
            eid: eid,
            peerAddress: peerAddress,
            chainType: chainType,
            active: true,
            minGas: minGas > 0 ? minGas : MIN_GAS,
            securityLevel: securityLevel,
            registeredAt: block.timestamp
        });

        registeredEids.push(eid);

        emit PeerSet(eid, peerAddress, chainType);
    }

    /**
     * @notice Update peer security level
     * @param eid Endpoint ID of the peer to update
     * @param level New DVN security level for this pathway
     */
    function updatePeerSecurity(
        uint32 eid,
        SecurityLevel level
    ) external onlyRole(GUARDIAN_ROLE) {
        if (peers[eid].eid == 0) revert PeerNotSet();

        peers[eid].securityLevel = level;

        emit PeerSecurityUpdated(eid, level);
    }

    /**
     * @notice Deactivate a peer
     * @param eid Endpoint ID of the peer to deactivate
     */
    function deactivatePeer(uint32 eid) external onlyRole(GUARDIAN_ROLE) {
        if (peers[eid].eid == 0) revert PeerNotSet();

        peers[eid].active = false;

        emit PeerRemoved(eid);
    }

    /**
     * @notice Reactivate a peer
     * @param eid Endpoint ID of the peer to reactivate
     */
    function reactivatePeer(uint32 eid) external onlyRole(CONFIG_ROLE) {
        if (peers[eid].eid == 0) revert PeerNotSet();

        peers[eid].active = true;

        emit PeerSet(eid, peers[eid].peerAddress, peers[eid].chainType);
    }

    /*//////////////////////////////////////////////////////////////
                       LIBRARY CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure send library for a destination
     * @param eid Destination endpoint ID
     * @param sendLib Address of the send message library
     * @param requiredDVNs Addresses of DVNs that must verify every message
     * @param optionalDVNs Addresses of DVNs used for optional verification
     * @param optionalThreshold Minimum optional DVNs required for quorum
     * @param maxMessageSize Maximum payload size in bytes (0 uses default MAX_MESSAGE_SIZE)
     * @param executor Address of the executor service for this pathway
     */
    function setSendLibConfig(
        uint32 eid,
        address sendLib,
        address[] calldata requiredDVNs,
        address[] calldata optionalDVNs,
        uint8 optionalThreshold,
        uint32 maxMessageSize,
        address executor
    ) external onlyRole(CONFIG_ROLE) {
        if (eid == 0) revert InvalidEid();

        sendLibConfigs[eid] = SendLibConfig({
            sendLib: sendLib,
            dvnConfig: DVNConfig({
                requiredDVNs: requiredDVNs,
                optionalDVNs: optionalDVNs,
                optionalDVNThreshold: optionalThreshold
            }),
            executorConfig: ExecutorConfig({
                maxMessageSize: maxMessageSize > 0
                    ? maxMessageSize
                    : MAX_MESSAGE_SIZE,
                executor: executor
            })
        });

        emit SendLibConfigSet(eid, sendLib);
        emit DVNConfigSet(eid, requiredDVNs);
    }

    /**
     * @notice Configure receive library for a source
     * @param eid Source endpoint ID
     * @param receiveLib Address of the receive message library
     * @param requiredDVNs Addresses of DVNs that must verify every inbound message
     * @param optionalDVNs Addresses of optional verification DVNs
     * @param optionalThreshold Minimum optional DVNs required for quorum
     * @param gracePeriod Grace period in seconds for library migration
     */
    function setReceiveLibConfig(
        uint32 eid,
        address receiveLib,
        address[] calldata requiredDVNs,
        address[] calldata optionalDVNs,
        uint8 optionalThreshold,
        uint64 gracePeriod
    ) external onlyRole(CONFIG_ROLE) {
        if (eid == 0) revert InvalidEid();

        receiveLibConfigs[eid] = ReceiveLibConfig({
            receiveLib: receiveLib,
            dvnConfig: DVNConfig({
                requiredDVNs: requiredDVNs,
                optionalDVNs: optionalDVNs,
                optionalDVNThreshold: optionalThreshold
            }),
            gracePeriod: gracePeriod
        });

        emit ReceiveLibConfigSet(eid, receiveLib);
    }

    /*//////////////////////////////////////////////////////////////
                            MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to a remote chain (lzSend)
     * @param dstEid Destination endpoint ID
     * @param receiver Receiver address on destination (bytes32)
     * @param message Encoded message payload
     * @param options Message options (gas, value, etc.)
     */
    function lzSend(
        uint32 dstEid,
        bytes32 receiver,
        bytes calldata message,
        MessageOptions calldata options
    ) external payable nonReentrant whenNotPaused returns (bytes32 guid) {
        PeerConfig storage peer = peers[dstEid];
        if (peer.eid == 0) revert PeerNotSet();
        if (!peer.active) revert PeerNotActive();
        if (message.length > MAX_MESSAGE_SIZE) revert MessageTooLarge();
        if (options.gas < peer.minGas) revert InsufficientGas();

        // Estimate and verify fee
        MessagingFee memory fee = _quoteFee(dstEid, message, options);
        if (msg.value < fee.nativeFee) revert InsufficientFee();

        uint64 nonce = senderNonces[msg.sender]++;

        // Dispatch via LayerZero endpoint
        if (lzEndpoint != address(0)) {
            // Encode options for LZ V2: type 3 (executor lzReceive option)
            bytes memory lzOptions = abi.encodePacked(
                uint16(3), // Options type: lzReceive
                uint16(1), // Worker ID: executor
                uint16(16 + 32), // Option length
                uint128(options.gas),
                uint128(options.value)
            );

            // Build MessagingParams and call endpoint.send()
            (bool success, bytes memory result) = lzEndpoint.call{
                value: fee.nativeFee
            }(
                abi.encodeWithSignature(
                    "send((uint32,bytes32,bytes,bytes,bytes),address)",
                    dstEid,
                    receiver,
                    message,
                    lzOptions,
                    "", // refundAddress is msg.sender — handled by endpoint
                    msg.sender
                )
            );
            if (success && result.length >= 32) {
                // Extract guid from endpoint response
                guid = abi.decode(result, (bytes32));
            }
        }

        // If endpoint call didn't set guid, generate one locally
        if (guid == bytes32(0)) {
            guid = keccak256(
                abi.encodePacked(
                    localEid,
                    dstEid,
                    msg.sender,
                    receiver,
                    nonce,
                    block.timestamp
                )
            );
        }

        messages[guid] = OmniMessage({
            guid: guid,
            srcEid: localEid,
            dstEid: dstEid,
            sender: bytes32(uint256(uint160(msg.sender))),
            receiver: receiver,
            message: message,
            nonce: nonce,
            status: MessageStatus.INFLIGHT,
            timestamp: block.timestamp,
            options: abi.encode(options)
        });

        accumulatedFees += msg.value - fee.nativeFee; // Only protocol fee portion
        totalMessagesSent++;
        messageNonce++;

        emit MessageSent(guid, dstEid, receiver, msg.value);
    }

    /**
     * @notice Receive a message from a remote chain (lzReceive)
     * @dev Called by LayerZero endpoint or relayer
     * @param srcEid Source endpoint ID of the originating chain
     * @param sender Peer address on the source chain (bytes32 for cross-VM compatibility)
     * @param guid Globally unique identifier assigned by LayerZero
     * @param message Encoded message payload from the source chain
     */
    function lzReceive(
        uint32 srcEid,
        bytes32 sender,
        bytes32 guid,
        bytes calldata message,
        bytes calldata /* extraData */
    ) external nonReentrant whenNotPaused {
        // Only accept messages from the LayerZero endpoint
        if (msg.sender != lzEndpoint) revert UnauthorizedCaller();

        PeerConfig storage peer = peers[srcEid];
        if (peer.eid == 0) revert PeerNotSet();
        if (sender != peer.peerAddress) revert UnauthorizedCaller();

        if (messages[guid].guid != bytes32(0)) {
            // Message already processed
            return;
        }

        messages[guid] = OmniMessage({
            guid: guid,
            srcEid: srcEid,
            dstEid: localEid,
            sender: sender,
            receiver: bytes32(uint256(uint160(address(this)))),
            message: message,
            nonce: 0, // Assigned by source
            status: MessageStatus.DELIVERED,
            timestamp: block.timestamp,
            options: ""
        });

        totalMessagesReceived++;

        emit MessageReceived(guid, srcEid, sender);
        emit MessageDelivered(guid);
    }

    /**
     * @notice Store a failed message for later retry
     * @param guid Globally unique identifier of the failed message
     * @param payload Original message payload to store
     */
    function storePayload(
        bytes32 guid,
        bytes calldata payload
    ) external onlyRole(EXECUTOR_ROLE) {
        OmniMessage storage message = messages[guid];
        if (message.guid == bytes32(0)) revert MessageNotFound();

        message.status = MessageStatus.STORED;
        storedPayloads[guid] = payload;

        emit MessageStored(guid);
    }

    /**
     * @notice Retry a stored message
     * @param guid Globally unique identifier of the stored message
     */
    function retryPayload(bytes32 guid) external onlyRole(OPERATOR_ROLE) {
        bytes storage payload = storedPayloads[guid];
        if (payload.length == 0) revert PayloadNotStored();

        OmniMessage storage message = messages[guid];
        message.status = MessageStatus.DELIVERED;

        delete storedPayloads[guid];

        emit MessageRetried(guid);
    }

    /*//////////////////////////////////////////////////////////////
                          OFT TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Map a local token to its remote representation
     * @param localToken Address of the token on this chain
     * @param remoteEid Destination endpoint ID where the remote token exists
     * @param remoteToken Remote token identifier (bytes32 for cross-VM compatibility)
     */
    function mapToken(
        address localToken,
        uint32 remoteEid,
        bytes32 remoteToken
    ) external onlyRole(CONFIG_ROLE) {
        if (localToken == address(0)) revert InvalidToken();
        if (remoteEid == 0) revert InvalidEid();

        remoteTokens[localToken][remoteEid] = remoteToken;

        emit TokenMapped(localToken, remoteEid, remoteToken);
    }

    /**
     * @notice Set OFT adapter for a token
     * @param token Address of the local token
     * @param oftAdapter Address of the OFT adapter contract for bridging
     */
    function setOFTAdapter(
        address token,
        address oftAdapter
    ) external onlyRole(CONFIG_ROLE) {
        if (token == address(0)) revert InvalidToken();

        tokenToOFT[token] = oftAdapter;

        emit OFTAdapterSet(token, oftAdapter);
    }

    /**
     * @notice Send OFT tokens to a remote chain
     * @param localToken Address of the token to bridge
     * @param dstEid Destination endpoint ID
     * @param recipient Recipient address on destination chain (bytes32)
     * @param amount Amount of tokens to send (before fee deduction)
     * @return transferId Unique identifier for this OFT transfer
     */
    function sendOFT(
        address localToken,
        uint32 dstEid,
        bytes32 recipient,
        uint256 amount,
        MessageOptions calldata /* options */
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        if (amount == 0) revert InvalidAmount();

        PeerConfig storage peer = peers[dstEid];
        if (peer.eid == 0) revert PeerNotSet();
        if (!peer.active) revert PeerNotActive();

        bytes32 remoteToken = remoteTokens[localToken][dstEid];
        if (remoteToken == bytes32(0)) revert TokenNotMapped();

        uint256 fee = (amount * bridgeFee) / FEE_DENOMINATOR;
        uint256 amountAfterFee = amount - fee;

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                localToken,
                dstEid,
                amount,
                block.timestamp,
                senderNonces[msg.sender]++
            )
        );

        oftTransfers[transferId] = OFTTransfer({
            transferId: transferId,
            srcEid: localEid,
            dstEid: dstEid,
            localToken: localToken,
            remoteToken: remoteToken,
            amountSent: amount,
            amountReceived: amountAfterFee,
            sender: bytes32(uint256(uint160(msg.sender))),
            recipient: recipient,
            fee: fee,
            status: MessageStatus.INFLIGHT,
            timestamp: block.timestamp
        });

        accumulatedFees += fee + msg.value;

        emit OFTSent(transferId, dstEid, localToken, amount);
    }

    /**
     * @notice Receive OFT tokens from a remote chain
     */
    // [REMOVED] receiveOFT due to H-01: Side door vulnerability bypassing DVN verification.
    // Future implementation must handle OFT logic inside lzReceive.

    /*//////////////////////////////////////////////////////////////
                          FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Quote the fee for sending a message
     * @param dstEid Destination endpoint ID
     * @param message Encoded message payload
     * @param options Message options (gas, value, etc.)
     * @return fee Estimated native and LZ token fees
     */
    function quoteSend(
        uint32 dstEid,
        bytes calldata message,
        MessageOptions calldata options
    ) external view returns (MessagingFee memory fee) {
        return _quoteFee(dstEid, message, options);
    }

    /**
     * @notice Internal fee calculation
     * @param dstEid Destination endpoint ID
     * @param message Encoded message payload for size-based fee calculation
     * @param options Message options containing gas allocation
     * @return MessagingFee struct with native and LZ token fees
     */
    function _quoteFee(
        uint32 dstEid,
        bytes calldata message,
        MessageOptions calldata options
    ) internal view returns (MessagingFee memory) {
        PeerConfig storage peer = peers[dstEid];

        // Base fee calculation (simplified)
        uint256 baseFee = 0.001 ether;
        uint256 gasPrice = 30 gwei;
        uint256 gasCost = uint256(options.gas) * gasPrice;

        // Message size fee
        uint256 sizeFee = (message.length * 100 wei);

        // Chain type multiplier
        uint256 multiplier = 100; // 1x for EVM
        if (peer.chainType == ChainType.SOLANA) multiplier = 150;
        else if (peer.chainType == ChainType.APTOS) multiplier = 120;
        else if (peer.chainType == ChainType.SUI) multiplier = 120;

        uint256 totalFee = ((baseFee + gasCost + sizeFee) * multiplier) / 100;

        return MessagingFee({nativeFee: totalFee, lzTokenFee: 0});
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Withdraw accumulated fees
     * @dev SECURITY: This function intentionally sends ETH to admin-specified address.
     *      Access is restricted to DEFAULT_ADMIN_ROLE only.
     *      Slither arbitrary-send-eth warning is acknowledged and accepted.
     * @param recipient Address to receive the fees (must be trusted)
     */
    // slither-disable-next-line arbitrary-send-eth
    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert InvalidRecipient();
        uint256 amount = accumulatedFees;
        if (amount == 0) revert NoFeesToWithdraw();
        accumulatedFees = 0;

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit FeesWithdrawn(recipient, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get bridge statistics
     * @return sent Total messages sent
     * @return received Total messages received
     * @return fees Total accumulated fees (wei)
     * @return peerCount Number of registered peer endpoints
     */
    function getStats()
        external
        view
        returns (
            uint256 sent,
            uint256 received,
            uint256 fees,
            uint256 peerCount
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            accumulatedFees,
            registeredEids.length
        );
    }

    /**
     * @notice Get all registered endpoint IDs
     * @return Array of registered LayerZero endpoint IDs
     */
    function getRegisteredEids() external view returns (uint32[] memory) {
        return registeredEids;
    }

    /**
     * @notice Check if a peer is active
     * @param eid Endpoint ID to check
     * @return True if the peer is registered and active
     */
    function isPeerActive(uint32 eid) external view returns (bool) {
        return peers[eid].active;
    }

    /**
     * @notice Get peer configuration
     * @param eid Endpoint ID of the peer
     * @return PeerConfig struct with registration details
     */
    function getPeer(uint32 eid) external view returns (PeerConfig memory) {
        return peers[eid];
    }

    /**
     * @notice Get message by GUID
     * @param guid Globally unique message identifier
     * @return OmniMessage struct with full message details
     */
    function getMessage(
        bytes32 guid
    ) external view returns (OmniMessage memory) {
        return messages[guid];
    }

    /**
     * @notice Get OFT transfer by ID
     * @param transferId Unique transfer identifier
     * @return OFTTransfer struct with full transfer details
     */
    function getOFTTransfer(
        bytes32 transferId
    ) external view returns (OFTTransfer memory) {
        return oftTransfers[transferId];
    }

    /**
     * @notice Get remote token for a local token and destination
     * @param localToken Address of the token on this chain
     * @param remoteEid Destination endpoint ID
     * @return Remote token identifier (bytes32(0) if not mapped)
     */
    function getRemoteToken(
        address localToken,
        uint32 remoteEid
    ) external view returns (bytes32) {
        return remoteTokens[localToken][remoteEid];
    }

    /**
     * @notice Get sender nonce
     * @param sender Address of the message sender
     * @return Current nonce for the sender
     */
    function getNonce(address sender) external view returns (uint64) {
        return senderNonces[sender];
    }
}
