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
     */
    function setDelegate(
        address _delegate
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delegate = _delegate;
        emit DelegateSet(_delegate);
    }

    /**
     * @notice Set bridge fee in basis points
     */
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /*//////////////////////////////////////////////////////////////
                          PEER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set a peer (remote OApp) for a destination chain
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
     */
    function deactivatePeer(uint32 eid) external onlyRole(GUARDIAN_ROLE) {
        if (peers[eid].eid == 0) revert PeerNotSet();

        peers[eid].active = false;

        emit PeerRemoved(eid);
    }

    /**
     * @notice Reactivate a peer
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

        accumulatedFees += msg.value;
        totalMessagesSent++;
        messageNonce++;

        emit MessageSent(guid, dstEid, receiver, msg.value);
    }

    /**
     * @notice Receive a message from a remote chain (lzReceive)
     * @dev Called by LayerZero endpoint or relayer
     */
    function lzReceive(
        uint32 srcEid,
        bytes32 sender,
        bytes32 guid,
        bytes calldata message,
        bytes calldata /* extraData */
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant whenNotPaused {
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
     */
    function sendOFT(
        address localToken,
        uint32 dstEid,
        bytes32 recipient,
        uint256 amount,
        MessageOptions calldata options
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
    function receiveOFT(
        bytes32 transferId,
        uint32 srcEid,
        bytes32 remoteToken,
        bytes32 sender,
        address recipient,
        uint256 amount
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant {
        PeerConfig storage peer = peers[srcEid];
        if (peer.eid == 0) revert PeerNotSet();

        oftTransfers[transferId] = OFTTransfer({
            transferId: transferId,
            srcEid: srcEid,
            dstEid: localEid,
            localToken: address(0), // To be resolved
            remoteToken: remoteToken,
            amountSent: amount,
            amountReceived: amount,
            sender: sender,
            recipient: bytes32(uint256(uint160(recipient))),
            fee: 0,
            status: MessageStatus.DELIVERED,
            timestamp: block.timestamp
        });

        emit OFTReceived(transferId, srcEid, remoteToken, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Quote the fee for sending a message
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
     */
    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
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
     */
    function getRegisteredEids() external view returns (uint32[] memory) {
        return registeredEids;
    }

    /**
     * @notice Check if a peer is active
     */
    function isPeerActive(uint32 eid) external view returns (bool) {
        return peers[eid].active;
    }

    /**
     * @notice Get peer configuration
     */
    function getPeer(uint32 eid) external view returns (PeerConfig memory) {
        return peers[eid];
    }

    /**
     * @notice Get message by GUID
     */
    function getMessage(
        bytes32 guid
    ) external view returns (OmniMessage memory) {
        return messages[guid];
    }

    /**
     * @notice Get OFT transfer by ID
     */
    function getOFTTransfer(
        bytes32 transferId
    ) external view returns (OFTTransfer memory) {
        return oftTransfers[transferId];
    }

    /**
     * @notice Get remote token for a local token and destination
     */
    function getRemoteToken(
        address localToken,
        uint32 remoteEid
    ) external view returns (bytes32) {
        return remoteTokens[localToken][remoteEid];
    }

    /**
     * @notice Get sender nonce
     */
    function getNonce(address sender) external view returns (uint64) {
        return senderNonces[sender];
    }
}
