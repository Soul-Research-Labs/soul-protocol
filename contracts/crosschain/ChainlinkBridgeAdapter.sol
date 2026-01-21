// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ChainlinkBridgeAdapter
 * @author PIL Protocol
 * @notice Cross-chain bridge adapter using Chainlink CCIP and oracle services
 * @dev Enables cross-chain interoperability via Chainlink's infrastructure
 *
 * CHAINLINK INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> Chainlink CCIP                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Remote Chains   │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ CCIP        │  │◄─────────►│  │ CCIP        │  │                 │
 * │  │  │ Sender      │  │           │  │ Receiver    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Router      │  │           │  │ Router      │  │                 │
 * │  │  │ (OnRamp)    │  │◄─────────►│  │ (OffRamp)   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Chainlink DON (Decentralized Oracle Network)     │ │
 * │  │  - CCIP (Cross-Chain Interoperability Protocol)                    │ │
 * │  │  - Data Feeds (Price Oracles)                                      │ │
 * │  │  - VRF (Verifiable Random Function)                                │ │
 * │  │  - Automation (Keepers)                                            │ │
 * │  │  - Functions (Serverless Compute)                                  │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * CHAINLINK CONCEPTS:
 * - CCIP: Cross-Chain Interoperability Protocol for secure messaging
 * - Router: Entry point for sending CCIP messages
 * - OnRamp: Source chain message processor
 * - OffRamp: Destination chain message executor
 * - Lane: Unidirectional path between two chains
 * - DON: Decentralized Oracle Network
 * - LINK: Native token for Chainlink payments
 * - Data Feeds: Decentralized price oracles
 * - VRF: Verifiable Random Function for on-chain randomness
 * - Automation: Decentralized smart contract automation
 * - Functions: Serverless compute for external API calls
 *
 * SUPPORTED FEATURES:
 * - CCIP Token Transfers
 * - CCIP Arbitrary Messaging
 * - CCIP Programmable Token Transfers
 * - Data Feed Integration
 * - VRF Integration
 * - Automation Integration
 */
contract ChainlinkBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant CCIP_ADMIN_ROLE = keccak256("CCIP_ADMIN_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Message type for CCIP
    enum CCIPMessageType {
        ARBITRARY_MESSAGE, // Data only
        TOKEN_TRANSFER, // Tokens only
        PROGRAMMABLE_TRANSFER // Tokens + Data
    }

    /// @notice Message status
    enum MessageStatus {
        PENDING,
        INFLIGHT,
        SUCCESS,
        FAILED
    }

    /// @notice Fee payment token
    enum FeeToken {
        NATIVE, // ETH/MATIC/etc
        LINK // LINK token
    }

    /// @notice Supported chain info
    struct ChainConfig {
        uint64 chainSelector; // CCIP chain selector
        address router; // CCIP router on that chain
        bytes32 peerAddress; // Our contract on that chain
        bool active;
        uint256 gasLimit; // Default gas limit
        uint256 registeredAt;
    }

    /// @notice CCIP message
    struct CCIPMessage {
        bytes32 messageId;
        uint64 sourceChainSelector;
        uint64 destChainSelector;
        address sender;
        bytes32 receiver;
        bytes data;
        CCIPMessageType messageType;
        MessageStatus status;
        uint256 timestamp;
        uint256 fees;
    }

    /// @notice Token amount for CCIP
    struct TokenAmount {
        address token;
        uint256 amount;
    }

    /// @notice CCIP token transfer
    struct CCIPTransfer {
        bytes32 messageId;
        uint64 sourceChainSelector;
        uint64 destChainSelector;
        address sender;
        bytes32 recipient;
        TokenAmount[] tokens;
        bytes data;
        MessageStatus status;
        uint256 timestamp;
    }

    /// @notice Data feed info
    struct DataFeed {
        address feedAddress;
        string description;
        uint8 decimals;
        uint256 heartbeat; // Maximum update interval
        bool active;
    }

    /// @notice VRF request
    struct VRFRequest {
        uint256 requestId;
        address requester;
        uint32 numWords;
        uint256[] randomWords;
        bool fulfilled;
        uint256 timestamp;
    }

    /// @notice Automation upkeep info
    struct UpkeepInfo {
        uint256 upkeepId;
        address target;
        bytes checkData;
        uint96 balance;
        bool active;
        uint256 lastPerformed;
    }

    /// @notice Functions request
    struct FunctionsRequest {
        bytes32 requestId;
        address requester;
        string source;
        bytes secrets;
        string[] args;
        bytes response;
        bytes error;
        bool fulfilled;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum gas limit for CCIP messages
    uint256 public constant MAX_GAS_LIMIT = 2_000_000;

    /// @notice Minimum gas limit for CCIP messages
    uint256 public constant MIN_GAS_LIMIT = 100_000;

    /// @notice Maximum data size (256KB)
    uint256 public constant MAX_DATA_SIZE = 262144;

    /// @notice Maximum tokens per message
    uint256 public constant MAX_TOKENS_PER_MESSAGE = 5;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice CCIP Router address
    address public ccipRouter;

    /// @notice LINK token address
    address public linkToken;

    /// @notice VRF Coordinator address
    address public vrfCoordinator;

    /// @notice Automation Registry address
    address public automationRegistry;

    /// @notice Functions Router address
    address public functionsRouter;

    /// @notice Default gas limit for messages
    uint256 public defaultGasLimit;

    /// @notice Bridge fee (basis points)
    uint256 public bridgeFee;

    /// @notice Accumulated fees in native token
    uint256 public accumulatedNativeFees;

    /// @notice Accumulated fees in LINK
    uint256 public accumulatedLinkFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value transferred (in USD)
    uint256 public totalValueTransferred;

    /// @notice Chain configurations by selector
    mapping(uint64 => ChainConfig) public chains;

    /// @notice Registered chain selectors
    uint64[] public registeredChains;

    /// @notice CCIP messages by ID
    mapping(bytes32 => CCIPMessage) public messages;

    /// @notice CCIP transfers by message ID
    mapping(bytes32 => CCIPTransfer) public transfers;

    /// @notice Token mappings (local -> remote chain -> remote token)
    mapping(address => mapping(uint64 => address)) public tokenMappings;

    /// @notice Supported tokens for CCIP
    mapping(address => bool) public supportedTokens;

    /// @notice Data feeds by asset
    mapping(bytes32 => DataFeed) public dataFeeds;

    /// @notice VRF requests
    mapping(uint256 => VRFRequest) public vrfRequests;

    /// @notice VRF subscription ID
    uint64 public vrfSubscriptionId;

    /// @notice VRF key hash
    bytes32 public vrfKeyHash;

    /// @notice Automation upkeeps
    mapping(uint256 => UpkeepInfo) public upkeeps;

    /// @notice Functions subscription ID
    uint64 public functionsSubscriptionId;

    /// @notice Functions DON ID
    bytes32 public functionsDonId;

    /// @notice Functions requests
    mapping(bytes32 => FunctionsRequest) public functionsRequests;

    /// @notice Sender nonces
    mapping(address => uint256) public senderNonces;

    /// @notice Allowed senders for receiving messages
    mapping(uint64 => mapping(bytes32 => bool)) public allowedSenders;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CCIPRouterSet(address indexed router);
    event LinkTokenSet(address indexed token);
    event VRFCoordinatorSet(address indexed coordinator);
    event AutomationRegistrySet(address indexed registry);
    event FunctionsRouterSet(address indexed router);
    event DefaultGasLimitSet(uint256 gasLimit);
    event BridgeFeeSet(uint256 feeBps);

    event ChainConfigured(
        uint64 indexed chainSelector,
        address router,
        bytes32 peerAddress
    );
    event ChainDeactivated(uint64 indexed chainSelector);

    event TokenSupported(address indexed token, bool supported);
    event TokenMapped(
        address indexed localToken,
        uint64 indexed chainSelector,
        address remoteToken
    );

    event CCIPMessageSent(
        bytes32 indexed messageId,
        uint64 indexed destChainSelector,
        CCIPMessageType messageType,
        uint256 fees
    );
    event CCIPMessageReceived(
        bytes32 indexed messageId,
        uint64 indexed sourceChainSelector,
        address sender
    );
    event CCIPMessageFailed(bytes32 indexed messageId, bytes reason);

    event CCIPTransferSent(
        bytes32 indexed messageId,
        uint64 indexed destChainSelector,
        address[] tokens,
        uint256[] amounts
    );
    event CCIPTransferReceived(
        bytes32 indexed messageId,
        uint64 indexed sourceChainSelector,
        address[] tokens,
        uint256[] amounts
    );

    event DataFeedRegistered(bytes32 indexed asset, address feed);
    event DataFeedUpdated(
        bytes32 indexed asset,
        int256 price,
        uint256 timestamp
    );

    event VRFRequested(uint256 indexed requestId, uint32 numWords);
    event VRFFulfilled(uint256 indexed requestId, uint256[] randomWords);

    event UpkeepRegistered(uint256 indexed upkeepId, address target);
    event UpkeepPerformed(uint256 indexed upkeepId);

    event FunctionsRequested(bytes32 indexed requestId, string source);
    event FunctionsFulfilled(bytes32 indexed requestId, bytes response);
    event FunctionsFailed(bytes32 indexed requestId, bytes error);

    event AllowedSenderSet(
        uint64 indexed chainSelector,
        bytes32 sender,
        bool allowed
    );
    event FeesWithdrawn(
        address indexed recipient,
        uint256 native,
        uint256 link
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidRouter();
    error InvalidChainSelector();
    error ChainNotSupported();
    error ChainNotActive();
    error InvalidReceiver();
    error InvalidMessage();
    error MessageTooLarge();
    error TooManyTokens();
    error TokenNotSupported();
    error InsufficientFee();
    error InvalidGasLimit();
    error MessageNotFound();
    error TransferNotFound();
    error UnauthorizedSender();
    error DataFeedNotFound();
    error VRFNotConfigured();
    error VRFRequestNotFound();
    error AutomationNotConfigured();
    error UpkeepNotFound();
    error FunctionsNotConfigured();
    error FunctionsRequestNotFound();
    error WithdrawalFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(CCIP_ADMIN_ROLE, msg.sender);

        defaultGasLimit = 200_000;
        bridgeFee = 10; // 0.1%
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set CCIP Router address
     */
    function setCCIPRouter(
        address _router
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_router == address(0)) revert InvalidRouter();
        ccipRouter = _router;
        emit CCIPRouterSet(_router);
    }

    /**
     * @notice Set LINK token address
     */
    function setLinkToken(
        address _token
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        linkToken = _token;
        emit LinkTokenSet(_token);
    }

    /**
     * @notice Set VRF Coordinator
     */
    function setVRFCoordinator(
        address _coordinator,
        uint64 _subscriptionId,
        bytes32 _keyHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        vrfCoordinator = _coordinator;
        vrfSubscriptionId = _subscriptionId;
        vrfKeyHash = _keyHash;
        emit VRFCoordinatorSet(_coordinator);
    }

    /**
     * @notice Set Automation Registry
     */
    function setAutomationRegistry(
        address _registry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        automationRegistry = _registry;
        emit AutomationRegistrySet(_registry);
    }

    /**
     * @notice Set Functions Router
     */
    function setFunctionsRouter(
        address _router,
        uint64 _subscriptionId,
        bytes32 _donId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        functionsRouter = _router;
        functionsSubscriptionId = _subscriptionId;
        functionsDonId = _donId;
        emit FunctionsRouterSet(_router);
    }

    /**
     * @notice Set default gas limit
     */
    function setDefaultGasLimit(
        uint256 _gasLimit
    ) external onlyRole(CCIP_ADMIN_ROLE) {
        if (_gasLimit < MIN_GAS_LIMIT || _gasLimit > MAX_GAS_LIMIT) {
            revert InvalidGasLimit();
        }
        defaultGasLimit = _gasLimit;
        emit DefaultGasLimitSet(_gasLimit);
    }

    /**
     * @notice Set bridge fee
     */
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /*//////////////////////////////////////////////////////////////
                       CHAIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a supported chain
     */
    function configureChain(
        uint64 chainSelector,
        address router,
        bytes32 peerAddress,
        uint256 gasLimit
    ) external onlyRole(CCIP_ADMIN_ROLE) {
        if (chainSelector == 0) revert InvalidChainSelector();

        if (chains[chainSelector].chainSelector == 0) {
            registeredChains.push(chainSelector);
        }

        chains[chainSelector] = ChainConfig({
            chainSelector: chainSelector,
            router: router,
            peerAddress: peerAddress,
            active: true,
            gasLimit: gasLimit > 0 ? gasLimit : defaultGasLimit,
            registeredAt: block.timestamp
        });

        emit ChainConfigured(chainSelector, router, peerAddress);
    }

    /**
     * @notice Deactivate a chain
     */
    function deactivateChain(
        uint64 chainSelector
    ) external onlyRole(GUARDIAN_ROLE) {
        if (chains[chainSelector].chainSelector == 0)
            revert ChainNotSupported();

        chains[chainSelector].active = false;

        emit ChainDeactivated(chainSelector);
    }

    /**
     * @notice Set allowed sender for a chain
     */
    function setAllowedSender(
        uint64 chainSelector,
        bytes32 sender,
        bool allowed
    ) external onlyRole(CCIP_ADMIN_ROLE) {
        allowedSenders[chainSelector][sender] = allowed;
        emit AllowedSenderSet(chainSelector, sender, allowed);
    }

    /*//////////////////////////////////////////////////////////////
                         TOKEN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set token support status
     */
    function setSupportedToken(
        address token,
        bool supported
    ) external onlyRole(CCIP_ADMIN_ROLE) {
        supportedTokens[token] = supported;
        emit TokenSupported(token, supported);
    }

    /**
     * @notice Map local token to remote token
     */
    function mapToken(
        address localToken,
        uint64 chainSelector,
        address remoteToken
    ) external onlyRole(CCIP_ADMIN_ROLE) {
        tokenMappings[localToken][chainSelector] = remoteToken;
        emit TokenMapped(localToken, chainSelector, remoteToken);
    }

    /*//////////////////////////////////////////////////////////////
                          CCIP MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send arbitrary message via CCIP
     */
    function sendMessage(
        uint64 destChainSelector,
        bytes32 receiver,
        bytes calldata data,
        uint256 gasLimit,
        FeeToken feeToken
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        ChainConfig storage chain = chains[destChainSelector];
        if (chain.chainSelector == 0) revert ChainNotSupported();
        if (!chain.active) revert ChainNotActive();
        if (receiver == bytes32(0)) revert InvalidReceiver();
        if (data.length > MAX_DATA_SIZE) revert MessageTooLarge();

        uint256 effectiveGasLimit = gasLimit > 0 ? gasLimit : chain.gasLimit;
        if (
            effectiveGasLimit < MIN_GAS_LIMIT ||
            effectiveGasLimit > MAX_GAS_LIMIT
        ) {
            revert InvalidGasLimit();
        }

        uint256 nonce = senderNonces[msg.sender]++;

        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                destChainSelector,
                receiver,
                nonce,
                block.timestamp
            )
        );

        uint256 fees = _estimateFee(
            destChainSelector,
            data.length,
            effectiveGasLimit
        );
        if (feeToken == FeeToken.NATIVE) {
            if (msg.value < fees) revert InsufficientFee();
            accumulatedNativeFees += msg.value;
        } else {
            // LINK payment would be handled here
            accumulatedLinkFees += fees;
        }

        messages[messageId] = CCIPMessage({
            messageId: messageId,
            sourceChainSelector: 0, // Local chain
            destChainSelector: destChainSelector,
            sender: msg.sender,
            receiver: receiver,
            data: data,
            messageType: CCIPMessageType.ARBITRARY_MESSAGE,
            status: MessageStatus.INFLIGHT,
            timestamp: block.timestamp,
            fees: fees
        });

        totalMessagesSent++;

        emit CCIPMessageSent(
            messageId,
            destChainSelector,
            CCIPMessageType.ARBITRARY_MESSAGE,
            fees
        );
    }

    /**
     * @notice Send tokens via CCIP
     */
    function sendTokens(
        uint64 destChainSelector,
        bytes32 recipient,
        TokenAmount[] calldata tokens,
        bytes calldata data,
        uint256 gasLimit,
        FeeToken feeToken
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        ChainConfig storage chain = chains[destChainSelector];
        if (chain.chainSelector == 0) revert ChainNotSupported();
        if (!chain.active) revert ChainNotActive();
        if (recipient == bytes32(0)) revert InvalidReceiver();
        if (tokens.length > MAX_TOKENS_PER_MESSAGE) revert TooManyTokens();

        // Validate tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            if (!supportedTokens[tokens[i].token]) revert TokenNotSupported();
        }

        uint256 effectiveGasLimit = gasLimit > 0 ? gasLimit : chain.gasLimit;
        uint256 nonce = senderNonces[msg.sender]++;

        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                destChainSelector,
                recipient,
                nonce,
                block.timestamp
            )
        );

        CCIPMessageType msgType = data.length > 0
            ? CCIPMessageType.PROGRAMMABLE_TRANSFER
            : CCIPMessageType.TOKEN_TRANSFER;

        uint256 fees = _estimateFee(
            destChainSelector,
            data.length,
            effectiveGasLimit
        );
        if (feeToken == FeeToken.NATIVE) {
            if (msg.value < fees) revert InsufficientFee();
            accumulatedNativeFees += msg.value;
        }

        // Store transfer details
        transfers[messageId].messageId = messageId;
        transfers[messageId].sourceChainSelector = 0;
        transfers[messageId].destChainSelector = destChainSelector;
        transfers[messageId].sender = msg.sender;
        transfers[messageId].recipient = recipient;
        transfers[messageId].data = data;
        transfers[messageId].status = MessageStatus.INFLIGHT;
        transfers[messageId].timestamp = block.timestamp;

        // Copy tokens array
        for (uint256 i = 0; i < tokens.length; i++) {
            transfers[messageId].tokens.push(tokens[i]);
            totalValueTransferred += tokens[i].amount; // Simplified
        }

        totalMessagesSent++;

        // Emit event with token details
        address[] memory tokenAddrs = new address[](tokens.length);
        uint256[] memory amounts = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenAddrs[i] = tokens[i].token;
            amounts[i] = tokens[i].amount;
        }

        emit CCIPTransferSent(
            messageId,
            destChainSelector,
            tokenAddrs,
            amounts
        );
        emit CCIPMessageSent(messageId, destChainSelector, msgType, fees);
    }

    /**
     * @notice Receive message from CCIP (called by router)
     */
    function ccipReceive(
        bytes32 messageId,
        uint64 sourceChainSelector,
        bytes32 sender,
        bytes calldata data
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        if (!allowedSenders[sourceChainSelector][sender]) {
            revert UnauthorizedSender();
        }

        messages[messageId] = CCIPMessage({
            messageId: messageId,
            sourceChainSelector: sourceChainSelector,
            destChainSelector: 0, // Local chain
            sender: address(uint160(uint256(sender))),
            receiver: bytes32(uint256(uint160(address(this)))),
            data: data,
            messageType: CCIPMessageType.ARBITRARY_MESSAGE,
            status: MessageStatus.SUCCESS,
            timestamp: block.timestamp,
            fees: 0
        });

        totalMessagesReceived++;

        emit CCIPMessageReceived(
            messageId,
            sourceChainSelector,
            address(uint160(uint256(sender)))
        );
    }

    /**
     * @notice Receive tokens from CCIP
     */
    function ccipReceiveTokens(
        bytes32 messageId,
        uint64 sourceChainSelector,
        bytes32 sender,
        TokenAmount[] calldata tokens,
        bytes calldata data
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        if (!allowedSenders[sourceChainSelector][sender]) {
            revert UnauthorizedSender();
        }

        transfers[messageId].messageId = messageId;
        transfers[messageId].sourceChainSelector = sourceChainSelector;
        transfers[messageId].destChainSelector = 0;
        transfers[messageId].sender = address(uint160(uint256(sender)));
        transfers[messageId].recipient = bytes32(
            uint256(uint160(address(this)))
        );
        transfers[messageId].data = data;
        transfers[messageId].status = MessageStatus.SUCCESS;
        transfers[messageId].timestamp = block.timestamp;

        for (uint256 i = 0; i < tokens.length; i++) {
            transfers[messageId].tokens.push(tokens[i]);
        }

        totalMessagesReceived++;

        // Emit event
        address[] memory tokenAddrs = new address[](tokens.length);
        uint256[] memory amounts = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenAddrs[i] = tokens[i].token;
            amounts[i] = tokens[i].amount;
        }

        emit CCIPTransferReceived(
            messageId,
            sourceChainSelector,
            tokenAddrs,
            amounts
        );
    }

    /*//////////////////////////////////////////////////////////////
                          DATA FEEDS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a data feed
     */
    function registerDataFeed(
        bytes32 asset,
        address feedAddress,
        string calldata description,
        uint8 decimals,
        uint256 heartbeat
    ) external onlyRole(ORACLE_ROLE) {
        dataFeeds[asset] = DataFeed({
            feedAddress: feedAddress,
            description: description,
            decimals: decimals,
            heartbeat: heartbeat,
            active: true
        });

        emit DataFeedRegistered(asset, feedAddress);
    }

    /**
     * @notice Get latest price from data feed
     */
    function getLatestPrice(
        bytes32 asset
    ) external view returns (int256 price, uint256 timestamp, uint8 decimals) {
        DataFeed storage feed = dataFeeds[asset];
        if (feed.feedAddress == address(0)) revert DataFeedNotFound();

        // In production, call the actual Chainlink aggregator
        // For now, return placeholder
        return (0, block.timestamp, feed.decimals);
    }

    /*//////////////////////////////////////////////////////////////
                          VRF FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request random words from VRF
     */
    function requestRandomWords(
        uint32 numWords
    ) external onlyRole(OPERATOR_ROLE) returns (uint256 requestId) {
        if (vrfCoordinator == address(0)) revert VRFNotConfigured();

        // Generate request ID (in production, get from coordinator)
        requestId = uint256(
            keccak256(abi.encodePacked(msg.sender, block.timestamp, numWords))
        );

        vrfRequests[requestId] = VRFRequest({
            requestId: requestId,
            requester: msg.sender,
            numWords: numWords,
            randomWords: new uint256[](0),
            fulfilled: false,
            timestamp: block.timestamp
        });

        emit VRFRequested(requestId, numWords);
    }

    /**
     * @notice Fulfill VRF request (called by coordinator)
     */
    function fulfillRandomWords(
        uint256 requestId,
        uint256[] calldata randomWords
    ) external onlyRole(ORACLE_ROLE) {
        VRFRequest storage request = vrfRequests[requestId];
        if (request.requestId == 0) revert VRFRequestNotFound();

        request.randomWords = randomWords;
        request.fulfilled = true;

        emit VRFFulfilled(requestId, randomWords);
    }

    /*//////////////////////////////////////////////////////////////
                       AUTOMATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an upkeep
     */
    function registerUpkeep(
        uint256 upkeepId,
        address target,
        bytes calldata checkData,
        uint96 balance
    ) external onlyRole(OPERATOR_ROLE) {
        if (automationRegistry == address(0)) revert AutomationNotConfigured();

        upkeeps[upkeepId] = UpkeepInfo({
            upkeepId: upkeepId,
            target: target,
            checkData: checkData,
            balance: balance,
            active: true,
            lastPerformed: 0
        });

        emit UpkeepRegistered(upkeepId, target);
    }

    /**
     * @notice Record upkeep performance
     */
    function recordUpkeepPerformed(
        uint256 upkeepId
    ) external onlyRole(ORACLE_ROLE) {
        UpkeepInfo storage upkeep = upkeeps[upkeepId];
        if (upkeep.upkeepId == 0) revert UpkeepNotFound();

        upkeep.lastPerformed = block.timestamp;

        emit UpkeepPerformed(upkeepId);
    }

    /*//////////////////////////////////////////////////////////////
                      FUNCTIONS (SERVERLESS)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a Functions request
     */
    function sendFunctionsRequest(
        string calldata source,
        bytes calldata secrets,
        string[] calldata args
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 requestId) {
        if (functionsRouter == address(0)) revert FunctionsNotConfigured();

        requestId = keccak256(
            abi.encodePacked(msg.sender, source, block.timestamp)
        );

        functionsRequests[requestId] = FunctionsRequest({
            requestId: requestId,
            requester: msg.sender,
            source: source,
            secrets: secrets,
            args: args,
            response: "",
            error: "",
            fulfilled: false,
            timestamp: block.timestamp
        });

        emit FunctionsRequested(requestId, source);
    }

    /**
     * @notice Fulfill Functions request
     */
    function fulfillFunctionsRequest(
        bytes32 requestId,
        bytes calldata response,
        bytes calldata err
    ) external onlyRole(ORACLE_ROLE) {
        FunctionsRequest storage request = functionsRequests[requestId];
        if (request.requestId == bytes32(0)) revert FunctionsRequestNotFound();

        request.response = response;
        request.error = err;
        request.fulfilled = true;

        if (err.length > 0) {
            emit FunctionsFailed(requestId, err);
        } else {
            emit FunctionsFulfilled(requestId, response);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Estimate fee for a message
     */
    function estimateFee(
        uint64 destChainSelector,
        uint256 dataSize,
        uint256 gasLimit
    ) external view returns (uint256) {
        return _estimateFee(destChainSelector, dataSize, gasLimit);
    }

    /**
     * @notice Internal fee estimation
     */
    function _estimateFee(
        uint64 /* destChainSelector */,
        uint256 dataSize,
        uint256 gasLimit
    ) internal view returns (uint256) {
        // Simplified fee calculation
        uint256 baseFee = 0.002 ether;
        uint256 gasFee = gasLimit * 50 gwei;
        uint256 dataFee = dataSize * 100 wei;

        return baseFee + gasFee + dataFee;
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
        uint256 nativeAmount = accumulatedNativeFees;
        uint256 linkAmount = accumulatedLinkFees;

        accumulatedNativeFees = 0;
        accumulatedLinkFees = 0;

        if (nativeAmount > 0) {
            (bool success, ) = recipient.call{value: nativeAmount}("");
            if (!success) revert WithdrawalFailed();
        }

        // LINK withdrawal would be handled separately

        emit FeesWithdrawn(recipient, nativeAmount, linkAmount);
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
            uint256 valueBridged,
            uint256 nativeFees,
            uint256 linkFees
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            totalValueTransferred,
            accumulatedNativeFees,
            accumulatedLinkFees
        );
    }

    /**
     * @notice Get all registered chains
     */
    function getRegisteredChains() external view returns (uint64[] memory) {
        return registeredChains;
    }

    /**
     * @notice Check if chain is supported and active
     */
    function isChainActive(uint64 chainSelector) external view returns (bool) {
        return chains[chainSelector].active;
    }

    /**
     * @notice Get chain configuration
     */
    function getChainConfig(
        uint64 chainSelector
    ) external view returns (ChainConfig memory) {
        return chains[chainSelector];
    }

    /**
     * @notice Get message details
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (CCIPMessage memory) {
        return messages[messageId];
    }

    /**
     * @notice Get transfer details
     */
    function getTransfer(
        bytes32 messageId
    ) external view returns (CCIPTransfer memory) {
        return transfers[messageId];
    }

    /**
     * @notice Get VRF request
     */
    function getVRFRequest(
        uint256 requestId
    ) external view returns (VRFRequest memory) {
        return vrfRequests[requestId];
    }

    /**
     * @notice Get Functions request
     */
    function getFunctionsRequest(
        bytes32 requestId
    ) external view returns (FunctionsRequest memory) {
        return functionsRequests[requestId];
    }

    /**
     * @notice Get sender nonce
     */
    function getNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }
}
