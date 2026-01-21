// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CosmosBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Cosmos ecosystem and IBC protocol integration
 * @dev Enables cross-chain interoperability between PIL (EVM) and Cosmos SDK chains via IBC
 *
 * COSMOS/IBC INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> Cosmos/IBC Bridge                           │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Cosmos Hub      │                 │
 * │  │  (EVM/Solidity)   │           │  (Tendermint)     │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ERC20/721   │  │◄─────────►│  │ ICS-20      │  │                 │
 * │  │  │ Tokens      │  │           │  │ Tokens      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Messages    │  │           │  │ IBC         │  │                 │
 * │  │  │             │  │◄─────────►│  │ Packets     │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Protocol Layer                            │ │
 * │  │  - IBC Light Client Verification                                   │ │
 * │  │  - Tendermint Consensus Proofs                                     │ │
 * │  │  - ICS-20 Token Transfers                                          │ │
 * │  │  - ICS-27 Interchain Accounts                                      │ │
 * │  │  - ICS-721 NFT Transfers                                           │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * IBC CONCEPTS:
 * - Light Client: Verifies consensus of counterparty chain
 * - Connection: Established between two light clients
 * - Channel: Message pathway with ordering guarantees
 * - Packet: Unit of data sent over a channel
 * - ICS-20: Fungible token transfer standard
 * - ICS-27: Interchain accounts for cross-chain contract calls
 * - ICS-721: Non-fungible token transfer standard
 *
 * SUPPORTED CHAINS:
 * - Cosmos Hub (ATOM)
 * - Osmosis (OSMO)
 * - Celestia (TIA)
 * - dYdX (DYDX)
 * - Injective (INJ)
 * - Stride (STRD)
 * - Neutron (NTRN)
 * - Noble (USDC)
 * - Sei (SEI)
 * - Kava (KAVA)
 */
contract CosmosBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant LIGHT_CLIENT_ROLE = keccak256("LIGHT_CLIENT_ROLE");

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice IBC channel state
    enum ChannelState {
        UNINITIALIZED,
        INIT,
        TRYOPEN,
        OPEN,
        CLOSED
    }

    /// @notice IBC packet state
    enum PacketState {
        PENDING,
        ACKNOWLEDGED,
        TIMED_OUT,
        RECEIVED
    }

    /// @notice ICS standard type
    enum ICSType {
        ICS20_TRANSFER, // Fungible tokens
        ICS27_ICA, // Interchain accounts
        ICS721_NFT // Non-fungible tokens
    }

    /// @notice Channel ordering
    enum ChannelOrdering {
        UNORDERED,
        ORDERED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cosmos chain configuration
    struct ChainConfig {
        string chainId; // e.g., "cosmoshub-4"
        bytes32 chainIdHash; // Hash for lookup
        uint64 trustingPeriod; // Light client trusting period
        uint64 unbondingPeriod; // Validator unbonding period
        string bech32Prefix; // e.g., "cosmos"
        bool active; // Is chain active
        uint256 registeredAt; // Registration timestamp
    }

    /// @notice IBC Light Client state
    struct LightClient {
        bytes32 clientId; // Client identifier
        bytes32 chainIdHash; // Target chain
        bytes32 latestHeight; // Latest verified height (revision_number || revision_height)
        bytes32 consensusStateRoot; // Latest consensus state root
        uint64 trustingPeriod; // Seconds
        uint256 frozenHeight; // 0 if not frozen
        uint256 lastUpdate; // Last update timestamp
    }

    /// @notice IBC Connection
    struct Connection {
        bytes32 connectionId; // Connection identifier
        bytes32 clientId; // Associated light client
        bytes32 counterpartyConnectionId; // Counterparty connection ID
        bytes32 counterpartyClientId; // Counterparty client ID
        uint8 state; // Connection state (same as ChannelState)
        uint256 createdAt; // Creation timestamp
    }

    /// @notice IBC Channel
    struct Channel {
        bytes32 channelId; // Channel identifier
        bytes32 connectionId; // Associated connection
        bytes32 counterpartyChannelId; // Counterparty channel ID
        string portId; // Port identifier (e.g., "transfer")
        ChannelState state; // Channel state
        ChannelOrdering ordering; // ORDERED or UNORDERED
        string version; // Channel version (e.g., "ics20-1")
        uint64 nextSequenceSend; // Next packet sequence to send
        uint64 nextSequenceRecv; // Next packet sequence to receive
        uint64 nextSequenceAck; // Next packet sequence to acknowledge
    }

    /// @notice IBC Packet
    struct Packet {
        bytes32 packetId; // Unique packet identifier
        uint64 sequence; // Packet sequence number
        bytes32 sourceChannelId; // Source channel
        bytes32 destChannelId; // Destination channel
        string sourcePort; // Source port
        string destPort; // Destination port
        bytes data; // Packet data (ICS-20, ICS-27, etc.)
        uint64 timeoutHeight; // Timeout block height
        uint64 timeoutTimestamp; // Timeout timestamp (nanoseconds)
        PacketState state; // Packet state
        uint256 createdAt; // Creation timestamp
    }

    /// @notice ICS-20 Token Transfer
    struct TokenTransfer {
        bytes32 transferId; // Unique transfer identifier
        string denom; // Token denomination
        uint256 amount; // Transfer amount
        address sender; // EVM sender
        string receiver; // Cosmos receiver (bech32)
        bytes32 channelId; // IBC channel
        uint64 timeoutHeight; // Timeout height
        uint64 timeoutTimestamp; // Timeout timestamp
        bool completed; // Transfer completed
        bool refunded; // Transfer refunded
        uint256 initiatedAt; // Initiation timestamp
    }

    /// @notice ICS-27 Interchain Account
    struct InterchainAccount {
        bytes32 accountId; // Account identifier
        address owner; // EVM owner
        string hostAddress; // Address on host chain
        bytes32 connectionId; // Associated connection
        bytes32 channelId; // Associated channel
        bool active; // Is account active
        uint256 createdAt; // Creation timestamp
    }

    /// @notice Tendermint consensus state
    struct ConsensusState {
        uint64 timestamp; // Block timestamp
        bytes32 root; // App state root (commitment root)
        bytes32 nextValidatorsHash; // Hash of next validator set
    }

    /// @notice Tendermint header for light client updates
    struct TendermintHeader {
        bytes32 chainIdHash; // Chain identifier hash
        uint64 height; // Block height
        uint64 time; // Block timestamp
        bytes32 lastBlockId; // Previous block hash
        bytes32 lastCommitHash; // Last commit hash
        bytes32 dataHash; // Merkle root of transactions
        bytes32 validatorsHash; // Current validators hash
        bytes32 nextValidatorsHash; // Next validators hash
        bytes32 consensusHash; // Consensus params hash
        bytes32 appHash; // Application state hash
        bytes32 lastResultsHash; // Last results hash
        bytes32 evidenceHash; // Evidence hash
        bytes32 proposerAddress; // Block proposer
    }

    /// @notice Registered denomination
    struct RegisteredDenom {
        string baseDenom; // Base denomination
        bytes32 denomHash; // Hash for lookup
        address evmToken; // Mapped EVM token (address(0) for native)
        uint8 decimals; // Token decimals
        string ibcPath; // IBC path (e.g., "transfer/channel-0")
        bool isNative; // Is native to this chain
        uint256 totalBridged; // Total bridged amount
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum transfer amount
    uint256 public minTransferAmount;

    /// @notice Maximum transfer amount
    uint256 public maxTransferAmount;

    /// @notice Default timeout in seconds
    uint64 public defaultTimeout;

    /// @notice Guardian threshold
    uint256 public guardianThreshold;

    /// @notice Guardian count
    uint256 public guardianCount;

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Treasury address
    address public treasury;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered chains
    mapping(bytes32 => ChainConfig) public chains;
    bytes32[] public chainIds;

    /// @notice Light clients
    mapping(bytes32 => LightClient) public lightClients;
    bytes32[] public lightClientIds;

    /// @notice Connections
    mapping(bytes32 => Connection) public connections;
    bytes32[] public connectionIds;

    /// @notice Channels
    mapping(bytes32 => Channel) public channels;
    bytes32[] public channelIds;

    /// @notice Packets by ID
    mapping(bytes32 => Packet) public packets;

    /// @notice Packet commitments (for verification)
    mapping(bytes32 => bytes32) public packetCommitments;

    /// @notice Packet receipts (received packets)
    mapping(bytes32 => bool) public packetReceipts;

    /// @notice Packet acknowledgements
    mapping(bytes32 => bytes32) public packetAcknowledgements;

    /// @notice Token transfers
    mapping(bytes32 => TokenTransfer) public tokenTransfers;

    /// @notice User transfers
    mapping(address => bytes32[]) public userTransfers;

    /// @notice Interchain accounts
    mapping(bytes32 => InterchainAccount) public interchainAccounts;

    /// @notice User's interchain accounts
    mapping(address => bytes32[]) public userICAAccounts;

    /// @notice Registered denominations
    mapping(bytes32 => RegisteredDenom) public denoms;
    bytes32[] public denomHashes;

    /// @notice EVM token to denom mapping
    mapping(address => bytes32) public evmTokenToDenom;

    /// @notice Consensus states by client and height
    mapping(bytes32 => mapping(uint64 => ConsensusState))
        public consensusStates;

    /// @notice Guardian approvals
    mapping(bytes32 => mapping(address => bool)) public guardianApprovals;
    mapping(bytes32 => uint256) public approvalCounts;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalPacketsSent;
    uint256 public totalPacketsReceived;
    uint256 public totalTransfersOut;
    uint256 public totalTransfersIn;
    uint256 public totalValueBridged;
    uint256 public totalFeesCollected;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ChainRegistered(bytes32 indexed chainIdHash, string chainId);
    event LightClientCreated(bytes32 indexed clientId, bytes32 chainIdHash);
    event LightClientUpdated(bytes32 indexed clientId, bytes32 newHeight);
    event ConnectionOpened(bytes32 indexed connectionId, bytes32 clientId);
    event ChannelOpened(
        bytes32 indexed channelId,
        bytes32 connectionId,
        string portId
    );
    event ChannelClosed(bytes32 indexed channelId);

    event PacketSent(
        bytes32 indexed packetId,
        uint64 sequence,
        bytes32 sourceChannel,
        bytes32 destChannel
    );

    event PacketReceived(
        bytes32 indexed packetId,
        uint64 sequence,
        bytes32 sourceChannel
    );

    event PacketAcknowledged(bytes32 indexed packetId, bool success);
    event PacketTimedOut(bytes32 indexed packetId);

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        string receiver,
        string denom,
        uint256 amount
    );

    event TransferCompleted(bytes32 indexed transferId);
    event TransferRefunded(bytes32 indexed transferId);

    event ICACreated(
        bytes32 indexed accountId,
        address owner,
        string hostAddress
    );
    event ICAExecuted(bytes32 indexed accountId, bytes32 txHash);

    event DenomRegistered(
        bytes32 indexed denomHash,
        string baseDenom,
        address evmToken
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error ChainNotRegistered();
    error ChainAlreadyRegistered();
    error ClientNotFound();
    error ClientFrozen();
    error ConnectionNotFound();
    error ConnectionNotOpen();
    error ChannelNotFound();
    error ChannelNotOpen();
    error ChannelIsClosedError();
    error InvalidPacket();
    error PacketNotFound();
    error PacketAlreadyReceived();
    error PacketTimedOutError();
    error InvalidDenom();
    error DenomNotRegistered();
    error InvalidAmount();
    error AmountTooLow();
    error AmountTooHigh();
    error InsufficientFee();
    error TransferNotFound();
    error TransferIsCompletedError();
    error TransferAlreadyRefunded();
    error InvalidReceiver();
    error InvalidProof();
    error ProofVerificationFailed();
    error ConsensusStateNotFound();
    error HeightNotFound();
    error ICANotFound();
    error ICANotActive();
    error NotAccountOwner();
    error InsufficientGuardianApprovals();
    error AlreadyApproved();
    error InvalidTimeout();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, uint256 _guardianThreshold) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        guardianThreshold = _guardianThreshold;
        guardianCount = 1;

        bridgeFee = 25; // 0.25%
        minTransferAmount = 1e15;
        maxTransferAmount = 1e24;
        defaultTimeout = 600; // 10 minutes
    }

    /*//////////////////////////////////////////////////////////////
                         CHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a Cosmos chain
     */
    function registerChain(
        string calldata chainId,
        uint64 trustingPeriod,
        uint64 unbondingPeriod,
        string calldata bech32Prefix
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 chainIdHash = keccak256(bytes(chainId));
        if (chains[chainIdHash].registeredAt != 0)
            revert ChainAlreadyRegistered();

        chains[chainIdHash] = ChainConfig({
            chainId: chainId,
            chainIdHash: chainIdHash,
            trustingPeriod: trustingPeriod,
            unbondingPeriod: unbondingPeriod,
            bech32Prefix: bech32Prefix,
            active: true,
            registeredAt: block.timestamp
        });

        chainIds.push(chainIdHash);

        emit ChainRegistered(chainIdHash, chainId);
    }

    /**
     * @notice Get chain configuration
     */
    function getChain(
        bytes32 chainIdHash
    ) external view returns (ChainConfig memory) {
        return chains[chainIdHash];
    }

    /*//////////////////////////////////////////////////////////////
                       LIGHT CLIENT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new IBC light client
     */
    function createLightClient(
        bytes32 clientId,
        bytes32 chainIdHash,
        uint64 trustingPeriod,
        bytes32 initialHeight,
        bytes32 consensusStateRoot,
        bytes32 nextValidatorsHash
    ) external onlyRole(LIGHT_CLIENT_ROLE) {
        if (chains[chainIdHash].registeredAt == 0) revert ChainNotRegistered();

        lightClients[clientId] = LightClient({
            clientId: clientId,
            chainIdHash: chainIdHash,
            latestHeight: initialHeight,
            consensusStateRoot: consensusStateRoot,
            trustingPeriod: trustingPeriod,
            frozenHeight: 0,
            lastUpdate: block.timestamp
        });

        // Store initial consensus state
        uint64 height = uint64(uint256(initialHeight));
        consensusStates[clientId][height] = ConsensusState({
            timestamp: uint64(block.timestamp),
            root: consensusStateRoot,
            nextValidatorsHash: nextValidatorsHash
        });

        lightClientIds.push(clientId);

        emit LightClientCreated(clientId, chainIdHash);
    }

    /**
     * @notice Update light client with new header
     */
    function updateLightClient(
        bytes32 clientId,
        TendermintHeader calldata header,
        bytes calldata validatorProof,
        bytes calldata commitSignatures
    ) external onlyRole(RELAYER_ROLE) {
        LightClient storage client = lightClients[clientId];
        if (client.lastUpdate == 0) revert ClientNotFound();
        if (client.frozenHeight != 0) revert ClientFrozen();

        // Verify trusting period
        if (block.timestamp > client.lastUpdate + client.trustingPeriod) {
            revert ClientFrozen();
        }

        // Verify header (simplified - production would verify signatures)
        if (
            !_verifyTendermintHeader(
                client,
                header,
                validatorProof,
                commitSignatures
            )
        ) {
            revert ProofVerificationFailed();
        }

        // Update client state
        bytes32 newHeight = bytes32(uint256(header.height));
        client.latestHeight = newHeight;
        client.consensusStateRoot = header.appHash;
        client.lastUpdate = block.timestamp;

        // Store new consensus state
        consensusStates[clientId][header.height] = ConsensusState({
            timestamp: header.time,
            root: header.appHash,
            nextValidatorsHash: header.nextValidatorsHash
        });

        emit LightClientUpdated(clientId, newHeight);
    }

    /**
     * @notice Get light client state
     */
    function getLightClient(
        bytes32 clientId
    ) external view returns (LightClient memory) {
        return lightClients[clientId];
    }

    /**
     * @notice Get consensus state at height
     */
    function getConsensusState(
        bytes32 clientId,
        uint64 height
    ) external view returns (ConsensusState memory) {
        return consensusStates[clientId][height];
    }

    /*//////////////////////////////////////////////////////////////
                       CONNECTION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Open a new IBC connection
     */
    function openConnection(
        bytes32 connectionId,
        bytes32 clientId,
        bytes32 counterpartyConnectionId,
        bytes32 counterpartyClientId
    ) external onlyRole(OPERATOR_ROLE) {
        if (lightClients[clientId].lastUpdate == 0) revert ClientNotFound();

        connections[connectionId] = Connection({
            connectionId: connectionId,
            clientId: clientId,
            counterpartyConnectionId: counterpartyConnectionId,
            counterpartyClientId: counterpartyClientId,
            state: uint8(ChannelState.OPEN),
            createdAt: block.timestamp
        });

        connectionIds.push(connectionId);

        emit ConnectionOpened(connectionId, clientId);
    }

    /**
     * @notice Get connection
     */
    function getConnection(
        bytes32 connectionId
    ) external view returns (Connection memory) {
        return connections[connectionId];
    }

    /*//////////////////////////////////////////////////////////////
                        CHANNEL MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Open a new IBC channel
     */
    function openChannel(
        bytes32 channelId,
        bytes32 connectionId,
        bytes32 counterpartyChannelId,
        string calldata portId,
        ChannelOrdering ordering,
        string calldata version
    ) external onlyRole(OPERATOR_ROLE) {
        Connection storage conn = connections[connectionId];
        if (conn.createdAt == 0) revert ConnectionNotFound();

        channels[channelId] = Channel({
            channelId: channelId,
            connectionId: connectionId,
            counterpartyChannelId: counterpartyChannelId,
            portId: portId,
            state: ChannelState.OPEN,
            ordering: ordering,
            version: version,
            nextSequenceSend: 1,
            nextSequenceRecv: 1,
            nextSequenceAck: 1
        });

        channelIds.push(channelId);

        emit ChannelOpened(channelId, connectionId, portId);
    }

    /**
     * @notice Close a channel
     */
    function closeChannel(bytes32 channelId) external onlyRole(GUARDIAN_ROLE) {
        Channel storage channel = channels[channelId];
        if (channel.state == ChannelState.UNINITIALIZED)
            revert ChannelNotFound();

        channel.state = ChannelState.CLOSED;

        emit ChannelClosed(channelId);
    }

    /**
     * @notice Get channel
     */
    function getChannel(
        bytes32 channelId
    ) external view returns (Channel memory) {
        return channels[channelId];
    }

    /*//////////////////////////////////////////////////////////////
                         TOKEN TRANSFERS (ICS-20)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate an ICS-20 token transfer
     */
    function transferToken(
        string calldata denom,
        uint256 amount,
        string calldata receiver,
        bytes32 channelId,
        uint64 timeoutHeight,
        uint64 timeoutTimestamp
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        bytes32 denomHash = keccak256(bytes(denom));
        RegisteredDenom storage regDenom = denoms[denomHash];
        if (regDenom.denomHash == bytes32(0)) revert DenomNotRegistered();

        if (amount < minTransferAmount) revert AmountTooLow();
        if (amount > maxTransferAmount) revert AmountTooHigh();
        if (bytes(receiver).length == 0) revert InvalidReceiver();

        Channel storage channel = channels[channelId];
        if (channel.state != ChannelState.OPEN) revert ChannelNotOpen();

        // Validate timeout
        if (timeoutHeight == 0 && timeoutTimestamp == 0) {
            timeoutTimestamp = uint64(block.timestamp + defaultTimeout) * 1e9; // nanoseconds
        }

        // Calculate fee
        uint256 fee = (amount * bridgeFee) / 10000;
        if (msg.value < fee) revert InsufficientFee();

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                receiver,
                denom,
                amount,
                channelId,
                transferNonce++,
                block.timestamp
            )
        );

        tokenTransfers[transferId] = TokenTransfer({
            transferId: transferId,
            denom: denom,
            amount: amount,
            sender: msg.sender,
            receiver: receiver,
            channelId: channelId,
            timeoutHeight: timeoutHeight,
            timeoutTimestamp: timeoutTimestamp,
            completed: false,
            refunded: false,
            initiatedAt: block.timestamp
        });

        userTransfers[msg.sender].push(transferId);

        // Create and send packet
        _sendTransferPacket(
            transferId,
            channel,
            denom,
            amount,
            msg.sender,
            receiver,
            timeoutHeight,
            timeoutTimestamp
        );

        regDenom.totalBridged += amount;
        totalTransfersOut++;
        totalValueBridged += amount;
        totalFeesCollected += fee;

        emit TransferInitiated(transferId, msg.sender, receiver, denom, amount);
    }

    /**
     * @notice Receive an ICS-20 token transfer
     */
    function receiveTransfer(
        bytes32 packetId,
        string calldata denom,
        uint256 amount,
        string calldata sender,
        address receiver,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        Packet storage packet = packets[packetId];
        if (packet.state != PacketState.PENDING) revert PacketAlreadyReceived();

        // Verify membership proof
        Channel storage channel = channels[packet.destChannelId];
        Connection storage conn = connections[channel.connectionId];
        if (!_verifyPacketProof(conn.clientId, packetId, proof)) {
            revert ProofVerificationFailed();
        }

        packet.state = PacketState.RECEIVED;
        packetReceipts[packetId] = true;

        totalTransfersIn++;
        totalPacketsReceived++;

        emit PacketReceived(packetId, packet.sequence, packet.sourceChannelId);
    }

    /**
     * @notice Acknowledge a transfer
     */
    function acknowledgeTransfer(
        bytes32 transferId,
        bytes32 acknowledgement,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        TokenTransfer storage transfer = tokenTransfers[transferId];
        if (transfer.initiatedAt == 0) revert TransferNotFound();
        if (transfer.completed) revert TransferIsCompletedError();

        // Verify acknowledgement proof
        // (simplified - production would verify Merkle proof)

        transfer.completed = true;

        emit TransferCompleted(transferId);
        emit PacketAcknowledged(keccak256(abi.encodePacked(transferId)), true);
    }

    /**
     * @notice Handle transfer timeout
     */
    function timeoutTransfer(
        bytes32 transferId,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        TokenTransfer storage transfer = tokenTransfers[transferId];
        if (transfer.initiatedAt == 0) revert TransferNotFound();
        if (transfer.completed) revert TransferIsCompletedError();
        if (transfer.refunded) revert TransferAlreadyRefunded();

        // Verify timeout has passed
        bool isTimedOut = false;
        if (transfer.timeoutTimestamp > 0) {
            isTimedOut = block.timestamp * 1e9 > transfer.timeoutTimestamp;
        }

        if (!isTimedOut) revert InvalidTimeout();

        transfer.refunded = true;

        emit TransferRefunded(transferId);
        emit PacketTimedOut(keccak256(abi.encodePacked(transferId)));
    }

    /**
     * @notice Get transfer
     */
    function getTransfer(
        bytes32 transferId
    ) external view returns (TokenTransfer memory) {
        return tokenTransfers[transferId];
    }

    /**
     * @notice Get user transfers
     */
    function getUserTransfers(
        address user
    ) external view returns (bytes32[] memory) {
        return userTransfers[user];
    }

    /*//////////////////////////////////////////////////////////////
                    INTERCHAIN ACCOUNTS (ICS-27)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an interchain account
     */
    function registerInterchainAccount(
        bytes32 connectionId,
        string calldata hostAddress
    ) external nonReentrant returns (bytes32 accountId) {
        Connection storage conn = connections[connectionId];
        if (conn.createdAt == 0) revert ConnectionNotFound();

        accountId = keccak256(
            abi.encodePacked(
                msg.sender,
                connectionId,
                hostAddress,
                block.timestamp
            )
        );

        interchainAccounts[accountId] = InterchainAccount({
            accountId: accountId,
            owner: msg.sender,
            hostAddress: hostAddress,
            connectionId: connectionId,
            channelId: bytes32(0), // Set when channel is opened
            active: true,
            createdAt: block.timestamp
        });

        userICAAccounts[msg.sender].push(accountId);

        emit ICACreated(accountId, msg.sender, hostAddress);
    }

    /**
     * @notice Execute transaction via interchain account
     */
    function executeICA(
        bytes32 accountId,
        bytes calldata txData,
        uint64 timeoutTimestamp
    ) external nonReentrant whenNotPaused {
        InterchainAccount storage ica = interchainAccounts[accountId];
        if (ica.createdAt == 0) revert ICANotFound();
        if (!ica.active) revert ICANotActive();
        if (ica.owner != msg.sender) revert NotAccountOwner();

        // Create and send ICA packet
        bytes32 txHash = keccak256(txData);

        // (Packet creation logic would go here)

        emit ICAExecuted(accountId, txHash);
    }

    /**
     * @notice Get interchain account
     */
    function getInterchainAccount(
        bytes32 accountId
    ) external view returns (InterchainAccount memory) {
        return interchainAccounts[accountId];
    }

    /*//////////////////////////////////////////////////////////////
                       DENOMINATION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a token denomination
     */
    function registerDenom(
        string calldata baseDenom,
        address evmToken,
        uint8 decimals,
        string calldata ibcPath,
        bool isNative
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 denomHash = keccak256(bytes(baseDenom));

        denoms[denomHash] = RegisteredDenom({
            baseDenom: baseDenom,
            denomHash: denomHash,
            evmToken: evmToken,
            decimals: decimals,
            ibcPath: ibcPath,
            isNative: isNative,
            totalBridged: 0
        });

        if (evmToken != address(0)) {
            evmTokenToDenom[evmToken] = denomHash;
        }

        denomHashes.push(denomHash);

        emit DenomRegistered(denomHash, baseDenom, evmToken);
    }

    /**
     * @notice Get denomination
     */
    function getDenom(
        bytes32 denomHash
    ) external view returns (RegisteredDenom memory) {
        return denoms[denomHash];
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function setBridgeFee(uint256 newFee) external onlyRole(OPERATOR_ROLE) {
        require(newFee <= 100, "Fee too high"); // Max 1%
        bridgeFee = newFee;
    }

    function setTransferLimits(
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minTransferAmount = minAmount;
        maxTransferAmount = maxAmount;
    }

    function setDefaultTimeout(
        uint64 timeout
    ) external onlyRole(OPERATOR_ROLE) {
        defaultTimeout = timeout;
    }

    function setTreasury(
        address newTreasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        treasury = newTreasury;
    }

    /*//////////////////////////////////////////////////////////////
                           PAUSABLE
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                           STATISTICS
    //////////////////////////////////////////////////////////////*/

    function getBridgeStats()
        external
        view
        returns (
            uint256 packetsSent,
            uint256 packetsReceived,
            uint256 transfersOut,
            uint256 transfersIn,
            uint256 valueBridged,
            uint256 fees
        )
    {
        return (
            totalPacketsSent,
            totalPacketsReceived,
            totalTransfersOut,
            totalTransfersIn,
            totalValueBridged,
            totalFeesCollected
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyTendermintHeader(
        LightClient storage client,
        TendermintHeader calldata header,
        bytes calldata validatorProof,
        bytes calldata commitSignatures
    ) internal view returns (bool) {
        // Simplified verification - production would:
        // 1. Verify header chain (previous block hash matches)
        // 2. Verify validator set (>2/3 signatures)
        // 3. Verify within trusting period
        if (header.chainIdHash != client.chainIdHash) return false;
        if (validatorProof.length == 0) return false;
        if (commitSignatures.length == 0) return false;
        return true;
    }

    function _verifyPacketProof(
        bytes32 clientId,
        bytes32 packetId,
        bytes calldata proof
    ) internal view returns (bool) {
        // Simplified - production would verify Merkle proof against consensus state
        LightClient storage client = lightClients[clientId];
        if (client.frozenHeight != 0) return false;
        if (proof.length == 0) return false;
        return packetId != bytes32(0);
    }

    function _sendTransferPacket(
        bytes32 transferId,
        Channel storage channel,
        string memory denom,
        uint256 amount,
        address sender,
        string memory receiver,
        uint64 timeoutHeight,
        uint64 timeoutTimestamp
    ) internal {
        uint64 sequence = channel.nextSequenceSend++;

        bytes32 packetId = keccak256(
            abi.encodePacked(channel.channelId, sequence, transferId)
        );

        // Encode ICS-20 packet data
        bytes memory packetData = abi.encode(denom, amount, sender, receiver);

        packets[packetId] = Packet({
            packetId: packetId,
            sequence: sequence,
            sourceChannelId: channel.channelId,
            destChannelId: channel.counterpartyChannelId,
            sourcePort: channel.portId,
            destPort: "transfer",
            data: packetData,
            timeoutHeight: timeoutHeight,
            timeoutTimestamp: timeoutTimestamp,
            state: PacketState.PENDING,
            createdAt: block.timestamp
        });

        // Store commitment
        packetCommitments[packetId] = keccak256(packetData);

        totalPacketsSent++;

        emit PacketSent(
            packetId,
            sequence,
            channel.channelId,
            channel.counterpartyChannelId
        );
    }

    /*//////////////////////////////////////////////////////////////
                        UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute IBC denom trace
     */
    function computeDenomTrace(
        string calldata port,
        string calldata channel,
        string calldata baseDenom
    ) external pure returns (string memory) {
        return string(abi.encodePacked(port, "/", channel, "/", baseDenom));
    }

    /**
     * @notice Compute packet commitment
     */
    function computePacketCommitment(
        uint64 timeoutTimestamp,
        uint64 timeoutHeight,
        bytes calldata data
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    timeoutTimestamp,
                    timeoutHeight,
                    keccak256(data)
                )
            );
    }

    receive() external payable {}
}
