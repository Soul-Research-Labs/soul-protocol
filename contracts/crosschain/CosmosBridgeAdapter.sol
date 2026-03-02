// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IGravityBridge
 * @notice Minimal interface for the Gravity Bridge Ethereum↔Cosmos contract
 * @dev Gravity Bridge enables trustless transfers between Ethereum and Cosmos Hub
 *      by relaying CometBFT validator set attestations (signatures) on chain.
 *      Validators on Cosmos sign batches of outgoing transfers; those signatures
 *      are verified on the Ethereum side by the Gravity contract.
 */
interface IGravityBridge {
    /// @notice Send tokens from Ethereum to a Cosmos destination address
    /// @param cosmosDestination The bech32-encoded Cosmos destination
    /// @param amount The token amount to send
    /// @param token The ERC-20 token address (address(0) for native ETH wrapping)
    /// @return transferId Unique transfer identifier
    function sendToCosmos(
        bytes calldata cosmosDestination,
        uint256 amount,
        address token
    ) external payable returns (bytes32 transferId);

    /// @notice Estimate the relay fee for a transfer
    /// @return fee The estimated relay fee in wei
    function estimateRelayFee() external view returns (uint256 fee);

    /// @notice Get the current Cosmos validator set nonce
    /// @return nonce The current valset nonce
    function state_lastValsetNonce() external view returns (uint256 nonce);

    /// @notice Get the hash of the current validator power set
    /// @return checkpoint The valset checkpoint hash
    function state_lastValsetCheckpoint()
        external
        view
        returns (bytes32 checkpoint);
}

/**
 * @title IIBCLightClient
 * @notice Interface for verifying IBC (Inter-Blockchain Communication) light client proofs
 * @dev IBC light clients verify CometBFT consensus state transitions, including
 *      validator set changes and committed blocks. Proofs consist of signed headers
 *      plus IAVL Merkle proofs against the application state root.
 */
interface IIBCLightClient {
    /// @notice Verify a Tendermint/CometBFT light client proof
    /// @param proof The IBC light client proof (signed header + IAVL proof)
    /// @param data The state data being proven
    /// @return valid Whether the proof is valid
    function verifyIBCProof(
        bytes calldata proof,
        bytes calldata data
    ) external returns (bool valid);

    /// @notice Get the latest verified consensus state height
    /// @return height The latest verified block height
    function latestHeight() external view returns (uint64 height);
}

/**
 * @title CosmosBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Cosmos Hub — IBC ecosystem via Gravity Bridge
 * @dev Enables ZASEON cross-chain interoperability with the Cosmos Hub and
 *      IBC-connected chains via Gravity Bridge and CometBFT light client verification.
 *
 * COSMOS INTEGRATION:
 * - Independent Proof-of-Stake L1 (Cosmos SDK + CometBFT consensus)
 * - Consensus: CometBFT (formerly Tendermint BFT), instant finality
 * - Cross-chain: IBC (Inter-Blockchain Communication) protocol
 * - Native token: ATOM
 * - Smart contracts: CosmWasm (Rust → Wasm) on enabled chains
 * - EVM bridge: Gravity Bridge (validator-attested, decentralized)
 *
 * MESSAGE FLOW:
 * - ZASEON→Cosmos: sendMessage() → Gravity Bridge → Cosmos Hub → IBC relay
 * - Cosmos→ZASEON: IBC light client proof → verifier validates → message delivered
 *
 * SECURITY NOTES:
 * - IBC light client proofs verified on-chain by IBCLightClient contract
 * - Gravity Bridge uses CometBFT validator set attestations (≥2/3 voting power)
 * - Nullifier-based replay protection (integrates with ZASEON's CDNA)
 * - CometBFT provides instant deterministic finality (~6 second blocks)
 */
contract CosmosBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                           CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON virtual chain ID for Cosmos (not an EVM chain ID)
    uint16 public constant COSMOS_CHAIN_ID = 7100;

    /// @notice CometBFT instant finality (~6 second blocks)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Minimum IBC proof size in bytes
    uint256 public constant MIN_PROOF_SIZE = 64;

    /// @notice Maximum bridge fee (1% = 100 basis points)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length in bytes
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Default Cosmos Hub IBC channel (channel-0 for most IBC connections)
    bytes32 public constant DEFAULT_IBC_CHANNEL =
        keccak256("channel-0");

    /*//////////////////////////////////////////////////////////////
                           STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Gravity Bridge contract
    IGravityBridge public gravityBridge;

    /// @notice IBC light client verifier
    IIBCLightClient public ibcLightClient;

    /// @notice Default Cosmos destination (bech32 bytes)
    bytes public defaultCosmosDestination;

    /// @notice Bridge fee in basis points (0–100)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees available for withdrawal
    uint256 public accumulatedFees;

    /// @notice Total messages sent to Cosmos
    uint256 public totalMessagesSent;

    /// @notice Total messages received from Cosmos
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (wei)
    uint256 public totalValueBridged;

    /*//////////////////////////////////////////////////////////////
                           MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tracks used nullifiers for replay protection
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Per-sender nonce counter
    mapping(address => uint256) public senderNonces;

    /// @notice Registered IBC channel IDs for valid source chains
    mapping(bytes32 => bool) public registeredChannels;

    /*//////////////////////////////////////////////////////////////
                          ENUMS & STRUCTS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        NONE,
        PENDING,
        SENT,
        DELIVERED,
        FAILED
    }

    struct MessageRecord {
        MessageStatus status;
        bytes32 ibcChannel;
        bytes32 consensusStateHash;
        bytes32 nullifier;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                           ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidGravityBridge();
    error InvalidLightClient();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidChannel();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                           EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 gravityTransferId,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 ibcChannel,
        bytes32 indexed nullifier,
        bytes payload
    );

    event GravityBridgeUpdated(
        address indexed oldBridge,
        address indexed newBridge
    );
    event IBCLightClientUpdated(
        address indexed oldClient,
        address indexed newClient
    );
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);
    event IBCChannelRegistered(bytes32 indexed channel);
    event IBCChannelDeregistered(bytes32 indexed channel);
    event DefaultDestinationUpdated(bytes oldDest, bytes newDest);

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _gravityBridge Gravity Bridge contract address
    /// @param _ibcLightClient IBC light client verifier address
    /// @param _admin Admin address (receives all initial roles)
    constructor(
        address _gravityBridge,
        address _ibcLightClient,
        address _admin
    ) {
        if (_gravityBridge == address(0)) revert InvalidGravityBridge();
        if (_ibcLightClient == address(0)) revert InvalidLightClient();
        if (_admin == address(0)) revert InvalidTarget();

        gravityBridge = IGravityBridge(_gravityBridge);
        ibcLightClient = IIBCLightClient(_ibcLightClient);

        // Register default IBC channel
        registeredChannels[DEFAULT_IBC_CHANNEL] = true;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON virtual chain ID for Cosmos
    function chainId() external pure returns (uint16) {
        return COSMOS_CHAIN_ID;
    }

    /// @notice Human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Cosmos";
    }

    /// @notice Whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(gravityBridge) != address(0) &&
            address(ibcLightClient) != address(0);
    }

    /// @notice Number of blocks for finality (CometBFT = instant)
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the current Cosmos validator set checkpoint
    function getValsetCheckpoint() external view returns (bytes32) {
        return gravityBridge.state_lastValsetCheckpoint();
    }

    /// @notice Get the current Cosmos validator set nonce
    function getValsetNonce() external view returns (uint256) {
        return gravityBridge.state_lastValsetNonce();
    }

    /// @notice Get the latest verified IBC height
    function getLatestIBCHeight() external view returns (uint64) {
        return ibcLightClient.latestHeight();
    }

    /*//////////////////////////////////////////////////////////////
                 SEND MESSAGE (ZASEON → COSMOS)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a cross-chain message from ZASEON to Cosmos Hub
     * @param cosmosDestination The bech32-encoded Cosmos address (as bytes)
     * @param payload The message payload (IBC-compatible)
     * @return messageHash The unique message hash
     */
    function sendMessage(
        bytes calldata cosmosDestination,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (cosmosDestination.length == 0) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Enforce minimum fee
        uint256 relayFee = gravityBridge.estimateRelayFee();
        uint256 requiredFee = relayFee + minMessageFee;
        if (msg.value < requiredFee)
            revert InsufficientFee(requiredFee, msg.value);

        // Protocol fee
        uint256 protocolFee = 0;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        // Forward via Gravity Bridge
        bytes memory fullPayload = abi.encodePacked(
            cosmosDestination,
            payload
        );
        bytes32 gravityId = gravityBridge.sendToCosmos{
            value: msg.value - protocolFee
        }(fullPayload, 0, address(0));

        // Build message record
        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                COSMOS_CHAIN_ID,
                msg.sender,
                nonce,
                block.timestamp,
                keccak256(payload)
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            ibcChannel: DEFAULT_IBC_CHANNEL,
            consensusStateHash: bytes32(0),
            nullifier: bytes32(0),
            timestamp: block.timestamp
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageHash, msg.sender, gravityId, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (COSMOS → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a cross-chain message from Cosmos
     * @param proof IBC light client proof (signed header + IAVL Merkle proof)
     * @param publicInputs [consensusStateHash, nullifier, ibcChannelHash, payloadHash]
     * @param payload The original message payload
     * @return messageHash The unique message hash
     */
    function receiveMessage(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        // Verify IBC light client proof
        bool valid = ibcLightClient.verifyIBCProof(proof, payload);
        if (!valid) revert InvalidProof();

        // Extract public inputs
        bytes32 consensusStateHash = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);
        bytes32 ibcChannel = bytes32(publicInputs[2]);
        bytes32 payloadHash = bytes32(publicInputs[3]);

        // Validate IBC channel is registered
        if (!registeredChannels[ibcChannel]) revert InvalidChannel();

        // Replay protection
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Build message hash
        messageHash = keccak256(
            abi.encodePacked(
                COSMOS_CHAIN_ID,
                consensusStateHash,
                nullifier,
                ibcChannel,
                payloadHash
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            ibcChannel: ibcChannel,
            consensusStateHash: consensusStateHash,
            nullifier: nullifier,
            timestamp: block.timestamp
        });

        totalMessagesReceived++;

        emit MessageReceived(messageHash, ibcChannel, nullifier, payload);
    }

    /*//////////////////////////////////////////////////////////////
                  IBridgeAdapter COMPLIANCE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
    )
        external
        payable
        override
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        if (targetAddress == address(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Wrap address + payload as Gravity Bridge transfer
        bytes memory cosmosPayload = abi.encodePacked(targetAddress, payload);

        bytes32 gravityId = gravityBridge.sendToCosmos{value: msg.value}(
            cosmosPayload,
            0,
            address(0)
        );

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                COSMOS_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                block.timestamp,
                keccak256(payload)
            )
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            ibcChannel: DEFAULT_IBC_CHANNEL,
            consensusStateHash: bytes32(0),
            nullifier: bytes32(0),
            timestamp: block.timestamp
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, gravityId, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        uint256 relayFee = gravityBridge.estimateRelayFee();
        return relayFee + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        MessageStatus status = messages[messageId].status;
        return
            status == MessageStatus.SENT || status == MessageStatus.DELIVERED;
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Gravity Bridge address
    function setGravityBridge(
        address _gravityBridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_gravityBridge == address(0)) revert InvalidGravityBridge();
        address old = address(gravityBridge);
        gravityBridge = IGravityBridge(_gravityBridge);
        emit GravityBridgeUpdated(old, _gravityBridge);
    }

    /// @notice Update the IBC light client verifier address
    function setIBCLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_client == address(0)) revert InvalidLightClient();
        address old = address(ibcLightClient);
        ibcLightClient = IIBCLightClient(_client);
        emit IBCLightClientUpdated(old, _client);
    }

    /// @notice Set the default Cosmos destination address
    function setDefaultCosmosDestination(
        bytes calldata _dest
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_dest.length == 0) revert InvalidTarget();
        bytes memory old = defaultCosmosDestination;
        defaultCosmosDestination = _dest;
        emit DefaultDestinationUpdated(old, _dest);
    }

    /// @notice Register an IBC channel as a valid incoming source
    function registerIBCChannel(
        bytes32 _channel
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        registeredChannels[_channel] = true;
        emit IBCChannelRegistered(_channel);
    }

    /// @notice Deregister an IBC channel
    function deregisterIBCChannel(
        bytes32 _channel
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        registeredChannels[_channel] = false;
        emit IBCChannelDeregistered(_channel);
    }

    /// @notice Set the bridge fee in basis points (max 100 = 1%)
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        uint256 old = bridgeFee;
        bridgeFee = _fee;
        emit BridgeFeeUpdated(old, _fee);
    }

    /// @notice Set the minimum per-message fee
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 old = minMessageFee;
        minMessageFee = _fee;
        emit MinMessageFeeUpdated(old, _fee);
    }

    /*//////////////////////////////////////////////////////////////
                      PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                     FEE & EMERGENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(
        address payable _recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_recipient == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = _recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(_recipient, amount);
    }

    /// @notice Emergency ETH withdrawal
    function emergencyWithdrawETH(
        address payable _to,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        (bool ok, ) = _to.call{value: _amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency ERC20 withdrawal
    function emergencyWithdrawERC20(
        address _token,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_token == address(0) || _to == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(_to, balance);
    }

    /// @notice Accept ETH transfers
    receive() external payable {}
}
