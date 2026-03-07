// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {IBridgeAdapter} from "./IBridgeAdapter.sol";
import {FixedSizeMessageWrapper} from "../libraries/FixedSizeMessageWrapper.sol";

/**
 * @title LayerZeroAdapter
 * @author ZASEON
 * @notice Bridge adapter for LayerZero V2 (OApp) cross-chain messaging
 * @dev Integrates with LayerZero V2 endpoint for generalized cross-chain messaging
 *      supporting 120+ chains via configurable Decentralized Verifier Networks (DVNs).
 *
 * LAYERZERO V2 ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                   Zaseon <-> LayerZero V2 Bridge                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Source Chain     │           │   Dest Chain       │                │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │ LZ Endpoint │  │──── DVN ──│  │ LZ Endpoint │  │                │
 * │  │  └─────────────┘  │  Network  │  └─────────────┘  │                │
 * │  │        │          │           │        │          │                │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                │
 * │  │  │ LayerZero   │  │           │  │ LayerZero   │  │                │
 * │  │  │  Adapter     │  │           │  │  Adapter     │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  └───────────────────┘           └───────────────────┘                │
 * │                                                                        │
 * │  DVN Security Model:                                                   │
 * │  - Configurable required + optional DVN sets per pathway               │
 * │  - Threshold signing for message verification                          │
 * │  - Executor handles destination gas payment                            │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract LayerZeroAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum message size (10 KB)
    uint256 public constant MAX_PAYLOAD_SIZE = 10240;

    /// @notice Maximum gas limit for destination execution
    uint256 public constant MAX_DST_GAS = 5_000_000;

    /// @notice Message expiry window (7 days)
    uint256 public constant MESSAGE_EXPIRY = 7 days;

    /// @notice Minimum required DVN confirmations
    uint256 public constant MIN_DVN_CONFIRMATIONS = 1;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        DELIVERED,
        VERIFIED,
        EXECUTED,
        FAILED,
        EXPIRED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice LayerZero endpoint configuration per chain
    struct EndpointConfig {
        uint32 eid; // LayerZero V2 endpoint ID
        address endpoint; // LZ endpoint contract address
        uint64 confirmations; // Required block confirmations
        uint128 baseGas; // Base gas for destination
        bool active; // Is endpoint active
    }

    /// @notice DVN (Decentralized Verifier Network) configuration
    struct DVNConfig {
        address[] requiredDVNs; // Required DVN addresses
        address[] optionalDVNs; // Optional DVN addresses
        uint8 optionalThreshold; // Min optional DVNs needed
    }

    /// @notice Cross-chain message
    struct LZMessage {
        bytes32 messageId; // Unique message identifier
        uint32 srcEid; // Source endpoint ID
        uint32 dstEid; // Destination endpoint ID
        address sender; // Message sender
        address receiver; // Destination receiver
        bytes payload; // Message payload
        uint256 nativeFee; // Fee paid in native currency
        uint128 dstGasLimit; // Gas limit for destination
        MessageStatus status; // Current status
        uint256 sentAt; // Send timestamp
        uint256 verifiedAt; // Verification timestamp
        bytes32 payloadHash; // keccak256 of payload
    }

    /// @notice Fee estimation result
    struct MessagingFee {
        uint256 nativeFee; // Fee in native currency
        uint256 lzTokenFee; // Fee in LZ token (if applicable)
    }

    /// @notice Messaging options for send
    struct MessagingOptions {
        uint128 dstGasLimit; // Gas for destination execution
        uint128 dstNativeAmount; // Native token to airdrop on destination
        bytes extraOptions; // Additional LZ options
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Local LayerZero endpoint address
    address public lzEndpoint;

    /// @notice Local chain's LayerZero endpoint ID
    uint32 public localEid;

    /// @notice Bridge fee in basis points (max 100 = 1%)
    uint256 public bridgeFeeBps;

    /// @notice Treasury for fee collection
    address public treasury;

    /// @notice Message nonce per destination endpoint
    mapping(uint32 => uint64) public outboundNonce;

    /// @notice Inbound nonce tracking (srcEid => nonce => processed)
    mapping(uint32 => mapping(uint64 => bool)) public inboundNonces;

    /// @notice Endpoint configurations by endpoint ID
    mapping(uint32 => EndpointConfig) public endpoints;

    /// @notice DVN config per pathway (srcEid => dstEid => config)
    mapping(uint32 => mapping(uint32 => DVNConfig)) internal dvnConfigs;

    /// @notice Messages by ID
    mapping(bytes32 => LZMessage) public messages;

    /// @notice User's sent messages
    mapping(address => bytes32[]) public userMessages;

    /// @notice Trusted remote peers (eid => peer address as bytes32)
    mapping(uint32 => bytes32) public peers;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalMessagesSent;
    uint256 public totalMessagesReceived;
    uint256 public totalFeesCollected;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event EndpointConfigured(
        uint32 indexed eid,
        address endpoint,
        uint64 confirmations
    );
    event PeerSet(uint32 indexed eid, bytes32 peer);
    event DVNConfigured(
        uint32 indexed srcEid,
        uint32 indexed dstEid,
        uint256 requiredCount,
        uint8 optionalThreshold
    );

    event MessageSent(
        bytes32 indexed messageId,
        uint32 indexed dstEid,
        address indexed sender,
        address receiver,
        uint256 nativeFee
    );

    event MessageReceived(
        bytes32 indexed messageId,
        uint32 indexed srcEid,
        address indexed sender,
        bytes32 payloadHash
    );

    event MessageVerified(bytes32 indexed messageId);
    event MessageExecuted(bytes32 indexed messageId);
    event MessageFailed(bytes32 indexed messageId, bytes reason);

    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error EndpointNotConfigured(uint32 eid);
    error PeerNotSet(uint32 eid);
    error InvalidEndpoint();
    error InvalidPeer();
    error PayloadTooLarge(uint256 size, uint256 max);
    error GasLimitExceeded(uint128 requested, uint256 max);
    error InsufficientFee(uint256 required, uint256 provided);
    error MessageNotFound(bytes32 messageId);
    error MessageAlreadyProcessed(bytes32 messageId);
    error MessageExpired(bytes32 messageId);
    error InvalidNonce(uint64 expected, uint64 received);
    error UnauthorizedCaller();
    error FeeTooHigh(uint256 bps);
    error ZeroAddress();
    error TransferFailed();
    error LZEndpointSendFailed();
    error ZeroReceiver();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _admin Admin address (receives all roles initially)
     * @param _lzEndpoint LayerZero V2 endpoint address on this chain
     * @param _localEid This chain's LayerZero endpoint ID
     */
    constructor(address _admin, address _lzEndpoint, uint32 _localEid) {
        if (_admin == address(0) || _lzEndpoint == address(0))
            revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        lzEndpoint = _lzEndpoint;
        localEid = _localEid;
        bridgeFeeBps = 15; // 0.15%
    }

    /*//////////////////////////////////////////////////////////////
                        ENDPOINT CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a remote LayerZero endpoint
     * @param eid LayerZero endpoint ID
     * @param endpoint Endpoint contract address on remote chain
     * @param confirmations Required block confirmations
     * @param baseGas Base gas for destination execution
     */
    function configureEndpoint(
        uint32 eid,
        address endpoint,
        uint64 confirmations,
        uint128 baseGas
    ) external onlyRole(OPERATOR_ROLE) {
        if (endpoint == address(0)) revert InvalidEndpoint();

        endpoints[eid] = EndpointConfig({
            eid: eid,
            endpoint: endpoint,
            confirmations: confirmations,
            baseGas: baseGas,
            active: true
        });

        emit EndpointConfigured(eid, endpoint, confirmations);
    }

    /**
     * @notice Set trusted peer for a remote endpoint
     * @param eid Remote endpoint ID
     * @param peer Peer address encoded as bytes32
     */
    function setPeer(
        uint32 eid,
        bytes32 peer
    ) external onlyRole(OPERATOR_ROLE) {
        if (peer == bytes32(0)) revert InvalidPeer();
        peers[eid] = peer;
        emit PeerSet(eid, peer);
    }

    /**
     * @notice Configure DVN set for a specific pathway
     * @param srcEid Source endpoint ID
     * @param dstEid Destination endpoint ID
     * @param requiredDVNs Required DVN addresses
     * @param optionalDVNs Optional DVN addresses
     * @param optionalThreshold Minimum optional DVNs needed
     */
    function configureDVN(
        uint32 srcEid,
        uint32 dstEid,
        address[] calldata requiredDVNs,
        address[] calldata optionalDVNs,
        uint8 optionalThreshold
    ) external onlyRole(OPERATOR_ROLE) {
        dvnConfigs[srcEid][dstEid] = DVNConfig({
            requiredDVNs: requiredDVNs,
            optionalDVNs: optionalDVNs,
            optionalThreshold: optionalThreshold
        });

        emit DVNConfigured(
            srcEid,
            dstEid,
            requiredDVNs.length,
            optionalThreshold
        );
    }

    /*//////////////////////////////////////////////////////////////
                          SEND MESSAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a cross-chain message via LayerZero V2
     * @param dstEid Destination endpoint ID
     * @param receiver Receiver address on destination chain
     * @param payload Message payload
     * @param options Messaging options (gas, native airdrop)
     * @return messageId Unique message identifier
     */
    function send(
        uint32 dstEid,
        address receiver,
        bytes calldata payload,
        MessagingOptions calldata options
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        EndpointConfig storage config = endpoints[dstEid];
        if (!config.active) revert EndpointNotConfigured(dstEid);
        if (peers[dstEid] == bytes32(0)) revert PeerNotSet(dstEid);
        if (receiver == address(0)) revert ZeroReceiver();
        if (payload.length > MAX_PAYLOAD_SIZE)
            revert PayloadTooLarge(payload.length, MAX_PAYLOAD_SIZE);

        uint128 dstGas = options.dstGasLimit > 0
            ? options.dstGasLimit
            : config.baseGas;
        if (dstGas > MAX_DST_GAS) revert GasLimitExceeded(dstGas, MAX_DST_GAS);

        // Calculate fee
        uint256 protocolFee = (msg.value * bridgeFeeBps) / 10000;
        uint256 lzFee = msg.value - protocolFee;
        if (lzFee == 0) revert InsufficientFee(1, 0);

        // Generate message ID
        uint64 nonce = outboundNonce[dstEid]++;
        messageId = keccak256(
            abi.encodePacked(
                localEid,
                dstEid,
                msg.sender,
                receiver,
                nonce,
                block.timestamp
            )
        );

        // Store message
        messages[messageId] = LZMessage({
            messageId: messageId,
            srcEid: localEid,
            dstEid: dstEid,
            sender: msg.sender,
            receiver: receiver,
            payload: payload,
            nativeFee: msg.value,
            dstGasLimit: dstGas,
            status: MessageStatus.SENT,
            sentAt: block.timestamp,
            verifiedAt: 0,
            payloadHash: keccak256(payload)
        });

        userMessages[msg.sender].push(messageId);

        // Collect protocol fee
        if (protocolFee > 0 && treasury != address(0)) {
            totalFeesCollected += protocolFee;
            (bool sent, ) = treasury.call{value: protocolFee}("");
            if (!sent) revert TransferFailed();
        }

        // Wrap payload to fixed size for privacy (prevent size-based inference)
        bytes memory wrappedPayload = FixedSizeMessageWrapper.wrap(payload);

        // Forward to LZ endpoint
        (bool success, ) = lzEndpoint.call{value: lzFee}(
            abi.encodeWithSignature(
                "send((uint32,bytes32,bytes,bytes,bytes),address)",
                _buildMessagingParams(
                    dstEid,
                    receiver,
                    wrappedPayload,
                    dstGas,
                    options.extraOptions
                ),
                msg.sender // refund address
            )
        );
        if (!success) {
            revert LZEndpointSendFailed();
        }

        totalMessagesSent++;

        emit MessageSent(messageId, dstEid, msg.sender, receiver, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE MESSAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called by LayerZero endpoint when a message arrives
     * @dev Only callable by the configured LZ endpoint
     * @param srcEid Source endpoint ID
     * @param sender Sender address (bytes32 encoded)
     * @param nonce Message nonce
     * @param payload Message payload
     */
    function lzReceive(
        uint32 srcEid,
        bytes32 sender,
        uint64 nonce,
        bytes calldata payload
    ) external {
        if (msg.sender != lzEndpoint) revert UnauthorizedCaller();
        if (sender != peers[srcEid]) revert InvalidPeer();
        if (inboundNonces[srcEid][nonce])
            revert MessageAlreadyProcessed(bytes32(uint256(nonce)));

        inboundNonces[srcEid][nonce] = true;

        bytes32 messageId = keccak256(
            abi.encodePacked(srcEid, localEid, sender, nonce)
        );

        messages[messageId] = LZMessage({
            messageId: messageId,
            srcEid: srcEid,
            dstEid: localEid,
            sender: address(uint160(uint256(sender))),
            receiver: address(this),
            payload: payload,
            nativeFee: 0,
            dstGasLimit: 0,
            status: MessageStatus.VERIFIED,
            sentAt: 0,
            verifiedAt: block.timestamp,
            payloadHash: keccak256(payload)
        });

        totalMessagesReceived++;

        emit MessageReceived(
            messageId,
            srcEid,
            address(uint160(uint256(sender))),
            keccak256(payload)
        );
        emit MessageVerified(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Estimate fee for sending a message
     * @param dstEid Destination endpoint ID
     * @param payload Message payload
     * @param dstGasLimit Gas limit for destination
     * @return fee Estimated fee breakdown
     */
    function estimateFee(
        uint32 dstEid,
        bytes calldata payload,
        uint128 dstGasLimit
    ) external view returns (MessagingFee memory fee) {
        EndpointConfig storage config = endpoints[dstEid];
        if (!config.active) revert EndpointNotConfigured(dstEid);

        uint128 gas = dstGasLimit > 0 ? dstGasLimit : config.baseGas;

        // Base fee estimation: gas * gas price estimation + overhead
        // In production, this delegates to the LZ endpoint's quote function
        uint256 baseFee = uint256(gas) * 20 gwei; // conservative estimate
        uint256 protocolFee = (baseFee * bridgeFeeBps) / (10000 - bridgeFeeBps);

        fee.nativeFee = baseFee + protocolFee;
        fee.lzTokenFee = 0; // Not using LZ token payment
    }

    /*//////////////////////////////////////////////////////////////
                     IBridgeAdapter COMPATIBILITY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice IBridgeAdapter-compatible bridge message
     */
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /*refundAddress*/
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        // Default to first configured endpoint — caller should use send() for full control
        revert("Use send() with explicit dstEid");
    }

    /**
     * @notice Check if a message has been verified
     */
    function isMessageVerified(bytes32 messageId) external view returns (bool) {
        MessageStatus status = messages[messageId].status;
        return
            status == MessageStatus.VERIFIED ||
            status == MessageStatus.EXECUTED;
    }

    /**
     * @notice IBridgeAdapter-compatible fee estimation
     */
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure returns (uint256 nativeFee) {
        // Use estimateFee(uint32,bytes,uint128) for accurate per-endpoint quotes
        revert("Use estimateFee(uint32,bytes,uint128)");
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update bridge fee
     * @param newFeeBps New fee in basis points (max 100 = 1%)
     */
    function setFee(uint256 newFeeBps) external onlyRole(OPERATOR_ROLE) {
        if (newFeeBps > 100) revert FeeTooHigh(newFeeBps);
        uint256 oldFee = bridgeFeeBps;
        bridgeFeeBps = newFeeBps;
        emit FeeUpdated(oldFee, newFeeBps);
    }

    /**
     * @notice Update treasury address
     */
    function setTreasury(address _treasury) external onlyRole(OPERATOR_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        address old = treasury;
        treasury = _treasury;
        emit TreasuryUpdated(old, _treasury);
    }

    /**
     * @notice Disable an endpoint
     */
    function disableEndpoint(uint32 eid) external onlyRole(GUARDIAN_ROLE) {
        endpoints[eid].active = false;
    }

    /**
     * @notice Pause bridge operations
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge operations
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get message details
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (LZMessage memory) {
        return messages[messageId];
    }

    /**
     * @notice Get user's message history
     */
    function getUserMessages(
        address user
    ) external view returns (bytes32[] memory) {
        return userMessages[user];
    }

    /**
     * @notice Get DVN config for a pathway
     */
    function getDVNConfig(
        uint32 srcEid,
        uint32 dstEid
    ) external view returns (DVNConfig memory) {
        return dvnConfigs[srcEid][dstEid];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Build the messaging params struct for LZ endpoint
     */
    function _buildMessagingParams(
        uint32 dstEid,
        address receiver,
        bytes memory payload,
        uint128 dstGas,
        bytes calldata extraOptions
    ) internal view returns (bytes memory) {
        bytes32 peerBytes = peers[dstEid];
        return
            abi.encode(
                dstEid,
                peerBytes,
                payload,
                abi.encodePacked(uint16(3), uint8(1), dstGas), // options: type 3 + gas
                extraOptions
            );
    }
}
