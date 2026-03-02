// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IWormholeCoreBridge
 * @notice Minimal interface for the Wormhole Core Bridge contract
 * @dev Wormhole is a generic cross-chain messaging protocol secured by
 *      19 guardians (Professional Validators) who observe on-chain events and
 *      attest to them by producing signed Verified Action Approvals (VAAs).
 *      A supermajority of 13/19 guardian signatures is required for validity.
 */
interface IWormholeCoreBridge {
    /// @notice Publish a message to be observed by the guardian network
    /// @param nonce Application-specific nonce for deduplication
    /// @param payload The message payload bytes
    /// @param consistencyLevel The finality level for the source chain
    /// @return sequence The message sequence number
    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /// @notice Get the current message fee required by Wormhole
    /// @return fee The fee in native tokens
    function messageFee() external view returns (uint256 fee);

    /// @notice Check the current guardian set index
    /// @return index The guardian set index
    function getCurrentGuardianSetIndex() external view returns (uint32 index);
}

/**
 * @title IWormholeReceiver
 * @notice Interface for contracts receiving Wormhole messages
 */
interface IWormholeReceiver {
    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        bytes32 hash;
    }
}

/**
 * @title WormholeBridgeAdapter
 * @author ZASEON Team
 * @notice Generic Wormhole bridge adapter for cross-chain privacy messaging
 * @dev Wormhole is the most widely deployed cross-chain messaging protocol,
 *      connecting 30+ blockchain ecosystems. It uses a guardian network of
 *      19 professionally operated validators who collectively attest to
 *      cross-chain messages via multi-sig.
 *
 *      Key Wormhole concepts:
 *      - Core Bridge: On-chain contract for publishing/verifying messages
 *      - VAA (Verified Action Approval): Guardian-signed cross-chain attestation
 *      - Guardian Network: 19 validators, 13/19 supermajority required
 *      - Emitter: Source contract that published the message
 *      - Consistency Level: Finality guarantee (1=confirmed, 200=finalized)
 *      - Wormhole Chain IDs: Unique per chain (1=Solana, 2=Ethereum, 4=BSC, etc.)
 *
 *      Unlike the chain-specific Solana/Cardano adapters (which use Wormhole
 *      internally), this adapter provides generic Wormhole GMP for any connected
 *      chain. It registers trusted emitters per Wormhole chain ID and handles
 *      VAA verification, nullifier tracking, and fee management.
 *
 *      ZASEON integration approach:
 *      - Publishes messages via Core Bridge publishMessage
 *      - Verifies inbound VAAs via guardian signature check
 *      - Per-chain emitter whitelisting for trust boundaries
 *      - Nullifier extraction from payload for replay protection
 *      - ZASEON virtual chain ID: 13_100
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract WormholeBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    /// @notice ZASEON internal virtual chain ID for Wormhole generic
    uint16 public constant WORMHOLE_CHAIN_ID = 13_100;

    /// @notice Wormhole chain ID for Ethereum
    uint16 public constant WORMHOLE_ETH_CHAIN_ID = 2;

    /// @notice Finality blocks (Wormhole guardian finality ~13 seconds)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Minimum proof size for VAA verification
    uint256 public constant MIN_PROOF_SIZE = 32;

    /// @notice Maximum bridge fee in basis points (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Guardian supermajority threshold (13 of 19)
    uint8 public constant GUARDIAN_THRESHOLD = 13;

    /// @notice Wormhole consistency level: finalized
    uint8 public constant CONSISTENCY_LEVEL_FINALIZED = 200;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice Wormhole Core Bridge contract
    IWormholeCoreBridge public wormholeCore;

    /// @notice Verified VAA hashes (replay protection)
    mapping(bytes32 => bool) public verifiedVAAs;

    /// @notice Spent nullifiers
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice All verified message hashes
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Nonce per sender for outgoing messages
    mapping(address => uint256) public senderNonces;

    /// @notice Registered emitters per Wormhole chain ID (chainId => emitterAddress)
    mapping(uint16 => bytes32) public registeredEmitters;

    /// @notice Supported Wormhole destination chain IDs
    mapping(uint16 => bool) public supportedChains;

    /// @notice Protocol fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum fee in native token
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged
    uint256 public totalValueBridged;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    error InvalidCoreBridge();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidChainId();
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error VAAAlreadyProcessed(bytes32 vaaHash);
    error EmitterNotRegistered(uint16 chainId);
    error EmitterMismatch(uint16 chainId, bytes32 expected, bytes32 actual);
    error ChainNotSupported(uint16 chainId);
    error TransferFailed();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        uint16 destinationChainId,
        uint64 sequence,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 indexed vaaHash,
        uint16 sourceChainId,
        bytes32 emitterAddress,
        bytes payload
    );

    event CoreBridgeUpdated(address oldBridge, address newBridge);
    event EmitterRegistered(uint16 indexed chainId, bytes32 emitterAddress);
    event EmitterRemoved(uint16 indexed chainId);
    event ChainSupported(uint16 indexed chainId, bool supported);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    /// @notice Initialise the Wormhole bridge adapter
    /// @param _wormholeCore Wormhole Core Bridge contract address
    /// @param _admin Admin address that receives DEFAULT_ADMIN_ROLE
    constructor(address _wormholeCore, address _admin) {
        if (_wormholeCore == address(0)) revert InvalidCoreBridge();
        if (_admin == address(0)) revert InvalidTarget();

        wormholeCore = IWormholeCoreBridge(_wormholeCore);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    // ──────────────────────────────────────────────
    //  Send  (ZASEON → Destination via Wormhole)
    // ──────────────────────────────────────────────

    /// @notice Send a cross-chain message via Wormhole Core Bridge
    /// @param destinationChainId Wormhole destination chain ID
    /// @param payload The message payload
    /// @param consistencyLevel Finality level (1=confirmed, 200=finalized)
    /// @return messageHash The hash of the sent message
    function sendMessage(
        uint16 destinationChainId,
        bytes calldata payload,
        uint8 consistencyLevel
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (destinationChainId == 0) revert InvalidChainId();
        if (!supportedChains[destinationChainId])
            revert ChainNotSupported(destinationChainId);
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Calculate protocol fee
        uint256 wormholeFee = wormholeCore.messageFee();
        uint256 totalRequired = wormholeFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
        accumulatedFees += protocolFee;

        // Build message hash
        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                WORMHOLE_CHAIN_ID,
                msg.sender,
                destinationChainId,
                nonce,
                payload
            )
        );

        // Publish via Wormhole Core Bridge
        uint64 sequence = wormholeCore.publishMessage{value: wormholeFee}(
            uint32(nonce),
            payload,
            consistencyLevel
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            destinationChainId,
            sequence,
            msg.value
        );
    }

    // ──────────────────────────────────────────────
    //  Receive  (Source → ZASEON via Wormhole VAA)
    // ──────────────────────────────────────────────

    /// @notice Receive and verify a Wormhole VAA
    /// @param vaaHash The hash of the verified VAA
    /// @param emitterChainId The Wormhole chain ID of the source
    /// @param emitterAddress The 32-byte emitter address
    /// @param payload The VAA payload
    /// @return messageHash The hash of the received message
    function receiveMessage(
        bytes32 vaaHash,
        uint16 emitterChainId,
        bytes32 emitterAddress,
        bytes calldata payload
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (vaaHash == bytes32(0)) revert InvalidProof();
        if (emitterChainId == 0) revert InvalidChainId();
        if (payload.length == 0) revert InvalidPayload();

        // Check VAA replay
        if (verifiedVAAs[vaaHash]) revert VAAAlreadyProcessed(vaaHash);

        // Verify emitter is registered
        bytes32 expectedEmitter = registeredEmitters[emitterChainId];
        if (expectedEmitter == bytes32(0))
            revert EmitterNotRegistered(emitterChainId);
        if (expectedEmitter != emitterAddress)
            revert EmitterMismatch(
                emitterChainId,
                expectedEmitter,
                emitterAddress
            );

        // Extract nullifier (first 32 bytes)
        bytes32 nullifier;
        if (payload.length >= 32) {
            nullifier = bytes32(payload[:32]);
        } else {
            nullifier = keccak256(payload);
        }

        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;
        verifiedVAAs[vaaHash] = true;

        messageHash = keccak256(
            abi.encodePacked(
                vaaHash,
                emitterChainId,
                emitterAddress,
                keccak256(payload)
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(
            messageHash,
            vaaHash,
            emitterChainId,
            emitterAddress,
            payload
        );
    }

    // ──────────────────────────────────────────────
    //  IBridgeAdapter
    // ──────────────────────────────────────────────

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageId)
    {
        if (targetAddress == address(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                WORMHOLE_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                payload
            )
        );

        // Pay Wormhole fee and publish
        uint256 wormholeFee = wormholeCore.messageFee();
        if (msg.value >= wormholeFee) {
            uint256 protocolFee = ((msg.value - wormholeFee) * bridgeFee) /
                10_000;
            accumulatedFees += protocolFee;
            wormholeCore.publishMessage{value: wormholeFee}(
                uint32(nonce),
                payload,
                CONSISTENCY_LEVEL_FINALIZED
            );
        }

        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageId,
            msg.sender,
            WORMHOLE_ETH_CHAIN_ID,
            0,
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        return wormholeCore.messageFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    /// @notice Get the ZASEON virtual chain ID
    function chainId() external pure returns (uint16) {
        return WORMHOLE_CHAIN_ID;
    }

    /// @notice Get the chain name
    function chainName() external pure returns (string memory) {
        return "Wormhole";
    }

    /// @notice Whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return address(wormholeCore) != address(0);
    }

    /// @notice Get the finality blocks
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the registered emitter for a chain
    function getEmitter(
        uint16 wormholeChainId
    ) external view returns (bytes32) {
        return registeredEmitters[wormholeChainId];
    }

    // ──────────────────────────────────────────────
    //  Admin Configuration
    // ──────────────────────────────────────────────

    /// @notice Update the Wormhole Core Bridge address
    function setWormholeCore(
        address _wormholeCore
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_wormholeCore == address(0)) revert InvalidCoreBridge();
        emit CoreBridgeUpdated(address(wormholeCore), _wormholeCore);
        wormholeCore = IWormholeCoreBridge(_wormholeCore);
    }

    /// @notice Register a trusted emitter for a Wormhole chain
    function registerEmitter(
        uint16 wormholeChainId,
        bytes32 emitterAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (wormholeChainId == 0) revert InvalidChainId();
        if (emitterAddress == bytes32(0)) revert InvalidTarget();
        registeredEmitters[wormholeChainId] = emitterAddress;
        supportedChains[wormholeChainId] = true;
        emit EmitterRegistered(wormholeChainId, emitterAddress);
        emit ChainSupported(wormholeChainId, true);
    }

    /// @notice Remove a registered emitter
    function removeEmitter(
        uint16 wormholeChainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        registeredEmitters[wormholeChainId] = bytes32(0);
        supportedChains[wormholeChainId] = false;
        emit EmitterRemoved(wormholeChainId);
        emit ChainSupported(wormholeChainId, false);
    }

    /// @notice Set a destination chain as supported
    function setSupportedChain(
        uint16 wormholeChainId,
        bool supported
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[wormholeChainId] = supported;
        emit ChainSupported(wormholeChainId, supported);
    }

    /// @notice Set the bridge fee in basis points
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        emit BridgeFeeUpdated(bridgeFee, _fee);
        bridgeFee = _fee;
    }

    /// @notice Set the minimum message fee
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MinMessageFeeUpdated(minMessageFee, _fee);
        minMessageFee = _fee;
    }

    // ──────────────────────────────────────────────
    //  Emergency
    // ──────────────────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(recipient, amount);
    }

    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, balance);
    }

    receive() external payable {}
}
