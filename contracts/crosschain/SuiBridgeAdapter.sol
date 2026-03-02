// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ISuiBridge
 * @notice Minimal interface for the Sui Native Bridge contract on Ethereum
 * @dev Sui Native Bridge is a committee-based bridge connecting Sui and
 *      Ethereum. The bridge committee is a subset of Sui validators who
 *      collectively sign cross-chain messages. Messages require a quorum
 *      of committee member signatures to be executed.
 */
interface ISuiBridge {
    /// @notice Send tokens to Sui via the native bridge
    /// @param suiAddress The recipient address on Sui (32-byte)
    /// @param amount The amount of tokens to send
    /// @param tokenId The bridge token identifier
    function sendToSui(
        bytes32 suiAddress,
        uint256 amount,
        uint8 tokenId
    ) external payable;

    /// @notice Execute a bridge message signed by the committee
    /// @param encodedMessage The BCS-encoded bridge message
    /// @param signatures Committee member signatures
    function executeMessage(
        bytes calldata encodedMessage,
        bytes[] calldata signatures
    ) external;

    /// @notice Check if a message nonce has been processed
    /// @param messageType The message type
    /// @param nonce The message nonce
    /// @return processed Whether the nonce has been processed
    function isMessageProcessed(
        uint8 messageType,
        uint64 nonce
    ) external view returns (bool processed);
}

/**
 * @title ISuiLightClient
 * @notice Interface for verifying Sui committee signatures
 * @dev Sui uses a BFT consensus (Mysticeti) with deterministic finality.
 *      The light client tracks the active committee and verifies aggregated
 *      BLS12-381 signatures from committee members.
 */
interface ISuiLightClient {
    /// @notice Verify a committee signature on a message
    /// @param messageHash The hash of the message
    /// @param signatures Aggregated committee signatures
    /// @return valid Whether the signatures meet the quorum threshold
    function verifyCommitteeSignature(
        bytes32 messageHash,
        bytes calldata signatures
    ) external view returns (bool valid);

    /// @notice Get the current committee epoch
    /// @return epoch The current epoch number
    function currentEpoch() external view returns (uint64 epoch);
}

/**
 * @title SuiBridgeAdapter
 * @author ZASEON Team
 * @notice Bridge adapter for Sui integration via the Sui Native Bridge
 * @dev Sui is a high-performance L1 blockchain built on the Move programming
 *      language (Move VM). It features object-centric data model, parallel
 *      transaction execution, and deterministic finality via Mysticeti BFT.
 *
 *      Key Sui concepts:
 *      - Move VM: Safe, resource-oriented smart contract language
 *      - Object Model: Assets are first-class objects with ownership
 *      - Mysticeti: DAG-based BFT consensus (~390ms finality)
 *      - Sui Bridge: Native validator committee bridge (not third-party)
 *      - BLS12-381: Signature scheme for committee attestations
 *      - Epochs: ~24hr periods for committee rotation (~2 second checkpoints)
 *
 *      ZASEON integration approach:
 *      - Uses Sui Native Bridge for cross-chain message passing
 *      - Committee signatures verified via ISuiLightClient
 *      - 32-byte Sui addresses (hex-encoded object IDs)
 *      - Nullifier-based replay protection via ZASEON CDNA
 *      - ZASEON virtual chain ID: 14_100
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract SuiBridgeAdapter is
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

    /// @notice ZASEON internal virtual chain ID for Sui
    uint16 public constant SUI_CHAIN_ID = 14_100;

    /// @notice Finality blocks (~390ms Mysticeti finality)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Minimum proof size for committee signature verification
    uint256 public constant MIN_PROOF_SIZE = 32;

    /// @notice Maximum bridge fee in basis points (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Committee quorum threshold (2/3 + 1 of committee)
    uint256 public constant COMMITTEE_QUORUM_BPS = 6_667;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice Sui Native Bridge contract
    ISuiBridge public suiBridge;

    /// @notice Sui Light Client for committee signature verification
    ISuiLightClient public suiLightClient;

    /// @notice Verified message hashes
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Spent nullifiers
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Nonce per sender
    mapping(address => uint256) public senderNonces;

    /// @notice Whitelisted Sui program addresses (32-byte object IDs)
    mapping(bytes32 => bool) public whitelistedPrograms;

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

    error InvalidBridge();
    error InvalidLightClient();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error ProgramNotWhitelisted(bytes32 program);
    error TransferFailed();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 suiTarget,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 indexed suiSender,
        bytes payload
    );

    event BridgeUpdated(address oldBridge, address newBridge);
    event LightClientUpdated(address oldClient, address newClient);
    event ProgramWhitelisted(bytes32 indexed program);
    event ProgramRemoved(bytes32 indexed program);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor(address _suiBridge, address _suiLightClient, address _admin) {
        if (_suiBridge == address(0)) revert InvalidBridge();
        if (_suiLightClient == address(0)) revert InvalidLightClient();
        if (_admin == address(0)) revert InvalidTarget();

        suiBridge = ISuiBridge(_suiBridge);
        suiLightClient = ISuiLightClient(_suiLightClient);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    // ──────────────────────────────────────────────
    //  Send  (ZASEON → Sui)
    // ──────────────────────────────────────────────

    /// @notice Send a cross-chain message to Sui
    /// @param suiTarget 32-byte Sui object ID of the target program
    /// @param payload The message payload
    /// @return messageHash The hash of the sent message
    function sendMessage(
        bytes32 suiTarget,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (suiTarget == bytes32(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();
        if (msg.value < minMessageFee)
            revert InsufficientFee(minMessageFee, msg.value);

        uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
        uint256 forwardValue = msg.value - protocolFee;
        accumulatedFees += protocolFee;

        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                SUI_CHAIN_ID,
                msg.sender,
                suiTarget,
                nonce,
                payload
            )
        );

        // Forward to Sui bridge
        suiBridge.sendToSui{value: forwardValue}(
            suiTarget,
            forwardValue,
            0 // native token type
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageHash, msg.sender, suiTarget, msg.value);
    }

    // ──────────────────────────────────────────────
    //  Receive  (Sui → ZASEON)
    // ──────────────────────────────────────────────

    /// @notice Receive and verify a message from Sui
    /// @param suiSender 32-byte Sui object ID of the sender
    /// @param payload The message payload
    /// @param committeeProof Committee signature proof
    /// @return messageHash The hash of the received message
    function receiveMessage(
        bytes32 suiSender,
        bytes calldata payload,
        bytes calldata committeeProof
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (suiSender == bytes32(0)) revert InvalidTarget();
        if (payload.length == 0) revert InvalidPayload();
        if (committeeProof.length < MIN_PROOF_SIZE) revert InvalidProof();

        // Verify Sui sender is whitelisted
        if (!whitelistedPrograms[suiSender])
            revert ProgramNotWhitelisted(suiSender);

        // Verify committee signature
        bytes32 payloadHash = keccak256(payload);
        bool valid = suiLightClient.verifyCommitteeSignature(
            payloadHash,
            committeeProof
        );
        if (!valid) revert InvalidProof();

        // Extract nullifier
        bytes32 nullifier;
        if (payload.length >= 32) {
            nullifier = bytes32(payload[:32]);
        } else {
            nullifier = keccak256(payload);
        }

        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        messageHash = keccak256(
            abi.encodePacked(suiSender, payloadHash, committeeProof)
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, suiSender, payload);
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
                SUI_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                payload
            )
        );

        if (msg.value > 0) {
            uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
            totalValueBridged += msg.value;
        }

        verifiedMessages[messageId] = true;
        totalMessagesSent++;

        emit MessageSent(
            messageId,
            msg.sender,
            bytes32(uint256(uint160(targetAddress))),
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        return minMessageFee;
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

    function chainId() external pure returns (uint16) {
        return SUI_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Sui";
    }

    function isConfigured() external view returns (bool) {
        return
            address(suiBridge) != address(0) &&
            address(suiLightClient) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    // ──────────────────────────────────────────────
    //  Admin Configuration
    // ──────────────────────────────────────────────

    function setSuiBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        emit BridgeUpdated(address(suiBridge), _bridge);
        suiBridge = ISuiBridge(_bridge);
    }

    function setSuiLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_client == address(0)) revert InvalidLightClient();
        emit LightClientUpdated(address(suiLightClient), _client);
        suiLightClient = ISuiLightClient(_client);
    }

    function whitelistProgram(
        bytes32 program
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (program == bytes32(0)) revert InvalidTarget();
        whitelistedPrograms[program] = true;
        emit ProgramWhitelisted(program);
    }

    function removeProgram(
        bytes32 program
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelistedPrograms[program] = false;
        emit ProgramRemoved(program);
    }

    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        emit BridgeFeeUpdated(bridgeFee, _fee);
        bridgeFee = _fee;
    }

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
