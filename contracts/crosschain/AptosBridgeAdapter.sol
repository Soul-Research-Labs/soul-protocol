// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAptosLayerZeroEndpoint
 * @notice Interface for LayerZero endpoint used for Aptos messaging
 * @dev Aptos connects to Ethereum primarily via LayerZero, which provides
 *      an oracle + relayer architecture for cross-chain verification.
 *      LayerZero on Aptos uses the same endpoint model as on EVM chains,
 *      with ultra-light nodes (ULN) and decentralized verifier networks (DVN).
 */
interface IAptosLayerZeroEndpoint {
    /// @notice Send a LayerZero message to Aptos
    /// @param dstChainId LayerZero chain ID for Aptos (108)
    /// @param destination Encoded Aptos destination address
    /// @param payload The message payload
    /// @param refundAddress Address to refund excess fees
    /// @param adapterParams Optional adapter parameters for relayer
    function send(
        uint16 dstChainId,
        bytes calldata destination,
        bytes calldata payload,
        address payable refundAddress,
        bytes calldata adapterParams
    ) external payable;

    /// @notice Estimate the fee for sending a message
    /// @param dstChainId LayerZero chain ID for Aptos (108)
    /// @param payload The message payload
    /// @param adapterParams Optional adapter parameters
    /// @return nativeFee The estimated native token fee
    /// @return zroFee The estimated ZRO token fee
    function estimateFees(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);

    /// @notice Check if a message has been received
    /// @param srcChainId The source chain's LayerZero chain ID
    /// @param srcAddress The source address
    /// @param nonce The message nonce
    /// @return Whether the message has been received
    function hasStoredPayload(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce
    ) external view returns (bool);
}

/**
 * @title IAptosLightClient
 * @notice Interface for verifying Aptos state proofs on Ethereum
 * @dev Aptos uses AptosBFT consensus (DiemBFT v4) with deterministic finality.
 *      State proofs leverage Jellyfish Merkle Trees (JMT) for efficient
 *      inclusion proofs of account resources.
 */
interface IAptosLightClient {
    /// @notice Verify a state proof from Aptos
    /// @param stateRoot The Aptos ledger state root hash
    /// @param proof The Jellyfish Merkle Tree proof
    /// @return valid Whether the proof is valid
    function verifyStateProof(
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool valid);

    /// @notice Get the latest verified Aptos ledger version
    /// @return version The latest verified ledger version
    function latestLedgerVersion() external view returns (uint64 version);
}

/**
 * @title AptosBridgeAdapter
 * @author ZASEON Team
 * @notice Bridge adapter for Aptos integration via LayerZero
 * @dev Aptos is a high-throughput L1 blockchain built on the Move programming
 *      language (Move VM), originally developed for the Diem project. It features
 *      Block-STM for parallel transaction execution and AptosBFT for consensus.
 *
 *      Key Aptos concepts:
 *      - Move VM: Resource-oriented programming (like Sui but account-based)
 *      - Block-STM: Optimistic parallel execution engine
 *      - AptosBFT (DiemBFT v4): Byzantine fault-tolerant consensus
 *      - Jellyfish Merkle Tree: State storage with efficient proofs
 *      - LayerZero: Primary cross-chain messaging protocol for Aptos
 *      - LZ Chain ID 108: Aptos LayerZero identifier
 *      - Account addresses: 32-byte hex, often with leading zeros stripped
 *
 *      ZASEON integration approach:
 *      - Uses LayerZero V1/V2 for cross-chain message delivery
 *      - Optional Aptos light client for state proof verification
 *      - DVN (Decentralized Verifier Network) security model
 *      - Nullifier-based replay protection via ZASEON CDNA
 *      - ZASEON virtual chain ID: 15_100
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract AptosBridgeAdapter is
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

    /// @notice ZASEON internal virtual chain ID for Aptos
    uint16 public constant APTOS_CHAIN_ID = 15_100;

    /// @notice LayerZero chain ID for Aptos
    uint16 public constant LZ_APTOS_CHAIN_ID = 108;

    /// @notice Finality blocks (AptosBFT has near-instant finality, ~700ms)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Maximum bridge fee in basis points (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Minimum proof size for state proof verification
    uint256 public constant MIN_PROOF_SIZE = 32;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice LayerZero endpoint for Aptos messaging
    IAptosLayerZeroEndpoint public lzEndpoint;

    /// @notice Optional Aptos light client for state proof verification
    IAptosLightClient public aptosLightClient;

    /// @notice Verified message hashes
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Spent nullifiers
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Nonce per sender
    mapping(address => uint256) public senderNonces;

    /// @notice Trusted remote Aptos module addresses per LZ chain ID
    mapping(uint16 => bytes) public trustedRemotes;

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

    /// @notice Default LayerZero adapter parameters
    bytes public defaultAdapterParams;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    error InvalidEndpoint();
    error InvalidLightClient();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidSourceChain(uint16 chainId);
    error UntrustedRemote(uint16 chainId, bytes remote);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error TransferFailed();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        uint16 dstChainId,
        uint256 lzFee
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        uint16 indexed srcChainId,
        bytes srcAddress,
        bytes payload
    );

    event EndpointUpdated(address oldEndpoint, address newEndpoint);
    event LightClientUpdated(address oldClient, address newClient);
    event TrustedRemoteSet(uint16 indexed chainId, bytes remote);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event AdapterParamsUpdated(bytes newParams);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor(address _lzEndpoint, address _admin) {
        if (_lzEndpoint == address(0)) revert InvalidEndpoint();
        if (_admin == address(0)) revert InvalidTarget();

        lzEndpoint = IAptosLayerZeroEndpoint(_lzEndpoint);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        // Default adapter params: version 1, 200k gas limit
        defaultAdapterParams = abi.encodePacked(uint16(1), uint256(200_000));
    }

    // ──────────────────────────────────────────────
    //  Send  (ZASEON → Aptos)
    // ──────────────────────────────────────────────

    /// @notice Send a cross-chain message to Aptos via LayerZero
    /// @param aptosTarget Encoded Aptos target module address
    /// @param payload The message payload
    /// @return messageHash The hash of the sent message
    function sendMessage(
        bytes calldata aptosTarget,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (aptosTarget.length == 0) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Calculate fees
        uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
        uint256 forwardValue = msg.value - protocolFee;

        if (forwardValue < minMessageFee)
            revert InsufficientFee(minMessageFee, forwardValue);

        accumulatedFees += protocolFee;

        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                APTOS_CHAIN_ID,
                msg.sender,
                aptosTarget,
                nonce,
                payload
            )
        );

        // Send via LayerZero
        lzEndpoint.send{value: forwardValue}(
            LZ_APTOS_CHAIN_ID,
            aptosTarget,
            payload,
            payable(msg.sender),
            defaultAdapterParams
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            LZ_APTOS_CHAIN_ID,
            forwardValue
        );
    }

    // ──────────────────────────────────────────────
    //  Receive  (Aptos → ZASEON)
    // ──────────────────────────────────────────────

    /// @notice Called by relayer when a message arrives from Aptos
    /// @param srcChainId LayerZero source chain ID (should be 108 for Aptos)
    /// @param srcAddress Source address on Aptos
    /// @param payload The message payload
    /// @return messageHash The verified message hash
    function receiveMessage(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (srcChainId != LZ_APTOS_CHAIN_ID)
            revert InvalidSourceChain(srcChainId);
        if (payload.length == 0) revert InvalidPayload();

        // Verify trusted remote
        bytes memory trusted = trustedRemotes[srcChainId];
        if (trusted.length == 0) revert UntrustedRemote(srcChainId, srcAddress);

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
            abi.encodePacked(srcChainId, srcAddress, payload)
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, srcChainId, srcAddress, payload);
    }

    /// @notice Verify an Aptos state proof via the light client
    /// @param stateRoot The Aptos state root
    /// @param proof The Jellyfish Merkle Tree proof
    /// @return valid Whether the proof is valid
    function verifyStateProof(
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool valid) {
        if (address(aptosLightClient) == address(0)) return false;
        if (proof.length < MIN_PROOF_SIZE) return false;
        return aptosLightClient.verifyStateProof(stateRoot, proof);
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
                APTOS_CHAIN_ID,
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

        emit MessageSent(messageId, msg.sender, LZ_APTOS_CHAIN_ID, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata payload
    ) external view override returns (uint256 nativeFee) {
        if (address(lzEndpoint) == address(0)) return minMessageFee;
        try
            lzEndpoint.estimateFees(
                LZ_APTOS_CHAIN_ID,
                payload,
                defaultAdapterParams
            )
        returns (uint256 fee, uint256) {
            return fee > minMessageFee ? fee : minMessageFee;
        } catch {
            return minMessageFee;
        }
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
        return APTOS_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Aptos";
    }

    function isConfigured() external view returns (bool) {
        return address(lzEndpoint) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    // ──────────────────────────────────────────────
    //  Admin Configuration
    // ──────────────────────────────────────────────

    function setLzEndpoint(
        address _endpoint
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_endpoint == address(0)) revert InvalidEndpoint();
        emit EndpointUpdated(address(lzEndpoint), _endpoint);
        lzEndpoint = IAptosLayerZeroEndpoint(_endpoint);
    }

    function setAptosLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit LightClientUpdated(address(aptosLightClient), _client);
        aptosLightClient = IAptosLightClient(_client);
    }

    function setTrustedRemote(
        uint16 _chainId,
        bytes calldata _remote
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        trustedRemotes[_chainId] = _remote;
        emit TrustedRemoteSet(_chainId, _remote);
    }

    function setDefaultAdapterParams(
        bytes calldata _params
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        defaultAdapterParams = _params;
        emit AdapterParamsUpdated(_params);
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
