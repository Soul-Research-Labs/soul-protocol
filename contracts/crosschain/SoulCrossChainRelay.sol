// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/**
 * @title SoulCrossChainRelay
 * @author Soul Protocol
 * @notice Bridges CrossChainProofHubV3 with LayerZero/Hyperlane adapters for
 *         real cross-chain proof relay. When a proof is finalized on the source
 *         chain, this relay encodes it and dispatches via the configured bridge.
 *         On the destination chain, incoming messages are decoded and submitted
 *         to the local CrossChainProofHubV3.
 * @dev Deployed on both source and destination chains. Source side relays
 *      finalized proofs outbound; destination side receives and submits.
 *
 *      Message format:
 *        abi.encode(MESSAGE_TYPE, proofId, proof, publicInputs, commitment, sourceChainId)
 */
contract SoulCrossChainRelay is AccessControl, ReentrancyGuard, Pausable {
    using SafeCast for uint256;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ──────────────────────────────────────────────
    //  Message Types
    // ──────────────────────────────────────────────
    uint8 public constant MSG_PROOF_RELAY = 1;
    uint8 public constant MSG_NULLIFIER_SYNC = 2;
    uint8 public constant MSG_LOCK_NOTIFICATION = 3;

    // ──────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────
    struct RelayedProof {
        bytes32 proofId;
        bytes proof;
        bytes publicInputs;
        bytes32 commitment;
        uint64 sourceChainId;
        uint64 destChainId;
        bytes32 proofType;
        uint256 timestamp;
        bool processed;
    }

    struct ChainConfig {
        address proofHub; // CrossChainProofHubV3 address on that chain
        address bridgeAdapter; // LayerZero or Hyperlane adapter address
        uint32 bridgeChainId; // Bridge-specific chain identifier (LZ eid / Hyperlane domain)
        bool active;
    }

    enum BridgeType {
        LAYERZERO,
        HYPERLANE
    }

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────
    address public proofHub; // Local CrossChainProofHubV3
    BridgeType public bridgeType;

    /// @notice Chain configs keyed by EVM chain ID
    mapping(uint256 => ChainConfig) public chainConfigs;

    /// @notice Supported destination chain IDs
    uint256[] public supportedChains;

    /// @notice Relayed proofs by ID
    mapping(bytes32 => RelayedProof) public relayedProofs;

    /// @notice Processed message dedup
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Relay nonce for unique message IDs
    uint256 public relayNonce;

    /// @notice Maximum proof size (prevents griefing)
    uint256 public constant MAX_PROOF_SIZE = 32_768; // 32 KB

    /// @notice Maximum public inputs size
    uint256 public constant MAX_PUBLIC_INPUTS_SIZE = 8_192; // 8 KB

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────
    event ProofRelayed(
        bytes32 indexed proofId,
        uint64 sourceChainId,
        uint64 destChainId,
        bytes32 commitment,
        bytes32 messageId
    );

    event ProofReceived(
        bytes32 indexed proofId,
        uint64 sourceChainId,
        bytes32 commitment,
        bool submitted
    );

    event ChainConfigured(
        uint256 indexed chainId,
        address proofHub,
        address bridgeAdapter,
        uint32 bridgeChainId
    );

    event ProofRelayFailed(
        bytes32 indexed proofId,
        uint64 destChainId,
        string reason
    );

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────
    error ChainNotSupported(uint256 chainId);
    error ProofTooLarge(uint256 size);
    error PublicInputsTooLarge(uint256 size);
    error AlreadyProcessed(bytes32 messageId);
    error InvalidProofHub();
    error InvalidBridgeAdapter();
    error InvalidMessage();
    error ZeroAddress();
    error BridgeCallFailed(string reason);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────
    constructor(address _proofHub, BridgeType _bridgeType) {
        if (_proofHub == address(0)) revert ZeroAddress();
        proofHub = _proofHub;
        bridgeType = _bridgeType;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ──────────────────────────────────────────────
    //  Configuration
    // ──────────────────────────────────────────────

    /**
     * @notice Configure a destination chain for cross-chain relay
     * @param chainId EVM chain ID of the destination
     * @param config Chain configuration (proofHub, bridgeAdapter, bridgeChainId)
     */
    function configureChain(
        uint256 chainId,
        ChainConfig calldata config
    ) external onlyRole(OPERATOR_ROLE) {
        if (config.proofHub == address(0)) revert InvalidProofHub();
        if (config.bridgeAdapter == address(0)) revert InvalidBridgeAdapter();

        // Track new chains
        if (!chainConfigs[chainId].active) {
            supportedChains.push(chainId);
        }

        chainConfigs[chainId] = config;

        emit ChainConfigured(
            chainId,
            config.proofHub,
            config.bridgeAdapter,
            config.bridgeChainId
        );
    }

    // ──────────────────────────────────────────────
    //  Outbound: Relay Proof to Destination Chain
    // ──────────────────────────────────────────────

    /**
     * @notice Relay a finalized proof from the local ProofHub to a destination chain.
     *         Called by authorized relayers after proof finalization.
     * @param proofId The proof ID from CrossChainProofHubV3
     * @param proof The ZK proof bytes
     * @param publicInputs The public inputs bytes
     * @param commitment The state commitment
     * @param destChainId Destination EVM chain ID
     * @param proofType The proof type identifier
     * @return messageId Unique message identifier for tracking
     */
    function relayProof(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 destChainId,
        bytes32 proofType
    )
        external
        payable
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        return _relayProof(proofId, proof, publicInputs, commitment, destChainId, proofType);
    }

    /**
     * @notice Permissionless self-relay for users.
     *         Allows anyone to relay a proof by paying the bridge fee directly.
     *         Bypasses RELAYER_ROLE check to prevent censorship/downtime.
     */
    function selfRelayProof(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 destChainId,
        bytes32 proofType
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        return _relayProof(proofId, proof, publicInputs, commitment, destChainId, proofType);
    }

    function _relayProof(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 destChainId,
        bytes32 proofType
    ) internal returns (bytes32 messageId) {
        // Validate sizes
        if (proof.length > MAX_PROOF_SIZE) revert ProofTooLarge(proof.length);
        if (publicInputs.length > MAX_PUBLIC_INPUTS_SIZE)
            revert PublicInputsTooLarge(publicInputs.length);

        ChainConfig storage config = chainConfigs[destChainId];
        if (!config.active) revert ChainNotSupported(destChainId);

        // Encode the message
        bytes memory payload = abi.encode(
            MSG_PROOF_RELAY,
            proofId,
            proof,
            publicInputs,
            commitment,
            block.chainid.toUint64(),
            proofType
        );

        // Generate unique message ID
        messageId = keccak256(
            abi.encodePacked(proofId, block.chainid, destChainId, relayNonce++)
        );

        // Store relay record
        relayedProofs[messageId] = RelayedProof({
            proofId: proofId,
            proof: proof,
            publicInputs: publicInputs,
            commitment: commitment,
            sourceChainId: block.chainid.toUint64(),
            destChainId: uint64(destChainId),
            proofType: proofType,
            timestamp: block.timestamp,
            processed: false
        });

        // Dispatch via bridge adapter
        _sendViaBridge(config, payload);

        emit ProofRelayed(
            proofId,
            block.chainid.toUint64(),
            uint64(destChainId),
            commitment,
            messageId
        );
    }

    // ──────────────────────────────────────────────
    //  Inbound: Receive Proof from Source Chain
    // ──────────────────────────────────────────────

    /**
     * @notice Called by bridge adapters when a cross-chain proof message arrives.
     *         Decodes the payload and submits to the local CrossChainProofHubV3.
     * @param payload The encoded proof message
     */
    function receiveRelayedProof(
        uint256 /* _sourceChainId */,
        bytes calldata payload
    ) external onlyRole(BRIDGE_ROLE) nonReentrant whenNotPaused {
        // Decode message type
        uint8 msgType = abi.decode(payload, (uint8));
        if (msgType != MSG_PROOF_RELAY) revert InvalidMessage();

        (
            ,
            bytes32 proofId,
            bytes memory proof,
            bytes memory publicInputs,
            bytes32 commitment,
            uint64 srcChainId,
            bytes32 proofType
        ) = abi.decode(
                payload,
                (uint8, bytes32, bytes, bytes, bytes32, uint64, bytes32)
            );

        // Dedup check
        bytes32 msgId = keccak256(
            abi.encodePacked(proofId, srcChainId, block.chainid)
        );
        if (processedMessages[msgId]) revert AlreadyProcessed(msgId);
        processedMessages[msgId] = true;

        // Submit to local ProofHub
        bool submitted = _submitToProofHub(
            proof,
            publicInputs,
            commitment,
            srcChainId,
            proofType
        );

        emit ProofReceived(proofId, srcChainId, commitment, submitted);
    }

    // ──────────────────────────────────────────────
    //  Internal: Bridge dispatch
    // ──────────────────────────────────────────────

    function _sendViaBridge(
        ChainConfig storage config,
        bytes memory payload
    ) internal {
        if (bridgeType == BridgeType.LAYERZERO) {
            _sendViaLayerZero(config, payload);
        } else {
            _sendViaHyperlane(config, payload);
        }
    }

    function _sendViaLayerZero(
        ChainConfig storage config,
        bytes memory payload
    ) internal {
        // Call LayerZeroAdapter.sendMessage(dstEid, payload, options)
        // The adapter handles LZ endpoint interaction
        (bool success, ) = config.bridgeAdapter.call{value: msg.value}(
            abi.encodeWithSignature(
                "sendMessage(uint32,bytes,(uint128,uint128))",
                config.bridgeChainId,
                payload,
                // ExecutorOptions: gasLimit=500000, value=0
                abi.encode(uint128(500_000), uint128(0))
            )
        );
        if (!success) {
            revert BridgeCallFailed("LayerZero send failed");
        }
    }

    function _sendViaHyperlane(
        ChainConfig storage config,
        bytes memory payload
    ) internal {
        // Call HyperlaneAdapter.dispatch(destinationDomain, recipient, message)
        (bool success, ) = config.bridgeAdapter.call{value: msg.value}(
            abi.encodeWithSignature(
                "dispatch(uint32,bytes32,bytes)",
                config.bridgeChainId,
                bytes32(uint256(uint160(config.proofHub))),
                payload
            )
        );
        if (!success) {
            revert BridgeCallFailed("Hyperlane dispatch failed");
        }
    }

    function _submitToProofHub(
        bytes memory proof,
        bytes memory publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        bytes32 proofType
    ) internal returns (bool) {
        // Call CrossChainProofHubV3.submitProofInstant() for immediate verification
        (bool success, ) = proofHub.call(
            abi.encodeWithSignature(
                "submitProofInstant(bytes,bytes,bytes32,uint64,uint64,bytes32)",
                proof,
                publicInputs,
                commitment,
                sourceChainId,
                block.chainid.toUint64(),
                proofType
            )
        );
        return success;
    }

    // ──────────────────────────────────────────────
    //  View functions
    // ──────────────────────────────────────────────

    /// @notice Get all chain IDs supported by this relay
    /// @return Array of supported chain IDs
    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    /// @notice Check whether a chain ID is supported and active
    /// @param chainId The chain ID to query
    /// @return True if the chain is supported and active
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].active;
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Pause cross-chain relay operations
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /// @notice Unpause cross-chain relay operations
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /// @notice Update the proof hub contract address
    /// @param _proofHub The new proof hub address (must be non-zero)
    function updateProofHub(
        address _proofHub
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_proofHub == address(0)) revert ZeroAddress();
        proofHub = _proofHub;
    }
}
