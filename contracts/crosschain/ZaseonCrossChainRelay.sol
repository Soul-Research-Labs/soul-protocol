// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/**
 * @title ZaseonCrossChainRelay
 * @author ZASEON
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
contract ZaseonCrossChainRelay is AccessControl, ReentrancyGuard, Pausable {
    using SafeCast for uint256;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant RELAY_ROLE = keccak256("RELAY_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ──────────────────────────────────────────────
    //  Message Types
    // ──────────────────────────────────────────────
    uint8 public constant MSG_PROOF_RELAY = 1;
    uint8 public constant MSG_NULLIFIER_SYNC = 2;
    uint8 public constant MSG_LOCK_NOTIFICATION = 3;
    bytes32 public constant NULLIFIER_SYNC_PROOF_TYPE =
        keccak256("NULLIFIER_SYNC");

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
        address relayAdapter; // LayerZero or Hyperlane adapter address
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
    address public nullifierSync; // Local CrossChainNullifierSync
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
        address relayAdapter,
        uint32 bridgeChainId
    );

    event NullifierSyncUpdated(address indexed nullifierSync);

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
    error InvalidRelayAdapter();
    error InvalidNullifierSync();
    error InvalidMessage();
    error ZeroAddress();
    error UnauthorizedNullifierSync();
    error BridgeCallFailed(string reason);
    error ProofHubSubmitFailed(bytes32 messageId);
    error NullifierSyncSubmitFailed(bytes32 messageId);

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
     * @param config Chain configuration (proofHub, relayAdapter, bridgeChainId)
     */
    function configureChain(
        uint256 chainId,
        ChainConfig calldata config
    ) external onlyRole(OPERATOR_ROLE) {
        if (config.proofHub == address(0)) revert InvalidProofHub();
        if (config.relayAdapter == address(0)) revert InvalidRelayAdapter();

        // Track new chains
        if (!chainConfigs[chainId].active) {
            supportedChains.push(chainId);
        }

        chainConfigs[chainId] = config;

        emit ChainConfigured(
            chainId,
            config.proofHub,
            config.relayAdapter,
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
        return
            _relayProof(
                proofId,
                proof,
                publicInputs,
                commitment,
                destChainId,
                proofType
            );
    }

    /**
     * @notice Permissionless self-relay for users.
     *         Allows anyone to relay a proof by paying the bridge fee directly.
     *         Bypasses RELAYER_ROLE check to prevent censorship/downtime.
     * @param proofId The proofId identifier
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param commitment The cryptographic commitment
     * @param destChainId The destination chain identifier
     * @param proofType The proof type
     * @return messageId The message id
     */
    function selfRelayProof(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 destChainId,
        bytes32 proofType
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        return
            _relayProof(
                proofId,
                proof,
                publicInputs,
                commitment,
                destChainId,
                proofType
            );
    }

    /**
     * @notice _relay proof
     * @param proofId The proofId identifier
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param commitment The cryptographic commitment
     * @param destChainId The destination chain identifier
     * @param proofType The proof type
     * @return messageId The message id
     */
    function _relayProof(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 destChainId,
        bytes32 proofType
    ) internal returns (bytes32 messageId) {
        if (proofType == NULLIFIER_SYNC_PROOF_TYPE) {
            if (nullifierSync == address(0)) revert InvalidNullifierSync();
            if (msg.sender != nullifierSync) revert UnauthorizedNullifierSync();
        }

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
    ) external onlyRole(RELAY_ROLE) nonReentrant whenNotPaused {
        // Decode message type
        uint8 msgType = abi.decode(payload, (uint8));

        if (msgType == MSG_BATCH_RELAY) {
            _processBatch(payload);
            return;
        }

        if (msgType != MSG_PROOF_RELAY) revert InvalidMessage();

        _processProofRelayPayload(payload, false, 0);
    }

    function _processProofRelayPayload(
        bytes memory payload,
        bool skipIfProcessed,
        uint64 expectedSourceChainId
    ) internal {
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

        if (expectedSourceChainId != 0 && srcChainId != expectedSourceChainId) {
            revert InvalidMessage();
        }

        bytes32 msgId = _messageId(proofId, srcChainId, proofType);
        if (processedMessages[msgId]) {
            if (skipIfProcessed) return;
            revert AlreadyProcessed(msgId);
        }

        if (proofType == NULLIFIER_SYNC_PROOF_TYPE) {
            _submitNullifierSyncPayload(msgId, proof, srcChainId);
            return;
        }

        if (
            !_submitToProofHub(
                proof,
                publicInputs,
                commitment,
                srcChainId,
                proofType
            )
        ) {
            revert ProofHubSubmitFailed(msgId);
        }

        processedMessages[msgId] = true;
        emit ProofReceived(proofId, srcChainId, commitment, true);
    }

    function _submitNullifierSyncPayload(
        bytes32 msgId,
        bytes memory payload,
        uint64 outerSourceChainId
    ) internal {
        (
            uint8 msgType,
            bytes32[] memory nullifiers,
            bytes32[] memory commitments,
            bytes32 sourceMerkleRoot,
            uint64 sourceChainId,
            uint256 sequence
        ) = abi.decode(
                payload,
                (uint8, bytes32[], bytes32[], bytes32, uint64, uint256)
            );

        sequence;

        if (
            msgType != MSG_NULLIFIER_SYNC || sourceChainId != outerSourceChainId
        ) {
            revert InvalidMessage();
        }
        if (nullifierSync == address(0)) revert InvalidNullifierSync();
        if (
            !_submitToNullifierSync(
                sourceChainId,
                nullifiers,
                commitments,
                sourceMerkleRoot
            )
        ) {
            revert NullifierSyncSubmitFailed(msgId);
        }

        processedMessages[msgId] = true;
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
        (bool success, ) = config.relayAdapter.call{value: msg.value}(
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
        (bool success, ) = config.relayAdapter.call{value: msg.value}(
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
        uint256 submitValue = _proofSubmissionFee();
        if (address(this).balance < submitValue) return false;

        // Call CrossChainProofHubV3.submitProofInstant() for immediate verification
        (bool success, ) = proofHub.call{value: submitValue}(
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

    function _submitToNullifierSync(
        uint256 sourceChainId,
        bytes32[] memory nullifiers,
        bytes32[] memory commitments,
        bytes32 sourceMerkleRoot
    ) internal returns (bool) {
        (bool success, ) = nullifierSync.call(
            abi.encodeWithSignature(
                "receiveNullifierBatch(uint256,bytes32[],bytes32[],bytes32)",
                sourceChainId,
                nullifiers,
                commitments,
                sourceMerkleRoot
            )
        );
        return success;
    }

    function _proofSubmissionFee() internal view returns (uint256 fee) {
        (bool success, bytes memory data) = proofHub.staticcall(
            abi.encodeWithSignature("proofSubmissionFee()")
        );
        if (success && data.length >= 32) {
            fee = abi.decode(data, (uint256));
        }
    }

    function _messageId(
        bytes32 proofId,
        uint64 sourceChainId,
        bytes32 proofType
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    proofId,
                    sourceChainId,
                    block.chainid,
                    proofType
                )
            );
    }

    // ──────────────────────────────────────────────
    //  View functions
    // ──────────────────────────────────────────────

    /// @notice Get all chain IDs supported by this relay
    /// @return Array of supported chain IDs
    /**
     * @notice Returns the supported chains
     * @return The result value
     */
    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    /// @notice Check whether a chain ID is supported and active
    /// @param chainId The chain ID to query
    /// @return True if the chain is supported and active
    /**
     * @notice Checks if chain supported
     * @param chainId The chain identifier
     * @return The result value
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].active;
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Pause cross-chain relay operations
    /**
     * @notice Pauses the operation
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /// @notice Unpause cross-chain relay operations
    /**
     * @notice Unpauses the operation
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // ──────────────────────────────────────────────
    //  Batch Relay
    // ──────────────────────────────────────────────

    uint8 public constant MSG_BATCH_RELAY = 4;

    /**
     * @notice Relay a batch of proofs to a destination chain.
     * @param destChainId Destination EVM chain ID
     * @param payloads Array of encoded proof payloads
     * @return messageId Unique message identifier for the batch
     */
    function relayBatch(
        uint64 destChainId,
        bytes[] calldata payloads
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        ChainConfig storage config = chainConfigs[destChainId];
        if (!config.active) revert ChainNotSupported(destChainId);

        // Encode batch payload
        bytes memory batchPayload = abi.encode(
            MSG_BATCH_RELAY,
            payloads,
            block.chainid.toUint64()
        );

        messageId = keccak256(
            abi.encodePacked("BATCH", block.chainid, destChainId, relayNonce++)
        );

        _sendViaBridge(config, batchPayload);

        emit ProofRelayed(
            bytes32(0), // No single proof ID
            block.chainid.toUint64(),
            destChainId,
            bytes32(0), // No single commitment
            messageId
        );
    }

    /**
     * @dev Process batch message in receiveRelayedProof
     */
    function _processBatch(bytes calldata payload) internal returns (bool) {
        (, bytes[] memory payloads, uint64 srcChainId) = abi.decode(
            payload,
            (uint8, bytes[], uint64)
        );

        for (uint256 i = 0; i < payloads.length; i++) {
            _processProofRelayPayload(payloads[i], true, srcChainId);
        }
        return true;
    }

    /// @notice Update the proof hub contract address
    /// @param _proofHub The new proof hub address (must be non-zero)
    /**
     * @notice Updates proof hub
     * @param _proofHub The _proof hub
     */
    function updateProofHub(
        address _proofHub
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_proofHub == address(0)) revert ZeroAddress();
        proofHub = _proofHub;
    }

    function updateNullifierSync(
        address _nullifierSync
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_nullifierSync == address(0)) revert InvalidNullifierSync();
        nullifierSync = _nullifierSync;
        emit NullifierSyncUpdated(_nullifierSync);
    }

    receive() external payable {}
}
