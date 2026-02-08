// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CrossChainNullifierSync
 * @notice Handles bidirectional nullifier synchronization between chains.
 *         Outbound: batches locally-registered nullifiers and sends via bridge.
 *         Inbound: receives batches and submits to NullifierRegistryV3.
 * @dev Integrates with SoulCrossChainRelay for message transport.
 *      Uses a batch accumulator to amortize bridge costs.
 *
 *      Nullifier batch format:
 *        abi.encode(MSG_NULLIFIER_SYNC, nullifiers[], commitments[], merkleRoot, sourceChainId)
 */
contract CrossChainNullifierSync is AccessControl, ReentrancyGuard, Pausable {
    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────
    bytes32 public constant SYNCER_ROLE = keccak256("SYNCER_ROLE");
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────
    uint8 public constant MSG_NULLIFIER_SYNC = 2;
    uint256 public constant MAX_BATCH_SIZE = 20;
    uint256 public constant MIN_SYNC_INTERVAL = 5 minutes;

    // ──────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────
    struct NullifierBatch {
        bytes32[] nullifiers;
        bytes32[] commitments;
        bytes32 merkleRoot;
        uint256 chainId;
        uint256 timestamp;
        bool sent;
    }

    struct SyncTarget {
        address nullifierRegistry; // NullifierRegistryV3 address
        address relay;             // SoulCrossChainRelay address
        uint256 chainId;           // Target chain ID
        bool active;
    }

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────
    
    /// @notice Local NullifierRegistryV3 address
    address public nullifierRegistry;

    /// @notice Pending nullifiers waiting to be batched
    bytes32[] public pendingNullifiers;
    bytes32[] public pendingCommitments;

    /// @notice Sync targets keyed by chain ID
    mapping(uint256 => SyncTarget) public syncTargets;
    uint256[] public targetChainIds;

    /// @notice Batch history
    NullifierBatch[] public batchHistory;

    /// @notice Last sync timestamp per target chain
    mapping(uint256 => uint256) public lastSyncTime;

    /// @notice Total nullifiers synced per chain (outbound)
    mapping(uint256 => uint256) public outboundSyncCount;

    /// @notice Total nullifiers received per chain (inbound)
    mapping(uint256 => uint256) public inboundSyncCount;

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────
    event NullifierQueued(bytes32 indexed nullifier, bytes32 commitment);
    
    event NullifierBatchSent(
        uint256 indexed targetChainId,
        uint256 count,
        bytes32 merkleRoot,
        uint256 batchIndex
    );

    event NullifierBatchReceived(
        uint256 indexed sourceChainId,
        uint256 count,
        bytes32 sourceMerkleRoot
    );

    event SyncTargetConfigured(
        uint256 indexed chainId,
        address nullifierRegistry,
        address relay
    );

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────
    error NoPendingNullifiers();
    error TargetNotConfigured(uint256 chainId);
    error SyncTooFrequent(uint256 chainId, uint256 nextAllowed);
    error BatchTooLarge(uint256 size);
    error ZeroAddress();
    error ArrayLengthMismatch();
    error EmptyBatch();

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────
    constructor(address _nullifierRegistry) {
        if (_nullifierRegistry == address(0)) revert ZeroAddress();
        nullifierRegistry = _nullifierRegistry;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SYNCER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ──────────────────────────────────────────────
    //  Configuration
    // ──────────────────────────────────────────────

    /**
     * @notice Configure a target chain for nullifier sync
     * @param chainId Target EVM chain ID
     * @param target Sync target configuration
     */
    function configureSyncTarget(
        uint256 chainId,
        SyncTarget calldata target
    ) external onlyRole(OPERATOR_ROLE) {
        if (target.nullifierRegistry == address(0)) revert ZeroAddress();
        if (target.relay == address(0)) revert ZeroAddress();

        if (!syncTargets[chainId].active) {
            targetChainIds.push(chainId);
        }

        syncTargets[chainId] = target;
        
        emit SyncTargetConfigured(chainId, target.nullifierRegistry, target.relay);
    }

    // ──────────────────────────────────────────────
    //  Outbound: Queue & Flush Nullifiers
    // ──────────────────────────────────────────────

    /**
     * @notice Queue a nullifier for cross-chain sync. Called by the local
     *         NullifierRegistryV3 (or an authorized registrar) when a new
     *         nullifier is registered.
     * @param nullifier The nullifier hash
     * @param commitment The associated commitment
     */
    function queueNullifier(
        bytes32 nullifier,
        bytes32 commitment
    ) external onlyRole(SYNCER_ROLE) whenNotPaused {
        pendingNullifiers.push(nullifier);
        pendingCommitments.push(commitment);
        
        emit NullifierQueued(nullifier, commitment);
    }

    /**
     * @notice Batch-queue multiple nullifiers
     * @param nullifiers Array of nullifier hashes
     * @param commitments Array of associated commitments
     */
    function queueNullifierBatch(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external onlyRole(SYNCER_ROLE) whenNotPaused {
        if (nullifiers.length != commitments.length) revert ArrayLengthMismatch();
        if (nullifiers.length > MAX_BATCH_SIZE) revert BatchTooLarge(nullifiers.length);

        for (uint256 i = 0; i < nullifiers.length; i++) {
            pendingNullifiers.push(nullifiers[i]);
            pendingCommitments.push(commitments[i]);
            emit NullifierQueued(nullifiers[i], commitments[i]);
        }
    }

    /**
     * @notice Flush pending nullifiers to a target chain via the relay.
     *         Encodes the batch and sends via SoulCrossChainRelay.
     * @param targetChainId The EVM chain ID to sync to
     */
    function flushToChain(
        uint256 targetChainId
    ) external payable onlyRole(SYNCER_ROLE) nonReentrant whenNotPaused {
        if (pendingNullifiers.length == 0) revert NoPendingNullifiers();

        SyncTarget storage target = syncTargets[targetChainId];
        if (!target.active) revert TargetNotConfigured(targetChainId);

        // Rate limit
        uint256 nextAllowed = lastSyncTime[targetChainId] + MIN_SYNC_INTERVAL;
        if (block.timestamp < nextAllowed) revert SyncTooFrequent(targetChainId, nextAllowed);

        // Get current merkle root from local registry
        bytes32 currentRoot = _getCurrentMerkleRoot();

        // Take snapshot of pending nullifiers (up to MAX_BATCH_SIZE)
        uint256 batchSize = pendingNullifiers.length > MAX_BATCH_SIZE 
            ? MAX_BATCH_SIZE 
            : pendingNullifiers.length;

        bytes32[] memory batchNullifiers = new bytes32[](batchSize);
        bytes32[] memory batchCommitments = new bytes32[](batchSize);
        
        for (uint256 i = 0; i < batchSize; i++) {
            batchNullifiers[i] = pendingNullifiers[i];
            batchCommitments[i] = pendingCommitments[i];
        }

        // Remove sent items from pending arrays
        _removeSentItems(batchSize);

        // Encode the sync message
        bytes memory payload = abi.encode(
            MSG_NULLIFIER_SYNC,
            batchNullifiers,
            batchCommitments,
            currentRoot,
            uint64(block.chainid)
        );

        // Record batch
        batchHistory.push(NullifierBatch({
            nullifiers: batchNullifiers,
            commitments: batchCommitments,
            merkleRoot: currentRoot,
            chainId: targetChainId,
            timestamp: block.timestamp,
            sent: true
        }));

        // Send via relay
        (bool success,) = target.relay.call{value: msg.value}(
            abi.encodeWithSignature(
                "relayProof(bytes32,bytes,bytes,bytes32,uint64,bytes32)",
                keccak256(abi.encodePacked("nullifier_sync", block.timestamp, batchSize)),
                payload,
                "",
                currentRoot,
                uint64(targetChainId),
                keccak256("NULLIFIER_SYNC")
            )
        );

        lastSyncTime[targetChainId] = block.timestamp;
        outboundSyncCount[targetChainId] += batchSize;

        emit NullifierBatchSent(
            targetChainId,
            batchSize,
            currentRoot,
            batchHistory.length - 1
        );
    }

    // ──────────────────────────────────────────────
    //  Inbound: Receive Nullifiers from Remote Chain
    // ──────────────────────────────────────────────

    /**
     * @notice Receive a batch of nullifiers from a remote chain.
     *         Called by SoulCrossChainRelay when a nullifier sync message
     *         arrives via bridge adapter.
     * @param sourceChainId The originating chain ID
     * @param nullifiers Array of nullifier hashes
     * @param commitments Array of associated commitments
     * @param sourceMerkleRoot Merkle root from the source chain (for verification)
     */
    function receiveNullifierBatch(
        uint256 sourceChainId,
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        bytes32 sourceMerkleRoot
    ) external onlyRole(BRIDGE_ROLE) nonReentrant whenNotPaused {
        if (nullifiers.length != commitments.length) revert ArrayLengthMismatch();
        if (nullifiers.length == 0) revert EmptyBatch();
        if (nullifiers.length > MAX_BATCH_SIZE) revert BatchTooLarge(nullifiers.length);

        // Submit to local NullifierRegistryV3
        (bool success,) = nullifierRegistry.call(
            abi.encodeWithSignature(
                "receiveCrossChainNullifiers(uint256,bytes32[],bytes32[],bytes32)",
                sourceChainId,
                nullifiers,
                commitments,
                sourceMerkleRoot
            )
        );

        inboundSyncCount[sourceChainId] += nullifiers.length;

        emit NullifierBatchReceived(sourceChainId, nullifiers.length, sourceMerkleRoot);
    }

    // ──────────────────────────────────────────────
    //  Internal
    // ──────────────────────────────────────────────

    function _getCurrentMerkleRoot() internal view returns (bytes32) {
        (bool success, bytes memory data) = nullifierRegistry.staticcall(
            abi.encodeWithSignature("getCurrentRoot()")
        );
        if (success && data.length == 32) {
            return abi.decode(data, (bytes32));
        }
        return bytes32(0);
    }

    function _removeSentItems(uint256 count) internal {
        uint256 remaining = pendingNullifiers.length - count;
        for (uint256 i = 0; i < remaining; i++) {
            pendingNullifiers[i] = pendingNullifiers[i + count];
            pendingCommitments[i] = pendingCommitments[i + count];
        }
        for (uint256 i = 0; i < count; i++) {
            pendingNullifiers.pop();
            pendingCommitments.pop();
        }
    }

    // ──────────────────────────────────────────────
    //  View Functions
    // ──────────────────────────────────────────────

    function getPendingCount() external view returns (uint256) {
        return pendingNullifiers.length;
    }

    function getTargetChains() external view returns (uint256[] memory) {
        return targetChainIds;
    }

    function getBatchCount() external view returns (uint256) {
        return batchHistory.length;
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
