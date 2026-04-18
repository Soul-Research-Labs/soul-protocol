// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ICrossChainNullifierSync} from "../interfaces/ICrossChainNullifierSync.sol";

/**
 * @title CrossChainNullifierSync
 * @author ZASEON
 * @notice Handles bidirectional nullifier synchronization between chains.
 *         Outbound: batches locally-registered nullifiers and sends via bridge.
 *         Inbound: receives batches and submits to NullifierRegistryV3.
 * @dev Integrates with ZaseonCrossChainRelay for message transport.
 *      Uses a batch accumulator to amortize bridge costs.
 *
 *      Nullifier batch format:
 *        abi.encode(MSG_NULLIFIER_SYNC, nullifiers[], commitments[], merkleRoot, sourceChainId)
 */
contract CrossChainNullifierSync is
    ICrossChainNullifierSync,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeCast for uint256;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────
    bytes32 public constant SYNCER_ROLE = keccak256("SYNCER_ROLE");
    bytes32 public constant RELAY_ROLE = keccak256("RELAY_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────
    uint8 public constant MSG_NULLIFIER_SYNC = 2;
    bytes32 public constant NULLIFIER_SYNC_PROOF_TYPE =
        keccak256("NULLIFIER_SYNC");
    uint256 public constant MAX_BATCH_SIZE = 20;
    uint256 public constant MIN_SYNC_INTERVAL = 5 minutes;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice Local NullifierRegistryV3 address
    address public nullifierRegistry;

    /// @notice Pending nullifiers waiting to be batched
    bytes32[] public pendingNullifiers;
    bytes32[] public pendingCommitments;

    /// @notice Head pointer for O(1) queue dequeue (SECURITY FIX M-3)
    uint256 public pendingHead;

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

    /// @notice Per-chain sync sequence number for replay protection
    mapping(uint256 => uint256) public syncSequence;

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

        emit SyncTargetConfigured(
            chainId,
            target.nullifierRegistry,
            target.relay
        );
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
        if (nullifiers.length != commitments.length)
            revert ArrayLengthMismatch();
        if (nullifiers.length > MAX_BATCH_SIZE)
            revert BatchTooLarge(nullifiers.length);

        for (uint256 i = 0; i < nullifiers.length; ) {
            pendingNullifiers.push(nullifiers[i]);
            pendingCommitments.push(commitments[i]);
            emit NullifierQueued(nullifiers[i], commitments[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Flush pending nullifiers to a target chain via the relay.
     *         Encodes the batch and sends via ZaseonCrossChainRelay.
     * @param targetChainId The EVM chain ID to sync to
     */
    function flushToChain(
        uint256 targetChainId
    ) external payable onlyRole(SYNCER_ROLE) nonReentrant whenNotPaused {
        if (pendingNullifiers.length - pendingHead == 0)
            revert NoPendingNullifiers();

        SyncTarget storage target = syncTargets[targetChainId];
        if (!target.active) revert TargetNotConfigured(targetChainId);

        // Rate limit
        uint256 nextAllowed = lastSyncTime[targetChainId] + MIN_SYNC_INTERVAL;
        if (block.timestamp < nextAllowed)
            revert SyncTooFrequent(targetChainId, nextAllowed);

        // Get current merkle root from local registry
        bytes32 currentRoot = _getCurrentMerkleRoot();

        // Take snapshot of pending nullifiers (up to MAX_BATCH_SIZE)
        uint256 pendingCount = pendingNullifiers.length - pendingHead;
        uint256 batchSize = pendingCount > MAX_BATCH_SIZE
            ? MAX_BATCH_SIZE
            : pendingCount;

        bytes32[] memory batchNullifiers = new bytes32[](batchSize);
        bytes32[] memory batchCommitments = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; ) {
            batchNullifiers[i] = pendingNullifiers[pendingHead + i];
            batchCommitments[i] = pendingCommitments[pendingHead + i];
            unchecked {
                ++i;
            }
        }

        // SECURITY FIX M-3: O(1) head pointer advance instead of O(n) array shift
        pendingHead += batchSize;

        uint256 seq = ++syncSequence[targetChainId];
        bytes32 batchId = keccak256(
            abi.encodePacked(
                "nullifier_sync",
                block.chainid,
                targetChainId,
                seq
            )
        );

        // Encode the sync message with sequence number for replay protection
        bytes memory payload = abi.encode(
            MSG_NULLIFIER_SYNC,
            batchNullifiers,
            batchCommitments,
            currentRoot,
            block.chainid.toUint64(),
            seq
        );

        // Record batch
        batchHistory.push(
            NullifierBatch({
                nullifiers: batchNullifiers,
                commitments: batchCommitments,
                merkleRoot: currentRoot,
                chainId: targetChainId,
                timestamp: block.timestamp,
                sent: true
            })
        );

        // Send via the relay's permissionless path so the sync contract does
        // not need RELAYER_ROLE. The relay itself restricts NULLIFIER_SYNC
        // payloads to the configured nullifierSync contract.
        (bool success, ) = target.relay.call{value: msg.value}(
            abi.encodeWithSignature(
                "selfRelayProof(bytes32,bytes,bytes,bytes32,uint64,bytes32)",
                batchId,
                payload,
                "",
                currentRoot,
                targetChainId.toUint64(),
                NULLIFIER_SYNC_PROOF_TYPE
            )
        );
        if (!success) revert RelayCallFailed();

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
     *         Called by ZaseonCrossChainRelay when a nullifier sync message
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
    ) external onlyRole(RELAY_ROLE) nonReentrant whenNotPaused {
        if (nullifiers.length != commitments.length)
            revert ArrayLengthMismatch();
        if (nullifiers.length == 0) revert EmptyBatch();
        if (nullifiers.length > MAX_BATCH_SIZE)
            revert BatchTooLarge(nullifiers.length);

        // Submit to local NullifierRegistryV3
        (bool success, ) = nullifierRegistry.call(
            abi.encodeWithSignature(
                "receiveCrossChainNullifiers(uint256,bytes32[],bytes32[],bytes32)",
                sourceChainId,
                nullifiers,
                commitments,
                sourceMerkleRoot
            )
        );
        if (!success) revert RegistryCallFailed();

        inboundSyncCount[sourceChainId] += nullifiers.length;

        emit NullifierBatchReceived(
            sourceChainId,
            nullifiers.length,
            sourceMerkleRoot
        );
    }

    // ──────────────────────────────────────────────
    //  Internal
    // ──────────────────────────────────────────────

    function _getCurrentMerkleRoot() internal view returns (bytes32) {
        (bool success, bytes memory data) = nullifierRegistry.staticcall(
            abi.encodeWithSignature("merkleRoot()")
        );
        if (success && data.length == 32) {
            return abi.decode(data, (bytes32));
        }
        return bytes32(0);
    }

    /// @dev DEPRECATED: No longer used after M-3 head-pointer fix
    /// Kept for ABI compatibility. Head pointer makes this O(1).
    function _removeSentItems(uint256 /* count */) internal pure {
        // No-op: pendingHead advancement handles dequeue
    }

    // ──────────────────────────────────────────────
    //  View Functions
    // ──────────────────────────────────────────────

    /// @notice Get the number of nullifiers pending synchronisation
    /// @return The count of pending nullifiers
    /**
     * @notice Returns the pending count
     * @return The result value
     */
    function getPendingCount() external view returns (uint256) {
        return pendingNullifiers.length - pendingHead;
    }

    /// @notice Get all target chain IDs configured for sync
    /// @return Array of target chain IDs
    /**
     * @notice Returns the target chains
     * @return The result value
     */
    function getTargetChains() external view returns (uint256[] memory) {
        return targetChainIds;
    }

    /// @notice Get the total number of sync batches sent
    /// @return The count of historical batches
    /**
     * @notice Returns the batch count
     * @return The result value
     */
    function getBatchCount() external view returns (uint256) {
        return batchHistory.length;
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Pause nullifier synchronisation
    /**
     * @notice Pauses the operation
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /// @notice Unpause nullifier synchronisation
    /**
     * @notice Unpauses the operation
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
