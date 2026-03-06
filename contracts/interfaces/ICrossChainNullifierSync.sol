// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ICrossChainNullifierSync
 * @notice Interface for bidirectional nullifier synchronization between chains
 */
interface ICrossChainNullifierSync {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct NullifierBatch {
        bytes32[] nullifiers;
        bytes32[] commitments;
        bytes32 merkleRoot;
        uint256 chainId;
        uint256 timestamp;
        bool sent;
    }

    struct SyncTarget {
        address nullifierRegistry;
        address relay;
        uint256 chainId;
        bool active;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

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

    // =========================================================================
    // ERRORS
    // =========================================================================

    error NoPendingNullifiers();
    error TargetNotConfigured(uint256 chainId);
    error SyncTooFrequent(uint256 chainId, uint256 nextAllowed);
    error BatchTooLarge(uint256 size);
    error ZeroAddress();
    error ArrayLengthMismatch();
    error EmptyBatch();
    error RelayCallFailed();
    error RegistryCallFailed();

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    function configureSyncTarget(
        uint256 chainId,
        SyncTarget calldata target
    ) external;

    // =========================================================================
    // OUTBOUND
    // =========================================================================

    function queueNullifier(bytes32 nullifier, bytes32 commitment) external;

    function queueNullifierBatch(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external;

    function flushToChain(uint256 targetChainId) external payable;

    // =========================================================================
    // INBOUND
    // =========================================================================

    function receiveNullifierBatch(
        uint256 sourceChainId,
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        bytes32 sourceMerkleRoot
    ) external;

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function nullifierRegistry() external view returns (address);

    function pendingNullifiers(uint256 index) external view returns (bytes32);

    function pendingCommitments(uint256 index) external view returns (bytes32);

    function pendingHead() external view returns (uint256);

    function syncTargets(
        uint256 chainId
    )
        external
        view
        returns (
            address nullifierRegistry_,
            address relay,
            uint256 chainId_,
            bool active
        );

    function targetChainIds(uint256 index) external view returns (uint256);

    function lastSyncTime(uint256 chainId) external view returns (uint256);

    function outboundSyncCount(uint256 chainId) external view returns (uint256);

    function inboundSyncCount(uint256 chainId) external view returns (uint256);

    function syncSequence(uint256 chainId) external view returns (uint256);

    function getPendingCount() external view returns (uint256);

    function getTargetChains() external view returns (uint256[] memory);

    function getBatchCount() external view returns (uint256);

    // =========================================================================
    // ADMIN
    // =========================================================================

    function pause() external;

    function unpause() external;
}
