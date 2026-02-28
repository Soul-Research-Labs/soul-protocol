/**
 * Certora Formal Verification Specification
 * ZASEON - CrossChainNullifierSync
 *
 * Verifies cross-chain nullifier synchronization integrity.
 * Bugs here could allow double-spends across chains.
 */

using CrossChainNullifierSync as sync;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / envfree
    function getPendingCount() external returns (uint256) envfree;
    function getBatchCount() external returns (uint256) envfree;
    function getTargetChains() external returns (uint256[]) envfree;
    function nullifierRegistry() external returns (address) envfree;
    function pendingHead() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;

    // State-changing
    function configureSyncTarget(uint256, CrossChainNullifierSync.SyncTarget) external;
    function queueNullifier(bytes32, bytes32) external;
    function queueNullifierBatch(bytes32[], bytes32[]) external;
    function flushToChain(uint256) external;
    function receiveNullifierBatch(uint256, bytes32[], bytes32[], bytes32) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostBatchCount {
    init_state axiom ghostBatchCount == 0;
}

ghost uint256 ghostPendingCount {
    init_state axiom ghostPendingCount == 0;
}

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Batch count is monotonically increasing
 * @notice Batch count must never decrease — ensures sync history integrity
 */
rule batchCountMonotonic() {
    uint256 countBefore = getBatchCount();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 countAfter = getBatchCount();

    assert countAfter >= countBefore,
        "Batch count must never decrease";
}

/**
 * @title Only SYNCER_ROLE can queue nullifiers
 */
rule onlySyncerCanQueue(bytes32 nullifier, bytes32 commitment) {
    env e;
    bytes32 syncerRole = keccak256("SYNCER_ROLE");

    require !hasRole(syncerRole, e.msg.sender);

    queueNullifier@withrevert(e, nullifier, commitment);

    assert lastReverted,
        "Non-syncer must not be able to queue nullifiers";
}

/**
 * @title Only SYNCER_ROLE can flush
 */
rule onlySyncerCanFlush(uint256 targetChainId) {
    env e;
    bytes32 syncerRole = keccak256("SYNCER_ROLE");

    require !hasRole(syncerRole, e.msg.sender);

    flushToChain@withrevert(e, targetChainId);

    assert lastReverted,
        "Non-syncer must not be able to flush nullifiers";
}

/**
 * @title Only RELAY_ROLE can receive batches
 */
rule onlyRelayCanReceive(
    uint256 sourceChainId,
    bytes32[] nullifiers,
    bytes32[] commitments,
    bytes32 merkleRoot
) {
    env e;
    bytes32 relayRole = keccak256("RELAY_ROLE");

    require !hasRole(relayRole, e.msg.sender);

    receiveNullifierBatch@withrevert(e, sourceChainId, nullifiers, commitments, merkleRoot);

    assert lastReverted,
        "Non-relay must not be able to receive nullifier batches";
}

/**
 * @title Paused state blocks queueing
 */
rule pausedBlocksQueue(bytes32 nullifier, bytes32 commitment) {
    env e;
    require paused();

    queueNullifier@withrevert(e, nullifier, commitment);

    assert lastReverted,
        "Queueing must fail when paused";
}

/**
 * @title Paused state blocks flushing
 */
rule pausedBlocksFlush(uint256 targetChainId) {
    env e;
    require paused();

    flushToChain@withrevert(e, targetChainId);

    assert lastReverted,
        "Flushing must fail when paused";
}

/**
 * @title Paused state blocks receiving
 */
rule pausedBlocksReceive(
    uint256 sourceChainId,
    bytes32[] nullifiers,
    bytes32[] commitments,
    bytes32 merkleRoot
) {
    env e;
    require paused();

    receiveNullifierBatch@withrevert(e, sourceChainId, nullifiers, commitments, merkleRoot);

    assert lastReverted,
        "Receiving must fail when paused";
}

/**
 * @title Sync frequency enforcement
 * @notice flushToChain must respect MIN_SYNC_INTERVAL (5 minutes)
 */
rule syncIntervalEnforced(uint256 targetChainId) {
    env e1; env e2;

    bytes32 syncerRole = keccak256("SYNCER_ROLE");
    require hasRole(syncerRole, e1.msg.sender);
    require hasRole(syncerRole, e2.msg.sender);
    require !paused();

    // First flush succeeds
    flushToChain(e1, targetChainId);

    // Immediate second flush (same block) should fail
    require e2.block.timestamp == e1.block.timestamp;
    flushToChain@withrevert(e2, targetChainId);

    assert lastReverted,
        "Consecutive flushes in the same block must revert (MIN_SYNC_INTERVAL)";
}

/**
 * @title Batch size enforcement
 * @notice Cannot queue more than MAX_BATCH_SIZE (20) in one call
 */
rule batchSizeLimited(bytes32[] nullifiers, bytes32[] commitments) {
    env e;

    require nullifiers.length > 20;

    queueNullifierBatch@withrevert(e, nullifiers, commitments);

    assert lastReverted,
        "Batch exceeding MAX_BATCH_SIZE must revert";
}

/**
 * @title Array length mismatch must revert
 */
rule arrayLengthMismatchReverts(bytes32[] nullifiers, bytes32[] commitments) {
    env e;

    require nullifiers.length != commitments.length;

    queueNullifierBatch@withrevert(e, nullifiers, commitments);

    assert lastReverted,
        "Mismatched nullifier/commitment arrays must revert";
}

/**
 * @title Nullifier registry address is immutable
 * @notice The registry address should never change after construction
 */
rule registryAddressImmutable() {
    address registryBefore = nullifierRegistry();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    address registryAfter = nullifierRegistry();

    assert registryBefore == registryAfter,
        "Nullifier registry address must not change";
}

/**
 * @title Only OPERATOR_ROLE can pause/unpause
 */
rule onlyOperatorCanPause() {
    env e;
    bytes32 operatorRole = keccak256("OPERATOR_ROLE");

    require !hasRole(operatorRole, e.msg.sender);

    pause@withrevert(e);

    assert lastReverted,
        "Non-operator must not be able to pause";
}

/**
 * @title Pending head only moves forward
 */
rule pendingHeadMonotonic() {
    uint256 headBefore = pendingHead();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 headAfter = pendingHead();

    assert headAfter >= headBefore,
        "Pending head must never decrease";
}
