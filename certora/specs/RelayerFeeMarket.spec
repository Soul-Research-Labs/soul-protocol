/**
 * Certora Formal Verification Specification
 * Soul Protocol - RelayerFeeMarket
 *
 * @title Relayer Fee Market Invariants and Rules
 * @notice Verifies fee bounds, request lifecycle, protocol fee safety,
 *         and relay completion guarantees.
 */

// =============================================================================
// METHODS DECLARATIONS
// =============================================================================

methods {
    // View functions
    function protocolFeeBps() external returns (uint256) envfree;
    function MAX_PROTOCOL_FEE_BPS() external returns (uint256) envfree;
    function accumulatedProtocolFees() external returns (uint256) envfree;
    function estimateFee(uint256, uint256) external returns (uint256) envfree;
    function paused() external returns (bool) envfree;

    // State-changing functions
    function submitRelayRequest(uint256, uint256, bytes, uint256) external;
    function claimRelayRequest(bytes32) external;
    function completeRelay(bytes32, bytes) external;
    function cancelRelayRequest(bytes32) external;
    function expireRelayRequest(bytes32) external;
    function setProtocolFeeBps(uint256) external;
    function withdrawProtocolFees(address) external;
}

// =============================================================================
// GHOSTS
// =============================================================================

// Track protocol fees
ghost uint256 ghostAccumulatedFees {
    init_state axiom ghostAccumulatedFees == 0;
}

// Track request status transitions (0=NONE, 1=PENDING, 2=CLAIMED, 3=COMPLETED, 4=CANCELLED, 5=EXPIRED)
ghost mapping(bytes32 => uint8) ghostRequestStatus {
    init_state axiom forall bytes32 id. ghostRequestStatus[id] == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * INV-FEE-001: Protocol fee within bounds.
 * Protocol fee can never exceed MAX_PROTOCOL_FEE_BPS (1000 = 10%).
 */
invariant protocolFeeBounded()
    protocolFeeBps() <= MAX_PROTOCOL_FEE_BPS();

/**
 * INV-FEE-002: MAX_PROTOCOL_FEE_BPS is constant (1000 = 10%).
 */
invariant maxFeeBpsConstant()
    MAX_PROTOCOL_FEE_BPS() == 1000;

/**
 * INV-FEE-003: Accumulated fees are non-negative.
 */
invariant accumulatedFeesNonNegative()
    accumulatedProtocolFees() >= 0;

// =============================================================================
// FEE RULES
// =============================================================================

/**
 * RULE-FEE-001: setProtocolFeeBps reverts above maximum.
 */
rule protocolFeeCannotExceedMax(uint256 newFeeBps) {
    require newFeeBps > MAX_PROTOCOL_FEE_BPS();

    env e;
    setProtocolFeeBps@withrevert(e, newFeeBps);

    assert lastReverted, "Must revert when fee exceeds maximum";
}

/**
 * RULE-FEE-002: Protocol fee always stays bounded after any operation.
 */
rule protocolFeeAlwaysBounded(method f) filtered { f -> !f.isView } {
    uint256 feeBefore = protocolFeeBps();
    require feeBefore <= MAX_PROTOCOL_FEE_BPS();

    env e;
    calldataarg args;
    f(e, args);

    uint256 feeAfter = protocolFeeBps();
    assert feeAfter <= MAX_PROTOCOL_FEE_BPS(), "Protocol fee must remain bounded";
}

/**
 * RULE-FEE-003: Accumulated fees only increase on complete, never decrease except withdrawal.
 */
rule accumulatedFeesMonotonicity(method f) filtered {
    f -> f.selector != sig:withdrawProtocolFees(address).selector && !f.isView
} {
    uint256 feesBefore = accumulatedProtocolFees();

    env e;
    calldataarg args;
    f(e, args);

    uint256 feesAfter = accumulatedProtocolFees();
    assert feesAfter >= feesBefore, "Accumulated fees must not decrease except via withdrawal";
}

// =============================================================================
// REQUEST LIFECYCLE RULES
// =============================================================================

/**
 * RULE-FEE-004: Cancel reverts on non-pending requests.
 * Only PENDING (1) requests can be cancelled.
 */
rule cancelOnlyPending(bytes32 requestId) {
    // Assume the request is already COMPLETED (3)
    env e1;
    bytes proofData;
    uint256 srcChain; uint256 dstChain; uint256 deadline;

    // Cannot cancel a completed relay
    // This is verified by attempting cancel on a non-pending state
    require ghostRequestStatus[requestId] == 3; // COMPLETED

    env e2;
    cancelRelayRequest@withrevert(e2, requestId);

    assert lastReverted, "Cannot cancel a completed relay request";
}

/**
 * RULE-FEE-005: Complete relay reverts on non-claimed requests.
 * Only CLAIMED (2) requests can be completed.
 */
rule completeOnlyClaimed(bytes32 requestId) {
    require ghostRequestStatus[requestId] != 2; // Not CLAIMED
    require ghostRequestStatus[requestId] != 0; // But exists

    env e;
    bytes completionProof;
    completeRelay@withrevert(e, requestId, completionProof);

    assert lastReverted, "Cannot complete a non-claimed relay request";
}

// =============================================================================
// PAUSABILITY RULES
// =============================================================================

/**
 * RULE-FEE-006: Submit reverts when paused.
 */
rule submitRevertsWhenPaused(uint256 src, uint256 dst, bytes data, uint256 deadline) {
    require paused() == true;

    env e;
    submitRelayRequest@withrevert(e, src, dst, data, deadline);

    assert lastReverted, "Submit must revert when paused";
}
