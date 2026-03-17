// SPDX-License-Identifier: MIT
// Certora CVL Specification for BitVMAdapter
// ZASEON - Formal Verification

/**
 * Security goals:
 * - bridgeMessage returns non-zero message id on success
 * - estimateFee is deterministic and non-negative
 * - finalized messages remain verified
 * - paused adapter cannot bridge messages
 */

methods {
    function bridgeMessage(address, bytes, address) external returns (bytes32);
    function estimateFee(address, bytes) external returns (uint256) envfree;
    function isMessageVerified(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

rule pausedAdapterCannotBridge(address target, bytes payload, address refund) {
    env e;
    require paused();

    bridgeMessage@withrevert(e, target, payload, refund);
    assert lastReverted;
}

rule bridgeMessageReturnsNonZeroId(address target, bytes payload, address refund) {
    env e;
    require !paused();

    bytes32 messageId = bridgeMessage(e, target, payload, refund);
    assert messageId != to_bytes32(0);
}

rule estimateFeeDeterministic(address target, bytes payload) {
    uint256 fee1 = estimateFee(target, payload);
    uint256 fee2 = estimateFee(target, payload);

    assert fee1 == fee2;
}

rule estimateFeeNonNegative(address target, bytes payload) {
    uint256 fee = estimateFee(target, payload);
    assert to_mathint(fee) >= 0;
}

rule finalizedMessagePermanence(bytes32 messageId, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    require isMessageVerified(messageId);

    f(e, args);

    assert isMessageVerified(messageId);
}
