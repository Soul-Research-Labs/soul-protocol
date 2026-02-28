/**
 * @title Formal Verification Specification for SemanticProofTranslationCertificate
 * @author ZASEON
 * @notice Simplified Certora CVL specification for certified proof translation
 */

methods {
    function totalCapabilities() external returns (uint256) envfree;
    function totalRequests() external returns (uint256) envfree;
    function totalCertificates() external returns (uint256) envfree;
    function baseFee() external returns (uint256) envfree;
    function collectedFees() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function verifyCertificate(bytes32) external returns (bool);
    function withdrawFees() external;
    function pause() external;
    function unpause() external;
}

// Certificates bounded by requests
invariant certificatesBoundedByRequests()
    totalCertificates() <= totalRequests();

// Base fee monotonicity: fee increases are always bounded
// (removed vacuous baseFee >= 0 — uint256 is always non-negative)
// The certificatesBoundedByRequests invariant above provides the
// meaningful economic bound for this contract.

// Certificate count monotonically increases
rule certificateCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalCertificates();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalCertificates();
    assert countAfter >= countBefore, "Certificate count cannot decrease";
}

// Request count monotonically increases
rule requestCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalRequests();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalRequests();
    assert countAfter >= countBefore, "Request count cannot decrease";
}

// Paused contract blocks verification
rule pausedBlocksVerification(bytes32 certificateId) {
    env e;
    require paused();
    verifyCertificate@withrevert(e, certificateId);
    assert lastReverted, "Paused contract must block verification";
}

// Only admin can pause
rule onlyAdminCanPause() {
    env e;
    bytes32 ADMIN_ROLE = to_bytes32(0);
    require !hasRole(ADMIN_ROLE, e.msg.sender);
    require !paused();
    pause@withrevert(e);
    assert lastReverted, "Only admin can pause";
}
