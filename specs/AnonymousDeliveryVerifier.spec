/**
 * @title Formal Verification Specification for AnonymousDeliveryVerifier
 * @author Soul Protocol
 * @notice Simplified Certora CVL specification for anonymous delivery claims
 */

methods {
    function totalClaims() external returns (uint256) envfree;
    function totalVerified() external returns (uint256) envfree;
    function isNullifierUsed(bytes32) external returns (bool) envfree;
    function minVerificationDelay() external returns (uint256) envfree;
    function getClaimStatus(bytes32) external returns (uint8) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function pause() external;
    function unpause() external;
}

// Nullifier usage is permanent
rule nullifierUsagePermanent(bytes32 nullifier) {
    env e;
    bool usedBefore = isNullifierUsed(nullifier);
    method f;
    calldataarg args;
    f(e, args);
    bool usedAfter = isNullifierUsed(nullifier);
    assert usedBefore => usedAfter, "Nullifier usage is permanent";
}

// Total claims is non-negative
invariant totalClaimsNonNegative()
    totalClaims() >= 0;

// Verified bounded by claims
invariant verifiedBoundedByClaims()
    totalVerified() <= totalClaims();

// Min verification delay is positive
invariant minVerificationDelayPositive()
    minVerificationDelay() > 0;

// Claim status transitions are valid
rule validClaimStatusTransitions(bytes32 claimId) {
    env e;
    uint8 statusBefore = getClaimStatus(claimId);
    method f;
    calldataarg args;
    f(e, args);
    uint8 statusAfter = getClaimStatus(claimId);
    // Verified claims cannot change (status 2)
    assert statusBefore == 2 => statusAfter == 2, "Verified claims are final";
    // Rejected claims cannot change (status 3)
    assert statusBefore == 3 => statusAfter == 3, "Rejected claims are final";
}

// Claim count monotonically increases
rule claimCountMonotonicallyIncreases() {
    env e;
    uint256 countBefore = totalClaims();
    method f;
    calldataarg args;
    f(e, args);
    uint256 countAfter = totalClaims();
    assert countAfter >= countBefore, "Claim count cannot decrease";
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
