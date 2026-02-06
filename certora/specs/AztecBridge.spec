/*
 * Certora Verification Spec: AztecBridgeAdapter
 * Verifies core invariants of the Aztec Bridge adapter
 */

methods {
    // View functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function totalSoulToAztec() external returns (uint256) envfree;
    function totalAztecToSoul() external returns (uint256) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function minBridgeAmount() external returns (uint256) envfree;
    function maxBridgeAmount() external returns (uint256) envfree;
    function bridgeFeeBps() external returns (uint256) envfree;

    // State-changing
    function bridgeToAztec(uint256, bytes32, bytes32, bytes32) external;
    function bridgeFromAztec(bytes32, address, uint256, bytes32, bytes) external;
    function pause() external;
    function unpause() external;
}

// Invariant: Nullifiers cannot be reused
rule nullifierUniqueness(env e) {
    bytes32 nullifier;
    require usedNullifiers(nullifier) == true;

    address recipient;
    uint256 amount;
    bytes32 noteCommitment;
    bytes proof;

    bridgeFromAztec@withrevert(e, nullifier, recipient, amount, noteCommitment, proof);
    assert lastReverted, "Reused nullifier must revert";
}

// Invariant: Bridge amounts within bounds
rule bridgeAmountBounds(env e) {
    uint256 amount;
    bytes32 noteHash;
    bytes32 secretHash;
    bytes32 nullifierHash;

    require amount < minBridgeAmount() || amount > maxBridgeAmount();

    bridgeToAztec@withrevert(e, amount, noteHash, secretHash, nullifierHash);
    assert lastReverted, "Out-of-bounds amount must revert";
}

// Invariant: Bridge fee is bounded
rule bridgeFeeBounded() {
    uint256 fee = bridgeFeeBps();
    assert fee <= 10000, "Fee cannot exceed 100%";
}

// Invariant: Paused blocks bridging
rule pausedBlocksBridging(env e) {
    require paused() == true;

    uint256 amount;
    bytes32 noteHash;
    bytes32 secretHash;
    bytes32 nullifierHash;

    bridgeToAztec@withrevert(e, amount, noteHash, secretHash, nullifierHash);
    assert lastReverted, "Bridging blocked when paused";
}

// Invariant: soulToAztec total increases after bridge
rule soulToAztecIncreases(env e) {
    uint256 totalBefore = totalSoulToAztec();

    uint256 amount;
    bytes32 noteHash;
    bytes32 secretHash;
    bytes32 nullifierHash;
    bridgeToAztec(e, amount, noteHash, secretHash, nullifierHash);

    uint256 totalAfter = totalSoulToAztec();
    assert totalAfter > totalBefore, "Total must increase after bridge";
}

// Invariant: Only guardian can pause
rule onlyGuardianPauses(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));

    require !hasRole(guardianRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    pause@withrevert(e);
    assert lastReverted, "Non-guardian should not pause";
}
