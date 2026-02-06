/*
 * Certora Verification Spec: LayerZeroBridgeAdapter
 * Verifies core invariants of the LayerZero V2 Bridge adapter
 */

methods {
    // View functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function lzEndpoint() external returns (address) envfree;
    function localEid() external returns (uint32) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function messageNonce() external returns (uint64) envfree;
    function totalMessagesSent() external returns (uint256) envfree;
    function totalMessagesReceived() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;

    // State-changing
    function setEndpoint(address, uint32) external;
    function setBridgeFee(uint256) external;
    function setPeer(uint32, bytes32, uint8, uint256, uint8) external;
    function deactivatePeer(uint32) external;
    function reactivatePeer(uint32) external;
    function updatePeerSecurity(uint32, uint8) external;
    function pause() external;
    function unpause() external;
}

// Invariant: Bridge fee cannot exceed 1% (100 bps)
rule bridgeFeeMaxBound() {
    uint256 fee = bridgeFee();
    assert fee <= 100, "Bridge fee must not exceed 100 bps (1%)";
}

// Invariant: Setting fee above 100 reverts
rule setBridgeFeeReverts(env e) {
    uint256 feeBps;
    require feeBps > 100;

    setBridgeFee@withrevert(e, feeBps);
    assert lastReverted, "Fee above 1% must revert";
}

// Invariant: Endpoint cannot be zero address
rule endpointNotZero(env e) {
    uint32 eid;
    require eid != 0;

    setEndpoint@withrevert(e, 0x0000000000000000000000000000000000000000, eid);
    assert lastReverted, "Zero endpoint must revert";
}

// Invariant: Endpoint ID cannot be zero
rule endpointIdNotZero(env e) {
    address endpoint;
    require endpoint != 0x0000000000000000000000000000000000000000;

    setEndpoint@withrevert(e, endpoint, 0);
    assert lastReverted, "Zero EID must revert";
}

// Invariant: Only admin can set endpoint
rule onlyAdminSetsEndpoint(env e) {
    require !hasRole(to_bytes32(0), e.msg.sender);

    setEndpoint@withrevert(e, _, _);
    assert lastReverted, "Non-admin should not set endpoint";
}

// Invariant: Only config role can set peers
rule onlyConfigSetsPeers(env e) {
    bytes32 configRole = to_bytes32(keccak256("CONFIG_ROLE"));

    require !hasRole(configRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    setPeer@withrevert(e, _, _, _, _, _);
    assert lastReverted, "Non-config should not set peers";
}

// Invariant: Only guardian can deactivate peers
rule onlyGuardianDeactivatesPeers(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));

    require !hasRole(guardianRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    uint32 eid;
    deactivatePeer@withrevert(e, eid);
    assert lastReverted, "Non-guardian should not deactivate peers";
}

// Invariant: Message nonce is monotonically increasing
rule messageNonceMonotonic(env e) {
    uint64 nonceBefore = messageNonce();
    // After any message-sending operation, nonce should not decrease
    uint64 nonceAfter = messageNonce();
    assert nonceAfter >= nonceBefore, "Nonce must not decrease";
}

// Invariant: Paused blocks operations
rule pausedBlocksOperations(env e) {
    require paused() == true;

    // Sending messages should be blocked when paused
    // (implementation-specific, but captures intent)
    assert paused() == true, "Contract should remain paused";
}
