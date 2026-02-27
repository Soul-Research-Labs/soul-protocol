/**
 * Certora Formal Verification Specification
 * Soul Protocol - CrossChainEmergencyRelay
 *
 * Verifies critical invariants for emergency propagation across chains.
 * A bug here could prevent halting a compromised chain.
 */

using CrossChainEmergencyRelay as relay;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / envfree
    function globalNonce() external returns (uint256) envfree;
    function maxMessageAge() external returns (uint48) envfree;
    function activeChainCount() external returns (uint256) envfree;
    function isHeartbeatOverdue() external returns (bool) envfree;
    function isInEmergency() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function getRegisteredChainIds() external returns (uint256[]) envfree;

    // State-changing
    function registerChain(uint256, address, address) external;
    function deactivateChain(uint256) external;
    function reactivateChain(uint256) external;
    function broadcastEmergency(uint8, uint256) external;
    function broadcastRecovery(uint256) external;
    function receiveEmergency(bytes) external;
    function sendHeartbeat(uint256) external;
    function receiveHeartbeat(uint256) external;
    function checkHeartbeatLiveness() external;
    function setHeartbeatInterval(uint48) external;
    function setMaxMessageAge(uint48) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostGlobalNonce {
    init_state axiom ghostGlobalNonce == 0;
}

ghost uint256 ghostActiveChains {
    init_state axiom ghostActiveChains == 0;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Active chain count bounded by MAX_CHAINS (20)
 */
invariant activeChainsBounded()
    activeChainCount() <= 20;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Global nonce is monotonically increasing
 * @notice The nonce must never decrease — ensures ordering and replay detection
 */
rule globalNonceMonotonic() {
    uint256 nonceBefore = globalNonce();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = globalNonce();

    assert nonceAfter >= nonceBefore,
        "Global nonce must never decrease";
}

/**
 * @title Only BROADCASTER_ROLE can broadcast emergencies
 */
rule onlyBroadcasterCanBroadcast(uint8 severity, uint256 incidentId) {
    env e;
    bytes32 broadcasterRole = keccak256("BROADCASTER_ROLE");

    require !hasRole(broadcasterRole, e.msg.sender);

    broadcastEmergency@withrevert(e, severity, incidentId);

    assert lastReverted,
        "Non-broadcaster must not be able to broadcast emergencies";
}

/**
 * @title Only BROADCASTER_ROLE can broadcast recovery
 */
rule onlyBroadcasterCanBroadcastRecovery(uint256 incidentId) {
    env e;
    bytes32 broadcasterRole = keccak256("BROADCASTER_ROLE");

    require !hasRole(broadcasterRole, e.msg.sender);

    broadcastRecovery@withrevert(e, incidentId);

    assert lastReverted,
        "Non-broadcaster must not be able to broadcast recovery";
}

/**
 * @title Only RECEIVER_ROLE can receive emergencies
 */
rule onlyReceiverCanReceive(bytes encodedMessage) {
    env e;
    bytes32 receiverRole = keccak256("RECEIVER_ROLE");

    require !hasRole(receiverRole, e.msg.sender);

    receiveEmergency@withrevert(e, encodedMessage);

    assert lastReverted,
        "Non-receiver must not be able to receive emergencies";
}

/**
 * @title Replay detection — same nonce from same chain must revert
 * @notice After receiving a message with nonce N from chain C,
 *         receiving another message with nonce <= N from chain C must fail.
 */
rule replayDetection() {
    env e1; env e2;
    bytes msg1; bytes msg2;
    bytes32 receiverRole = keccak256("RECEIVER_ROLE");

    require hasRole(receiverRole, e1.msg.sender);
    require hasRole(receiverRole, e2.msg.sender);

    receiveEmergency(e1, msg1);

    // Replaying the exact same message should fail
    receiveEmergency@withrevert(e2, msg1);

    assert lastReverted,
        "Replaying the same emergency message must revert";
}

/**
 * @title Paused state blocks broadcast
 */
rule pausedBlocksBroadcast(uint8 severity, uint256 incidentId) {
    env e;
    require paused();

    broadcastEmergency@withrevert(e, severity, incidentId);

    assert lastReverted,
        "Broadcasting must fail when paused";
}

/**
 * @title Paused state blocks heartbeat
 */
rule pausedBlocksHeartbeat(uint256 chainId) {
    env e;
    require paused();

    sendHeartbeat@withrevert(e, chainId);

    assert lastReverted,
        "Heartbeat sending must fail when paused";
}

/**
 * @title Only admin can register chains
 */
rule onlyAdminCanRegisterChain(uint256 chainId, address messenger, address remote) {
    env e;
    bytes32 adminRole = 0x0000000000000000000000000000000000000000000000000000000000000000;

    require !hasRole(adminRole, e.msg.sender);

    registerChain@withrevert(e, chainId, messenger, remote);

    assert lastReverted,
        "Non-admin must not register chains";
}

/**
 * @title Chain deactivation is admin-only
 */
rule onlyAdminCanDeactivateChain(uint256 chainId) {
    env e;
    bytes32 adminRole = 0x0000000000000000000000000000000000000000000000000000000000000000;

    require !hasRole(adminRole, e.msg.sender);

    deactivateChain@withrevert(e, chainId);

    assert lastReverted,
        "Non-admin must not deactivate chains";
}

/**
 * @title Emergency state enters on receive
 * @notice After receiving a valid emergency of CRITICAL severity,
 *         the contract should be in an emergency state.
 */
rule emergencyStateOnReceive() {
    env e;
    bytes msg;
    bytes32 receiverRole = keccak256("RECEIVER_ROLE");
    require hasRole(receiverRole, e.msg.sender);

    bool emergencyBefore = isInEmergency();

    receiveEmergency(e, msg);

    bool emergencyAfter = isInEmergency();

    // If not in emergency before, should be in emergency after receiving
    assert !emergencyBefore => emergencyAfter,
        "Receiving emergency must trigger emergency state";
}

/**
 * @title Heartbeat interval bounds
 * @notice Interval must be within [MIN_HEARTBEAT_INTERVAL, MAX_HEARTBEAT_INTERVAL]
 */
rule heartbeatIntervalBounded(uint48 newInterval) {
    env e;
    bytes32 adminRole = 0x0000000000000000000000000000000000000000000000000000000000000000;
    require hasRole(adminRole, e.msg.sender);

    // Intervals outside [10 minutes, 24 hours] should revert
    require newInterval < 600 || newInterval > 86400;

    setHeartbeatInterval@withrevert(e, newInterval);

    assert lastReverted,
        "Heartbeat interval must be within bounds";
}

/**
 * @title Emergency broadcast increments nonce
 * @notice Each successful broadcast must increase the global nonce
 */
rule broadcastIncrementsNonce(uint8 severity, uint256 incidentId) {
    env e;
    uint256 nonceBefore = globalNonce();

    broadcastEmergency(e, severity, incidentId);

    uint256 nonceAfter = globalNonce();

    assert nonceAfter > nonceBefore,
        "Broadcast must increment the global nonce";
}

/**
 * @title Zero address rejection on chain registration
 */
rule zeroAddressRejected(uint256 chainId) {
    env e;
    bytes32 adminRole = 0x0000000000000000000000000000000000000000000000000000000000000000;
    require hasRole(adminRole, e.msg.sender);

    registerChain@withrevert(e, chainId, 0, 0);

    assert lastReverted,
        "Zero address messenger/receiver must be rejected";
}
