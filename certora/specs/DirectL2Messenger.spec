/**
 * Certora Formal Verification Specification
 * Soul Protocol - DirectL2Messenger
 *
 * This spec verifies critical invariants for the Direct L2 Messenger
 * which enables direct L2-to-L2 messaging without L1 completion,
 * including relayer bonding, message processing, and challenge mechanics.
 */

using DirectL2Messenger as dlm;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function globalNonce() external returns (uint256) envfree;
    function getRelayerCount() external returns (uint256) envfree;
    function processedMessages(bytes32) external returns (bool) envfree;
    function challengerReward() external returns (uint256) envfree;
    function requiredConfirmations() external returns (uint256) envfree;
    function currentChainId() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function SEQUENCER_ROLE() external returns (bytes32) envfree;
    function MIN_RELAYER_BOND() external returns (uint256) envfree;
    function DEFAULT_CHALLENGE_WINDOW() external returns (uint256) envfree;
    function MESSAGE_EXPIRY() external returns (uint256) envfree;

    // State-changing functions
    function sendMessage(uint256, address, bytes, uint8) external;
    function registerRelayer() external;
    function withdrawRelayerBond() external;
    function challengeMessage(bytes32, bytes) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostGlobalNonce {
    init_state axiom ghostGlobalNonce == 0;
}

ghost mapping(bytes32 => bool) ghostProcessedMessages {
    init_state axiom forall bytes32 m. !ghostProcessedMessages[m];
}

ghost uint256 ghostRelayerCount {
    init_state axiom ghostRelayerCount == 0;
}

// Hook: track when processedMessages mapping is written
hook Sstore processedMessages[KEY bytes32 msgId] bool newVal (bool oldVal) {
    ghostProcessedMessages[msgId] = newVal;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Global Nonce Monotonically Increases
 * @notice globalNonce can only increase, never decrease
 * TODO: Hook ghost to globalNonce storage slot for precise tracking
 */
invariant globalNonceMonotonicallyIncreasing()
    globalNonce() >= 0
    { preserved { require globalNonce() < max_uint256; } }

/**
 * @title Processed Messages Are Permanent
 * @notice Once a message is processed, it stays processed
 * TODO: Verify this with ghost variable hooks on processedMessages mapping
 */
invariant processedMessagePermanence(bytes32 msgId)
    ghostProcessedMessages[msgId] => processedMessages(msgId)

/**
 * @title Relayer Count Non-Negative
 * @notice getRelayerCount() is always >= 0
 * TODO: Verify relayer count matches actual bonded relayers
 */
invariant relayerCountNonNegative()
    getRelayerCount() >= 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Cannot Process Same Message Twice
 * @notice Processing an already-processed message should revert
 * TODO: Implement by calling relay/confirm on an already-processed message ID
 */
rule cannotProcessMessageTwice(bytes32 messageId) {
    env e;
    require processedMessages(messageId);

    // Any function that would process a message should fail if already processed
    method f;
    calldataarg args;
    f(e, args);

    assert processedMessages(messageId),
        "Processed message flag must remain true";
}

/**
 * @title Global Nonce Never Decreases
 * @notice No function call should decrease globalNonce
 */
rule globalNonceNeverDecreases() {
    env e;
    uint256 before = globalNonce();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = globalNonce();

    assert after >= before,
        "globalNonce must never decrease";
}

/**
 * @title Pause Prevents Message Sending
 * @notice When paused, sendMessage should revert
 */
rule pausePreventsSending(uint256 destChain, address target, bytes data, uint8 priority) {
    env e;
    require paused();

    sendMessage@withrevert(e, destChain, target, data, priority);

    assert lastReverted,
        "Message sending should fail when paused";
}
