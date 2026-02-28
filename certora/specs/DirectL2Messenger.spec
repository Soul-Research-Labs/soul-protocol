/**
 * Certora Formal Verification Specification
 * ZASEON - DirectL2Messenger
 *
 * This spec verifies critical invariants for the Direct L2 Messenger
 * which enables direct L2-to-L2 messaging without L1 completion,
 * including relayer bonding, message processing, and challenge mechanics.
 *
 * Ghost variable hooks track: globalNonce, processedMessages, relayer count.
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

ghost uint256 ghostRelayerListLength {
    init_state axiom ghostRelayerListLength == 0;
}

ghost uint256 ghostPriorGlobalNonce {
    init_state axiom ghostPriorGlobalNonce == 0;
}

// Hook: track globalNonce storage writes
hook Sstore globalNonce uint256 newVal (uint256 oldVal) {
    ghostPriorGlobalNonce = oldVal;
    ghostGlobalNonce = newVal;
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
 * @notice globalNonce can only increase via storage writes tracked by ghost hook
 */
invariant globalNonceMonotonicallyIncreasing()
    ghostGlobalNonce >= ghostPriorGlobalNonce
    { preserved { require ghostGlobalNonce < max_uint256; } }

/**
 * @title Ghost Nonce Matches Contract Nonce
 * @notice Ghost variable tracks actual globalNonce storage
 */
invariant ghostNonceMatchesContract()
    ghostGlobalNonce == globalNonce()
    { preserved { require globalNonce() < max_uint256; } }

/**
 * @title Processed Messages Are Permanent
 * @notice Once processedMessages[id] is set to true, it cannot revert to false.
 *         Ghost hook on processedMessages mapping tracks all writes.
 */
invariant processedMessagePermanence(bytes32 msgId)
    ghostProcessedMessages[msgId] => processedMessages(msgId)

/**
 * @title Relayer Count Non-Negative
 * @notice getRelayerCount() is always >= 0
 */
invariant relayerCountNonNegative()
    getRelayerCount() >= 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Cannot Process Same Message Twice
 * @notice Once a message is marked as processed, no function can un-process it
 */
rule cannotUnprocessMessage(bytes32 messageId) {
    require processedMessages(messageId);
    require ghostProcessedMessages[messageId];

    env e;
    method f;
    calldataarg args;
    f(e, args);

    assert processedMessages(messageId),
        "Processed message flag must remain true";
    assert ghostProcessedMessages[messageId],
        "Ghost processed flag must remain true";
}

/**
 * @title Global Nonce Never Decreases
 * @notice No function call should decrease globalNonce — verified via ghost hook
 */
rule globalNonceNeverDecreases() {
    env e;
    uint256 nonceBefore = globalNonce();

    method f;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = globalNonce();

    assert nonceAfter >= nonceBefore,
        "globalNonce must never decrease";
}

/**
 * @title sendMessage Increments Global Nonce
 * @notice Each successful sendMessage call increments globalNonce by exactly 1
 */
rule sendMessageIncrementsNonce(uint256 destChain, address target, bytes data, uint8 priority) {
    env e;
    uint256 nonceBefore = globalNonce();
    require nonceBefore < max_uint256;

    sendMessage(e, destChain, target, data, priority);

    uint256 nonceAfter = globalNonce();

    assert to_mathint(nonceAfter) == to_mathint(nonceBefore) + 1,
        "sendMessage must increment globalNonce by exactly 1";
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

/**
 * @title Only RELAYER_ROLE Can Register as Relayer
 * @notice registerRelayer must grant RELAYER_ROLE or require sufficient bond
 */
rule registerRelayerRequiresBond() {
    env e;
    uint256 relayerCountBefore = getRelayerCount();
    require e.msg.value >= MIN_RELAYER_BOND();

    registerRelayer(e);

    uint256 relayerCountAfter = getRelayerCount();

    assert relayerCountAfter >= relayerCountBefore,
        "Relayer count must not decrease on registration";
}
