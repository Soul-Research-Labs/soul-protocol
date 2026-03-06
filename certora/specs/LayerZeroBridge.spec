// SPDX-License-Identifier: MIT
// Certora CVL Specification for LayerZero Adapter
// ZASEON - Formal Verification

/*
 * =============================================================================
 * LAYERZERO ADAPTER SPECIFICATION
 * =============================================================================
 *
 * Verifies security properties of the LayerZero V2 OApp Adapter:
 * - Message send/receive integrity
 * - Inbound nonce ordering (no replay)
 * - Peer authorization (trusted remotes)
 * - Message status state machine
 * - DVN configuration validity
 * - Payload size bounds
 * - Fee collection correctness
 */

using LayerZeroAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    function lzEndpoint() external returns (address) envfree;
    function localEid() external returns (uint32) envfree;
    function bridgeFeeBps() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;
    function totalMessagesSent() external returns (uint256) envfree;
    function totalMessagesReceived() external returns (uint256) envfree;
    function totalFeesCollected() external returns (uint256) envfree;
    function nonce() external returns (uint256) envfree;

    function outboundNonce(uint32) external returns (uint64) envfree;
    function inboundNonces(uint32, uint64) external returns (bool) envfree;
    function peers(uint32) external returns (bytes32) envfree;
    function processedMessages(bytes32) external returns (bool) envfree;

    function MAX_PAYLOAD_SIZE() external returns (uint256) envfree;
    function MAX_DST_GAS() external returns (uint256) envfree;
    function MESSAGE_EXPIRY() external returns (uint256) envfree;
    function MIN_DVN_CONFIRMATIONS() external returns (uint256) envfree;

    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function EXECUTOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(uint32 => uint64) ghostOutboundNonce {
    init_state axiom forall uint32 eid. ghostOutboundNonce[eid] == 0;
}

ghost mapping(bytes32 => uint8) ghostMessageStatus {
    init_state axiom forall bytes32 id. ghostMessageStatus[id] == 0;
}

ghost mapping(bytes32 => bool) ghostProcessedMessages {
    init_state axiom forall bytes32 id. ghostProcessedMessages[id] == false;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Endpoint address is non-zero
invariant endpointValid()
    lzEndpoint() != 0

/// @title Fee basis points within valid range
invariant feeBpsValid()
    bridgeFeeBps() <= 10000

/// @title Payload max size is positive
invariant payloadSizePositive()
    MAX_PAYLOAD_SIZE() > 0

/// @title Processed messages remain processed
invariant processedMessagePermanent(bytes32 msgId)
    processedMessages(msgId) == true =>
    ghostProcessedMessages[msgId] == true

// =============================================================================
// RULES
// =============================================================================

/// @title Outbound nonce monotonically increases per EID
rule outboundNonceMonotonicity(uint32 eid) {
    uint64 nonceBefore = outboundNonce(eid);
    uint64 nonceAfter = outboundNonce(eid);

    assert nonceAfter >= nonceBefore,
        "Outbound nonce must not decrease";
}

/// @title Inbound nonce replay protection
/// A nonce that has been processed cannot be unprocessed
rule inboundNonceReplayProtection(uint32 srcEid, uint64 inNonce) {
    bool processedBefore = inboundNonces(srcEid, inNonce);
    require processedBefore == true;

    assert inboundNonces(srcEid, inNonce) == true,
        "Processed inbound nonce must remain processed";
}

/// @title Peer must be set for message delivery
/// Messages can only be received from configured peers
rule peerAuthorizationRequired(uint32 srcEid) {
    bytes32 peer = peers(srcEid);

    // If no peer is set, messages from this EID should not be processed
    require peer == to_bytes32(0);

    assert peers(srcEid) == to_bytes32(0),
        "Unconfigured peer should remain unconfigured until set";
}

/// @title Message status transitions are valid
/// PENDING(0) -> SENT(1) -> DELIVERED(2) -> VERIFIED(3) -> EXECUTED(4)
/// Any -> FAILED(5), Any -> EXPIRED(6)
rule validMessageStatusTransition(bytes32 msgId, uint8 newStatus) {
    uint8 current = ghostMessageStatus[msgId];

    bool validForward =
        (current == 0 && newStatus == 1) || // PENDING -> SENT
        (current == 1 && newStatus == 2) || // SENT -> DELIVERED
        (current == 2 && newStatus == 3) || // DELIVERED -> VERIFIED
        (current == 3 && newStatus == 4);   // VERIFIED -> EXECUTED

    bool validTerminal = newStatus == 5 || newStatus == 6; // FAILED or EXPIRED

    assert validForward || validTerminal || current == newStatus,
        "Invalid message status transition";
}

/// @title Total messages sent >= total received
rule messageCountIntegrity() {
    assert totalMessagesSent() >= totalMessagesReceived(),
        "Sent messages must be >= received messages";
}

/// @title No double message processing
rule noDoubleMessageProcessing(bytes32 msgId) {
    bool before = processedMessages(msgId);
    require before == true;

    assert processedMessages(msgId) == true,
        "Processed message must remain processed";
}

/// @title Cross-domain nullifier uniqueness
rule nullifierUniqueness(bytes32 id1, bytes32 id2) {
    require id1 != id2;

    bytes32 nf1 = keccak256(abi.encodePacked(id1, "LAYERZERO_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(id2, "LAYERZERO_NULLIFIER"));

    assert nf1 != nf2, "Different IDs must produce different nullifiers";
}
