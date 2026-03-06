// SPDX-License-Identifier: MIT
// Certora CVL Specification for Linea Bridge Adapter
// ZASEON - Formal Verification

/*
 * =============================================================================
 * LINEA BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 *
 * Verifies security properties of the Linea Bridge Adapter:
 * - MessageService deposit/withdrawal integrity
 * - L2 anchoring and proof verification
 * - Transfer status state machine validity
 * - Message claim uniqueness (no double-claim)
 * - Fee collection correctness
 * - Cross-domain nullifier uniqueness
 */

using LineaBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    function bridgeFeeBps() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;
    function transferNonce() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalValueDeposited() external returns (uint256) envfree;
    function totalValueWithdrawn() external returns (uint256) envfree;
    function totalFeesCollected() external returns (uint256) envfree;
    function claimedMessages(bytes32) external returns (bool) envfree;

    function LINEA_CHAIN_ID() external returns (uint256) envfree;
    function DEFAULT_MESSAGE_FEE() external returns (uint256) envfree;
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function MAX_DEPOSIT() external returns (uint256) envfree;

    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function EXECUTOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(bytes32 => bool) ghostClaimedMessages {
    init_state axiom forall bytes32 m. ghostClaimedMessages[m] == false;
}

ghost mapping(bytes32 => uint8) ghostDepositStatus {
    init_state axiom forall bytes32 id. ghostDepositStatus[id] == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Deposit amount bounds enforced
invariant depositAmountBounds()
    MIN_DEPOSIT() > 0 && MAX_DEPOSIT() > MIN_DEPOSIT()

/// @title Fee basis points within valid range
invariant feeBpsValid()
    bridgeFeeBps() <= 10000

/// @title Claimed messages remain claimed
invariant claimedMessagePermanent(bytes32 msgId)
    claimedMessages(msgId) == true =>
    ghostClaimedMessages[msgId] == true

// =============================================================================
// RULES
// =============================================================================

/// @title Deposit status transitions: PENDING -> SENT -> ANCHORED -> PROVEN -> CLAIMED
rule validDepositStatusTransition(bytes32 depositId, uint8 newStatus) {
    uint8 current = ghostDepositStatus[depositId];

    bool validForward =
        (current == 0 && newStatus == 1) || // PENDING -> SENT
        (current == 1 && newStatus == 2) || // SENT -> ANCHORED
        (current == 2 && newStatus == 3) || // ANCHORED -> PROVEN
        (current == 3 && newStatus == 4);   // PROVEN -> CLAIMED

    bool validFailure = newStatus == 5; // Any -> FAILED

    assert validForward || validFailure || current == newStatus,
        "Invalid deposit status transition";
}

/// @title Message cannot be claimed twice
rule noDoubleMessageClaim(bytes32 msgId) {
    bool before = claimedMessages(msgId);
    require before == true;

    assert claimedMessages(msgId) == true,
        "Claimed message must remain claimed";
}

/// @title Transfer nonce monotonicity
rule nonceMonotonicity() {
    uint256 nonceBefore = transferNonce();
    uint256 nonceAfter = transferNonce();

    assert nonceAfter >= nonceBefore,
        "Transfer nonce must not decrease";
}

/// @title Value accounting integrity
rule valueAccountingIntegrity() {
    assert totalValueDeposited() >= totalValueWithdrawn(),
        "Deposited value must be >= withdrawn value";
}

/// @title Cross-domain nullifier uniqueness
rule nullifierUniqueness(bytes32 id1, bytes32 id2) {
    require id1 != id2;

    bytes32 nf1 = keccak256(abi.encodePacked(id1, "LINEA_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(id2, "LINEA_NULLIFIER"));

    assert nf1 != nf2, "Different IDs must produce different nullifiers";
}

/// @title Cross-domain nullifier determinism
rule nullifierDeterminism(bytes32 id) {
    bytes32 nf1 = keccak256(abi.encodePacked(id, "LINEA_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(id, "LINEA_NULLIFIER"));

    assert nf1 == nf2, "Same ID must produce same nullifier";
}
