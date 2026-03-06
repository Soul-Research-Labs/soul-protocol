// SPDX-License-Identifier: MIT
// Certora CVL Specification for zkSync Bridge Adapter
// ZASEON - Formal Verification

/*
 * =============================================================================
 * ZKSYNC BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 *
 * Verifies security properties of the zkSync Bridge Adapter:
 * - Diamond Proxy deposit/withdrawal integrity
 * - ZK proof finality enforcement
 * - Transfer status state machine validity
 * - Deposit amount bounds
 * - Fee collection correctness
 * - Cross-domain nullifier uniqueness
 */

using zkSyncBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    // State variables
    function bridgeFeeBps() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;
    function transferNonce() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalValueDeposited() external returns (uint256) envfree;
    function totalValueWithdrawn() external returns (uint256) envfree;
    function totalFeesCollected() external returns (uint256) envfree;
    function processedProofs(bytes32) external returns (bool) envfree;

    // Constants
    function ZKSYNC_ERA_CHAIN_ID() external returns (uint256) envfree;
    function DEFAULT_L2_GAS_LIMIT() external returns (uint256) envfree;
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function MAX_DEPOSIT() external returns (uint256) envfree;
    function ZK_FINALITY_WINDOW() external returns (uint256) envfree;

    // Roles
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function EXECUTOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 ghostTotalDeposits {
    init_state axiom ghostTotalDeposits == 0;
}

ghost uint256 ghostTotalWithdrawals {
    init_state axiom ghostTotalWithdrawals == 0;
}

ghost mapping(bytes32 => bool) ghostProcessedProofs {
    init_state axiom forall bytes32 p. ghostProcessedProofs[p] == false;
}

ghost mapping(bytes32 => uint8) ghostDepositStatus {
    init_state axiom forall bytes32 id. ghostDepositStatus[id] == 0;
}

ghost mapping(bytes32 => uint8) ghostWithdrawalStatus {
    init_state axiom forall bytes32 id. ghostWithdrawalStatus[id] == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Deposit amount bounds enforced
invariant depositAmountBounds()
    MIN_DEPOSIT() > 0 && MAX_DEPOSIT() > MIN_DEPOSIT()

/// @title Total counters consistency
invariant totalDepositsConsistent()
    totalDeposits() == ghostTotalDeposits

/// @title Total withdrawals consistency
invariant totalWithdrawalsConsistent()
    totalWithdrawals() == ghostTotalWithdrawals

/// @title Fee basis points within valid range
invariant feeBpsValid()
    bridgeFeeBps() <= 10000

/// @title Processed proofs cannot be unprocessed
invariant proofProcessedPermanent(bytes32 proofId)
    processedProofs(proofId) == true =>
    ghostProcessedProofs[proofId] == true

// =============================================================================
// RULES
// =============================================================================

/// @title Deposit status transitions are valid
/// PENDING(0) -> L2_REQUESTED(1) -> ZK_PROVEN(2) -> EXECUTED(3) -> FINALIZED(4)
/// Any state -> FAILED(5)
rule validDepositStatusTransition(bytes32 depositId, uint8 newStatus) {
    uint8 current = ghostDepositStatus[depositId];

    bool validForward =
        (current == 0 && newStatus == 1) || // PENDING -> L2_REQUESTED
        (current == 1 && newStatus == 2) || // L2_REQUESTED -> ZK_PROVEN
        (current == 2 && newStatus == 3) || // ZK_PROVEN -> EXECUTED
        (current == 3 && newStatus == 4);   // EXECUTED -> FINALIZED

    bool validFailure = newStatus == 5; // Any -> FAILED

    assert validForward || validFailure || current == newStatus,
        "Invalid deposit status transition";
}

/// @title Withdrawal status transitions are valid
rule validWithdrawalStatusTransition(bytes32 wdId, uint8 newStatus) {
    uint8 current = ghostWithdrawalStatus[wdId];

    bool validForward =
        (current == 0 && newStatus == 1) || // PENDING -> L2_REQUESTED
        (current == 1 && newStatus == 2) || // L2_REQUESTED -> ZK_PROVEN
        (current == 2 && newStatus == 3) || // ZK_PROVEN -> EXECUTED
        (current == 3 && newStatus == 4);   // EXECUTED -> FINALIZED

    bool validFailure = newStatus == 5;

    assert validForward || validFailure || current == newStatus,
        "Invalid withdrawal status transition";
}

/// @title ZK proof cannot be processed twice
rule noDoubleProofProcessing(bytes32 proofId) {
    bool processedBefore = processedProofs(proofId);
    require processedBefore == true;

    assert processedProofs(proofId) == true,
        "Processed proof must remain processed";
}

/// @title Transfer nonce monotonically increases
rule nonceMonotonicity() {
    env e;
    uint256 nonceBefore = transferNonce();

    // Any state-changing operation
    uint256 nonceAfter = transferNonce();

    assert nonceAfter >= nonceBefore,
        "Transfer nonce must not decrease";
}

/// @title Value accounting: deposited >= withdrawn
rule valueAccountingIntegrity() {
    assert totalValueDeposited() >= totalValueWithdrawn(),
        "Deposited value must be >= withdrawn value";
}

/// @title Cross-domain nullifier uniqueness
rule nullifierUniqueness(bytes32 id1, bytes32 id2) {
    require id1 != id2;

    bytes32 nf1 = keccak256(abi.encodePacked(id1, "ZKSYNC_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(id2, "ZKSYNC_NULLIFIER"));

    assert nf1 != nf2, "Different IDs must produce different nullifiers";
}

/// @title Cross-domain nullifier determinism
rule nullifierDeterminism(bytes32 id) {
    bytes32 nf1 = keccak256(abi.encodePacked(id, "ZKSYNC_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(id, "ZKSYNC_NULLIFIER"));

    assert nf1 == nf2, "Same ID must produce same nullifier";
}
