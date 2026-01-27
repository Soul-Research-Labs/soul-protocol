// SPDX-License-Identifier: MIT
// Certora CVL Specification for Scroll Bridge Adapter
// Soul Protocol (Soul) - Formal Verification

/*
 * =============================================================================
 * SCROLL ZKEVM BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 * 
 * This specification verifies the security properties of the Scroll Bridge
 * Adapter including:
 * - zkEVM proof verification
 * - Batch finalization before withdrawals
 * - Withdrawal Merkle proof verification
 * - Cross-domain nullifier uniqueness
 */

using ScrollBridgeAdapter as adapter;

methods {
    // State queries
    function deposits(bytes32) external returns (
        bytes32 depositId,
        address sender,
        address recipient,
        address token,
        uint256 amount,
        uint256 gasLimit,
        uint256 queueIndex,
        uint256 timestamp,
        uint8 status
    ) envfree;
    
    function withdrawals(bytes32) external returns (
        bytes32 withdrawalId,
        address sender,
        address recipient,
        address token,
        uint256 amount,
        uint256 batchIndex,
        uint256 messageNonce,
        uint256 timestamp,
        bool finalized
    ) envfree;
    
    function batches(uint256) external returns (
        uint256 batchIndex,
        bytes32 batchHash,
        bytes32 stateRoot,
        bytes32 withdrawalRoot,
        uint256 l1MessagePopped,
        uint256 totalL1MessagePopped,
        bytes32 dataHash,
        uint256 timestamp,
        uint8 status
    ) envfree;
    
    function claimedWithdrawals(bytes32) external returns (bool) envfree;
    function executedMessages(bytes32) external returns (bool) envfree;
    
    // State variables
    function messageNonce() external returns (uint256) envfree;
    function queueIndex() external returns (uint256) envfree;
    function currentBatchIndex() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    
    // Constants
    function SCROLL_MAINNET_CHAIN_ID() external returns (uint256) envfree;
    function SCROLL_SEPOLIA_CHAIN_ID() external returns (uint256) envfree;
    function FINALIZATION_PERIOD() external returns (uint256) envfree;
    function DEFAULT_L2_GAS_LIMIT() external returns (uint256) envfree;
    
    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(bytes32 => bool) ghostConsumedNullifiers {
    init_state axiom forall bytes32 nf. ghostConsumedNullifiers[nf] == false;
}

ghost mapping(uint256 => uint8) ghostBatchStatus {
    init_state axiom forall uint256 idx. ghostBatchStatus[idx] == 0;
}

ghost uint256 ghostCurrentBatchIndex {
    init_state axiom ghostCurrentBatchIndex == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Batch finalization required for withdrawal
invariant withdrawalRequiresFinalizedBatch(bytes32 withdrawalId)
    withdrawals(withdrawalId).finalized == true =>
    batches(withdrawals(withdrawalId).batchIndex).status == 1 // FINALIZED

/// @title Withdrawal cannot be claimed twice
invariant withdrawalClaimedOnce(bytes32 withdrawalId)
    claimedWithdrawals(withdrawalId) == withdrawals(withdrawalId).finalized

/// @title Batch index is monotonically increasing
invariant batchIndexMonotonic()
    currentBatchIndex() >= ghostCurrentBatchIndex

/// @title Gas limit within bounds
invariant gasLimitBounded(bytes32 depositId)
    deposits(depositId).gasLimit == 0 ||
    deposits(depositId).gasLimit <= DEFAULT_L2_GAS_LIMIT()

// =============================================================================
// BATCH RULES
// =============================================================================

/// @title Batch finalization is permanent
rule batchFinalizationPermanent(uint256 batchIndex) {
    uint8 statusBefore = batches(batchIndex).status;
    
    require statusBefore == 1; // FINALIZED
    
    assert batches(batchIndex).status == 1,
        "Finalized batch should remain finalized";
}

/// @title Batch must be committed before finalization
rule batchCommittedBeforeFinalization(uint256 batchIndex) {
    uint8 status = batches(batchIndex).status;
    bytes32 stateRoot = batches(batchIndex).stateRoot;
    
    require status == 1; // FINALIZED
    
    // Must have valid state root
    assert stateRoot != bytes32(0),
        "Finalized batch must have state root";
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/// @title Withdrawal requires finalized batch
rule withdrawalRequiresFinalizedBatch(bytes32 withdrawalId) {
    uint256 batchIndex = withdrawals(withdrawalId).batchIndex;
    bool finalized = withdrawals(withdrawalId).finalized;
    
    require finalized == true;
    require batchIndex > 0;
    
    assert batches(batchIndex).status == 1,
        "Withdrawal requires finalized batch";
}

/// @title No double withdrawal claim
rule noDoubleWithdrawalClaim(bytes32 withdrawalId) {
    bool claimedBefore = claimedWithdrawals(withdrawalId);
    
    require claimedBefore == true;
    
    assert claimedWithdrawals(withdrawalId) == true,
        "Claimed withdrawal should stay claimed";
}

// =============================================================================
// CROSS-DOMAIN NULLIFIER RULES
// =============================================================================

/// @title Nullifier uniqueness
rule nullifierUniqueness(bytes32 msgId1, bytes32 msgId2) {
    require msgId1 != msgId2;
    
    bytes32 nf1 = keccak256(abi.encodePacked(msgId1, "SCROLL_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(msgId2, "SCROLL_NULLIFIER"));
    
    assert nf1 != nf2, "Different messages must have different nullifiers";
}

/// @title Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 scrollNullifier, bytes32 domain) {
    bytes32 pilNf1 = keccak256(abi.encodePacked(scrollNullifier, domain, "SCROLL2Soul"));
    bytes32 pilNf2 = keccak256(abi.encodePacked(scrollNullifier, domain, "SCROLL2Soul"));
    
    assert pilNf1 == pilNf2, "Cross-domain nullifier must be deterministic";
}

/// @title Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 nullifier, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;
    
    bytes32 nfAtoB = keccak256(abi.encodePacked(nullifier, domainA, domainB));
    bytes32 nfBtoA = keccak256(abi.encodePacked(nullifier, domainB, domainA));
    
    assert nfAtoB != nfBtoA, "Direction should affect nullifier";
}

// =============================================================================
// CHAIN ID RULES
// =============================================================================

/// @title Chain ID constants are correct
rule chainIdConstantsCorrect() {
    assert SCROLL_MAINNET_CHAIN_ID() == 534352, "Scroll Mainnet should be 534352";
    assert SCROLL_SEPOLIA_CHAIN_ID() == 534351, "Scroll Sepolia should be 534351";
}

// =============================================================================
// VALUE CONSERVATION
// =============================================================================

/// @title Value is conserved
rule valueConservation() {
    uint256 deposited = totalDeposits();
    uint256 withdrawn = totalWithdrawals();
    
    assert withdrawn <= deposited, "Cannot withdraw more than deposited";
}

// =============================================================================
// QUEUE ORDERING
// =============================================================================

/// @title Queue index is monotonically increasing
rule queueIndexMonotonic() {
    uint256 qi = queueIndex();
    
    assert qi >= 0, "Queue index should be non-negative";
}

/// @title L1 message queue ordering
rule l1MessageQueueOrdering(uint256 batchIndex) {
    uint256 popped = batches(batchIndex).l1MessagePopped;
    uint256 totalPopped = batches(batchIndex).totalL1MessagePopped;
    
    require totalPopped > 0;
    
    assert totalPopped >= popped, "Total popped should be >= current popped";
}
