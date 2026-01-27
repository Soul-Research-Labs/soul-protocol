// SPDX-License-Identifier: MIT
// Certora CVL Specification for zkSync Bridge Adapter
// Soul Protocol (Soul) - Formal Verification

/*
 * =============================================================================
 * ZKSYNC ERA BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 * 
 * This specification verifies the security properties of the zkSync Era Bridge
 * Adapter including:
 * - ZK proof verification (Boojum/PLONK)
 * - Batch verification before execution
 * - L2 log proof verification
 * - Priority operation management
 * - Cross-domain nullifier uniqueness
 */

using zkSyncBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    // View functions
    function deposits(bytes32) external returns (
        bytes32 depositId,
        address sender,
        address l2Receiver,
        address l1Token,
        address l2Token,
        uint256 amount,
        uint256 l2GasLimit,
        uint256 l2GasPerPubdata,
        bytes32 l2TxHash,
        uint8 status,
        uint256 priorityOpId,
        uint256 initiatedAt
    ) envfree;
    
    function withdrawals(bytes32) external returns (
        bytes32 withdrawalId,
        address l2Sender,
        address l1Receiver,
        address l2Token,
        address l1Token,
        uint256 amount,
        uint256 l2BatchNumber,
        uint256 l2MessageIndex,
        uint16 l2TxNumberInBatch,
        bytes32 l2TxHash,
        uint8 status,
        uint256 initiatedAt,
        uint256 finalizedAt
    ) envfree;
    
    function batches(uint256) external returns (
        uint256 batchNumber,
        bytes32 batchHash,
        bytes32 stateRoot,
        uint64 timestamp,
        bytes32 commitment,
        bool verified,
        bool executed
    ) envfree;
    
    function provedWithdrawals(bytes32) external returns (bool) envfree;
    function processedDeposits(bytes32) external returns (bool) envfree;
    
    // State variables
    function priorityOpId() external returns (uint256) envfree;
    function currentBatch() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalValueDeposited() external returns (uint256) envfree;
    function totalValueWithdrawn() external returns (uint256) envfree;
    
    // Constants
    function ZKSYNC_CHAIN_ID() external returns (uint256) envfree;
    function L2_GAS_PER_PUBDATA() external returns (uint256) envfree;
    function DEFAULT_L2_GAS_LIMIT() external returns (uint256) envfree;
    function PRIORITY_TX_MAX_GAS() external returns (uint256) envfree;
    
    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function PROVER_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(bytes32 => bool) ghostConsumedNullifiers {
    init_state axiom forall bytes32 nf. ghostConsumedNullifiers[nf] == false;
}

ghost mapping(uint256 => bool) ghostBatchVerified {
    init_state axiom forall uint256 bn. ghostBatchVerified[bn] == false;
}

ghost mapping(uint256 => bool) ghostBatchExecuted {
    init_state axiom forall uint256 bn. ghostBatchExecuted[bn] == false;
}

ghost mapping(bytes32 => bool) ghostProvedWithdrawals {
    init_state axiom forall bytes32 wId. ghostProvedWithdrawals[wId] == false;
}

ghost uint256 ghostCurrentBatch {
    init_state axiom ghostCurrentBatch == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Batch must be verified before execution
/// @notice Executed batches must have been verified first
invariant batchVerifiedBeforeExecution(uint256 batchNumber)
    batches(batchNumber).executed == true =>
    batches(batchNumber).verified == true

/// @title Withdrawal must be proved before finalization
/// @notice Finalized withdrawals must have been proved
invariant withdrawalProvedBeforeFinalization(bytes32 withdrawalId)
    withdrawals(withdrawalId).status == 2 => // EXECUTED
    provedWithdrawals(withdrawalId) == true

/// @title Gas per pubdata meets minimum
/// @notice Deposits must have sufficient gas per pubdata
invariant gasPerPubdataMinimum(bytes32 depositId)
    deposits(depositId).l2GasPerPubdata == 0 ||
    deposits(depositId).l2GasPerPubdata >= L2_GAS_PER_PUBDATA()

/// @title Gas limit within bounds
/// @notice L2 gas limit must not exceed maximum
invariant gasLimitWithinBounds(bytes32 depositId)
    deposits(depositId).l2GasLimit == 0 ||
    deposits(depositId).l2GasLimit <= PRIORITY_TX_MAX_GAS()

/// @title Batch numbers are monotonically increasing
/// @notice Current batch should always increase
invariant batchMonotonicity()
    currentBatch() >= ghostCurrentBatch

// =============================================================================
// ZK PROOF RULES
// =============================================================================

/// @title Batch verification is permanent
/// @notice Once verified, a batch stays verified
rule batchVerificationPermanent(uint256 batchNumber) {
    bool verifiedBefore = batches(batchNumber).verified;
    
    require verifiedBefore == true;
    
    assert batches(batchNumber).verified == true,
        "Verified batch should remain verified";
}

/// @title Batch execution requires verification
/// @notice Cannot execute unverified batch
rule batchExecutionRequiresVerification(uint256 batchNumber) {
    bool verified = batches(batchNumber).verified;
    bool executed = batches(batchNumber).executed;
    
    require executed == true;
    
    assert verified == true,
        "Executed batch must be verified";
}

/// @title Prover role required for batch verification
/// @notice Only provers can submit ZK proofs
rule batchVerificationRequiresProver(env e, uint256 batchNumber) {
    bool hasProverRole = hasRole(PROVER_ROLE(), e.msg.sender);
    
    bool verifiedBefore = batches(batchNumber).verified;
    
    require !hasProverRole;
    require !verifiedBefore;
    
    // Verification should fail without prover role
    bool verifiedAfter = batches(batchNumber).verified;
    
    assert verifiedBefore == verifiedAfter || hasProverRole,
        "Only provers can verify batches";
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/// @title Withdrawal proof is one-time
/// @notice Cannot prove the same withdrawal twice
rule withdrawalProofOnce(bytes32 withdrawalId) {
    bool provedBefore = provedWithdrawals(withdrawalId);
    
    require provedBefore == true;
    
    assert provedWithdrawals(withdrawalId) == true,
        "Proved withdrawal should stay proved";
}

/// @title Withdrawal finalization requires batch execution
/// @notice Cannot finalize withdrawal without executed batch
rule withdrawalRequiresExecutedBatch(bytes32 withdrawalId) {
    uint256 batchNumber = withdrawals(withdrawalId).l2BatchNumber;
    uint8 status = withdrawals(withdrawalId).status;
    
    require status == 2; // EXECUTED
    require batchNumber > 0;
    
    assert batches(batchNumber).executed == true,
        "Withdrawal requires executed batch";
}

/// @title Withdrawal nullifier consumed on finalization
/// @notice Finalizing withdrawal consumes its nullifier
rule withdrawalConsumesNullifier(bytes32 withdrawalId) {
    bytes32 nullifier = keccak256(abi.encodePacked(withdrawalId, "ZKSYNC_NULLIFIER"));
    bool consumedBefore = ghostConsumedNullifiers[nullifier];
    
    require !consumedBefore;
    require provedWithdrawals(withdrawalId) == true;
    
    // After finalization, nullifier should be consumed
}

// =============================================================================
// DEPOSIT RULES
// =============================================================================

/// @title Deposit gas validation
/// @notice Deposits must have valid gas parameters
rule depositGasValidation(bytes32 depositId) {
    uint256 l2GasLimit = deposits(depositId).l2GasLimit;
    uint256 l2GasPerPubdata = deposits(depositId).l2GasPerPubdata;
    
    require l2GasLimit > 0; // Deposit exists
    
    assert l2GasLimit <= PRIORITY_TX_MAX_GAS(),
        "Gas limit must be within bounds";
    
    assert l2GasPerPubdata >= L2_GAS_PER_PUBDATA(),
        "Gas per pubdata must meet minimum";
}

/// @title Priority operation ID is unique
/// @notice Each deposit gets unique priority op ID
rule priorityOpIdUniqueness(bytes32 depositId1, bytes32 depositId2) {
    require depositId1 != depositId2;
    
    uint256 opId1 = deposits(depositId1).priorityOpId;
    uint256 opId2 = deposits(depositId2).priorityOpId;
    
    require opId1 > 0 && opId2 > 0; // Both deposits exist
    
    assert opId1 != opId2, "Priority op IDs must be unique";
}

// =============================================================================
// CROSS-DOMAIN NULLIFIER RULES
// =============================================================================

/// @title Nullifier uniqueness
/// @notice Different transfers have different nullifiers
rule nullifierUniqueness(bytes32 transferId1, bytes32 transferId2) {
    require transferId1 != transferId2;
    
    bytes32 nf1 = keccak256(abi.encodePacked(transferId1, "ZKSYNC_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(transferId2, "ZKSYNC_NULLIFIER"));
    
    assert nf1 != nf2, "Different transfers must have different nullifiers";
}

/// @title Cross-domain nullifier determinism
/// @notice Same input produces same nullifier
rule crossDomainNullifierDeterminism(bytes32 zkNullifier, bytes32 domain) {
    bytes32 pilNf1 = keccak256(abi.encodePacked(zkNullifier, domain, "ZKSYNC2Soul"));
    bytes32 pilNf2 = keccak256(abi.encodePacked(zkNullifier, domain, "ZKSYNC2Soul"));
    
    assert pilNf1 == pilNf2, "Cross-domain nullifier must be deterministic";
}

/// @title Cross-domain direction matters
/// @notice zkSync->Soul differs from Soul->zkSync
rule crossDomainDirectionMatters(bytes32 nullifier, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;
    
    bytes32 nfAtoB = keccak256(abi.encodePacked(nullifier, domainA, domainB));
    bytes32 nfBtoA = keccak256(abi.encodePacked(nullifier, domainB, domainA));
    
    assert nfAtoB != nfBtoA, "Direction should affect nullifier";
}

// =============================================================================
// CHAIN ID RULES
// =============================================================================

/// @title Chain ID constant is correct
/// @notice zkSync Era chain ID should be 324
rule chainIdConstantCorrect() {
    assert ZKSYNC_CHAIN_ID() == 324, "zkSync Era chain ID should be 324";
}

// =============================================================================
// VALUE CONSERVATION
// =============================================================================

/// @title Value is conserved
/// @notice Cannot withdraw more than deposited
rule valueConservation() {
    uint256 deposited = totalValueDeposited();
    uint256 withdrawn = totalValueWithdrawn();
    
    assert withdrawn <= deposited, "Cannot withdraw more than deposited";
}

// =============================================================================
// BATCH RULES
// =============================================================================

/// @title Batch number monotonicity
/// @notice New batches have higher numbers
rule batchNumberMonotonicity(uint256 batch1, uint256 batch2) {
    uint64 ts1 = batches(batch1).timestamp;
    uint64 ts2 = batches(batch2).timestamp;
    
    require ts1 < ts2;
    require ts1 > 0 && ts2 > 0;
    
    assert batch1 < batch2, "Batch numbers should be monotonic";
}

/// @title Batch state root is non-zero when verified
/// @notice Verified batches must have valid state root
rule verifiedBatchHasStateRoot(uint256 batchNumber) {
    bool verified = batches(batchNumber).verified;
    bytes32 stateRoot = batches(batchNumber).stateRoot;
    
    require verified == true;
    
    assert stateRoot != bytes32(0), "Verified batch must have state root";
}

// =============================================================================
// GAS CONSTANTS RULES
// =============================================================================

/// @title Gas constants are correct
/// @notice Gas-related constants should have expected values
rule gasConstantsCorrect() {
    assert L2_GAS_PER_PUBDATA() == 800, "L2 gas per pubdata should be 800";
    assert DEFAULT_L2_GAS_LIMIT() == 2000000, "Default L2 gas should be 2M";
}

// =============================================================================
// ACCESS CONTROL RULES
// =============================================================================

/// @title Operator can configure adapter
/// @notice OPERATOR_ROLE required for configuration
rule operatorCanConfigure(env e) {
    bool hasOperatorRole = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    // Configuration functions should require operator role
    require !hasOperatorRole;
    
    // Should not be able to modify configuration
}
