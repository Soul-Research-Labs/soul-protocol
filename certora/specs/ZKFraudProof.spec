/**
 * Certora Formal Verification Specification
 * ZASEON - ZKFraudProof
 *
 * Verifies safety invariants for the ZK-based fraud proof system
 * that secures batch finalization and dispute resolution.
 */

using ZKFraudProof as zfp;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function PROVER_ROLE() external returns (bytes32) envfree;
    function VERIFIER_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function isInDisputePeriod(bytes32) external returns (bool) envfree;
    function getPendingProofCount() external returns (uint256) envfree;
    function getDisputePeriod(bool) external returns (uint256) envfree;

    // State-changing functions
    function submitBatch(bytes32, bytes32, bytes32, bytes32) external;
    function finalizeBatch(bytes32) external;
    function submitFraudProof(uint8, bytes32, bytes32, bytes32, uint256, bytes, bytes32) external;
    function verifyFraudProof(bytes32) external returns (bool);
    function applyFraudProof(bytes32) external;
    function addVerificationKey(bytes32, uint8, bytes) external;
    function deactivateVerificationKey(bytes32) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-ZFP-001: Only provers can submit fraud proofs
 * submitFraudProof requires PROVER_ROLE
 */
rule onlyProverCanSubmitFraudProof(
    uint8 proofType,
    bytes32 batchId,
    bytes32 stateRoot,
    bytes32 correctStateRoot,
    uint256 txIndex,
    bytes zkProof,
    bytes32 publicInputsHash
) {
    env e;
    require !hasRole(zfp.PROVER_ROLE(), e.msg.sender);

    submitFraudProof@withrevert(e, proofType, batchId, stateRoot, correctStateRoot, txIndex, zkProof, publicInputsHash);

    assert lastReverted,
        "Only PROVER_ROLE can submit fraud proofs";
}

/**
 * RULE-ZFP-002: Only verifiers can verify fraud proofs
 * verifyFraudProof requires VERIFIER_ROLE
 */
rule onlyVerifierCanVerify(bytes32 proofId) {
    env e;
    require !hasRole(zfp.VERIFIER_ROLE(), e.msg.sender);

    verifyFraudProof@withrevert(e, proofId);

    assert lastReverted,
        "Only VERIFIER_ROLE can verify fraud proofs";
}

/**
 * RULE-ZFP-003: Cannot finalize batch during dispute period
 * A batch in its dispute period must not be finalized
 */
rule cannotFinalizeDisputedBatch(bytes32 batchId) {
    env e;
    require isInDisputePeriod(batchId);

    finalizeBatch@withrevert(e, batchId);

    assert lastReverted,
        "Cannot finalize a batch during its dispute period";
}

/**
 * RULE-ZFP-004: ZK proofs get expedited dispute window
 * Dispute period for ZK proofs is shorter than standard
 */
rule zkProofsGetExpeditedWindow() {
    uint256 standardPeriod = getDisputePeriod(false);
    uint256 zkPeriod = getDisputePeriod(true);

    assert zkPeriod < standardPeriod,
        "ZK proofs must have shorter dispute period";
}

/**
 * RULE-ZFP-005: Paused state blocks submissions
 * When paused, batch submissions should fail
 */
rule pausedBlocksSubmissions(
    bytes32 stateRoot,
    bytes32 previousStateRoot,
    bytes32 txRoot,
    bytes32 batchId
) {
    env e;
    require paused();

    submitBatch@withrevert(e, stateRoot, previousStateRoot, txRoot, batchId);

    assert lastReverted,
        "Paused state must block batch submissions";
}

/**
 * RULE-ZFP-006: Only admin can pause
 * pause() requires DEFAULT_ADMIN_ROLE
 */
rule onlyAdminCanPause() {
    env e;
    require !hasRole(zfp.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    pause@withrevert(e);

    assert lastReverted,
        "Only admin can pause the contract";
}

/**
 * RULE-ZFP-007: Pending proof count monotonicity
 * Pending proof count can only increase (proofs transition out of pending, not in)
 */
rule pendingProofCountIntegrity(method f) filtered { f -> !f.isView } {
    env e;
    uint256 countBefore = getPendingProofCount();

    calldataarg args;
    f(e, args);

    uint256 countAfter = getPendingProofCount();

    // Pending count changes only through submission or verification
    assert countBefore != countAfter =>
        f.selector == sig:submitFraudProof(uint8,bytes32,bytes32,bytes32,uint256,bytes,bytes32).selector ||
        f.selector == sig:verifyFraudProof(bytes32).selector ||
        f.selector == sig:applyFraudProof(bytes32).selector,
        "Pending count changes only through proof lifecycle functions";
}

/**
 * RULE-ZFP-008: Verification key management is admin-only
 * addVerificationKey requires proper authorization
 */
rule onlyAdminCanAddVerificationKey(bytes32 keyId, uint8 proofType, bytes vkData) {
    env e;
    require !hasRole(zfp.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    addVerificationKey@withrevert(e, keyId, proofType, vkData);

    assert lastReverted,
        "Only admin can add verification keys";
}
