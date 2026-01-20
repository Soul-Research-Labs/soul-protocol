/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - ComposableRevocationProofs
 * 
 * This spec verifies critical invariants for the Composable Revocation Proofs (CRP)
 * which enables privacy-preserving credential revocation with composable proofs
 */

using ComposableRevocationProofs as crp;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalAccumulators() external returns (uint256) envfree;
    function totalRevocations() external returns (uint256) envfree;
    function totalProofs() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function isRevoked(bytes32, bytes32) external returns (bool) envfree;
    
    // Accumulator functions
    function createAccumulator(bytes32) external returns (bytes32);
    function revokeCredential(bytes32, bytes32, bytes32, string) external returns (bytes32);
    function batchRevokeCredentials(bytes32, bytes32[], bytes32[], string) external;
    function unrevokeCredential(bytes32, bytes32) external;
    
    // Proof functions
    function createNonMembershipProof(bytes32, bytes32, bytes, uint64) external returns (bytes32);
    function verifyNonMembershipProof(bytes32) external returns (bool);
    
    // Delta updates
    function publishDeltaUpdate(bytes32, uint256, uint256, bytes32[], bytes32[], bytes32) external returns (bytes32);
    
    // Composable proofs
    function createComposableProof(bytes32, bytes32[], bytes32) external returns (bytes32);
    
    // Admin
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalAccumulators {
    init_state axiom ghostTotalAccumulators == 0;
}

ghost uint256 ghostTotalRevocations {
    init_state axiom ghostTotalRevocations == 0;
}

ghost mapping(bytes32 => mapping(bytes32 => bool)) ghostRevocationStatus {
    init_state axiom forall bytes32 a. forall bytes32 c. !ghostRevocationStatus[a][c];
}

// ============================================================================
// INVARIANTS - Removed trivial ones (uint256 is always >= 0)
// ============================================================================

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Create Accumulator Increases Count
 * @notice Creating an accumulator should increase the total count
 */
rule createAccumulatorIncreasesCount(bytes32 initialValue) {
    env e;
    require !paused();
    
    uint256 countBefore = totalAccumulators();
    
    createAccumulator(e, initialValue);
    
    uint256 countAfter = totalAccumulators();
    
    assert countAfter == countBefore + 1,
        "Creating accumulator should increase count by 1";
}

/**
 * @title Revocation Sets Status
 * @notice Revoking a credential should mark it as revoked
 */
rule revocationSetsStatus(bytes32 accumulatorId, bytes32 credentialHash, bytes32 witness, string reason) {
    env e;
    require !paused();
    require !isRevoked(accumulatorId, credentialHash);
    
    revokeCredential(e, accumulatorId, credentialHash, witness, reason);
    
    bool revokedAfter = isRevoked(accumulatorId, credentialHash);
    
    assert revokedAfter == true,
        "Revocation should set status to true";
}

/**
 * @title Revocation Increases Count
 * @notice Revoking a credential should increase total revocations
 */
rule revocationIncreasesCount(bytes32 accumulatorId, bytes32 credentialHash, bytes32 witness, string reason) {
    env e;
    require !paused();
    
    uint256 countBefore = totalRevocations();
    
    revokeCredential(e, accumulatorId, credentialHash, witness, reason);
    
    uint256 countAfter = totalRevocations();
    
    assert countAfter == countBefore + 1,
        "Revocation should increase count by 1";
}

/**
 * @title Cannot Revoke Twice
 * @notice Cannot revoke an already revoked credential
 */
rule cannotRevokeTwice(bytes32 accumulatorId, bytes32 credentialHash, bytes32 witness, string reason) {
    env e1;
    env e2;
    
    // First revocation
    revokeCredential(e1, accumulatorId, credentialHash, witness, reason);
    
    // Second revocation should fail
    revokeCredential@withrevert(e2, accumulatorId, credentialHash, witness, reason);
    
    assert lastReverted,
        "Cannot revoke an already revoked credential";
}

/**
 * @title Unrevoke Clears Status
 * @notice Unrevoking should clear the revocation status
 */
rule unrevokeClearsStatus(bytes32 accumulatorId, bytes32 credentialHash) {
    env e;
    require isRevoked(accumulatorId, credentialHash);
    
    unrevokeCredential(e, accumulatorId, credentialHash);
    
    bool revokedAfter = isRevoked(accumulatorId, credentialHash);
    
    assert revokedAfter == false,
        "Unrevoke should clear revocation status";
}

/**
 * @title Cannot Unrevoke Non-Revoked
 * @notice Cannot unrevoke a credential that is not revoked
 */
rule cannotUnrevokeNonRevoked(bytes32 accumulatorId, bytes32 credentialHash) {
    env e;
    require !isRevoked(accumulatorId, credentialHash);
    
    unrevokeCredential@withrevert(e, accumulatorId, credentialHash);
    
    assert lastReverted,
        "Cannot unrevoke a non-revoked credential";
}

/**
 * @title Accumulators Are Monotonic
 * @notice Total accumulators count never decreases
 */
rule accumulatorsMonotonic() {
    env e;
    
    uint256 countBefore = totalAccumulators();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalAccumulators();
    
    assert countAfter >= countBefore,
        "Accumulators count should never decrease";
}

/**
 * @title Pause Prevents Operations
 * @notice When paused, state-changing operations should revert
 */
rule pausePreventsOperations(bytes32 initialValue) {
    env e;
    require paused();
    
    createAccumulator@withrevert(e, initialValue);
    
    assert lastReverted,
        "Operations should fail when paused";
}

/**
 * @title Proofs Are Monotonic
 * @notice Total proofs count never decreases
 */
rule proofsMonotonic() {
    env e;
    
    uint256 countBefore = totalProofs();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalProofs();
    
    assert countAfter >= countBefore,
        "Proofs count should never decrease";
}
