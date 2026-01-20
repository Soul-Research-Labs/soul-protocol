/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - HomomorphicHiding
 * 
 * This spec verifies critical invariants for the Homomorphic Hiding primitive
 * which enables computations on encrypted/committed values
 */

using HomomorphicHiding as hh;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalCommitments() external returns (uint256) envfree;
    function totalOperations() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    
    // Commitment functions
    function createCommitment(bytes32, bytes32, bytes32, uint64) external returns (bytes32);
    function revealCommitment(bytes32, uint256, bytes32) external;
    
    // Homomorphic operations
    function homomorphicAdd(bytes32, bytes32) external returns (bytes32, bytes32);
    function homomorphicSubtract(bytes32, bytes32) external returns (bytes32, bytes32);
    function homomorphicScalarMultiply(bytes32, uint256) external returns (bytes32, bytes32);
    
    // Range proofs
    function submitRangeProof(bytes32, uint256, uint256, bytes) external returns (bytes32);
    function verifyRangeProof(bytes32) external returns (bool);
    
    // Admin functions
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalCommitments {
    init_state axiom ghostTotalCommitments == 0;
}

ghost uint256 ghostTotalOperations {
    init_state axiom ghostTotalOperations == 0;
}

ghost mapping(bytes32 => bool) ghostCommitmentRevealed {
    init_state axiom forall bytes32 c. !ghostCommitmentRevealed[c];
}

ghost mapping(bytes32 => bool) ghostCommitmentExists {
    init_state axiom forall bytes32 c. !ghostCommitmentExists[c];
}

// ============================================================================
// INVARIANTS - Removed trivial ones (uint256 is always >= 0)
// ============================================================================

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Create Commitment Increases Count
 * @notice Creating a commitment should increase the total count
 */
rule createCommitmentIncreasesCount(bytes32 commitment, bytes32 genG, bytes32 genH, uint64 expiry) {
    env e;
    require !paused();
    
    uint256 countBefore = totalCommitments();
    
    createCommitment(e, commitment, genG, genH, expiry);
    
    uint256 countAfter = totalCommitments();
    
    assert countAfter == countBefore + 1,
        "Creating a commitment should increase total count by 1";
}

/**
 * @title Commitment Reveal Is Permanent
 * @notice Once a commitment is revealed, it cannot be revealed again
 */
rule revealPermanence(bytes32 commitmentId, uint256 value, bytes32 randomness) {
    env e1;
    env e2;
    
    // First reveal succeeds
    revealCommitment(e1, commitmentId, value, randomness);
    
    // Second reveal should revert
    revealCommitment@withrevert(e2, commitmentId, value, randomness);
    
    assert lastReverted,
        "Cannot reveal a commitment twice";
}

/**
 * @title Homomorphic Add Increases Operations
 * @notice Performing homomorphic addition should increase operation count
 */
rule homomorphicAddIncreasesOperations(bytes32 commitmentA, bytes32 commitmentB) {
    env e;
    require !paused();
    
    uint256 opsBefore = totalOperations();
    
    homomorphicAdd(e, commitmentA, commitmentB);
    
    uint256 opsAfter = totalOperations();
    
    assert opsAfter == opsBefore + 1,
        "Homomorphic add should increase operation count";
}

/**
 * @title Homomorphic Subtract Increases Operations
 * @notice Performing homomorphic subtraction should increase operation count
 */
rule homomorphicSubtractIncreasesOperations(bytes32 commitmentA, bytes32 commitmentB) {
    env e;
    require !paused();
    
    uint256 opsBefore = totalOperations();
    
    homomorphicSubtract(e, commitmentA, commitmentB);
    
    uint256 opsAfter = totalOperations();
    
    assert opsAfter == opsBefore + 1,
        "Homomorphic subtract should increase operation count";
}

/**
 * @title Homomorphic Scalar Multiply Increases Operations
 * @notice Performing scalar multiplication should increase operation count
 */
rule homomorphicScalarMultiplyIncreasesOperations(bytes32 commitmentId, uint256 scalar) {
    env e;
    require !paused();
    
    uint256 opsBefore = totalOperations();
    
    homomorphicScalarMultiply(e, commitmentId, scalar);
    
    uint256 opsAfter = totalOperations();
    
    assert opsAfter == opsBefore + 1,
        "Scalar multiply should increase operation count";
}

/**
 * @title Pause Prevents Operations
 * @notice When paused, state-changing operations should revert
 */
rule pausePreventsOperations(bytes32 commitment, bytes32 genG, bytes32 genH, uint64 expiry) {
    env e;
    require paused();
    
    createCommitment@withrevert(e, commitment, genG, genH, expiry);
    
    assert lastReverted,
        "Operations should fail when paused";
}

/**
 * @title Range Proof Bounds Valid
 * @notice Range proof lower bound must be less than or equal to upper bound
 */
rule rangeProofBoundsValid(bytes32 commitmentId, uint256 lower, uint256 upper, bytes proof) {
    env e;
    require lower > upper;
    
    submitRangeProof@withrevert(e, commitmentId, lower, upper, proof);
    
    assert lastReverted,
        "Range proof with invalid bounds should revert";
}

/**
 * @title Operations Are Monotonic
 * @notice Total operations count never decreases
 */
rule operationsMonotonic() {
    env e;
    
    uint256 opsBefore = totalOperations();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 opsAfter = totalOperations();
    
    assert opsAfter >= opsBefore,
        "Operations count should never decrease";
}

/**
 * @title Commitments Are Monotonic
 * @notice Total commitments count never decreases
 */
rule commitmentsMonotonic() {
    env e;
    
    uint256 countBefore = totalCommitments();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalCommitments();
    
    assert countAfter >= countBefore,
        "Commitments count should never decrease";
}
