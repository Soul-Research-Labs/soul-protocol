/**
 * Certora Formal Verification Specification
 * Soul Protocol - NullifierRegistryV3
 * 
 * This spec verifies critical invariants for the Nullifier Registry
 * which manages nullifier registration with merkle tree support
 */

using NullifierRegistryV3 as nr;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalNullifiers() external returns (uint256) envfree;
    function merkleRoot() external returns (bytes32) envfree;
    function isNullifierUsed(bytes32) external returns (bool) envfree;
    function historicalRoots(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function exists(bytes32) external returns (bool) envfree;
    function REGISTRAR_ROLE() external returns (bytes32) envfree;
    
    // Registration functions
    function registerNullifier(bytes32, bytes32) external returns (uint256);
    function batchRegisterNullifiers(bytes32[], bytes32[]) external returns (uint256);
    
    // Verification functions
    function isRootValid(bytes32) external returns (bool);
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost mapping(bytes32 => bool) ghostNullifierUsed {
    init_state axiom forall bytes32 n. !ghostNullifierUsed[n];
}

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Cannot Register Same Nullifier Twice
 * @notice Registering an already used nullifier should fail
 */
rule cannotRegisterTwice(bytes32 nullifier, bytes32 commitment) {
    env e1;
    env e2;
    require nullifier != to_bytes32(0);
    require hasRole(nr.REGISTRAR_ROLE(), e1.msg.sender);
    require hasRole(nr.REGISTRAR_ROLE(), e2.msg.sender);
    require !paused();
    
    // First registration
    registerNullifier(e1, nullifier, commitment);
    
    // Second registration should fail
    registerNullifier@withrevert(e2, nullifier, commitment);
    
    assert lastReverted,
        "Cannot register the same nullifier twice";
}

/**
 * @title Zero Nullifier Fails
 * @notice Registering a zero nullifier should fail
 */
rule zeroNullifierFails(bytes32 commitment) {
    env e;
    
    registerNullifier@withrevert(e, to_bytes32(0), commitment);
    
    assert lastReverted,
        "Zero nullifier should fail";
}

/**
 * @title Nullifier Usage Is Permanent
 * @notice Once a nullifier is used, it stays used
 */
rule nullifierUsagePermanent(bytes32 nullifier) {
    env e;
    
    bool usedBefore = isNullifierUsed(nullifier);
    
    method f;
    calldataarg args;
    f(e, args);
    
    bool usedAfter = isNullifierUsed(nullifier);
    
    assert usedBefore => usedAfter,
        "Nullifier usage is permanent";
}

/**
 * @title Pause Prevents Registration
 * @notice When paused, registration should fail
 */
rule pausePreventsRegistration(bytes32 nullifier, bytes32 commitment) {
    env e;
    require paused();
    
    registerNullifier@withrevert(e, nullifier, commitment);
    
    assert lastReverted,
        "Registration should fail when paused";
}

/**
 * @title Existence Matches Usage
 * @notice exists() returns the same as isNullifierUsed()
 */
rule existenceMatchesUsage(bytes32 nullifier) {
    bool used = isNullifierUsed(nullifier);
    bool ex = exists(nullifier);
    
    assert used == ex,
        "exists() should match isNullifierUsed()";
}
