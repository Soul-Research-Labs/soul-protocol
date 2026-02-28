/**
 * Certora Formal Verification Specification
 * ZASEON - NullifierRegistryV3
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
    function isValidRoot(bytes32) external returns (bool);
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

// ============================================================================
// EXPANDED RULES — Batch registration, merkle roots, access control
// ============================================================================

/**
 * @title Total nullifiers monotonically increasing
 * @notice The total nullifier count must never decrease
 */
rule totalNullifiersMonotonic() {
    uint256 countBefore = totalNullifiers();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 countAfter = totalNullifiers();

    assert countAfter >= countBefore,
        "Total nullifiers must never decrease";
}

/**
 * @title Registration increments total by exactly 1
 * @notice A single registerNullifier call must increase totalNullifiers by 1
 */
rule registerIncrementsTotal(bytes32 nullifier, bytes32 commitment) {
    env e;
    uint256 countBefore = totalNullifiers();

    registerNullifier(e, nullifier, commitment);

    uint256 countAfter = totalNullifiers();

    assert countAfter == countBefore + 1,
        "Single registration must increment total by exactly 1";
}

/**
 * @title Batch registration increments total correctly
 * @notice batchRegisterNullifiers should increase totalNullifiers by the batch length
 */
rule batchRegisterIncrements(bytes32[] nullifiers, bytes32[] commitments) {
    env e;
    uint256 countBefore = totalNullifiers();
    uint256 batchLen = nullifiers.length;

    batchRegisterNullifiers(e, nullifiers, commitments);

    uint256 countAfter = totalNullifiers();

    assert countAfter == countBefore + batchLen,
        "Batch registration must increment total by batch length";
}

/**
 * @title Only REGISTRAR_ROLE can register nullifiers
 * @notice Callers without REGISTRAR_ROLE must be rejected
 */
rule onlyRegistrarCanRegister(bytes32 nullifier, bytes32 commitment) {
    env e;

    require !hasRole(nr.REGISTRAR_ROLE(), e.msg.sender);

    registerNullifier@withrevert(e, nullifier, commitment);

    assert lastReverted,
        "Non-registrar must not register nullifiers";
}

/**
 * @title Only REGISTRAR_ROLE can batch register
 */
rule onlyRegistrarCanBatchRegister(bytes32[] nullifiers, bytes32[] commitments) {
    env e;

    require !hasRole(nr.REGISTRAR_ROLE(), e.msg.sender);

    batchRegisterNullifiers@withrevert(e, nullifiers, commitments);

    assert lastReverted,
        "Non-registrar must not batch register nullifiers";
}

/**
 * @title Pause prevents batch registration
 */
rule pausePreventsBatchRegistration(bytes32[] nullifiers, bytes32[] commitments) {
    env e;
    require paused();

    batchRegisterNullifiers@withrevert(e, nullifiers, commitments);

    assert lastReverted,
        "Batch registration should fail when paused";
}

/**
 * @title Historical root immutability
 * @notice Once a root is in historicalRoots, it stays there forever
 */
rule historicalRootImmutable(bytes32 root) {
    bool validBefore = historicalRoots(root);

    env e;
    method f;
    calldataarg args;
    f(e, args);

    bool validAfter = historicalRoots(root);

    assert validBefore => validAfter,
        "Historical roots are immutable — once valid, always valid";
}

/**
 * @title Merkle root changes on registration
 * @notice After a successful registration, the merkleRoot should change
 */
rule registrationChangesMerkleRoot(bytes32 nullifier, bytes32 commitment) {
    env e;
    bytes32 rootBefore = merkleRoot();

    registerNullifier(e, nullifier, commitment);

    bytes32 rootAfter = merkleRoot();

    assert rootBefore != rootAfter,
        "Registration must update the merkle root";
}

/**
 * @title Old root becomes historical after registration
 * @notice After registration, the previous root should be in historicalRoots
 */
rule oldRootPreservedInHistory(bytes32 nullifier, bytes32 commitment) {
    env e;
    bytes32 rootBefore = merkleRoot();
    require rootBefore != to_bytes32(0);

    registerNullifier(e, nullifier, commitment);

    bool isHistorical = historicalRoots(rootBefore);

    assert isHistorical,
        "Previous merkle root must be preserved in historicalRoots";
}

/**
 * @title isValidRoot accepts current root
 * @notice The current merkle root should always be valid
 */
rule currentRootIsValid() {
    env e;
    bytes32 currentRoot = merkleRoot();
    require currentRoot != to_bytes32(0);

    bool valid = isValidRoot(e, currentRoot);

    assert valid,
        "Current merkle root must be valid";
}
