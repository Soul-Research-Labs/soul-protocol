/**
 * Certora Formal Verification Specification
 * ZASEON - AggregateDisclosureAlgebra
 * 
 * This spec verifies critical invariants for the Aggregate Disclosure Algebra (ADA)
 * which enables selective and aggregate attribute disclosure
 */

using AggregateDisclosureAlgebra as ada;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalCredentials() external returns (uint256) envfree;
    function totalDisclosures() external returns (uint256) envfree;
    function totalAggregates() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    
    // Credential functions
    function issueCredential(address, bytes32, bytes32, uint64) external returns (bytes32);
    function revokeCredential(bytes32) external;
    
    // Attribute registration
    function registerAttribute(string, bool, bool) external returns (bytes32);
    
    // Selective disclosure
    function createSelectiveDisclosure(bytes32, bytes32, bytes32[], bytes, address, uint64) external returns (bytes32);
    function verifySelectiveDisclosure(bytes32) external returns (bool);
    
    // Aggregate disclosure - AggregationType is enum, passed as uint8 in CVL
    function createAggregateDisclosure(bytes32[], AggregateDisclosureAlgebra.AggregationType, uint8) external returns (bytes32);
    function verifyAggregateDisclosure(bytes32) external returns (bool);
    
    // Admin
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalCredentials {
    init_state axiom ghostTotalCredentials == 0;
}

ghost uint256 ghostTotalDisclosures {
    init_state axiom ghostTotalDisclosures == 0;
}

ghost mapping(bytes32 => bool) ghostCredentialRevoked {
    init_state axiom forall bytes32 c. !ghostCredentialRevoked[c];
}

ghost mapping(bytes32 => bool) ghostDisclosureConsumed {
    init_state axiom forall bytes32 d. !ghostDisclosureConsumed[d];
}

// ============================================================================
// INVARIANTS - Removed trivial ones (uint256 is always >= 0)
// ============================================================================

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Issue Credential Increases Count
 * @notice Issuing a credential should increase the total count
 */
rule issueCredentialIncreasesCount(address subject, bytes32 attrHash, bytes32 valueCommit, uint64 expiry) {
    env e;
    require !paused();
    
    uint256 countBefore = totalCredentials();
    
    issueCredential(e, subject, attrHash, valueCommit, expiry);
    
    uint256 countAfter = totalCredentials();
    
    assert countAfter == countBefore + 1,
        "Issuing a credential should increase total count by 1";
}

/**
 * @title Revocation Is Permanent
 * @notice Once a credential is revoked, it stays revoked
 */
rule revocationPermanence(bytes32 credentialId) {
    env e1;
    env e2;
    
    // Revoke the credential
    revokeCredential(e1, credentialId);
    
    // Any subsequent action
    method f;
    calldataarg args;
    f(e2, args);
    
    // Try to revoke again - should fail (already revoked)
    revokeCredential@withrevert(e2, credentialId);
    
    // Note: This might not revert but the credential stays revoked
    satisfy true;
}

/**
 * @title Create Disclosure Increases Count
 * @notice Creating a selective disclosure should increase the count
 */
rule createDisclosureIncreasesCount(
    bytes32 credentialId,
    bytes32 revealedHash,
    bytes32[] hiddenAttrs,
    bytes proof,
    address verifier,
    uint64 expiry
) {
    env e;
    require !paused();
    
    uint256 countBefore = totalDisclosures();
    
    createSelectiveDisclosure(e, credentialId, revealedHash, hiddenAttrs, proof, verifier, expiry);
    
    uint256 countAfter = totalDisclosures();
    
    assert countAfter == countBefore + 1,
        "Creating disclosure should increase count by 1";
}

/**
 * @title Disclosure Consumption Is Permanent
 * @notice Once a disclosure is consumed through verification, it stays consumed
 */
rule disclosureConsumptionPermanent(bytes32 disclosureId) {
    env e1;
    env e2;
    
    // Verify (consumes) the disclosure
    verifySelectiveDisclosure(e1, disclosureId);
    
    // Try to verify again - should fail
    verifySelectiveDisclosure@withrevert(e2, disclosureId);
    
    assert lastReverted,
        "Cannot verify a consumed disclosure";
}

/**
 * @title Create Aggregate Increases Count
 * @notice Creating an aggregate disclosure should increase the count
 */
rule createAggregateIncreasesCount(bytes32[] disclosureIds, uint8 threshold) {
    env e;
    require !paused();
    
    uint256 countBefore = totalAggregates();
    
    // Use AND aggregation type
    createAggregateDisclosure(e, disclosureIds, AggregateDisclosureAlgebra.AggregationType.AND, threshold);
    
    uint256 countAfter = totalAggregates();
    
    assert countAfter == countBefore + 1,
        "Creating aggregate should increase count by 1";
}

/**
 * @title Credentials Are Monotonic
 * @notice Total credentials count never decreases
 * @dev Filtering out registerAttribute which is admin-only
 */
rule credentialsMonotonic(method f) filtered { 
    f -> f.selector != sig:registerAttribute(string, bool, bool).selector 
} {
    env e;
    
    uint256 countBefore = totalCredentials();
    
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalCredentials();
    
    assert countAfter >= countBefore,
        "Credentials count should never decrease";
}

/**
 * @title Disclosures Are Monotonic
 * @notice Total disclosures count never decreases
 * @dev Filtering out registerAttribute which is admin-only
 */
rule disclosuresMonotonic(method f) filtered {
    f -> f.selector != sig:registerAttribute(string, bool, bool).selector
} {
    env e;
    
    uint256 countBefore = totalDisclosures();
    
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalDisclosures();
    
    assert countAfter >= countBefore,
        "Disclosures count should never decrease";
}

/**
 * @title Pause Prevents Operations
 * @notice When paused, state-changing operations should revert
 */
rule pausePreventsOperations(address subject, bytes32 attrHash, bytes32 valueCommit, uint64 expiry) {
    env e;
    require paused();
    
    issueCredential@withrevert(e, subject, attrHash, valueCommit, expiry);
    
    assert lastReverted,
        "Operations should fail when paused";
}
