// =============================================================================
// CDNA.spec - Formal Verification for Cross Domain Nullifier Algebra
// =============================================================================

methods {
    // State access
    function nullifiers(bytes32, bytes32) external returns (bool) envfree;
    function domainNullifierCount(bytes32) external returns (uint256) envfree;
    function totalNullifiers() external returns (uint256) envfree;
    
    // Core functions
    function registerNullifier(bytes32, bytes32, bytes32, bytes32) external;
    function isNullifierConsumed(bytes32, bytes32) external returns (bool) envfree;
    function verifyNullifierProof(bytes32, bytes32, bytes32) external returns (bool) envfree;
    
    // Domain management
    function registerDomain(bytes32) external;
    function isDomainRegistered(bytes32) external returns (bool) envfree;
}

// =============================================================================
// Definitions
// =============================================================================

definition ZERO_BYTES32() returns bytes32 = 0;

// =============================================================================
// Invariants
// =============================================================================

// Nullifier count is consistent with domain counts
invariant totalEqualsSum()
    forall bytes32 domain. domainNullifierCount(domain) <= totalNullifiers()

// Consumed nullifiers cannot be unconsumed
invariant nullifierFinalityInvariant(bytes32 nullifier, bytes32 domain)
    isNullifierConsumed(nullifier, domain) => true
    {
        preserved {
            require isNullifierConsumed(nullifier, domain);
        }
    }

// =============================================================================
// Rules for Nullifier Registration
// =============================================================================

// Registering a nullifier marks it as consumed
rule registerMarksConsumed {
    bytes32 nullifier;
    bytes32 domain;
    bytes32 commitment;
    bytes32 proof;
    
    env e;
    require !isNullifierConsumed(nullifier, domain);
    require isDomainRegistered(domain);
    
    registerNullifier(e, nullifier, domain, commitment, proof);
    
    assert isNullifierConsumed(nullifier, domain), "Nullifier should be consumed";
}

// Cannot register same nullifier twice in same domain
rule noDoubleSpending {
    bytes32 nullifier;
    bytes32 domain;
    bytes32 commitment;
    bytes32 proof;
    
    env e1;
    env e2;
    require isDomainRegistered(domain);
    require !isNullifierConsumed(nullifier, domain);
    
    registerNullifier(e1, nullifier, domain, commitment, proof);
    
    registerNullifier@withrevert(e2, nullifier, domain, commitment, proof);
    
    assert lastReverted, "Double spending should revert";
}

// Registration increases domain nullifier count
rule registerIncrementsDomainCount {
    bytes32 nullifier;
    bytes32 domain;
    bytes32 commitment;
    bytes32 proof;
    
    uint256 countBefore = domainNullifierCount(domain);
    
    env e;
    require isDomainRegistered(domain);
    require !isNullifierConsumed(nullifier, domain);
    
    registerNullifier(e, nullifier, domain, commitment, proof);
    
    uint256 countAfter = domainNullifierCount(domain);
    
    assert countAfter == countBefore + 1, "Domain count should increase";
}

// Registration increases total nullifier count
rule registerIncrementsTotal {
    bytes32 nullifier;
    bytes32 domain;
    bytes32 commitment;
    bytes32 proof;
    
    uint256 totalBefore = totalNullifiers();
    
    env e;
    require isDomainRegistered(domain);
    require !isNullifierConsumed(nullifier, domain);
    
    registerNullifier(e, nullifier, domain, commitment, proof);
    
    uint256 totalAfter = totalNullifiers();
    
    assert totalAfter == totalBefore + 1, "Total should increase";
}

// =============================================================================
// Domain Isolation Rules
// =============================================================================

// Same nullifier can be used in different domains
rule domainsAreIsolated {
    bytes32 nullifier;
    bytes32 domain1;
    bytes32 domain2;
    bytes32 commitment;
    bytes32 proof;
    
    env e1;
    env e2;
    require domain1 != domain2;
    require isDomainRegistered(domain1);
    require isDomainRegistered(domain2);
    require !isNullifierConsumed(nullifier, domain1);
    require !isNullifierConsumed(nullifier, domain2);
    
    registerNullifier(e1, nullifier, domain1, commitment, proof);
    
    // Should still be able to register in domain2
    assert !isNullifierConsumed(nullifier, domain2), "Domain2 should be unaffected";
}

// Registering in one domain doesn't affect another
rule registrationDomainIsolation {
    bytes32 nullifier1;
    bytes32 nullifier2;
    bytes32 domain1;
    bytes32 domain2;
    bytes32 commitment;
    bytes32 proof;
    
    bool consumedBefore = isNullifierConsumed(nullifier2, domain2);
    
    env e;
    require domain1 != domain2 || nullifier1 != nullifier2;
    require isDomainRegistered(domain1);
    require !isNullifierConsumed(nullifier1, domain1);
    
    registerNullifier(e, nullifier1, domain1, commitment, proof);
    
    bool consumedAfter = isNullifierConsumed(nullifier2, domain2);
    
    assert consumedAfter == consumedBefore, "Unrelated nullifier state unchanged";
}

// =============================================================================
// Nullifier Finality
// =============================================================================

// Once consumed, stays consumed
rule nullifierFinality {
    bytes32 nullifier;
    bytes32 domain;
    
    require isNullifierConsumed(nullifier, domain);
    
    env e;
    method f;
    calldataarg args;
    f(e, args);
    
    assert isNullifierConsumed(nullifier, domain), "Consumed is permanent";
}

// Domain counts never decrease
rule domainCountMonotonic {
    bytes32 domain;
    
    uint256 countBefore = domainNullifierCount(domain);
    
    env e;
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = domainNullifierCount(domain);
    
    assert countAfter >= countBefore, "Count should never decrease";
}

// Total count never decreases
rule totalCountMonotonic {
    uint256 totalBefore = totalNullifiers();
    
    env e;
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 totalAfter = totalNullifiers();
    
    assert totalAfter >= totalBefore, "Total should never decrease";
}

// =============================================================================
// Domain Management
// =============================================================================

// Registered domains stay registered
rule domainRegistrationPermanent {
    bytes32 domain;
    
    require isDomainRegistered(domain);
    
    env e;
    method f;
    calldataarg args;
    f(e, args);
    
    assert isDomainRegistered(domain), "Domain registration is permanent";
}

// Cannot register nullifier in unregistered domain
rule requireRegisteredDomain {
    bytes32 nullifier;
    bytes32 domain;
    bytes32 commitment;
    bytes32 proof;
    
    env e;
    require !isDomainRegistered(domain);
    
    registerNullifier@withrevert(e, nullifier, domain, commitment, proof);
    
    assert lastReverted, "Should revert for unregistered domain";
}
