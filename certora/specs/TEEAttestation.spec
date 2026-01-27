/**
 * Certora Formal Verification Specification
 * Soul Protocol - TEEAttestation
 * 
 * This spec verifies critical invariants for the TEE Attestation contract
 * which enables remote attestation verification for trusted execution environments
 */

using TEEAttestation as tee;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalEnclaves() external returns (uint256) envfree;
    function totalAttestations() external returns (uint256) envfree;
    function attestationValidityPeriod() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function trustedSigners(bytes32) external returns (bool) envfree;
    function trustedEnclaves(bytes32) external returns (bool) envfree;
    function minIsvSvn(uint16) external returns (uint16) envfree;
    
    // Enclave registration - TEEPlatform is enum
    function registerEnclave(bytes32, bytes32, uint16, uint16, TEEAttestation.TEEPlatform) external returns (bytes32);
    function deregisterEnclave(bytes32) external;
    
    // Trust management
    function addTrustedSigner(bytes32) external;
    function removeTrustedSigner(bytes32) external;
    function addTrustedEnclave(bytes32) external;
    function removeTrustedEnclave(bytes32) external;
    function setMinIsvSvn(uint16, uint16) external;
    
    // Admin
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalEnclaves {
    init_state axiom ghostTotalEnclaves == 0;
}

ghost uint256 ghostTotalAttestations {
    init_state axiom ghostTotalAttestations == 0;
}

ghost mapping(bytes32 => bool) ghostEnclaveActive {
    init_state axiom forall bytes32 e. !ghostEnclaveActive[e];
}

// ============================================================================
// INVARIANTS - Removed, setAttestationValidityPeriod can change value
// ============================================================================

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Register Enclave Increases Count
 * @notice Registering an enclave should increase the total count
 */
rule registerEnclaveIncreasesCount(
    bytes32 mrenclave,
    bytes32 mrsigner,
    uint16 isvProdId,
    uint16 isvSvn
) {
    env e;
    require !paused();
    
    uint256 countBefore = totalEnclaves();
    
    // Use SGX_DCAP platform type
    registerEnclave(e, mrenclave, mrsigner, isvProdId, isvSvn, TEEAttestation.TEEPlatform.SGX_DCAP);
    
    uint256 countAfter = totalEnclaves();
    
    assert countAfter == countBefore + 1,
        "Registering enclave should increase count by 1";
}

/**
 * @title Trusted Signer Addition Is Effective
 * @notice Adding a trusted signer should mark it as trusted
 */
rule trustedSignerAdditionEffective(bytes32 mrsigner) {
    env e;
    require !trustedSigners(mrsigner);
    
    addTrustedSigner(e, mrsigner);
    
    bool trustedAfter = trustedSigners(mrsigner);
    
    assert trustedAfter == true,
        "Adding trusted signer should mark it as trusted";
}

/**
 * @title Trusted Signer Removal Is Effective
 * @notice Removing a trusted signer should mark it as untrusted
 */
rule trustedSignerRemovalEffective(bytes32 mrsigner) {
    env e;
    require trustedSigners(mrsigner);
    
    removeTrustedSigner(e, mrsigner);
    
    bool trustedAfter = trustedSigners(mrsigner);
    
    assert trustedAfter == false,
        "Removing trusted signer should mark it as untrusted";
}

/**
 * @title Trusted Enclave Addition Is Effective
 * @notice Adding a trusted enclave should mark it as trusted
 */
rule trustedEnclaveAdditionEffective(bytes32 mrenclave) {
    env e;
    require !trustedEnclaves(mrenclave);
    
    addTrustedEnclave(e, mrenclave);
    
    bool trustedAfter = trustedEnclaves(mrenclave);
    
    assert trustedAfter == true,
        "Adding trusted enclave should mark it as trusted";
}

/**
 * @title Trusted Enclave Removal Is Effective
 * @notice Removing a trusted enclave should mark it as untrusted
 */
rule trustedEnclaveRemovalEffective(bytes32 mrenclave) {
    env e;
    require trustedEnclaves(mrenclave);
    
    removeTrustedEnclave(e, mrenclave);
    
    bool trustedAfter = trustedEnclaves(mrenclave);
    
    assert trustedAfter == false,
        "Removing trusted enclave should mark it as untrusted";
}

/**
 * @title Min ISV SVN Is Set Correctly
 * @notice Setting min ISV SVN should update the value
 */
rule minIsvSvnSetCorrectly(uint16 prodId, uint16 svn) {
    env e;
    
    setMinIsvSvn(e, prodId, svn);
    
    uint16 svnAfter = minIsvSvn(prodId);
    
    assert svnAfter == svn,
        "Min ISV SVN should be set to the provided value";
}

/**
 * @title Enclaves Are Monotonic
 * @notice Total enclaves count never decreases (deregistration doesn't decrease count)
 */
rule enclavesMonotonic() {
    env e;
    
    uint256 countBefore = totalEnclaves();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalEnclaves();
    
    assert countAfter >= countBefore,
        "Enclaves count should never decrease";
}

/**
 * @title Attestations Are Monotonic
 * @notice Total attestations count never decreases
 */
rule attestationsMonotonic() {
    env e;
    
    uint256 countBefore = totalAttestations();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalAttestations();
    
    assert countAfter >= countBefore,
        "Attestations count should never decrease";
}
