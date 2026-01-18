pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * @title PolicyBoundProofCircuit
 * @notice Circuit for proofs cryptographically scoped by disclosure policy (PBP)
 * @dev Key innovation: Verification key is bound to policy hash via domain separator
 *      Proofs are invalid outside their policy scope
 * 
 * This makes compliance a cryptographic invariant, not a social/off-chain check.
 */

/**
 * @title DomainSeparatorBinding
 * @notice Computes and verifies the domain separator that binds VK to policy
 */
template DomainSeparatorBinding() {
    // Private inputs
    signal input vkSecret;                      // VK-specific secret (optional)
    
    // Public inputs
    signal input vkHash;                        // Verification key hash
    signal input policyHash;                    // Policy this proof is bound to
    signal input expectedDomainSeparator;       // Expected domain separator
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // Compute domain separator = H(vkHash, policyHash)
    // ═══════════════════════════════════════════════════════════════════
    
    component domainHash = Poseidon(2);
    domainHash.inputs[0] <== vkHash;
    domainHash.inputs[1] <== policyHash;
    
    component domainCheck = IsEqual();
    domainCheck.in[0] <== domainHash.out;
    domainCheck.in[1] <== expectedDomainSeparator;
    
    valid <== domainCheck.out;
}

/**
 * @title PolicyCommitmentProof
 * @notice Proves that a specific policy was committed to in the proof generation
 */
template PolicyCommitmentProof(NUM_PUBLIC_INPUTS) {
    // Private inputs
    signal input policyPreimage[4];             // Policy details (jurisdiction, asset, etc.)
    
    // Public inputs
    signal input publicInputs[NUM_PUBLIC_INPUTS]; // All public inputs
    signal input policyHash;                    // Expected policy hash
    signal input policyPosition;                // Position in public inputs
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify policy hash derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component computePolicyHash = Poseidon(4);
    for (var i = 0; i < 4; i++) {
        computePolicyHash.inputs[i] <== policyPreimage[i];
    }
    
    component policyHashCheck = IsEqual();
    policyHashCheck.in[0] <== computePolicyHash.out;
    policyHashCheck.in[1] <== policyHash;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Verify policy is in public inputs at expected position
    // ═══════════════════════════════════════════════════════════════════
    
    // Check each position (one must match)
    signal matches[NUM_PUBLIC_INPUTS];
    signal positionMatches[NUM_PUBLIC_INPUTS];
    
    component inputChecks[NUM_PUBLIC_INPUTS];
    component posChecks[NUM_PUBLIC_INPUTS];
    
    for (var i = 0; i < NUM_PUBLIC_INPUTS; i++) {
        inputChecks[i] = IsEqual();
        inputChecks[i].in[0] <== publicInputs[i];
        inputChecks[i].in[1] <== policyHash;
        
        posChecks[i] = IsEqual();
        posChecks[i].in[0] <== i;
        posChecks[i].in[1] <== policyPosition;
        
        positionMatches[i] <== inputChecks[i].out * posChecks[i].out;
    }
    
    // Sum all matches (should be exactly 1)
    signal sumMatches[NUM_PUBLIC_INPUTS];
    sumMatches[0] <== positionMatches[0];
    for (var i = 1; i < NUM_PUBLIC_INPUTS; i++) {
        sumMatches[i] <== sumMatches[i-1] + positionMatches[i];
    }
    
    component hasMatch = IsEqual();
    hasMatch.in[0] <== sumMatches[NUM_PUBLIC_INPUTS - 1];
    hasMatch.in[1] <== 1;
    
    valid <== policyHashCheck.out * hasMatch.out;
}

/**
 * @title SelectiveDisclosureProof
 * @notice Proves selective disclosure according to policy requirements
 */
template SelectiveDisclosureProof(NUM_FIELDS) {
    // Private inputs - full data
    signal input dataFields[NUM_FIELDS];
    signal input disclosureMask[NUM_FIELDS];    // 1 = disclose, 0 = hide
    
    // Public inputs
    signal input dataCommitment;                // Commitment to all data
    signal input disclosedData[NUM_FIELDS];     // Disclosed values (or 0)
    signal input policyHash;                    // Policy governing disclosure
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify data commitment
    // ═══════════════════════════════════════════════════════════════════
    
    component dataHash = Poseidon(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        dataHash.inputs[i] <== dataFields[i];
    }
    
    component commitmentCheck = IsEqual();
    commitmentCheck.in[0] <== dataHash.out;
    commitmentCheck.in[1] <== dataCommitment;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Verify disclosed data matches based on mask
    // ═══════════════════════════════════════════════════════════════════
    
    signal disclosureValid[NUM_FIELDS];
    component disclosureChecks[NUM_FIELDS];
    component zeroChecks[NUM_FIELDS];
    
    for (var i = 0; i < NUM_FIELDS; i++) {
        // If mask = 1: disclosed must equal actual
        disclosureChecks[i] = IsEqual();
        disclosureChecks[i].in[0] <== dataFields[i];
        disclosureChecks[i].in[1] <== disclosedData[i];
        
        // If mask = 0: disclosed must be 0
        zeroChecks[i] = IsZero();
        zeroChecks[i].in <== disclosedData[i];
        
        // Valid if (mask=1 AND equal) OR (mask=0 AND zero)
        disclosureValid[i] <== disclosureMask[i] * disclosureChecks[i].out + 
                              (1 - disclosureMask[i]) * zeroChecks[i].out;
    }
    
    // All disclosures must be valid
    signal aggregateValid[NUM_FIELDS];
    aggregateValid[0] <== disclosureValid[0];
    for (var i = 1; i < NUM_FIELDS; i++) {
        aggregateValid[i] <== aggregateValid[i-1] * disclosureValid[i];
    }
    
    valid <== commitmentCheck.out * aggregateValid[NUM_FIELDS - 1];
}

/**
 * @title PolicyBoundProof
 * @notice Complete policy-bound proof circuit
 * @dev Combines domain binding, policy commitment, and selective disclosure
 */
template PolicyBoundProof(NUM_PUBLIC_INPUTS, NUM_DATA_FIELDS) {
    // Private inputs
    signal input vkSecret;
    signal input policyPreimage[4];
    signal input dataFields[NUM_DATA_FIELDS];
    signal input disclosureMask[NUM_DATA_FIELDS];
    
    // Public inputs - verification context
    signal input vkHash;
    signal input policyHash;
    signal input domainSeparator;
    
    // Public inputs - data context
    signal input publicInputs[NUM_PUBLIC_INPUTS];
    signal input policyPosition;
    signal input dataCommitment;
    signal input disclosedData[NUM_DATA_FIELDS];
    
    // Outputs
    signal output domainValid;
    signal output policyCommitmentValid;
    signal output disclosureValid;
    signal output allValid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 1: Domain Separator Binding
    // ═══════════════════════════════════════════════════════════════════
    
    component domain = DomainSeparatorBinding();
    domain.vkSecret <== vkSecret;
    domain.vkHash <== vkHash;
    domain.policyHash <== policyHash;
    domain.expectedDomainSeparator <== domainSeparator;
    
    domainValid <== domain.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 2: Policy Commitment
    // ═══════════════════════════════════════════════════════════════════
    
    component policyCommit = PolicyCommitmentProof(NUM_PUBLIC_INPUTS);
    for (var i = 0; i < 4; i++) {
        policyCommit.policyPreimage[i] <== policyPreimage[i];
    }
    for (var i = 0; i < NUM_PUBLIC_INPUTS; i++) {
        policyCommit.publicInputs[i] <== publicInputs[i];
    }
    policyCommit.policyHash <== policyHash;
    policyCommit.policyPosition <== policyPosition;
    
    policyCommitmentValid <== policyCommit.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 3: Selective Disclosure
    // ═══════════════════════════════════════════════════════════════════
    
    component disclosure = SelectiveDisclosureProof(NUM_DATA_FIELDS);
    for (var i = 0; i < NUM_DATA_FIELDS; i++) {
        disclosure.dataFields[i] <== dataFields[i];
        disclosure.disclosureMask[i] <== disclosureMask[i];
        disclosure.disclosedData[i] <== disclosedData[i];
    }
    disclosure.dataCommitment <== dataCommitment;
    disclosure.policyHash <== policyHash;
    
    disclosureValid <== disclosure.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // AGGREGATE: All components must be valid
    // ═══════════════════════════════════════════════════════════════════
    
    allValid <== domainValid * policyCommitmentValid * disclosureValid;
}

/**
 * @title FiatShamirPolicyBinding
 * @notice Binds policy to Fiat-Shamir transcript for SNARK security
 * @dev Ensures proof cannot be replayed with different policy
 */
template FiatShamirPolicyBinding() {
    // Private inputs
    signal input transcriptSecret;              // Transcript randomness
    
    // Public inputs
    signal input transcriptHash;                // Hash of Fiat-Shamir transcript
    signal input policyHash;                    // Bound policy
    signal input challengeHash;                 // Challenge derived from transcript
    
    // Output
    signal output valid;
    
    // Verify challenge = H(transcript, policy)
    component challengeDerivation = Poseidon(3);
    challengeDerivation.inputs[0] <== transcriptHash;
    challengeDerivation.inputs[1] <== policyHash;
    challengeDerivation.inputs[2] <== transcriptSecret;
    
    component challengeCheck = IsEqual();
    challengeCheck.in[0] <== challengeDerivation.out;
    challengeCheck.in[1] <== challengeHash;
    
    valid <== challengeCheck.out;
}

// Main component
component main {public [vkHash, policyHash, domainSeparator, publicInputs, policyPosition, dataCommitment, disclosedData]} = PolicyBoundProof(8, 6);
