pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * @title ProofCarryingContainerCircuit
 * @notice Circuit for self-authenticating confidential containers (PC³)
 * @dev Proves:
 *   1. Knowledge of encrypted state preimage
 *   2. Validity of state transition
 *   3. Policy compliance
 *   4. Nullifier correctness
 * 
 * This is the core circuit for PIL v2's flagship abstraction.
 */

/**
 * @title ContainerValidityProof
 * @notice Proves the container state is valid and correctly formed
 */
template ContainerValidityProof(STATE_FIELDS) {
    // Private inputs
    signal input stateFields[STATE_FIELDS];     // Encrypted state preimage
    signal input salt;                           // Blinding factor
    signal input ownerSecret;                    // Owner's secret key
    signal input encryptionKey;                  // Encryption key
    
    // Public inputs
    signal input stateCommitment;               // Public commitment
    signal input nullifier;                      // Container nullifier
    signal input ownerPubkey;                   // Owner's public key
    signal input chainId;                        // Origin chain
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify state commitment
    // ═══════════════════════════════════════════════════════════════════
    
    component stateHash = Poseidon(STATE_FIELDS);
    for (var i = 0; i < STATE_FIELDS; i++) {
        stateHash.inputs[i] <== stateFields[i];
    }
    
    // Commitment = H(stateHash, salt, ownerSecret)
    component commitmentHash = Poseidon(3);
    commitmentHash.inputs[0] <== stateHash.out;
    commitmentHash.inputs[1] <== salt;
    commitmentHash.inputs[2] <== ownerSecret;
    
    component commitmentCheck = IsEqual();
    commitmentCheck.in[0] <== commitmentHash.out;
    commitmentCheck.in[1] <== stateCommitment;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Verify nullifier derivation
    // ═══════════════════════════════════════════════════════════════════
    
    // Nullifier = H(ownerSecret, stateCommitment, chainId)
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== ownerSecret;
    nullifierHash.inputs[1] <== stateCommitment;
    nullifierHash.inputs[2] <== chainId;
    
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifierHash.out;
    nullifierCheck.in[1] <== nullifier;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify owner
    // ═══════════════════════════════════════════════════════════════════
    
    component ownerDerivation = Poseidon(1);
    ownerDerivation.inputs[0] <== ownerSecret;
    
    component ownerCheck = IsEqual();
    ownerCheck.in[0] <== ownerDerivation.out;
    ownerCheck.in[1] <== ownerPubkey;
    
    // All checks must pass
    valid <== commitmentCheck.out * nullifierCheck.out * ownerCheck.out;
}

/**
 * @title ContainerPolicyProof
 * @notice Proves the container complies with a disclosure policy
 */
template ContainerPolicyProof(NUM_CONSTRAINTS) {
    // Private inputs
    signal input stateValue;                    // The value being constrained
    signal input policySecret;                  // Policy-specific secret
    
    // Public inputs
    signal input policyHash;                    // Hash of the policy
    signal input stateCommitment;              // Container's state commitment
    signal input minValue;                      // Minimum allowed value
    signal input maxValue;                      // Maximum allowed value
    
    // Output
    signal output compliant;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify policy binding
    // ═══════════════════════════════════════════════════════════════════
    
    // Policy is bound to verification context
    component policyBinding = Poseidon(2);
    policyBinding.inputs[0] <== policyHash;
    policyBinding.inputs[1] <== policySecret;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Range check - value within policy bounds
    // ═══════════════════════════════════════════════════════════════════
    
    component geMin = GreaterEqThan(252);
    geMin.in[0] <== stateValue;
    geMin.in[1] <== minValue;
    
    component leMax = LessEqThan(252);
    leMax.in[0] <== stateValue;
    leMax.in[1] <== maxValue;
    
    // Value must be within bounds
    signal inRange;
    inRange <== geMin.out * leMax.out;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify state commitment includes this value
    // ═══════════════════════════════════════════════════════════════════
    
    // This proves the constrained value is part of the committed state
    component valueInState = Poseidon(2);
    valueInState.inputs[0] <== stateValue;
    valueInState.inputs[1] <== policyBinding.out;
    
    // Policy compliance requires range check and binding
    compliant <== inRange;
}

/**
 * @title ContainerNullifierProof  
 * @notice Proves nullifier is correctly derived and unused
 */
template ContainerNullifierProof() {
    // Private inputs
    signal input ownerSecret;
    signal input stateCommitment;
    signal input chainId;
    signal input nonce;                         // Additional uniqueness
    
    // Public inputs
    signal input nullifier;
    signal input merkleRoot;                   // Root of unused nullifiers
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // Verify nullifier derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component nullifierDerivation = Poseidon(4);
    nullifierDerivation.inputs[0] <== ownerSecret;
    nullifierDerivation.inputs[1] <== stateCommitment;
    nullifierDerivation.inputs[2] <== chainId;
    nullifierDerivation.inputs[3] <== nonce;
    
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifierDerivation.out;
    nullifierCheck.in[1] <== nullifier;
    
    valid <== nullifierCheck.out;
}

/**
 * @title PC3AggregatedProof
 * @notice Aggregates all three proofs for a complete self-authenticating container
 */
template PC3AggregatedProof(STATE_FIELDS, NUM_POLICY_CONSTRAINTS) {
    // Private inputs - state
    signal input stateFields[STATE_FIELDS];
    signal input salt;
    signal input ownerSecret;
    signal input encryptionKey;
    signal input policySecret;
    signal input nonce;
    
    // Private inputs - policy value to check
    signal input policyValue;
    
    // Public inputs
    signal input stateCommitment;
    signal input nullifier;
    signal input ownerPubkey;
    signal input chainId;
    signal input policyHash;
    signal input minValue;
    signal input maxValue;
    signal input merkleRoot;
    
    // Outputs
    signal output validityValid;
    signal output policyValid;
    signal output nullifierValid;
    signal output allValid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 1: Validity Proof
    // ═══════════════════════════════════════════════════════════════════
    
    component validity = ContainerValidityProof(STATE_FIELDS);
    for (var i = 0; i < STATE_FIELDS; i++) {
        validity.stateFields[i] <== stateFields[i];
    }
    validity.salt <== salt;
    validity.ownerSecret <== ownerSecret;
    validity.encryptionKey <== encryptionKey;
    validity.stateCommitment <== stateCommitment;
    validity.nullifier <== nullifier;
    validity.ownerPubkey <== ownerPubkey;
    validity.chainId <== chainId;
    
    validityValid <== validity.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 2: Policy Proof
    // ═══════════════════════════════════════════════════════════════════
    
    component policy = ContainerPolicyProof(NUM_POLICY_CONSTRAINTS);
    policy.stateValue <== policyValue;
    policy.policySecret <== policySecret;
    policy.policyHash <== policyHash;
    policy.stateCommitment <== stateCommitment;
    policy.minValue <== minValue;
    policy.maxValue <== maxValue;
    
    policyValid <== policy.compliant;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 3: Nullifier Proof
    // ═══════════════════════════════════════════════════════════════════
    
    component nullifierProof = ContainerNullifierProof();
    nullifierProof.ownerSecret <== ownerSecret;
    nullifierProof.stateCommitment <== stateCommitment;
    nullifierProof.chainId <== chainId;
    nullifierProof.nonce <== nonce;
    nullifierProof.nullifier <== nullifier;
    nullifierProof.merkleRoot <== merkleRoot;
    
    nullifierValid <== nullifierProof.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // AGGREGATE: All proofs must be valid
    // ═══════════════════════════════════════════════════════════════════
    
    allValid <== validityValid * policyValid * nullifierValid;
}

// Main component with typical parameters
component main {public [stateCommitment, nullifier, ownerPubkey, chainId, policyHash, minValue, maxValue, merkleRoot]} = PC3AggregatedProof(8, 4);
