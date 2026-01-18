pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

/**
 * Cross-Domain Nullifier Circuit (CDNA)
 * 
 * Proves that a nullifier is correctly derived and hasn't been consumed,
 * enabling cross-domain double-spend prevention.
 * 
 * The nullifier scheme uses:
 * - A secret known only to the user
 * - A domain identifier for cross-chain uniqueness
 * - A nonce for fresh nullifier generation
 */

template NullifierDerivation() {
    // Public inputs
    signal input nullifierHash;          // The public nullifier hash
    signal input domainId;               // Domain/chain identifier
    signal input commitmentRoot;         // Merkle root of valid commitments
    
    // Private inputs
    signal input secret;                 // User's secret key
    signal input nonce;                  // Unique nonce for this nullifier
    signal input commitment;             // The commitment being nullified
    signal input commitmentSalt;         // Salt used in commitment
    signal input assetId;                // Asset identifier
    signal input amount;                 // Amount in the commitment
    
    // Output
    signal output valid;
    
    // Step 1: Verify the commitment is correctly formed
    component commitmentHasher = Poseidon(4);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== assetId;
    commitmentHasher.inputs[2] <== amount;
    commitmentHasher.inputs[3] <== commitmentSalt;
    signal computedCommitment <== commitmentHasher.out;
    
    signal commitmentValid;
    commitmentValid <== IsEqual()([computedCommitment, commitment]);
    
    // Step 2: Derive the nullifier
    // nullifier = Poseidon(secret, commitment, domainId, nonce)
    component nullifierHasher = Poseidon(4);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== commitment;
    nullifierHasher.inputs[2] <== domainId;
    nullifierHasher.inputs[3] <== nonce;
    signal computedNullifier <== nullifierHasher.out;
    
    signal nullifierValid;
    nullifierValid <== IsEqual()([computedNullifier, nullifierHash]);
    
    // Both conditions must be met
    valid <== commitmentValid * nullifierValid;
}

/**
 * Cross-Domain Nullifier with Merkle Membership
 * 
 * Extended version that also proves the commitment exists in a Merkle tree.
 */
template NullifierWithMembership(MERKLE_DEPTH) {
    // Public inputs
    signal input nullifierHash;          // The public nullifier hash
    signal input domainId;               // Domain/chain identifier
    signal input commitmentRoot;         // Merkle root of valid commitments
    signal input timestamp;              // Current timestamp for freshness
    
    // Private inputs
    signal input secret;                 // User's secret key
    signal input nonce;                  // Unique nonce for this nullifier
    signal input commitment;             // The commitment being nullified
    signal input commitmentSalt;         // Salt used in commitment
    signal input assetId;                // Asset identifier
    signal input amount;                 // Amount in the commitment
    signal input merklePathElements[MERKLE_DEPTH];
    signal input merklePathIndices[MERKLE_DEPTH];
    signal input expiryTime;             // Nullifier expiry time
    
    // Output
    signal output valid;
    
    // Step 1: Verify the commitment is correctly formed
    component commitmentHasher = Poseidon(4);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== assetId;
    commitmentHasher.inputs[2] <== amount;
    commitmentHasher.inputs[3] <== commitmentSalt;
    signal computedCommitment <== commitmentHasher.out;
    
    signal commitmentValid;
    commitmentValid <== IsEqual()([computedCommitment, commitment]);
    
    // Step 2: Prove commitment is in the Merkle tree
    signal hashes[MERKLE_DEPTH + 1];
    hashes[0] <== commitment;
    
    component hashers[MERKLE_DEPTH];
    
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        hashers[i] = Poseidon(2);
        // When pathIndex = 0: left = current, right = sibling
        // When pathIndex = 1: left = sibling, right = current
        hashers[i].inputs[0] <== (1 - merklePathIndices[i]) * hashes[i] + merklePathIndices[i] * merklePathElements[i];
        hashers[i].inputs[1] <== merklePathIndices[i] * hashes[i] + (1 - merklePathIndices[i]) * merklePathElements[i];
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    signal merkleValid;
    merkleValid <== IsEqual()([hashes[MERKLE_DEPTH], commitmentRoot]);
    
    // Step 3: Derive the nullifier
    component nullifierHasher = Poseidon(4);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== commitment;
    nullifierHasher.inputs[2] <== domainId;
    nullifierHasher.inputs[3] <== nonce;
    signal computedNullifier <== nullifierHasher.out;
    
    signal nullifierValid;
    nullifierValid <== IsEqual()([computedNullifier, nullifierHash]);
    
    // Step 4: Check nullifier hasn't expired
    component expiryCheck = LessThan(64);
    expiryCheck.in[0] <== timestamp;
    expiryCheck.in[1] <== expiryTime;
    signal notExpired <== expiryCheck.out;
    
    // All conditions must be met
    signal cond1 <== commitmentValid * merkleValid;
    signal cond2 <== cond1 * nullifierValid;
    valid <== cond2 * notExpired;
}

/**
 * Batch Nullifier Verification
 * 
 * Efficiently verifies multiple nullifiers in a single proof.
 */
template BatchNullifierVerification(BATCH_SIZE) {
    // Public inputs
    signal input nullifierHashes[BATCH_SIZE];
    signal input domainId;
    signal input batchRoot;              // Root of batch Merkle tree
    
    // Private inputs
    signal input secrets[BATCH_SIZE];
    signal input nonces[BATCH_SIZE];
    signal input commitments[BATCH_SIZE];
    
    // Output
    signal output allValid;
    
    component nullifierDerivations[BATCH_SIZE];
    signal validations[BATCH_SIZE];
    
    for (var i = 0; i < BATCH_SIZE; i++) {
        nullifierDerivations[i] = NullifierDerivationSimple();
        nullifierDerivations[i].secret <== secrets[i];
        nullifierDerivations[i].commitment <== commitments[i];
        nullifierDerivations[i].domainId <== domainId;
        nullifierDerivations[i].nonce <== nonces[i];
        nullifierDerivations[i].expectedHash <== nullifierHashes[i];
        
        validations[i] <== nullifierDerivations[i].valid;
    }
    
    // Aggregate all validations
    signal runningProduct[BATCH_SIZE];
    runningProduct[0] <== validations[0];
    for (var i = 1; i < BATCH_SIZE; i++) {
        runningProduct[i] <== runningProduct[i-1] * validations[i];
    }
    
    allValid <== runningProduct[BATCH_SIZE - 1];
}

/**
 * Simple nullifier derivation (helper template)
 */
template NullifierDerivationSimple() {
    signal input secret;
    signal input commitment;
    signal input domainId;
    signal input nonce;
    signal input expectedHash;
    
    signal output valid;
    
    component hasher = Poseidon(4);
    hasher.inputs[0] <== secret;
    hasher.inputs[1] <== commitment;
    hasher.inputs[2] <== domainId;
    hasher.inputs[3] <== nonce;
    
    valid <== IsEqual()([hasher.out, expectedHash]);
}

// Default instantiation
component main { public [nullifierHash, domainId, commitmentRoot] } = NullifierDerivation();
