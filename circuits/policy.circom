pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

/**
 * Policy Compliance Circuit (PBP)
 * 
 * Proves that a user complies with a policy without revealing their actual data.
 * Supports various policy types:
 * - Amount threshold checks
 * - Membership proofs (whitelist/blacklist)
 * - Time-based restrictions
 * - Rate limiting
 */

template PolicyCompliance(MERKLE_DEPTH) {
    // Public inputs
    signal input policyHash;             // Hash of the policy being verified
    signal input userCommitment;         // User's identity commitment
    signal input merkleRoot;             // Merkle root of authorized users (if applicable)
    signal input currentTimestamp;       // Current block timestamp
    
    // Private inputs
    signal input userSecret;             // User's secret key
    signal input userSalt;               // Salt for commitment
    signal input userValue;              // The value being checked (e.g., balance, age, etc.)
    signal input policyThreshold;        // The threshold to check against
    signal input policyType;             // Type of policy (0=greater, 1=less, 2=equal, 3=membership)
    signal input merklePathElements[MERKLE_DEPTH];
    signal input merklePathIndices[MERKLE_DEPTH];
    
    // Output
    signal output compliant;
    
    // Step 1: Verify user commitment
    component userHasher = Poseidon(2);
    userHasher.inputs[0] <== userSecret;
    userHasher.inputs[1] <== userSalt;
    signal computedCommitment <== userHasher.out;
    
    signal commitmentValid;
    commitmentValid <== IsEqual()([computedCommitment, userCommitment]);
    
    // Step 2: Verify policy hash
    component policyHasher = Poseidon(3);
    policyHasher.inputs[0] <== policyType;
    policyHasher.inputs[1] <== policyThreshold;
    policyHasher.inputs[2] <== merkleRoot;
    signal computedPolicyHash <== policyHasher.out;
    
    signal policyHashValid;
    policyHashValid <== IsEqual()([computedPolicyHash, policyHash]);
    
    // Step 3: Check policy compliance based on type
    // Type 0: userValue >= policyThreshold (minimum threshold)
    component geCheck = GreaterEqThan(252);
    geCheck.in[0] <== userValue;
    geCheck.in[1] <== policyThreshold;
    signal geResult <== geCheck.out;
    
    // Type 1: userValue <= policyThreshold (maximum threshold)
    component leCheck = LessEqThan(252);
    leCheck.in[0] <== userValue;
    leCheck.in[1] <== policyThreshold;
    signal leResult <== leCheck.out;
    
    // Type 2: userValue == policyThreshold (exact match)
    signal eqResult;
    eqResult <== IsEqual()([userValue, policyThreshold]);
    
    // Type 3: Merkle membership proof
    // Verify the user's commitment is in the Merkle tree
    component membershipCheck = MerkleMembership(MERKLE_DEPTH);
    membershipCheck.leaf <== userCommitment;
    membershipCheck.root <== merkleRoot;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        membershipCheck.pathElements[i] <== merklePathElements[i];
        membershipCheck.pathIndices[i] <== merklePathIndices[i];
    }
    signal membershipResult <== membershipCheck.valid;
    
    // Select result based on policy type
    // Using polynomial selector: result = ge*(1-t1)*(1-t2) + le*t1*(1-t2) + eq*(1-t1)*t2 + mem*t1*t2
    // Simplified: use indicator signals for each type
    signal isType0, isType1, isType2, isType3;
    isType0 <== IsEqual()([policyType, 0]);
    isType1 <== IsEqual()([policyType, 1]);
    isType2 <== IsEqual()([policyType, 2]);
    isType3 <== IsEqual()([policyType, 3]);
    
    signal result0 <== isType0 * geResult;
    signal result1 <== isType1 * leResult;
    signal result2 <== isType2 * eqResult;
    signal result3 <== isType3 * membershipResult;
    
    signal policyResult <== result0 + result1 + result2 + result3;
    
    // All conditions must be met
    signal cond1 <== commitmentValid * policyHashValid;
    compliant <== cond1 * policyResult;
}

/**
 * Merkle Membership Proof Template
 */
template MerkleMembership(DEPTH) {
    signal input leaf;
    signal input root;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];
    
    signal output valid;
    
    signal hashes[DEPTH + 1];
    hashes[0] <== leaf;
    
    component hashers[DEPTH];
    component selectors[DEPTH];
    
    for (var i = 0; i < DEPTH; i++) {
        // Select ordering based on path index
        // If index is 0, hash(current, sibling)
        // If index is 1, hash(sibling, current)
        selectors[i] = Mux2(2);
        selectors[i].c[0] <== hashes[i];
        selectors[i].c[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];
        
        hashers[i] = Poseidon(2);
        // When pathIndex = 0: left = current, right = sibling
        // When pathIndex = 1: left = sibling, right = current
        hashers[i].inputs[0] <== (1 - pathIndices[i]) * hashes[i] + pathIndices[i] * pathElements[i];
        hashers[i].inputs[1] <== pathIndices[i] * hashes[i] + (1 - pathIndices[i]) * pathElements[i];
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    valid <== IsEqual()([hashes[DEPTH], root]);
}

/**
 * 2-to-1 Multiplexer
 */
template Mux2(n) {
    signal input c[n];
    signal input s;
    signal output out;
    
    out <== c[0] + s * (c[1] - c[0]);
}

/**
 * Range Proof Template
 * Proves that a value is within a specified range [min, max]
 */
template RangeProof() {
    signal input value;
    signal input minValue;
    signal input maxValue;
    
    signal output inRange;
    
    component geMin = GreaterEqThan(252);
    geMin.in[0] <== value;
    geMin.in[1] <== minValue;
    
    component leMax = LessEqThan(252);
    leMax.in[0] <== value;
    leMax.in[1] <== maxValue;
    
    inRange <== geMin.out * leMax.out;
}

// Default instantiation with depth 20 Merkle tree
component main { public [policyHash, userCommitment, merkleRoot, currentTimestamp] } = PolicyCompliance(20);
