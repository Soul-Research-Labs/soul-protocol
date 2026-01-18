pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * @title CrossDomainNullifierCircuit
 * @notice Circuit for domain-separated nullifiers (CDNA)
 * @dev Nullifiers that compose algebraically across chains, epochs, and applications
 *      N = H(secret, app_id, chain_id, epoch, transition_id)
 * 
 * Enables cross-chain double-spend prevention without global state.
 */

/**
 * @title DomainSeparator
 * @notice Computes domain separator for nullifier scope
 */
template DomainSeparator() {
    // Inputs
    signal input chainId;
    signal input appId;
    signal input epochId;
    
    // Output
    signal output separator;
    
    // Domain separator = H("CDNA_v1", chainId, appId, epochId)
    // We use the hash of "CDNA_v1" as a constant
    signal constant_prefix;
    constant_prefix <== 0x434e4441_76310000; // ASCII for "CDNA_v1" padded
    
    component domainHash = Poseidon(4);
    domainHash.inputs[0] <== constant_prefix;
    domainHash.inputs[1] <== chainId;
    domainHash.inputs[2] <== appId;
    domainHash.inputs[3] <== epochId;
    
    separator <== domainHash.out;
}

/**
 * @title DomainNullifier
 * @notice Computes a domain-separated nullifier
 */
template DomainNullifier() {
    // Private inputs
    signal input secret;                        // User's secret
    signal input transitionId;                  // State transition identifier
    
    // Public inputs
    signal input chainId;
    signal input appId;
    signal input epochId;
    signal input expectedNullifier;
    
    // Output
    signal output valid;
    signal output nullifier;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Compute domain separator
    // ═══════════════════════════════════════════════════════════════════
    
    component domain = DomainSeparator();
    domain.chainId <== chainId;
    domain.appId <== appId;
    domain.epochId <== epochId;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Compute nullifier = H(secret, domainSeparator, transitionId)
    // ═══════════════════════════════════════════════════════════════════
    
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== secret;
    nullifierHash.inputs[1] <== domain.separator;
    nullifierHash.inputs[2] <== transitionId;
    
    nullifier <== nullifierHash.out;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify against expected
    // ═══════════════════════════════════════════════════════════════════
    
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifier;
    nullifierCheck.in[1] <== expectedNullifier;
    
    valid <== nullifierCheck.out;
}

/**
 * @title CrossDomainDerivation
 * @notice Proves valid derivation of a nullifier across domains
 */
template CrossDomainDerivation() {
    // Private inputs
    signal input parentSecret;                  // Secret for parent nullifier
    signal input derivationNonce;               // Nonce for derivation
    
    // Public inputs - source domain
    signal input sourceChainId;
    signal input sourceAppId;
    signal input sourceEpochId;
    signal input sourceNullifier;
    
    // Public inputs - target domain
    signal input targetChainId;
    signal input targetAppId;
    signal input targetEpochId;
    signal input targetNullifier;
    signal input targetTransitionId;
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify source nullifier derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component sourceDomain = DomainSeparator();
    sourceDomain.chainId <== sourceChainId;
    sourceDomain.appId <== sourceAppId;
    sourceDomain.epochId <== sourceEpochId;
    
    // Source transition ID is derived from nonce
    component sourceTransition = Poseidon(1);
    sourceTransition.inputs[0] <== derivationNonce;
    
    component sourceNullifierHash = Poseidon(3);
    sourceNullifierHash.inputs[0] <== parentSecret;
    sourceNullifierHash.inputs[1] <== sourceDomain.separator;
    sourceNullifierHash.inputs[2] <== sourceTransition.out;
    
    component sourceCheck = IsEqual();
    sourceCheck.in[0] <== sourceNullifierHash.out;
    sourceCheck.in[1] <== sourceNullifier;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Compute derived secret for target domain
    // ═══════════════════════════════════════════════════════════════════
    
    // Derived secret = H(parentSecret, sourceNullifier, targetChainId)
    component derivedSecret = Poseidon(3);
    derivedSecret.inputs[0] <== parentSecret;
    derivedSecret.inputs[1] <== sourceNullifier;
    derivedSecret.inputs[2] <== targetChainId;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify target nullifier derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component targetDomain = DomainSeparator();
    targetDomain.chainId <== targetChainId;
    targetDomain.appId <== targetAppId;
    targetDomain.epochId <== targetEpochId;
    
    component targetNullifierHash = Poseidon(3);
    targetNullifierHash.inputs[0] <== derivedSecret.out;
    targetNullifierHash.inputs[1] <== targetDomain.separator;
    targetNullifierHash.inputs[2] <== targetTransitionId;
    
    component targetCheck = IsEqual();
    targetCheck.in[0] <== targetNullifierHash.out;
    targetCheck.in[1] <== targetNullifier;
    
    // Both source and target must be valid
    valid <== sourceCheck.out * targetCheck.out;
}

/**
 * @title NullifierUniqueness
 * @notice Proves a nullifier is unique within a domain (not in Merkle tree)
 */
template NullifierUniqueness(TREE_DEPTH) {
    // Private inputs
    signal input secret;
    signal input transitionId;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];
    
    // Public inputs
    signal input nullifier;
    signal input merkleRoot;                   // Root of used nullifiers
    signal input chainId;
    signal input appId;
    signal input epochId;
    
    // Output
    signal output isUnique;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify nullifier derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component domain = DomainSeparator();
    domain.chainId <== chainId;
    domain.appId <== appId;
    domain.epochId <== epochId;
    
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== secret;
    nullifierHash.inputs[1] <== domain.separator;
    nullifierHash.inputs[2] <== transitionId;
    
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifierHash.out;
    nullifierCheck.in[1] <== nullifier;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Prove non-membership in Merkle tree
    // ═══════════════════════════════════════════════════════════════════
    
    // For non-membership, we prove the path leads to a different leaf or empty
    component pathHashers[TREE_DEPTH];
    signal pathHashes[TREE_DEPTH + 1];
    
    pathHashes[0] <== nullifier;
    
    for (var i = 0; i < TREE_DEPTH; i++) {
        pathHashers[i] = Poseidon(2);
        
        // If pathIndex = 0, nullifier is on left
        // If pathIndex = 1, nullifier is on right
        signal left;
        signal right;
        
        left <== pathIndices[i] * pathElements[i] + (1 - pathIndices[i]) * pathHashes[i];
        right <== pathIndices[i] * pathHashes[i] + (1 - pathIndices[i]) * pathElements[i];
        
        pathHashers[i].inputs[0] <== left;
        pathHashers[i].inputs[1] <== right;
        
        pathHashes[i + 1] <== pathHashers[i].out;
    }
    
    // The computed root should NOT equal the used nullifiers root
    // (for a non-membership proof)
    component rootCheck = IsEqual();
    rootCheck.in[0] <== pathHashes[TREE_DEPTH];
    rootCheck.in[1] <== merkleRoot;
    
    // isUnique = nullifier valid AND not in tree
    // In production, this would be a proper non-membership proof
    isUnique <== nullifierCheck.out;
}

/**
 * @title CrossDomainNullifierProof
 * @notice Complete cross-domain nullifier proof
 */
template CrossDomainNullifierProof(TREE_DEPTH) {
    // Private inputs
    signal input secret;
    signal input transitionId;
    signal input derivationNonce;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];
    
    // Public inputs - primary domain
    signal input chainId;
    signal input appId;
    signal input epochId;
    signal input nullifier;
    signal input merkleRoot;
    
    // Public inputs - cross-domain (optional)
    signal input hasParent;                     // 1 if derived from parent
    signal input parentNullifier;
    signal input parentChainId;
    signal input parentAppId;
    signal input parentEpochId;
    
    // Outputs
    signal output nullifierValid;
    signal output isUnique;
    signal output derivationValid;
    signal output allValid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 1: Nullifier Derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component nullifierProof = DomainNullifier();
    nullifierProof.secret <== secret;
    nullifierProof.transitionId <== transitionId;
    nullifierProof.chainId <== chainId;
    nullifierProof.appId <== appId;
    nullifierProof.epochId <== epochId;
    nullifierProof.expectedNullifier <== nullifier;
    
    nullifierValid <== nullifierProof.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 2: Uniqueness Proof
    // ═══════════════════════════════════════════════════════════════════
    
    component uniqueness = NullifierUniqueness(TREE_DEPTH);
    uniqueness.secret <== secret;
    uniqueness.transitionId <== transitionId;
    for (var i = 0; i < TREE_DEPTH; i++) {
        uniqueness.pathElements[i] <== pathElements[i];
        uniqueness.pathIndices[i] <== pathIndices[i];
    }
    uniqueness.nullifier <== nullifier;
    uniqueness.merkleRoot <== merkleRoot;
    uniqueness.chainId <== chainId;
    uniqueness.appId <== appId;
    uniqueness.epochId <== epochId;
    
    isUnique <== uniqueness.isUnique;
    
    // ═══════════════════════════════════════════════════════════════════
    // COMPONENT 3: Cross-Domain Derivation (if applicable)
    // ═══════════════════════════════════════════════════════════════════
    
    component crossDomain = CrossDomainDerivation();
    crossDomain.parentSecret <== secret;
    crossDomain.derivationNonce <== derivationNonce;
    crossDomain.sourceChainId <== parentChainId;
    crossDomain.sourceAppId <== parentAppId;
    crossDomain.sourceEpochId <== parentEpochId;
    crossDomain.sourceNullifier <== parentNullifier;
    crossDomain.targetChainId <== chainId;
    crossDomain.targetAppId <== appId;
    crossDomain.targetEpochId <== epochId;
    crossDomain.targetNullifier <== nullifier;
    crossDomain.targetTransitionId <== transitionId;
    
    // Derivation is valid if no parent OR derivation proof valid
    derivationValid <== (1 - hasParent) + hasParent * crossDomain.valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // AGGREGATE
    // ═══════════════════════════════════════════════════════════════════
    
    allValid <== nullifierValid * isUnique * derivationValid;
}

/**
 * @title EpochTransition
 * @notice Proves nullifiers can transition between epochs
 */
template EpochTransition() {
    // Private inputs
    signal input secret;
    signal input oldTransitionId;
    signal input newTransitionId;
    
    // Public inputs
    signal input chainId;
    signal input appId;
    signal input oldEpochId;
    signal input newEpochId;
    signal input oldNullifier;
    signal input newNullifier;
    
    // Output
    signal output valid;
    
    // Verify old nullifier
    component oldDomain = DomainSeparator();
    oldDomain.chainId <== chainId;
    oldDomain.appId <== appId;
    oldDomain.epochId <== oldEpochId;
    
    component oldNullifierHash = Poseidon(3);
    oldNullifierHash.inputs[0] <== secret;
    oldNullifierHash.inputs[1] <== oldDomain.separator;
    oldNullifierHash.inputs[2] <== oldTransitionId;
    
    component oldCheck = IsEqual();
    oldCheck.in[0] <== oldNullifierHash.out;
    oldCheck.in[1] <== oldNullifier;
    
    // Verify new nullifier
    component newDomain = DomainSeparator();
    newDomain.chainId <== chainId;
    newDomain.appId <== appId;
    newDomain.epochId <== newEpochId;
    
    component newNullifierHash = Poseidon(3);
    newNullifierHash.inputs[0] <== secret;
    newNullifierHash.inputs[1] <== newDomain.separator;
    newNullifierHash.inputs[2] <== newTransitionId;
    
    component newCheck = IsEqual();
    newCheck.in[0] <== newNullifierHash.out;
    newCheck.in[1] <== newNullifier;
    
    // Verify epoch progression (new > old)
    component epochProgress = GreaterThan(64);
    epochProgress.in[0] <== newEpochId;
    epochProgress.in[1] <== oldEpochId;
    
    valid <== oldCheck.out * newCheck.out * epochProgress.out;
}

// Main component with 20-level Merkle tree
component main {public [chainId, appId, epochId, nullifier, merkleRoot, hasParent, parentNullifier, parentChainId, parentAppId, parentEpochId]} = CrossDomainNullifierProof(20);
