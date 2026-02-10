use std::hash::poseidon::bn254;

/// @title MerkleProofVerifier
/// @notice Optimized Merkle tree inclusion proof for nullifier registry
/// @dev Uses Poseidon hashing for ~8x constraint reduction
/// 
/// Optimizations:
/// 1. Poseidon vs SHA256: 240 vs 25000 constraints per hash
/// 2. Binary path encoding (1 bit per level)
/// 3. In-circuit sibling selection
/// 4. Total: ~(240 * depth + 100) constraints

/// Verify a Merkle proof for a single leaf
/// @param leaf The leaf to prove inclusion of
/// @param root The expected Merkle root
/// @param path_indices Path direction (0=left, 1=right) for each level
/// @param siblings Sibling hashes along the path
/// @return valid Whether the proof is valid
fn verify_merkle_proof<let DEPTH: u32>(
    leaf: Field,
    root: Field,
    path_indices: [Field; DEPTH],
    siblings: [Field; DEPTH]
) -> bool {
    let mut current_hash = leaf;

    for i in 0..DEPTH {
        // Ensure path_indices is binary
        assert(path_indices[i] * (1 - path_indices[i]) == 0);

        // Select left and right based on path
        // If path_indices[i] = 0: current is left child
        // If path_indices[i] = 1: current is right child
        let (left, right) = if path_indices[i] == 0 {
            (current_hash, siblings[i])
        } else {
            (siblings[i], current_hash)
        };

        // Poseidon hash of (left, right)
        current_hash = bn254::hash_2([left, right]);
    }

    current_hash == root
}

/// Batch verify multiple Merkle proofs
/// @param leaves Array of leaves to verify
/// @param root The shared Merkle root
/// @param path_indices_batch Path indices for each proof
/// @param siblings_batch Sibling hashes for each proof
/// @return valid Whether all proofs are valid
fn verify_batch_merkle_proofs<let BATCH_SIZE: u32, let DEPTH: u32>(
    leaves: [Field; BATCH_SIZE],
    root: Field,
    path_indices_batch: [[Field; DEPTH]; BATCH_SIZE],
    siblings_batch: [[Field; DEPTH]; BATCH_SIZE]
) -> bool {
    let mut all_valid = true;
    
    for i in 0..BATCH_SIZE {
        let valid = verify_merkle_proof(
            leaves[i],
            root,
            path_indices_batch[i],
            siblings_batch[i]
        );
        all_valid = all_valid & valid;
    }
    
    all_valid
}

/// Main entry point for single Merkle proof verification
/// DEPTH = 20 (supports ~1 million leaves)
fn main(
    leaf: pub Field,
    root: pub Field,
    path_indices: [Field; 20],
    siblings: [Field; 20]
) -> pub bool {
    verify_merkle_proof(leaf, root, path_indices, siblings)
}

#[test]
fn test_merkle_proof_single_level() {
    // Simple test with depth 1
    let leaf = 0x1234;
    let sibling = 0x5678;
    let expected_root = bn254::hash_2([leaf, sibling]);
    
    let path_indices: [Field; 1] = [0]; // leaf is on left
    let siblings: [Field; 1] = [sibling];
    
    assert(verify_merkle_proof(leaf, expected_root, path_indices, siblings));
}
