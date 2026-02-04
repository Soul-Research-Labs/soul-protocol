// State Expiry Resurrection Proof
// Proves ownership of expired state for resurrection
//
// Per Vitalik's "The Purge" (Part 5):
// EIP-7736 introduces leaf-level state expiry where:
// 1. Unused state expires after ~1 year
// 2. Expired state can be resurrected with a proof
// 3. Proof shows the state value at time of expiry

use dep::std;

// Maximum merkle proof depth for archive tree
global MAX_ARCHIVE_DEPTH: u32 = 32;

// Archived Soul state
struct ArchivedState {
    commitment: Field,           // Original Soul commitment
    nullifier_hash: Field,       // Nullifier hash (not revealed)
    balance_encrypted: Field,    // Encrypted balance at expiry
    expiry_epoch: Field,         // When it expired
    last_access_block: Field,    // Last access before expiry
}

// Resurrection request
struct ResurrectionRequest {
    state_key: Field,            // Key in state tree
    new_owner_commitment: Field, // New commitment after resurrection
    resurrection_fee: Field,     // Fee paid for resurrection
}

// Archive inclusion proof
struct ArchiveProof {
    sibling_hashes: [Field; MAX_ARCHIVE_DEPTH],
    path_bits: u32,              // Bit-packed path directions
    leaf_index: Field,
}

fn main(
    // Private inputs
    archived_state: ArchivedState,
    secret: Field,
    archive_proof: ArchiveProof,
    
    // Public inputs
    public_archive_root: pub Field,
    public_state_key: pub Field,
    public_commitment: pub Field,
    public_expiry_epoch: pub Field,
    public_current_epoch: pub Field,
) {
    // 1. Verify the state was legitimately expired
    // (expiry epoch < current epoch)
    assert(archived_state.expiry_epoch as u64 <= public_current_epoch as u64);
    assert(archived_state.expiry_epoch == public_expiry_epoch);
    
    // 2. Verify ownership via commitment
    let computed_commitment = compute_commitment(secret, archived_state.nullifier_hash);
    assert(computed_commitment == public_commitment);
    assert(computed_commitment == archived_state.commitment);
    
    // 3. Compute the leaf hash for archive tree
    let leaf_hash = compute_archive_leaf_hash(archived_state, public_state_key);
    
    // 4. Verify merkle inclusion in archive
    let computed_root = verify_merkle_path(
        leaf_hash,
        archive_proof.sibling_hashes,
        archive_proof.path_bits
    );
    assert(computed_root == public_archive_root);
    
    // 5. Verify state key derivation
    let derived_key = derive_state_key(archived_state.commitment);
    assert(derived_key == public_state_key);
}

// Compute Soul commitment
fn compute_commitment(secret: Field, nullifier: Field) -> Field {
    let inputs = [secret, nullifier];
    let result = std::hash::pedersen_commitment(inputs);
    result[0]
}

// Compute archive leaf hash
fn compute_archive_leaf_hash(state: ArchivedState, key: Field) -> Field {
    let inputs = [
        key,
        state.commitment,
        state.nullifier_hash,
        state.balance_encrypted,
        state.expiry_epoch,
        state.last_access_block
    ];
    let result = std::hash::pedersen_commitment(inputs);
    result[0]
}

// Derive state key from commitment
fn derive_state_key(commitment: Field) -> Field {
    let inputs = [commitment, 0]; // Simple derivation
    let result = std::hash::pedersen_commitment(inputs);
    result[0]
}

// Verify merkle path
fn verify_merkle_path(
    leaf: Field,
    siblings: [Field; MAX_ARCHIVE_DEPTH],
    path_bits: u32
) -> Field {
    let mut current = leaf;
    
    for i in 0..MAX_ARCHIVE_DEPTH {
        let sibling = siblings[i];
        
        // Skip zero siblings (shorter tree)
        if sibling != 0 {
            let bit = (path_bits >> i) & 1;
            
            if bit == 0 {
                // Current is left child
                let inputs = [current, sibling];
                let result = std::hash::pedersen_commitment(inputs);
                current = result[0];
            } else {
                // Current is right child
                let inputs = [sibling, current];
                let result = std::hash::pedersen_commitment(inputs);
                current = result[0];
            }
        }
    }
    
    current
}

// Extended proof for nullifier preservation
// Ensures nullifier history survives expiry
struct NullifierPreservationProof {
    nullifier: Field,
    nullifier_tree_root: Field,
    nullifier_path: [Field; MAX_ARCHIVE_DEPTH],
    nullifier_path_bits: u32,
    was_spent: bool,
}

// Verify nullifier was/wasn't spent before expiry
fn verify_nullifier_preservation(
    proof: NullifierPreservationProof,
    expected_nullifier_root: Field
) -> bool {
    // Compute nullifier leaf
    let leaf = if proof.was_spent {
        // Spent nullifiers are stored as hash(nullifier, 1)
        let inputs = [proof.nullifier, 1];
        let result = std::hash::pedersen_commitment(inputs);
        result[0]
    } else {
        // Unspent = zero leaf
        0
    };
    
    // Verify path
    let computed_root = verify_merkle_path(
        leaf,
        proof.nullifier_path,
        proof.nullifier_path_bits
    );
    
    computed_root == expected_nullifier_root
}

// Test resurrection proof
#[test]
fn test_resurrection_proof() {
    let secret = 12345;
    let nullifier = 67890;
    
    // Compute commitment
    let commitment_inputs = [secret, nullifier];
    let commitment_result = std::hash::pedersen_commitment(commitment_inputs);
    let commitment = commitment_result[0];
    
    // Create archived state
    let archived_state = ArchivedState {
        commitment: commitment,
        nullifier_hash: nullifier,
        balance_encrypted: 1000,
        expiry_epoch: 5,
        last_access_block: 1000000,
    };
    
    // Derive state key
    let state_key = derive_state_key(commitment);
    
    // Compute leaf hash
    let leaf_hash = compute_archive_leaf_hash(archived_state, state_key);
    
    // Simple proof (single node tree - root equals leaf)
    let siblings: [Field; MAX_ARCHIVE_DEPTH] = [0; MAX_ARCHIVE_DEPTH];
    
    let archive_proof = ArchiveProof {
        sibling_hashes: siblings,
        path_bits: 0,
        leaf_index: 0,
    };
    
    // Archive root = leaf for single-node tree
    let archive_root = leaf_hash;
    
    main(
        archived_state,
        secret,
        archive_proof,
        archive_root,
        state_key,
        commitment,
        5, // expiry epoch
        10 // current epoch (after expiry)
    );
}
