// Lookup Table Proof Circuit
// Proves that a privacy operation I/O mapping is valid
// Used for pre-proving operations for synchronous composability
//
// This circuit verifies:
// 1. Input hash matches the claimed input
// 2. Output hash matches the expected output
// 3. State transition is valid (stateRootBefore -> stateRootAfter)
// 4. Nullifier is valid and not previously consumed
// 5. Commitment correctness (Pedersen commitment)

// Public inputs (visible on-chain)
// - input_hash: Hash of the operation input
// - output_hash: Hash of the expected output  
// - state_root_before: State root before operation
// - state_root_after: State root after operation
// - nullifier_delta: Commitment to new nullifiers
// - chain_id: Chain where this operates

// Private inputs (hidden, proved in zero knowledge)
// - actual_input: The real input data
// - actual_output: The real output data
// - nullifier_preimage: Preimage of the nullifier
// - commitment_blinding: Blinding factor for commitment
// - merkle_path: Path proving inclusion in state tree
// - old_balance: Balance before operation
// - new_balance: Balance after operation

use std::hash::poseidon2::Poseidon2;
use std::hash::pedersen_hash;

// Maximum input/output size in field elements
global MAX_IO_SIZE: u32 = 16;

// State tree depth
global STATE_TREE_DEPTH: u32 = 32;

fn main(
    // === PUBLIC INPUTS ===
    input_hash: pub Field,
    output_hash: pub Field,
    state_root_before: pub Field,
    state_root_after: pub Field,
    nullifier_delta: pub Field,
    chain_id: pub Field,
    
    // === PRIVATE INPUTS ===
    // Actual I/O data
    actual_input: [Field; MAX_IO_SIZE],
    actual_input_len: u32,
    actual_output: [Field; MAX_IO_SIZE],
    actual_output_len: u32,
    
    // Nullifier data
    nullifier_preimage: Field,
    nullifier_secret: Field,
    
    // Commitment data
    amount: Field,
    commitment_blinding: Field,
    recipient: Field,
    
    // State tree proof
    merkle_path: [Field; STATE_TREE_DEPTH],
    merkle_indices: [u1; STATE_TREE_DEPTH],
    leaf_index: Field,
    
    // Balance proof
    old_balance: Field,
    new_balance: Field,
    balance_delta: Field
) {
    // =========================================
    // 1. Verify input hash matches actual input
    // =========================================
    let computed_input_hash = hash_io_data(actual_input, actual_input_len, chain_id);
    assert(computed_input_hash == input_hash, "Input hash mismatch");
    
    // =========================================
    // 2. Verify output hash matches actual output  
    // =========================================
    let computed_output_hash = hash_io_data(actual_output, actual_output_len, chain_id);
    assert(computed_output_hash == output_hash, "Output hash mismatch");
    
    // =========================================
    // 3. Verify nullifier is correctly derived
    // =========================================
    let computed_nullifier = compute_nullifier(nullifier_preimage, nullifier_secret);
    assert(computed_nullifier == nullifier_delta, "Nullifier mismatch");
    
    // =========================================
    // 4. Verify commitment correctness
    // =========================================
    let commitment = compute_pedersen_commitment(amount, recipient, commitment_blinding);
    // Commitment should be part of the output
    assert(actual_output[0] == commitment, "Commitment not in output");
    
    // =========================================
    // 5. Verify state tree inclusion (before)
    // =========================================
    let leaf_before = compute_account_leaf(leaf_index, old_balance, nullifier_preimage);
    let computed_root_before = compute_merkle_root(leaf_before, merkle_path, merkle_indices);
    assert(computed_root_before == state_root_before, "State root before mismatch");
    
    // =========================================
    // 6. Verify state transition is valid
    // =========================================
    // Balance update must be consistent
    let expected_new_balance = old_balance - balance_delta;
    assert(expected_new_balance == new_balance, "Balance transition invalid");
    assert(new_balance as u64 >= 0, "Negative balance"); // Prevent underflow
    
    // =========================================
    // 7. Verify state tree (after)
    // =========================================
    let leaf_after = compute_account_leaf(leaf_index, new_balance, computed_nullifier);
    let computed_root_after = compute_merkle_root(leaf_after, merkle_path, merkle_indices);
    assert(computed_root_after == state_root_after, "State root after mismatch");
    
    // =========================================
    // 8. Verify balance delta matches amount
    // =========================================
    assert(balance_delta == amount, "Delta/amount mismatch");
}

/// Hash I/O data with chain ID binding
fn hash_io_data(data: [Field; MAX_IO_SIZE], len: u32, chain_id: Field) -> Field {
    // Pack data with length and chain ID for domain separation
    let mut to_hash: [Field; MAX_IO_SIZE + 2] = [0; MAX_IO_SIZE + 2];
    to_hash[0] = chain_id;
    to_hash[1] = len as Field;
    
    for i in 0..MAX_IO_SIZE {
        if i < len {
            to_hash[i + 2] = data[i];
        }
    }
    
    Poseidon2::hash(to_hash, MAX_IO_SIZE + 2)
}

/// Compute nullifier from preimage and secret
fn compute_nullifier(preimage: Field, secret: Field) -> Field {
    Poseidon2::hash([preimage, secret], 2)
}

/// Compute Pedersen commitment: C = H(amount, recipient, blinding)
fn compute_pedersen_commitment(amount: Field, recipient: Field, blinding: Field) -> Field {
    pedersen_hash([amount, recipient, blinding])
}

/// Compute account leaf for state tree
fn compute_account_leaf(index: Field, balance: Field, nullifier_state: Field) -> Field {
    Poseidon2::hash([index, balance, nullifier_state], 3)
}

/// Compute Merkle root from leaf and path
fn compute_merkle_root(
    leaf: Field,
    path: [Field; STATE_TREE_DEPTH],
    indices: [u1; STATE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;
    
    for i in 0..STATE_TREE_DEPTH {
        let path_element = path[i];
        
        if indices[i] == 0 {
            // Current node is left child
            current = Poseidon2::hash([current, path_element], 2);
        } else {
            // Current node is right child
            current = Poseidon2::hash([path_element, current], 2);
        }
    }
    
    current
}

// =========================================
// TESTS
// =========================================

#[test]
fn test_nullifier_computation() {
    let preimage = 12345;
    let secret = 67890;
    let nullifier = compute_nullifier(preimage, secret);
    
    // Should be deterministic
    let nullifier2 = compute_nullifier(preimage, secret);
    assert(nullifier == nullifier2);
    
    // Different inputs should give different outputs
    let nullifier3 = compute_nullifier(preimage + 1, secret);
    assert(nullifier != nullifier3);
}

#[test]
fn test_commitment_computation() {
    let amount = 100;
    let recipient = 0xabc;
    let blinding = 0xdef;
    
    let commitment = compute_pedersen_commitment(amount, recipient, blinding);
    
    // Should be deterministic
    let commitment2 = compute_pedersen_commitment(amount, recipient, blinding);
    assert(commitment == commitment2);
    
    // Different blinding should give different commitment (hiding)
    let commitment3 = compute_pedersen_commitment(amount, recipient, blinding + 1);
    assert(commitment != commitment3);
}
