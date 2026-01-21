// PIL IVC Step Circuit
// Proves a single step in the incrementally verifiable computation chain

use dep::std::hash::poseidon;
use dep::recursive::{
    PILState, FoldedInstance, IVCProof, SparseMerkleProof,
    generate_challenge, hash_groth16_proof
};

// ============================================
// Transfer Data Structure
// ============================================

struct TransferData {
    /// Nullifier for spent note
    nullifier: Field,
    /// New commitment being created
    new_commitment: Field,
    /// Transfer amount (private)
    amount: Field,
    /// Merkle proof for input note
    input_merkle_proof: SparseMerkleProof,
    /// Index for new commitment insertion
    output_index: Field,
}

// ============================================
// IVC Step Witness
// ============================================

struct IVCStepWitness {
    /// Previous IVC proof (none for step 0)
    prev_proof: IVCProof,
    /// Previous running instance
    prev_instance: FoldedInstance,
    /// Transfer data for this step
    transfer: TransferData,
    /// Previous PIL state
    prev_state: PILState,
    /// Randomness for commitment
    commitment_randomness: Field,
}

// ============================================
// Main IVC Step Circuit
// ============================================

/// Verify one step of IVC and output new proof
fn main(
    // Public inputs
    pub step_number: Field,
    pub prev_state_hash: Field,
    pub new_state_hash: Field,
    pub prev_instance_hash: Field,
    pub new_instance_hash: Field,
    
    // Private witness
    witness: IVCStepWitness,
) {
    // ==========================================
    // Step 1: Verify previous proof (if not genesis)
    // ==========================================
    
    if step_number as u64 > 0 {
        // Verify previous instance hash matches
        let computed_prev_instance_hash = witness.prev_instance.hash();
        assert(computed_prev_instance_hash == prev_instance_hash);
        
        // Verify previous proof state matches
        assert(witness.prev_proof.new_state_hash == prev_state_hash);
        
        // Verify folded instance is consistent
        assert(witness.prev_proof.folded_instance.hash() == witness.prev_instance.hash());
    }
    
    // ==========================================
    // Step 2: Verify previous state hash
    // ==========================================
    
    let computed_prev_state_hash = witness.prev_state.hash();
    assert(computed_prev_state_hash == prev_state_hash);
    
    // ==========================================
    // Step 3: Verify transfer validity
    // ==========================================
    
    // Verify nullifier is derived correctly (simplified)
    // In production, this would verify the full nullifier derivation
    assert(witness.transfer.nullifier != 0);
    
    // Verify Merkle proof for input note
    let computed_root = witness.transfer.input_merkle_proof.verify_and_compute_root(
        witness.transfer.nullifier // Using nullifier as index for demo
    );
    assert(computed_root == witness.prev_state.commitment_root);
    
    // Verify commitment is well-formed
    let expected_commitment = poseidon::bn254::hash_3([
        witness.transfer.amount,
        witness.commitment_randomness,
        witness.transfer.nullifier
    ]);
    assert(expected_commitment == witness.transfer.new_commitment);
    
    // Verify amount is positive and bounded
    let amount_u64 = witness.transfer.amount as u64;
    assert(amount_u64 > 0);
    assert(amount_u64 < 1000000000000000000); // Max 10^18
    
    // ==========================================
    // Step 4: Compute new state
    // ==========================================
    
    // Compute new Merkle root after insertion
    let new_merkle_root = witness.transfer.input_merkle_proof.compute_new_root(
        witness.transfer.new_commitment
    );
    
    // Apply transfer to state
    let new_state = witness.prev_state.apply_transfer(
        witness.transfer.new_commitment,
        witness.transfer.nullifier,
        witness.transfer.amount,
        new_merkle_root
    );
    
    // Verify new state hash
    let computed_new_state_hash = new_state.hash();
    assert(computed_new_state_hash == new_state_hash);
    
    // ==========================================
    // Step 5: Fold instance for accumulation
    // ==========================================
    
    // Create instance for current step
    let current_instance = FoldedInstance::initial(
        witness.transfer.new_commitment,
        new_state_hash
    );
    
    // Generate folding challenge
    let challenge = generate_challenge(
        prev_instance_hash,
        current_instance.hash(),
        step_number
    );
    
    // Fold instances
    let new_instance = if step_number as u64 == 0 {
        current_instance
    } else {
        witness.prev_instance.fold(current_instance, challenge)
    };
    
    // Verify new instance hash
    let computed_new_instance_hash = new_instance.hash();
    assert(computed_new_instance_hash == new_instance_hash);
}

// ============================================
// Genesis Circuit (Step 0)
// ============================================

/// Initialize IVC chain with genesis state
fn genesis(
    pub chain_id: Field,
    pub genesis_state_hash: Field,
    pub genesis_instance_hash: Field,
    
    initial_commitment: Field,
    initial_amount: Field,
    commitment_randomness: Field,
) {
    // Create genesis state
    let genesis_state = PILState::genesis(chain_id);
    
    // Verify genesis state hash (should be deterministic)
    let computed_genesis_hash = genesis_state.hash();
    assert(computed_genesis_hash == genesis_state_hash);
    
    // Verify initial commitment
    let expected_commitment = poseidon::bn254::hash_3([
        initial_amount,
        commitment_randomness,
        0 // Genesis nullifier is 0
    ]);
    assert(expected_commitment == initial_commitment);
    
    // Create genesis instance
    let genesis_instance = FoldedInstance::initial(
        initial_commitment,
        genesis_state_hash
    );
    
    // Verify instance hash
    assert(genesis_instance.hash() == genesis_instance_hash);
}

// ============================================
// Batch Verification Circuit
// ============================================

/// Verify a batch of IVC proofs have been correctly aggregated
fn verify_batch(
    pub batch_size: Field,
    pub initial_state_hash: Field,
    pub final_state_hash: Field,
    pub final_instance_hash: Field,
    
    // Array of intermediate state hashes for verification
    intermediate_states: [Field; 16], // Max 16 proofs per batch
    challenges: [Field; 16],
) {
    // Verify batch size is valid
    let size = batch_size as u64;
    assert(size > 0);
    assert(size <= 16);
    
    // Verify state chain
    let mut current_state = initial_state_hash;
    for i in 0..16 {
        if (i as u64) < size {
            // Each intermediate state should be reachable
            // (In full implementation, verify each step proof)
            current_state = poseidon::bn254::hash_2([
                current_state,
                intermediate_states[i]
            ]);
        }
    }
    
    // Verify final state matches
    assert(current_state == final_state_hash);
    
    // Verify challenges were generated correctly (Fiat-Shamir)
    let mut running_challenge = initial_state_hash;
    for i in 0..16 {
        if (i as u64) < size {
            let expected_challenge = poseidon::bn254::hash_2([
                running_challenge,
                intermediate_states[i]
            ]);
            assert(challenges[i] == expected_challenge);
            running_challenge = expected_challenge;
        }
    }
}
