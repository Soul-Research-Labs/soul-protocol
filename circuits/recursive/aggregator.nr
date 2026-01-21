// PIL Proof Aggregator Circuit
// Aggregates multiple proofs into a single proof using folding

use dep::std::hash::poseidon;
use dep::recursive::{
    PILState, FoldedInstance, IVCProof, ProofBatch,
    generate_challenge, generate_challenge_batch
};

// ============================================
// Aggregation Configuration
// ============================================

global MAX_BATCH_SIZE: u32 = 32;
global DOMAIN_SEPARATOR_AGGREGATION: Field = 0x50494C5F4147475245474154494F4E; // "PIL_AGGREGATION"

// ============================================
// Aggregated Proof Structure
// ============================================

struct AggregatedProof {
    /// Number of original proofs
    proof_count: Field,
    /// Initial state (before all transfers)
    initial_state_hash: Field,
    /// Final state (after all transfers)
    final_state_hash: Field,
    /// Final accumulated instance
    accumulated_instance: FoldedInstance,
    /// Merkle root of all nullifiers in batch
    nullifier_batch_root: Field,
    /// Total volume in batch
    batch_volume: Field,
}

impl AggregatedProof {
    /// Hash for on-chain verification
    fn hash(self) -> Field {
        let h1 = poseidon::bn254::hash_4([
            self.proof_count,
            self.initial_state_hash,
            self.final_state_hash,
            self.nullifier_batch_root
        ]);
        let h2 = self.accumulated_instance.hash();
        poseidon::bn254::hash_3([h1, h2, self.batch_volume])
    }
}

// ============================================
// Individual Proof Input
// ============================================

struct ProofInput {
    /// State hash before this transfer
    prev_state_hash: Field,
    /// State hash after this transfer
    new_state_hash: Field,
    /// Nullifier used
    nullifier: Field,
    /// New commitment created
    commitment: Field,
    /// Transfer amount
    amount: Field,
    /// Instance commitment
    instance_commitment: Field,
}

impl ProofInput {
    /// Create folded instance from proof
    fn to_instance(self) -> FoldedInstance {
        FoldedInstance::initial(
            self.instance_commitment,
            self.new_state_hash
        )
    }

    /// Hash for challenge generation
    fn hash(self) -> Field {
        poseidon::bn254::hash_5([
            self.prev_state_hash,
            self.new_state_hash,
            self.nullifier,
            self.commitment,
            self.amount
        ])
    }
}

// ============================================
// Main Aggregation Circuit
// ============================================

/// Aggregate up to MAX_BATCH_SIZE proofs into one
fn main(
    // Public outputs
    pub aggregated_proof_hash: Field,
    pub initial_state_hash: Field,
    pub final_state_hash: Field,
    pub batch_nullifier_root: Field,
    pub batch_volume: Field,
    pub proof_count: Field,
    
    // Private inputs - array of proofs to aggregate
    proofs: [ProofInput; MAX_BATCH_SIZE],
    // Validity flags (1 = valid proof, 0 = padding)
    validity_flags: [Field; MAX_BATCH_SIZE],
) {
    // ==========================================
    // Step 1: Validate inputs
    // ==========================================
    
    let count = proof_count as u64;
    assert(count > 0);
    assert(count <= MAX_BATCH_SIZE as u64);
    
    // Count valid proofs
    let mut valid_count: u64 = 0;
    for i in 0..MAX_BATCH_SIZE {
        if validity_flags[i] == 1 {
            valid_count += 1;
        }
    }
    assert(valid_count == count);
    
    // ==========================================
    // Step 2: Verify state chain
    // ==========================================
    
    // First valid proof should start from initial state
    let mut found_first = false;
    let mut current_state = initial_state_hash;
    
    for i in 0..MAX_BATCH_SIZE {
        if validity_flags[i] == 1 {
            if !found_first {
                // First proof must match initial state
                assert(proofs[i].prev_state_hash == initial_state_hash);
                found_first = true;
            } else {
                // Subsequent proofs must chain
                assert(proofs[i].prev_state_hash == current_state);
            }
            current_state = proofs[i].new_state_hash;
        }
    }
    
    // Final state must match
    assert(current_state == final_state_hash);
    
    // ==========================================
    // Step 3: Generate challenges
    // ==========================================
    
    let mut proof_hashes: [Field; MAX_BATCH_SIZE] = [0; MAX_BATCH_SIZE];
    for i in 0..MAX_BATCH_SIZE {
        if validity_flags[i] == 1 {
            proof_hashes[i] = proofs[i].hash();
        }
    }
    
    let challenges = generate_challenge_batch(proof_hashes, DOMAIN_SEPARATOR_AGGREGATION);
    
    // ==========================================
    // Step 4: Fold all instances
    // ==========================================
    
    let mut accumulated = FoldedInstance::initial(0, initial_state_hash);
    let mut is_first = true;
    
    for i in 0..MAX_BATCH_SIZE {
        if validity_flags[i] == 1 {
            let proof_instance = proofs[i].to_instance();
            
            if is_first {
                accumulated = proof_instance;
                is_first = false;
            } else {
                accumulated = accumulated.fold(proof_instance, challenges[i]);
            }
        }
    }
    
    // ==========================================
    // Step 5: Compute nullifier batch root
    // ==========================================
    
    let mut nullifier_hash = 0 as Field;
    for i in 0..MAX_BATCH_SIZE {
        if validity_flags[i] == 1 {
            nullifier_hash = poseidon::bn254::hash_2([nullifier_hash, proofs[i].nullifier]);
        }
    }
    assert(nullifier_hash == batch_nullifier_root);
    
    // ==========================================
    // Step 6: Sum batch volume
    // ==========================================
    
    let mut total_volume: Field = 0;
    for i in 0..MAX_BATCH_SIZE {
        if validity_flags[i] == 1 {
            total_volume += proofs[i].amount;
        }
    }
    assert(total_volume == batch_volume);
    
    // ==========================================
    // Step 7: Verify aggregated proof hash
    // ==========================================
    
    let aggregated = AggregatedProof {
        proof_count: proof_count,
        initial_state_hash: initial_state_hash,
        final_state_hash: final_state_hash,
        accumulated_instance: accumulated,
        nullifier_batch_root: batch_nullifier_root,
        batch_volume: batch_volume,
    };
    
    assert(aggregated.hash() == aggregated_proof_hash);
}

// ============================================
// Recursive Aggregation (Tree Structure)
// ============================================

/// Aggregate two aggregated proofs into one (for tree aggregation)
fn aggregate_aggregated(
    pub final_proof_hash: Field,
    pub initial_state_hash: Field,
    pub final_state_hash: Field,
    pub total_proof_count: Field,
    
    left_proof: AggregatedProof,
    right_proof: AggregatedProof,
    challenge: Field,
) {
    // Verify left proof starts from initial state
    assert(left_proof.initial_state_hash == initial_state_hash);
    
    // Verify right proof starts where left ends
    assert(right_proof.initial_state_hash == left_proof.final_state_hash);
    
    // Verify right proof ends at final state
    assert(right_proof.final_state_hash == final_state_hash);
    
    // Verify total count
    let expected_count = left_proof.proof_count + right_proof.proof_count;
    assert(expected_count == total_proof_count);
    
    // Fold the two accumulated instances
    let folded_instance = left_proof.accumulated_instance.fold(
        right_proof.accumulated_instance,
        challenge
    );
    
    // Combine nullifier roots
    let combined_nullifier_root = poseidon::bn254::hash_2([
        left_proof.nullifier_batch_root,
        right_proof.nullifier_batch_root
    ]);
    
    // Sum volumes
    let total_volume = left_proof.batch_volume + right_proof.batch_volume;
    
    // Create final aggregated proof
    let final_proof = AggregatedProof {
        proof_count: total_proof_count,
        initial_state_hash: initial_state_hash,
        final_state_hash: final_state_hash,
        accumulated_instance: folded_instance,
        nullifier_batch_root: combined_nullifier_root,
        batch_volume: total_volume,
    };
    
    assert(final_proof.hash() == final_proof_hash);
}

// ============================================
// Cross-Chain Aggregation
// ============================================

struct CrossChainProof {
    /// Source chain aggregated proof
    source_proof_hash: Field,
    /// Destination chain ID
    dest_chain_id: Field,
    /// Bridge message hash
    bridge_message_hash: Field,
    /// Relayer signature hash (for accountability)
    relayer_sig_hash: Field,
}

/// Verify aggregated proof is valid for cross-chain bridging
fn verify_for_bridge(
    pub bridge_commitment: Field,
    pub source_chain_id: Field,
    pub dest_chain_id: Field,
    
    aggregated_proof: AggregatedProof,
    cross_chain: CrossChainProof,
) {
    // Verify aggregated proof hash
    assert(aggregated_proof.hash() == cross_chain.source_proof_hash);
    
    // Verify destination chain
    assert(cross_chain.dest_chain_id == dest_chain_id);
    
    // Compute bridge commitment
    let computed_commitment = poseidon::bn254::hash_5([
        cross_chain.source_proof_hash,
        source_chain_id,
        dest_chain_id,
        aggregated_proof.final_state_hash,
        aggregated_proof.batch_volume
    ]);
    
    assert(computed_commitment == bridge_commitment);
}
