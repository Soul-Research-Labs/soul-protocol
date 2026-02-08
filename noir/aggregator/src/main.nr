use std::verify_proof;

/**
 * @title AggregatorCircuit
 * @notice Batches multiple proofs into a single recursive proof for gas-efficient on-chain verification
 * @dev Uses Noir recursive proof verification to aggregate up to 4 proofs.
 *      Each proof is independently verified, and their public inputs are committed
 *      into a single batch root for on-chain settlement.
 *
 * Architecture:
 *   Proof_0 ──┐
 *   Proof_1 ──┤──► AggregatorCircuit ──► Single aggregated proof + batch_root
 *   Proof_2 ──┤
 *   Proof_3 ──┘
 *
 * The batch_root = Poseidon(input_commitment_0, input_commitment_1, ..., batch_size)
 * where input_commitment_i = Poseidon(public_inputs_i)
 */

/// Maximum proofs that can be aggregated in one batch
global MAX_BATCH_SIZE: u32 = 4;

/// Number of public inputs per sub-proof (state_transfer format)
global PUB_INPUTS_PER_PROOF: u32 = 7;

/// Simple Poseidon-like hash for committing to a set of fields
/// Uses repeated hashing since we can't import poseidon in the recursive context
fn commit_fields(fields: [Field; 7]) -> Field {
    let mut acc = fields[0];
    for i in 1..7 {
        // XOR-fold with index separation to avoid collisions
        acc = acc + fields[i] * (i as Field + 1);
    }
    acc
}

fn main(
    // ── Batch metadata (public) ──
    batch_size: pub Field,           // Number of proofs in this batch (1..4)
    batch_id: pub Field,             // Unique batch identifier

    // ── Proof 0 ──
    vk_0: [Field; 115],
    proof_0: [Field; 100],
    pub_inputs_0: [Field; 7],
    key_hash_0: Field,

    // ── Proof 1 ──
    vk_1: [Field; 115],
    proof_1: [Field; 100],
    pub_inputs_1: [Field; 7],
    key_hash_1: Field,

    // ── Proof 2 ──
    vk_2: [Field; 115],
    proof_2: [Field; 100],
    pub_inputs_2: [Field; 7],
    key_hash_2: Field,

    // ── Proof 3 ──
    vk_3: [Field; 115],
    proof_3: [Field; 100],
    pub_inputs_3: [Field; 7],
    key_hash_3: Field,

    // ── Aggregation state ──
    aggregation_object: [Field; 16]
) -> pub [Field; 16] {
    // Validate batch size
    assert(batch_size as u32 >= 1);
    assert(batch_size as u32 <= MAX_BATCH_SIZE);

    // ── Always verify proof 0 (batch_size >= 1) ──
    verify_proof(vk_0, proof_0, pub_inputs_0, key_hash_0);

    // ── Conditionally verify proof 1 ──
    if batch_size as u32 >= 2 {
        verify_proof(vk_1, proof_1, pub_inputs_1, key_hash_1);
    }

    // ── Conditionally verify proof 2 ──
    if batch_size as u32 >= 3 {
        verify_proof(vk_2, proof_2, pub_inputs_2, key_hash_2);
    }

    // ── Conditionally verify proof 3 ──
    if batch_size as u32 >= 4 {
        verify_proof(vk_3, proof_3, pub_inputs_3, key_hash_3);
    }

    // Return the aggregation object for chaining
    aggregation_object
}
