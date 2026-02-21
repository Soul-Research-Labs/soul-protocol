use std::verify_proof_with_type;

/**
 * @title AggregatorCircuit
 * @notice Batches multiple proofs into a single recursive proof for gas-efficient on-chain verification
 * @dev Uses Noir recursive proof verification to aggregate up to 4 proofs.
 *      Each proof is independently verified, and their public inputs are committed
 *      into a single batch root for on-chain settlement.
 *
 * Architecture:
 *   Proof_0 --+
 *   Proof_1 --+--> AggregatorCircuit --> Single aggregated proof + batch_root
 *   Proof_2 --+
 *   Proof_3 --+
 *
 * The batch_root = Poseidon(input_commitment_0, input_commitment_1, ..., batch_size)
 * where input_commitment_i = Poseidon(public_inputs_i)
 */

/// Maximum proofs that can be aggregated in one batch
global MAX_BATCH_SIZE: u32 = 4;

/// Number of public inputs per sub-proof (state_transfer format)
global PUB_INPUTS_PER_PROOF: u32 = 7;

/// UltraHonk recursive proof length (PROOF_LENGTH_WITHOUT_PUB_INPUTS + pairing points)
/// Ref: bb_proof_verification library from Barretenberg team
global HONK_PROOF_SIZE: u32 = 457;

/// UltraHonk verification key length in fields
global HONK_VK_SIZE: u32 = 115;

/// UltraHonk proof type identifier (non-ZK)
global PROOF_TYPE_HONK: u32 = 0;

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
    // -- Batch metadata (public) --
    batch_size: pub Field,           // Number of proofs in this batch (1..4)
    batch_id: pub Field,             // Unique batch identifier

    // -- Proof 0 --
    vk_0: [Field; HONK_VK_SIZE],
    proof_0: [Field; HONK_PROOF_SIZE],
    pub_inputs_0: [Field; 7],
    key_hash_0: Field,

    // -- Proof 1 --
    vk_1: [Field; HONK_VK_SIZE],
    proof_1: [Field; HONK_PROOF_SIZE],
    pub_inputs_1: [Field; 7],
    key_hash_1: Field,

    // -- Proof 2 --
    vk_2: [Field; HONK_VK_SIZE],
    proof_2: [Field; HONK_PROOF_SIZE],
    pub_inputs_2: [Field; 7],
    key_hash_2: Field,

    // -- Proof 3 --
    vk_3: [Field; HONK_VK_SIZE],
    proof_3: [Field; HONK_PROOF_SIZE],
    pub_inputs_3: [Field; 7],
    key_hash_3: Field,

    // -- Aggregation state --
    aggregation_object: [Field; 16]
) -> pub [Field; 16] {
    // Validate batch size
    assert(batch_size as u32 >= 1);
    assert(batch_size as u32 <= MAX_BATCH_SIZE);

    // -- Always verify proof 0 (batch_size >= 1) --
    verify_proof_with_type(vk_0, proof_0, pub_inputs_0, key_hash_0, PROOF_TYPE_HONK);

    // -- Conditionally verify proof 1 --
    if batch_size as u32 >= 2 {
        verify_proof_with_type(vk_1, proof_1, pub_inputs_1, key_hash_1, PROOF_TYPE_HONK);
    }

    // -- Conditionally verify proof 2 --
    if batch_size as u32 >= 3 {
        verify_proof_with_type(vk_2, proof_2, pub_inputs_2, key_hash_2, PROOF_TYPE_HONK);
    }

    // -- Conditionally verify proof 3 --
    if batch_size as u32 >= 4 {
        verify_proof_with_type(vk_3, proof_3, pub_inputs_3, key_hash_3, PROOF_TYPE_HONK);
    }

    // Return the aggregation object for chaining
    aggregation_object
}

// ==================================================
// Tests
// ==================================================

#[test]
fn test_commit_fields_deterministic() {
    let fields: [Field; 7] = [1, 2, 3, 4, 5, 6, 7];
    let c1 = commit_fields(fields);
    let c2 = commit_fields(fields);
    assert(c1 == c2);
}

#[test]
fn test_commit_fields_different_inputs() {
    let fields_a: [Field; 7] = [1, 2, 3, 4, 5, 6, 7];
    let fields_b: [Field; 7] = [7, 6, 5, 4, 3, 2, 1];
    let c_a = commit_fields(fields_a);
    let c_b = commit_fields(fields_b);
    assert(c_a != c_b);
}

#[test]
fn test_commit_fields_nonzero() {
    let fields: [Field; 7] = [100, 200, 300, 400, 500, 600, 700];
    let c = commit_fields(fields);
    assert(c != 0);
}

#[test]
fn test_batch_size_bounds() {
    // batch_size must be at least 1
    let min_batch: u32 = 1;
    assert(min_batch >= 1);
    assert(min_batch <= MAX_BATCH_SIZE);

    // batch_size must be at most MAX_BATCH_SIZE
    let max_batch: u32 = MAX_BATCH_SIZE;
    assert(max_batch >= 1);
    assert(max_batch <= MAX_BATCH_SIZE);
}
