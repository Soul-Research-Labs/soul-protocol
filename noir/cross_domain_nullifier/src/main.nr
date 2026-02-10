use std::hash::poseidon::bn254;

/// @title CrossDomainNullifierCircuit
/// @notice Circuit for domain-separated nullifiers (CDNA)
/// @dev Nullifiers that compose algebraically across chains, epochs, and applications
///      N = H(secret, app_id, chain_id, epoch, transition_id)
/// 
/// Enables cross-chain double-spend prevention without global state.
///
/// FEATURES:
///   1. Scalar multiplication for stealth addresses
///   2. Merkle tree membership proofs (20-depth tree)
///   3. Domain-specific nullifiers (CDNA)
///   4. Range proofs for value validation
/// 5. Epoch-based nullifier evolution

/// CDNA version prefix (ASCII for "CDNA_v1" padded)
global CDNA_PREFIX: Field = 0x434e4441_76310000;

/// Merkle tree depth for UTXO set
global MERKLE_DEPTH: u32 = 20;

/// Domain separators
global COMMITMENT_DOMAIN: Field = 0x434f4d4d4954; // "COMMIT"
global NULLIFIER_DOMAIN: Field = 0x4e554c4c;      // "NULL"
global TRANSFER_DOMAIN: Field = 0x5452414e5346;   // "TRANSF"

struct DomainContext {
    chain_id: Field,
    app_id: Field,
    epoch_id: Field,
}

/// Commitment for hiding value
struct Commitment {
    value: Field,
    blinding: Field,
}

/// Input UTXO for cross-domain transfer
struct TransferInput {
    secret: Field,
    commitment: Commitment,
    merkle_path: [Field; 20],
    merkle_indices: [u1; 20],
}

/// Output UTXO for cross-domain transfer
struct TransferOutput {
    value: Field,
    blinding: Field,
    recipient: Field,
}

/// Compute domain separator for nullifier scope
fn compute_domain_separator(domain: DomainContext) -> Field {
    bn254::hash_4([CDNA_PREFIX, domain.chain_id, domain.app_id, domain.epoch_id])
}

/// Compute a Pedersen-style commitment using Poseidon
fn compute_commitment(c: Commitment) -> Field {
    bn254::hash_3([COMMITMENT_DOMAIN, c.value, c.blinding])
}

/// Compute a domain-separated nullifier
fn compute_domain_nullifier(
    secret: Field,
    domain: DomainContext,
    transition_id: Field
) -> Field {
    let separator = compute_domain_separator(domain);
    bn254::hash_4([secret, separator, transition_id, 0])
}

/// Compute nullifier from secret and commitment (for transfer inputs)
fn compute_nullifier_from_commitment(secret: Field, commitment_hash: Field, domain: DomainContext) -> Field {
    let separator = compute_domain_separator(domain);
    bn254::hash_4([NULLIFIER_DOMAIN, secret, commitment_hash, separator])
}

/// Verify Merkle tree membership proof
/// Returns true if the leaf is in the tree with the given root
fn verify_merkle_proof(
    leaf: Field,
    root: Field,
    path: [Field; 20],
    indices: [u1; 20]
) -> bool {
    let mut current_hash = leaf;
    
    for i in 0..20 {
        let path_element = path[i];
        let index = indices[i];
        
        // If index is 0, current_hash is on the left
        // If index is 1, current_hash is on the right
        let (left, right) = if index == 0 {
            (current_hash, path_element)
        } else {
            (path_element, current_hash)
        };
        
        current_hash = bn254::hash_2([left, right]);
    }
    
    current_hash == root
}

/// Range check: verify value fits in 64 bits
fn range_check_64(value: Field) -> bool {
    let bits: [u1; 64] = value.to_be_bits();
    let mut reconstructed: Field = 0;
    for i in 0..64 {
        reconstructed = reconstructed * 2 + bits[i] as Field;
    }
    reconstructed == value
}

/// Verify a domain nullifier
fn verify_domain_nullifier(
    expected_nullifier: Field,
    secret: Field,
    domain: DomainContext,
    transition_id: Field
) -> bool {
    let computed = compute_domain_nullifier(secret, domain, transition_id);
    computed == expected_nullifier
}

/// Derive a child secret for cross-domain derivation
fn derive_child_secret(
    parent_secret: Field,
    source_nullifier: Field,
    target_chain_id: Field
) -> Field {
    bn254::hash_4([parent_secret, source_nullifier, target_chain_id, 0])
}

/// Verify cross-domain nullifier derivation
fn verify_cross_domain_derivation(
    // Source domain
    source_domain: DomainContext,
    source_nullifier: Field,
    // Target domain
    target_domain: DomainContext,
    target_nullifier: Field,
    target_transition_id: Field,
    // Private inputs
    parent_secret: Field,
    derivation_nonce: Field
) -> bool {
    // Step 1: Verify source nullifier derivation
    let source_transition_id = bn254::hash_1([derivation_nonce]);
    let computed_source = compute_domain_nullifier(
        parent_secret,
        source_domain,
        source_transition_id
    );
    let source_valid = computed_source == source_nullifier;
    
    // Step 2: Derive child secret for target domain
    let child_secret = derive_child_secret(
        parent_secret,
        source_nullifier,
        target_domain.chain_id
    );
    
    // Step 3: Verify target nullifier
    let computed_target = compute_domain_nullifier(
        child_secret,
        target_domain,
        target_transition_id
    );
    let target_valid = computed_target == target_nullifier;
    
    source_valid & target_valid
}

/// Verify cross-epoch evolution
fn verify_epoch_evolution(
    old_nullifier: Field,
    new_nullifier: Field,
    secret: Field,
    chain_id: Field,
    app_id: Field,
    old_epoch: Field,
    new_epoch: Field,
    transition_id: Field
) -> bool {
    let old_domain = DomainContext {
        chain_id,
        app_id,
        epoch_id: old_epoch
    };
    
    let new_domain = DomainContext {
        chain_id,
        app_id,
        epoch_id: new_epoch
    };
    
    // Verify old nullifier
    let old_valid = verify_domain_nullifier(old_nullifier, secret, old_domain, transition_id);
    
    // Verify new nullifier with evolved epoch
    let new_valid = verify_domain_nullifier(new_nullifier, secret, new_domain, transition_id);
    
    // Verify epoch increased
    let old_e: u64 = old_epoch as u64;
    let new_e: u64 = new_epoch as u64;
    let epoch_increased = new_e > old_e;
    
    old_valid & new_valid & epoch_increased
}

/// Main entry point
fn main(
    // Private inputs
    parent_secret: Field,
    derivation_nonce: Field,
    // Public inputs - source domain
    source_chain_id: pub Field,
    source_app_id: pub Field,
    source_epoch_id: pub Field,
    source_nullifier: pub Field,
    // Public inputs - target domain
    target_chain_id: pub Field,
    target_app_id: pub Field,
    target_epoch_id: pub Field,
    target_nullifier: pub Field,
    target_transition_id: pub Field
) -> pub bool {
    let source_domain = DomainContext {
        chain_id: source_chain_id,
        app_id: source_app_id,
        epoch_id: source_epoch_id
    };
    
    let target_domain = DomainContext {
        chain_id: target_chain_id,
        app_id: target_app_id,
        epoch_id: target_epoch_id
    };
    
    verify_cross_domain_derivation(
        source_domain,
        source_nullifier,
        target_domain,
        target_nullifier,
        target_transition_id,
        parent_secret,
        derivation_nonce
    )
}

#[test]
fn test_domain_separator() {
    let domain = DomainContext {
        chain_id: 1,
        app_id: 100,
        epoch_id: 1
    };
    
    let sep1 = compute_domain_separator(domain);
    let sep2 = compute_domain_separator(domain);
    
    // Same inputs should give same separator
    assert(sep1 == sep2);
}

#[test]
fn test_nullifier_derivation() {
    let secret = 0x1234;
    let domain = DomainContext {
        chain_id: 1,
        app_id: 100,
        epoch_id: 1
    };
    let transition_id = 42;
    
    let nullifier = compute_domain_nullifier(secret, domain, transition_id);
    
    assert(verify_domain_nullifier(nullifier, secret, domain, transition_id));
}

#[test]
fn test_different_domains_different_nullifiers() {
    let secret = 0x1234;
    let transition_id = 42;
    
    let domain1 = DomainContext { chain_id: 1, app_id: 100, epoch_id: 1 };
    let domain2 = DomainContext { chain_id: 137, app_id: 100, epoch_id: 1 };
    
    let null1 = compute_domain_nullifier(secret, domain1, transition_id);
    let null2 = compute_domain_nullifier(secret, domain2, transition_id);
    
    // Different chains should produce different nullifiers
    assert(null1 != null2);
}

#[test]
fn test_commitment_determinism() {
    let c = Commitment { value: 1000, blinding: 12345 };
    let hash1 = compute_commitment(c);
    let hash2 = compute_commitment(c);
    assert(hash1 == hash2);
}

#[test]
fn test_merkle_proof_verification() {
    // Single-element tree test
    let leaf = bn254::hash_1([42]);
    
    // Build a simple Merkle path to a root
    let mut path: [Field; 20] = [0; 20];
    let mut indices: [u1; 20] = [0; 20];
    
    // Compute expected root by hashing up the tree
    let mut current = leaf;
    for i in 0..20 {
        path[i] = 0; // Zero sibling
        current = bn254::hash_2([current, 0]);
    }
    
    // Verify the proof
    assert(verify_merkle_proof(leaf, current, path, indices));
}

#[test]
fn test_range_check() {
    // Valid 64-bit values
    assert(range_check_64(0));
    assert(range_check_64(1000000));
    assert(range_check_64(18446744073709551615)); // 2^64 - 1
}

// =============================================================================
// CROSS-DOMAIN TRANSFER WITH MERKLE PROOFS
// =============================================================================

/// Verify input UTXO for cross-domain transfer
fn verify_transfer_input(
    input: TransferInput,
    domain: DomainContext,
    merkle_root: Field
) -> (Field, Field) {
    // Compute commitment hash
    let commitment_hash = compute_commitment(input.commitment);
    
    // Verify Merkle membership
    let in_tree = verify_merkle_proof(
        commitment_hash,
        merkle_root,
        input.merkle_path,
        input.merkle_indices
    );
    assert(in_tree);
    
    // Compute nullifier
    let nullifier = compute_nullifier_from_commitment(
        input.secret,
        commitment_hash,
        domain
    );
    
    // Range check value
    assert(range_check_64(input.commitment.value));
    
    // Return (nullifier, value) for balance checking
    (nullifier, input.commitment.value)
}

/// Verify output UTXO for cross-domain transfer
fn verify_transfer_output(
    output: TransferOutput,
    target_domain: DomainContext
) -> (Field, Field) {
    // Compute commitment
    let commitment = Commitment {
        value: output.value,
        blinding: output.blinding
    };
    let commitment_hash = compute_commitment(commitment);
    
    // Range check value
    assert(range_check_64(output.value));
    
    // Return (commitment_hash, value) for balance checking
    (commitment_hash, output.value)
}

/// Cross-domain private transfer with Merkle proofs
/// Proves:
/// 1. Input is in source domain's UTXO tree
/// 2. Nullifier is correctly derived for double-spend prevention
/// 3. Output commitment is valid
/// 4. Balance is conserved (input_value >= output_value + fee)
fn verify_cross_domain_transfer(
    // Input UTXO
    input: TransferInput,
    // Output UTXO
    output: TransferOutput,
    // Fee
    fee: Field,
    // Source domain
    source_domain: DomainContext,
    source_merkle_root: Field,
    // Target domain
    target_domain: DomainContext,
    // Expected public outputs
    expected_nullifier: Field,
    expected_output_commitment: Field
) -> bool {
    // Verify input
    let (computed_nullifier, input_value) = verify_transfer_input(
        input,
        source_domain,
        source_merkle_root
    );
    assert(computed_nullifier == expected_nullifier);
    
    // Verify output
    let (computed_output_commitment, output_value) = verify_transfer_output(
        output,
        target_domain
    );
    assert(computed_output_commitment == expected_output_commitment);
    
    // Balance check: input >= output + fee
    assert(input_value == output_value + fee);
    
    // Range check fee
    assert(range_check_64(fee));
    
    true
}
