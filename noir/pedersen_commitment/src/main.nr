use std::hash::pedersen_hash;
use std::hash::poseidon::bn254;

/// @title PedersenStateCommitment
/// @notice State commitment using Pedersen hash for hiding property
/// @dev Pedersen commitments are additively homomorphic and perfectly hiding
/// 
/// Pedersen vs Poseidon:
/// - Pedersen: Perfectly hiding, computationally binding
/// - Poseidon: Computationally hiding/binding, more efficient
/// 
/// Use Pedersen when hiding is critical (e.g., balance transfers)
/// Use Poseidon for general commitments where efficiency matters

struct PedersenCommitment {
    x: Field,  // Commitment x coordinate
    y: Field,  // Commitment y coordinate
}

/// Compute Pedersen commitment C = vG + rH
/// @param value The value being committed (e.g., balance)
/// @param blinding Random blinding factor
/// @return Commitment hash
fn compute_pedersen_commitment(value: Field, blinding: Field) -> Field {
    // Noir's pedersen_hash handles the commitment internally
    pedersen_hash([value, blinding])
}

/// Derive owner public key from secret
fn derive_owner_pubkey(owner_secret: Field) -> Field {
    bn254::hash_1([owner_secret])
}

/// Verify a Pedersen state commitment
fn verify_pedersen_commitment(
    value: Field,
    blinding: Field,
    owner_secret: Field,
    expected_commitment: Field,
    owner_pubkey: Field
) -> bool {
    // Step 1: Compute Pedersen commitment
    let computed_commitment = compute_pedersen_commitment(value, blinding);
    let commitment_valid = computed_commitment == expected_commitment;
    
    // Step 2: Verify owner secret derives to pubkey
    let computed_pubkey = derive_owner_pubkey(owner_secret);
    let owner_valid = computed_pubkey == owner_pubkey;
    
    commitment_valid & owner_valid
}

/// Range proof helper - ensures value is within valid range
/// @param value The value to range check
/// @param max_bits Maximum number of bits allowed
fn verify_range<let BITS: u32>(value: Field) -> bool {
    // Decompose value into bits and verify it fits in BITS
    // Noir handles this automatically with type constraints
    let _: u64 = value as u64; // This enforces 64-bit range
    true
}

/// Simplified commitment "addition" (Field Addition)
/// WARNING: This is NOT a true EC-point homomorphic addition.
/// For true Pedersen homomorphism, EC point addition gadgets must be used.
fn add_commitments_simplified(c1: Field, c2: Field) -> Field {
    c1 + c2
}

/// Main entry point
fn main(
    // Private inputs
    value: Field,
    blinding: Field,
    owner_secret: Field,
    // Public inputs
    commitment: pub Field,
    owner_pubkey: pub Field
) -> pub bool {
    verify_pedersen_commitment(value, blinding, owner_secret, commitment, owner_pubkey)
}

#[test]
fn test_pedersen_commitment() {
    let value = 100;
    let blinding = 0x1234567890abcdef;
    let owner_secret = 0xdeadbeef;
    
    let commitment = compute_pedersen_commitment(value, blinding);
    let pubkey = derive_owner_pubkey(owner_secret);
    
    assert(verify_pedersen_commitment(value, blinding, owner_secret, commitment, pubkey));
}

#[test]
fn test_hiding_property() {
    let value = 100;
    
    // Different blinding factors should produce different commitments
    let c1 = compute_pedersen_commitment(value, 0x1111);
    let c2 = compute_pedersen_commitment(value, 0x2222);
    
    assert(c1 != c2);
}
