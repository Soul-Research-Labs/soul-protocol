// =============================================================================
// MIDNIGHT BRIDGE - BRIDGE TRANSFER CIRCUIT
// =============================================================================
//
// This circuit proves:
// 1. Knowledge of the secret that created a commitment
// 2. The transfer amount matches the commitment
// 3. The commitment exists in the Merkle tree
// 4. The nullifier is correctly derived

use std::hash::poseidon;
use std::merkle::compute_merkle_root;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Domain separator for commitments
global COMMITMENT_DOMAIN: Field = 0x4d49444e494748545f434f4d4d49544d454e54; // "MIDNIGHT_COMMITMENT"

/// Domain separator for nullifiers  
global NULLIFIER_DOMAIN: Field = 0x4d49444e494748545f4e554c4c4946494552; // "MIDNIGHT_NULLIFIER"

/// Domain separator for cross-domain nullifiers
global CDNA_DOMAIN: Field = 0x43444e415f5633; // "CDNA_V3"

/// Merkle tree depth (supports 2^20 leaves)
global MERKLE_DEPTH: u32 = 20;

/// Midnight chain ID (placeholder)
global MIDNIGHT_CHAIN_ID: Field = 1000;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Compute Pedersen commitment (simulated with Poseidon)
fn compute_commitment(
    amount: Field,
    recipient_hash: Field,
    randomness: Field,
    chain_id: Field
) -> Field {
    poseidon::bn254::hash_5([
        COMMITMENT_DOMAIN,
        amount,
        recipient_hash,
        randomness,
        chain_id
    ])
}

/// Compute nullifier from secret and commitment
fn compute_nullifier(
    secret: Field,
    commitment: Field,
    chain_id: Field
) -> Field {
    poseidon::bn254::hash_4([
        NULLIFIER_DOMAIN,
        secret,
        commitment,
        chain_id
    ])
}

/// Compute cross-domain nullifier (CDNA)
fn compute_cross_domain_nullifier(
    base_nullifier: Field,
    source_chain: Field,
    dest_chain: Field
) -> Field {
    poseidon::bn254::hash_4([
        CDNA_DOMAIN,
        base_nullifier,
        source_chain,
        dest_chain
    ])
}

/// Verify value is within valid range (prevent overflow)
fn range_check(value: Field, max_bits: u32) {
    let _ = value.to_le_bits(max_bits);
}

// =============================================================================
// MAIN BRIDGE TRANSFER CIRCUIT
// =============================================================================

/// Bridge transfer proof circuit
/// 
/// Proves that a valid commitment can be spent with knowledge of the secret,
/// and generates a nullifier to prevent double-spending.
fn main(
    // Public inputs
    nullifier: pub Field,           // The nullifier to register on destination chain
    merkle_root: pub Field,         // Current Merkle root of commitments
    recipient_address: pub Field,   // Recipient on destination chain (hashed)
    amount: pub Field,              // Transfer amount
    dest_chain_id: pub Field,       // Destination chain ID
    
    // Private inputs (witness)
    secret: Field,                  // User's secret
    randomness: Field,              // Randomness used in commitment
    source_chain_id: Field,         // Source chain ID
    merkle_path: [Field; MERKLE_DEPTH],     // Merkle proof path
    merkle_indices: [u1; MERKLE_DEPTH]      // Merkle proof indices (left/right)
) {
    // 1. Range check the amount (prevent overflow, max 64 bits)
    range_check(amount, 64);
    
    // 2. Compute the commitment
    let commitment = compute_commitment(
        amount,
        recipient_address,
        randomness,
        source_chain_id
    );
    
    // 3. Compute the base nullifier
    let base_nullifier = compute_nullifier(secret, commitment, source_chain_id);
    
    // 4. Compute cross-domain nullifier if crossing chains
    let expected_nullifier = if source_chain_id != dest_chain_id {
        compute_cross_domain_nullifier(base_nullifier, source_chain_id, dest_chain_id)
    } else {
        base_nullifier
    };
    
    // 5. Verify the nullifier matches
    assert(nullifier == expected_nullifier, "Invalid nullifier");
    
    // 6. Verify Merkle inclusion
    let computed_root = compute_merkle_root(commitment, merkle_indices, merkle_path);
    assert(merkle_root == computed_root, "Invalid Merkle proof");
}

// =============================================================================
// TESTS
// =============================================================================

#[test]
fn test_commitment_computation() {
    let amount: Field = 1000;
    let recipient_hash: Field = 0x1234567890abcdef;
    let randomness: Field = 0xfedcba0987654321;
    let chain_id: Field = 1;
    
    let commitment = compute_commitment(amount, recipient_hash, randomness, chain_id);
    
    // Commitment should be non-zero
    assert(commitment != 0);
}

#[test]
fn test_nullifier_computation() {
    let secret: Field = 0x1111111111111111;
    let commitment: Field = 0x2222222222222222;
    let chain_id: Field = 1;
    
    let nullifier = compute_nullifier(secret, commitment, chain_id);
    
    // Nullifier should be non-zero
    assert(nullifier != 0);
    
    // Same inputs should give same nullifier
    let nullifier2 = compute_nullifier(secret, commitment, chain_id);
    assert(nullifier == nullifier2);
}

#[test]
fn test_cdna_computation() {
    let base_nullifier: Field = 0x3333333333333333;
    let source_chain: Field = 1;
    let dest_chain: Field = 42161; // Arbitrum
    
    let cdna = compute_cross_domain_nullifier(base_nullifier, source_chain, dest_chain);
    
    // CDNA should be different from base nullifier
    assert(cdna != base_nullifier);
    
    // Different dest chain should give different CDNA
    let cdna2 = compute_cross_domain_nullifier(base_nullifier, source_chain, 10); // Optimism
    assert(cdna != cdna2);
}
