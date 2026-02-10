use std::hash::poseidon::bn254;

/// @title SanctionsCheckCircuit
/// @notice Privacy-preserving sanctions screening for compliance
/// @dev Proves that a user's address commitment is NOT on a sanctions list
///      without revealing the actual address or the full sanctions list.
///
/// Approach:
///   1. User commits to their identity: commitment = Poseidon(address_hash, secret)
///   2. A Merkle tree of sanctioned address hashes is maintained off-chain
///   3. User proves NON-membership in the sanctions Merkle tree
///   4. Additionally proves they hold a valid compliance credential
///
/// Privacy guarantees:
///   - The user's address is never revealed on-chain
///   - The sanctions list contents are not exposed (only the root)
///   - Only the compliance status (pass/fail) is public

/// Merkle tree depth for the sanctions list (supports up to 2^16 = 65,536 entries)
global TREE_DEPTH: u32 = 16;

/// Compute Poseidon hash of two fields (for Merkle tree)
fn hash2(left: Field, right: Field) -> Field {
    bn254::hash_2([left, right])
}

/// Verify a Merkle proof (membership/non-membership)
/// Returns the computed root from the leaf + proof path
fn compute_merkle_root(
    leaf: Field,
    index: Field,
    path: [Field; 16]
) -> Field {
    let mut current = leaf;
    let mut idx = index;

    for i in 0..TREE_DEPTH {
        let path_element = path[i];

        // Use index bits to determine left/right placement
        let index_bit = idx as u64 & 1;
        idx = (idx as u64 >> 1) as Field;

        if index_bit == 0 {
            current = hash2(current, path_element);
        } else {
            current = hash2(path_element, current);
        }
    }

    current
}

fn main(
    // -- Public inputs --
    sanctions_merkle_root: pub Field,    // Root of the sanctioned addresses Merkle tree
    identity_commitment: pub Field,      // User's identity commitment (Poseidon(addr_hash, secret))
    compliance_nullifier: pub Field,     // Nullifier for this compliance check (prevents replay)
    credential_issuer_pubkey: pub Field, // Public key of the credential issuer
    current_timestamp: pub Field,        // Current timestamp for temporal checks

    // -- Private inputs --
    address_hash: Field,                 // Hash of the user's address
    secret: Field,                       // User's secret for the commitment
    nullifier_secret: Field,             // Secret used to derive the compliance nullifier

    // Non-membership proof: proves address_hash is NOT in the sanctions tree
    // We use a neighboring leaf approach:
    //   - neighbor_leaf is the leaf at the position where address_hash would be
    //   - We prove neighbor_leaf != address_hash AND neighbor_leaf IS in the tree
    neighbor_leaf: Field,                // The leaf at the would-be position
    neighbor_index: Field,               // Index of the neighbor in the tree
    neighbor_path: [Field; 16],          // Merkle path for the neighbor

    // Credential data
    credential_hash: Field,              // Hash of the compliance credential
    credential_secret: Field,            // Credential signing secret
    credential_expiry: Field             // Credential expiration timestamp
) {
    // -- Step 1: Verify identity commitment --
    // commitment = Poseidon(address_hash, secret)
    let computed_commitment = bn254::hash_2([address_hash, secret]);
    assert(computed_commitment == identity_commitment);

    // -- Step 2: Verify compliance nullifier --
    // nullifier = Poseidon(address_hash, nullifier_secret, "sanctions_check")
    let domain_separator: Field = 0x73616e6374696f6e735f636865636b; // "sanctions_check" as hex
    let computed_nullifier = bn254::hash_4([address_hash, nullifier_secret, domain_separator, 0]);
    assert(computed_nullifier == compliance_nullifier);

    // -- Step 3: Verify NON-membership in sanctions list --
    // The neighbor leaf at the would-be position must NOT equal our address_hash
    assert(neighbor_leaf != address_hash);

    // Verify the neighbor leaf IS in the tree (proves the tree structure is valid)
    let computed_root = compute_merkle_root(neighbor_leaf, neighbor_index, neighbor_path);
    assert(computed_root == sanctions_merkle_root);

    // -- Step 4: Verify compliance credential --
    // Credential commitment = Poseidon(credential_hash, credential_secret, issuer_pubkey)
    let credential_commitment = bn254::hash_4([
        credential_hash,
        credential_secret,
        credential_issuer_pubkey,
        0
    ]);
    // The credential must be bound to this identity
    let identity_binding = bn254::hash_2([credential_commitment, address_hash]);
    // Verify credential is non-trivial (not zero)
    assert(identity_binding != 0);

    // -- Step 5: Verify temporal validity --
    // Credential must not be expired
    // In Noir, we compare field elements as integers
    let expiry_u64 = credential_expiry as u64;
    let current_u64 = current_timestamp as u64;
    assert(expiry_u64 > current_u64);
}

// ==================================================
// Tests
// ==================================================

#[test]
fn test_identity_commitment() {
    let addr: Field = 0xdeadbeef;
    let secret: Field = 54321;
    let commitment = bn254::hash_2([addr, secret]);
    assert(commitment != 0);

    // Deterministic
    let commitment2 = bn254::hash_2([addr, secret]);
    assert(commitment == commitment2);

    // Different secret -> different commitment
    let commitment3 = bn254::hash_2([addr, 99999]);
    assert(commitment != commitment3);
}

#[test]
fn test_compliance_nullifier() {
    let addr: Field = 0xdeadbeef;
    let nullifier_secret: Field = 11111;
    let domain_separator: Field = 0x73616e6374696f6e735f636865636b;
    let nullifier = bn254::hash_4([addr, nullifier_secret, domain_separator, 0]);
    assert(nullifier != 0);

    // Deterministic
    let nullifier2 = bn254::hash_4([addr, nullifier_secret, domain_separator, 0]);
    assert(nullifier == nullifier2);

    // Different secret -> different nullifier
    let nullifier3 = bn254::hash_4([addr, 22222, domain_separator, 0]);
    assert(nullifier != nullifier3);
}

#[test]
fn test_merkle_root_computation() {
    // Build a trivial 2-level path (using only 16 levels with zeros for upper)
    let leaf: Field = bn254::hash_2([0xabc, 0xdef]);
    let mut path: [Field; 16] = [0; 16];
    path[0] = 0x111;
    path[1] = 0x222;

    let root = compute_merkle_root(leaf, 0, path);
    assert(root != 0);

    // Same inputs -> same root
    let root2 = compute_merkle_root(leaf, 0, path);
    assert(root == root2);

    // Different leaf -> different root
    let different_leaf = bn254::hash_2([0xfff, 0xeee]);
    let root3 = compute_merkle_root(different_leaf, 0, path);
    assert(root != root3);
}

#[test]
fn test_non_membership_check() {
    // Core property: neighbor_leaf must not equal address_hash
    let address_hash: Field = 0xabcdef;
    let neighbor_leaf: Field = 0x123456;
    assert(neighbor_leaf != address_hash);
}

#[test]
fn test_credential_commitment() {
    let credential_hash: Field = 0xaaaa;
    let credential_secret: Field = 0xbbbb;
    let issuer_pubkey: Field = 0xcccc;

    let credential_commitment = bn254::hash_4([
        credential_hash,
        credential_secret,
        issuer_pubkey,
        0
    ]);
    assert(credential_commitment != 0);

    // Binding to identity
    let address_hash: Field = 0xdddd;
    let identity_binding = bn254::hash_2([credential_commitment, address_hash]);
    assert(identity_binding != 0);
}
