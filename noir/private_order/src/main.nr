use std::hash::poseidon;

/// @title PrivateOrderCircuit
/// @notice Private Order Circuit for Soul Exchange
/// 
/// Proves:
/// 1. Order commitment is correctly formed
/// 2. Amount is within valid range
/// 3. Nullifier is correctly derived
/// 4. User has sufficient balance (using Merkle proof)

/// Order inputs structure
struct OrderInputs {
    // Order details (private)
    token_in: Field,         // Token being sold
    token_out: Field,        // Token being bought
    amount_in: Field,        // Amount to sell
    deadline: Field,         // Order deadline
    order_type: Field,       // Limit, Market, etc. (0-3)
    side: Field,             // Buy (0) or Sell (1)
    salt: Field,             // Random salt for commitment
    nullifier_secret: Field, // Secret for nullifier derivation
    
    // User details (private)
    user_address: Field,
    user_balance: Field,
}

/// Merkle proof for balance verification
struct BalanceMerkleProof<let DEPTH: u32> {
    path_elements: [Field; DEPTH],
    path_indices: [Field; DEPTH],
}

/// Compute order commitment hash
fn compute_order_commitment(
    token_in: Field,
    token_out: Field,
    amount_in: Field,
    min_amount_out: Field,
    deadline: Field,
    order_type: Field,
    side: Field,
    salt: Field
) -> Field {
    // Hash all order parameters
    let h1 = poseidon::bn254::hash_4([token_in, token_out, amount_in, min_amount_out]);
    let h2 = poseidon::bn254::hash_4([deadline, order_type, side, salt]);
    poseidon::bn254::hash_2([h1, h2])
}

/// Derive nullifier from secret and commitment
fn derive_nullifier(
    nullifier_secret: Field,
    order_commitment: Field,
    user_address: Field
) -> Field {
    poseidon::bn254::hash_4([nullifier_secret, order_commitment, user_address, 0])
}

/// Compute balance leaf hash
fn compute_balance_leaf(
    user_address: Field,
    token: Field,
    balance: Field
) -> Field {
    poseidon::bn254::hash_4([user_address, token, balance, 0])
}

/// Verify Merkle proof for balance tree
fn verify_merkle_proof<let DEPTH: u32>(
    leaf: Field,
    root: Field,
    path_elements: [Field; DEPTH],
    path_indices: [Field; DEPTH]
) -> bool {
    let mut current_hash = leaf;
    
    for i in 0..DEPTH {
        // Ensure path index is binary
        assert(path_indices[i] * (1 - path_indices[i]) == 0);
        
        // Select left and right based on path
        let (left, right) = if path_indices[i] == 0 {
            (current_hash, path_elements[i])
        } else {
            (path_elements[i], current_hash)
        };
        
        current_hash = poseidon::bn254::hash_2([left, right]);
    }
    
    current_hash == root
}

/// Verify order is valid
fn verify_order_constraints(inputs: OrderInputs, min_amount_out: Field) -> bool {
    // Amount must be positive
    let amount_positive = inputs.amount_in as u64 > 0;
    
    // Min output must be positive
    let min_out_positive = min_amount_out as u64 > 0;
    
    // Order type in valid range (0-3)
    let order_type_valid = inputs.order_type as u64 < 4;
    
    // Side in valid range (0-1)
    let side_valid = inputs.side as u64 < 2;
    
    // Tokens must be different
    let tokens_different = inputs.token_in != inputs.token_out;
    
    // Balance sufficient
    let balance_sufficient = inputs.user_balance as u64 >= inputs.amount_in as u64;
    
    amount_positive & min_out_positive & order_type_valid & side_valid & tokens_different & balance_sufficient
}

/// Main entry point for private order verification
/// DEPTH = 20 (supports ~1 million balance entries)
fn main(
    // Public inputs
    order_commitment: pub Field,
    nullifier_hash: pub Field,
    merkle_root: pub Field,
    min_amount_out: pub Field,
    
    // Private inputs - Order details
    token_in: Field,
    token_out: Field,
    amount_in: Field,
    deadline: Field,
    order_type: Field,
    side: Field,
    salt: Field,
    nullifier_secret: Field,
    
    // Private inputs - User details
    user_address: Field,
    user_balance: Field,
    
    // Private inputs - Merkle proof
    balance_path_elements: [Field; 20],
    balance_path_indices: [Field; 20]
) {
    // 1. Verify order commitment
    let computed_commitment = compute_order_commitment(
        token_in,
        token_out,
        amount_in,
        min_amount_out,
        deadline,
        order_type,
        side,
        salt
    );
    assert(computed_commitment == order_commitment);
    
    // 2. Verify nullifier derivation
    let computed_nullifier = derive_nullifier(
        nullifier_secret,
        order_commitment,
        user_address
    );
    assert(computed_nullifier == nullifier_hash);
    
    // 3. Verify balance Merkle proof
    let balance_leaf = compute_balance_leaf(user_address, token_in, user_balance);
    let merkle_valid = verify_merkle_proof(
        balance_leaf,
        merkle_root,
        balance_path_elements,
        balance_path_indices
    );
    assert(merkle_valid);
    
    // 4. Verify order constraints
    let inputs = OrderInputs {
        token_in,
        token_out,
        amount_in,
        deadline,
        order_type,
        side,
        salt,
        nullifier_secret,
        user_address,
        user_balance
    };
    
    assert(verify_order_constraints(inputs, min_amount_out));
}

/// Helper for external verification
fn verify_private_order(
    order_commitment: Field,
    nullifier_hash: Field,
    merkle_root: Field,
    min_amount_out: Field,
    inputs: OrderInputs,
    balance_path_elements: [Field; 20],
    balance_path_indices: [Field; 20]
) -> bool {
    // Verify commitment
    let computed_commitment = compute_order_commitment(
        inputs.token_in,
        inputs.token_out,
        inputs.amount_in,
        min_amount_out,
        inputs.deadline,
        inputs.order_type,
        inputs.side,
        inputs.salt
    );
    
    if computed_commitment != order_commitment {
        return false;
    }
    
    // Verify nullifier
    let computed_nullifier = derive_nullifier(
        inputs.nullifier_secret,
        order_commitment,
        inputs.user_address
    );
    
    if computed_nullifier != nullifier_hash {
        return false;
    }
    
    // Verify Merkle proof
    let balance_leaf = compute_balance_leaf(inputs.user_address, inputs.token_in, inputs.user_balance);
    let merkle_valid = verify_merkle_proof(
        balance_leaf,
        merkle_root,
        balance_path_elements,
        balance_path_indices
    );
    
    if !merkle_valid {
        return false;
    }
    
    // Verify constraints
    verify_order_constraints(inputs, min_amount_out)
}

#[test]
fn test_order_commitment() {
    let commitment = compute_order_commitment(
        1,  // token_in
        2,  // token_out
        100,// amount_in
        90, // min_amount_out
        1000000,  // deadline
        0,  // order_type (market)
        1,  // side (sell)
        12345  // salt
    );
    // Commitment should be non-zero
    assert(commitment != 0);
}

#[test]
fn test_nullifier_derivation() {
    let commitment = compute_order_commitment(1, 2, 100, 90, 1000000, 0, 1, 12345);
    let nullifier = derive_nullifier(99999, commitment, 0xabcd);
    // Nullifier should be non-zero
    assert(nullifier != 0);
    // Same inputs should give same nullifier
    let nullifier2 = derive_nullifier(99999, commitment, 0xabcd);
    assert(nullifier == nullifier2);
}

#[test]
fn test_balance_leaf() {
    let leaf = compute_balance_leaf(0xabcd, 1, 1000);
    assert(leaf != 0);
}
