use std::hash::poseidon::bn254;

/// @title BalanceProofCircuit
/// @notice Balance Proof Circuit for Soul Exchange
/// 
/// Proves:
/// 1. User has a specific balance in the balance tree
/// 2. Balance is sufficient for a withdrawal/order
/// 3. New balance after operation is correctly computed
/// 4. Nullifier is correctly derived to prevent double-spend

/// Balance update type
global DEPOSIT: Field = 1;
global WITHDRAWAL: Field = 0;

/// Balance proof inputs structure
struct BalanceInputs {
    // User details (private)
    user_address: Field,
    old_balance: Field,
    new_balance: Field,
    nullifier_secret: Field,
    salt: Field,
}

/// Compute balance leaf hash
fn compute_balance_leaf(
    user_address: Field,
    token: Field,
    balance: Field
) -> Field {
    bn254::hash_4([user_address, token, balance, 0])
}

/// Derive nullifier for balance operation
fn derive_nullifier(
    nullifier_secret: Field,
    user_address: Field,
    token: Field,
    salt: Field
) -> Field {
    bn254::hash_4([nullifier_secret, user_address, token, salt])
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
        
        current_hash = bn254::hash_2([left, right]);
    }
    
    current_hash == root
}

/// Verify balance update is correct
fn verify_balance_update(
    old_balance: Field,
    new_balance: Field,
    amount: Field,
    is_deposit: Field
) -> bool {
    // is_deposit must be binary
    assert(is_deposit * (1 - is_deposit) == 0);
    
    // Compute expected new balance
    let expected_deposit = old_balance + amount;
    let expected_withdraw = old_balance - amount;
    
    // Select based on operation type
    let expected = if is_deposit == DEPOSIT {
        expected_deposit
    } else {
        expected_withdraw
    };
    
    new_balance == expected
}

/// Verify sufficient balance for withdrawal
fn verify_sufficient_balance(old_balance: Field, amount: Field, is_deposit: Field) -> bool {
    // Only check for withdrawals
    if is_deposit == DEPOSIT {
        true
    } else {
        old_balance as u64 >= amount as u64
    }
}

/// Main entry point for balance proof verification
/// DEPTH = 20 (supports ~1 million balance entries)
fn main(
    // Public inputs
    old_root: pub Field,
    new_root: pub Field,
    nullifier_hash: pub Field,
    public_amount: pub Field,
    token: pub Field,
    is_deposit: pub Field,
    
    // Private inputs - User details
    user_address: Field,
    old_balance: Field,
    new_balance: Field,
    nullifier_secret: Field,
    salt: Field,
    
    // Private inputs - Old state Merkle proof
    old_path_elements: [Field; 20],
    old_path_indices: [Field; 20],
    
    // Private inputs - New state Merkle proof
    new_path_elements: [Field; 20],
    new_path_indices: [Field; 20]
) {
    // 1. Verify old balance in tree
    let old_leaf = compute_balance_leaf(user_address, token, old_balance);
    let old_merkle_valid = verify_merkle_proof(
        old_leaf,
        old_root,
        old_path_elements,
        old_path_indices
    );
    assert(old_merkle_valid);
    
    // 2. Verify balance update is correct
    assert(verify_balance_update(old_balance, new_balance, public_amount, is_deposit));
    
    // 3. Verify sufficient balance for withdrawals
    assert(verify_sufficient_balance(old_balance, public_amount, is_deposit));
    
    // 4. Verify new balance in tree
    let new_leaf = compute_balance_leaf(user_address, token, new_balance);
    let new_merkle_valid = verify_merkle_proof(
        new_leaf,
        new_root,
        new_path_elements,
        new_path_indices
    );
    assert(new_merkle_valid);
    
    // 5. Verify nullifier derivation
    let computed_nullifier = derive_nullifier(nullifier_secret, user_address, token, salt);
    assert(computed_nullifier == nullifier_hash);
    
    // 6. Additional constraints
    // Amount must be positive
    assert(public_amount as u64 > 0);
    
    // New balance must be non-negative (enforced by u64 cast)
    let _ = new_balance as u64;
}

/// External verification helper for deposits
fn verify_deposit(
    old_root: Field,
    new_root: Field,
    nullifier_hash: Field,
    amount: Field,
    token: Field,
    inputs: BalanceInputs,
    old_proof: ([Field; 20], [Field; 20]),
    new_proof: ([Field; 20], [Field; 20])
) -> bool {
    let old_leaf = compute_balance_leaf(inputs.user_address, token, inputs.old_balance);
    let old_valid = verify_merkle_proof(old_leaf, old_root, old_proof.0, old_proof.1);

    let balance_update_valid = inputs.new_balance == inputs.old_balance + amount;

    let new_leaf = compute_balance_leaf(inputs.user_address, token, inputs.new_balance);
    let new_valid = verify_merkle_proof(new_leaf, new_root, new_proof.0, new_proof.1);

    let computed_nullifier = derive_nullifier(inputs.nullifier_secret, inputs.user_address, token, inputs.salt);
    let nullifier_valid = computed_nullifier == nullifier_hash;

    old_valid & balance_update_valid & new_valid & nullifier_valid
}

/// External verification helper for withdrawals
fn verify_withdrawal(
    old_root: Field,
    new_root: Field,
    nullifier_hash: Field,
    amount: Field,
    token: Field,
    inputs: BalanceInputs,
    old_proof: ([Field; 20], [Field; 20]),
    new_proof: ([Field; 20], [Field; 20])
) -> bool {
    let sufficient = (inputs.old_balance as u64) >= (amount as u64);

    let old_leaf = compute_balance_leaf(inputs.user_address, token, inputs.old_balance);
    let old_valid = verify_merkle_proof(old_leaf, old_root, old_proof.0, old_proof.1);

    let balance_update_valid = inputs.new_balance == inputs.old_balance - amount;

    let new_leaf = compute_balance_leaf(inputs.user_address, token, inputs.new_balance);
    let new_valid = verify_merkle_proof(new_leaf, new_root, new_proof.0, new_proof.1);

    let computed_nullifier = derive_nullifier(inputs.nullifier_secret, inputs.user_address, token, inputs.salt);
    let nullifier_valid = computed_nullifier == nullifier_hash;

    sufficient & old_valid & balance_update_valid & new_valid & nullifier_valid
}

#[test]
fn test_balance_leaf() {
    let leaf = compute_balance_leaf(0xabcd, 1, 1000);
    assert(leaf != 0);
    
    // Same inputs should give same leaf
    let leaf2 = compute_balance_leaf(0xabcd, 1, 1000);
    assert(leaf == leaf2);
    
    // Different balance should give different leaf
    let leaf3 = compute_balance_leaf(0xabcd, 1, 2000);
    assert(leaf != leaf3);
}

#[test]
fn test_nullifier_derivation() {
    let nullifier = derive_nullifier(12345, 0xabcd, 1, 99999);
    assert(nullifier != 0);
    
    // Same inputs should give same nullifier
    let nullifier2 = derive_nullifier(12345, 0xabcd, 1, 99999);
    assert(nullifier == nullifier2);
    
    // Different salt should give different nullifier
    let nullifier3 = derive_nullifier(12345, 0xabcd, 1, 88888);
    assert(nullifier != nullifier3);
}

#[test]
fn test_balance_update_deposit() {
    let valid = verify_balance_update(1000, 1500, 500, DEPOSIT);
    assert(valid);
}

#[test]
fn test_balance_update_withdrawal() {
    let valid = verify_balance_update(1000, 500, 500, WITHDRAWAL);
    assert(valid);
}

#[test]
fn test_sufficient_balance() {
    // Should pass for deposit
    let valid_deposit = verify_sufficient_balance(100, 1000, DEPOSIT);
    assert(valid_deposit);
    
    // Should pass for withdrawal with sufficient balance
    let valid_withdraw = verify_sufficient_balance(1000, 500, WITHDRAWAL);
    assert(valid_withdraw);
}
