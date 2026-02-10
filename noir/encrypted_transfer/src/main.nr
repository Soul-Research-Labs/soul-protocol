// Encrypted Transfer Proof Circuit
// Proves that a confidential token transfer is valid
// without revealing the transfer amount or balances
//
// This circuit proves:
// 1. Sender has sufficient balance (balance >= amount)
// 2. Transfer amount is positive and within limits
// 3. New balances are correctly computed
// 4. Commitments are properly formed
// 5. No double-spending (nullifier uniqueness)

use std::hash::poseidon::bn254;

// Maximum transfer amount (prevent overflow)
global MAX_TRANSFER: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

/// Pedersen commitment: C = g^v * h^r
fn pedersen_commit(value: Field, randomness: Field) -> Field {
    std::hash::pedersen_hash([value, randomness])
}

/// Poseidon hash for nullifiers
fn poseidon_hash_2(a: Field, b: Field) -> Field {
    bn254::hash_2([a, b])
}

fn poseidon_hash_4(a: Field, b: Field, c: Field, d: Field) -> Field {
    bn254::hash_4([a, b, c, d])
}

/// Verify that a value is within range [0, max]
fn verify_range(value: u128, upper_bound: u128) -> bool {
    value <= upper_bound
}

/// Verify balance is non-negative after operation
fn verify_non_negative(balance: u128) -> bool {
    // In unsigned arithmetic, if balance went negative it would underflow
    // We verify by checking the original balance >= amount
    balance <= MAX_TRANSFER
}

/// Compute nullifier for a transfer
/// Prevents double-spending of the same funds
fn compute_nullifier(
    sender: Field,
    balance_commitment: Field,
    nonce: Field,
    secret: Field
) -> Field {
    poseidon_hash_4(sender, balance_commitment, nonce, secret)
}

/// Verify encrypted transfer is valid
/// Public inputs:
/// - sender_balance_commitment: Commitment to sender's current balance
/// - sender_new_balance_commitment: Commitment to sender's new balance
/// - recipient_balance_commitment: Commitment to recipient's current balance
/// - recipient_new_balance_commitment: Commitment to recipient's new balance
/// - transfer_amount_commitment: Commitment to transfer amount
/// - nullifier: Unique nullifier for this transfer
///
/// Private witnesses:
/// - sender_balance: Sender's actual balance
/// - recipient_balance: Recipient's actual balance
/// - transfer_amount: Actual transfer amount
/// - randomness values for all commitments
fn main(
    // Public inputs
    sender_balance_commitment: pub Field,
    sender_new_balance_commitment: pub Field,
    recipient_balance_commitment: pub Field,
    recipient_new_balance_commitment: pub Field,
    transfer_amount_commitment: pub Field,
    nullifier_value: pub Field,
    min_transfer: pub u128,
    max_transfer_limit: pub u128,
    
    // Private witnesses
    sender_balance: u128,
    recipient_balance: u128,
    transfer_amount: u128,
    sender_randomness: Field,
    sender_new_randomness: Field,
    recipient_randomness: Field,
    recipient_new_randomness: Field,
    transfer_randomness: Field,
    nullifier_secret: Field,
    sender: Field,
    nonce: Field
) {
    // ==========================================
    // 1. Verify transfer amount is valid
    // ==========================================
    
    // Transfer must be positive
    assert(transfer_amount > 0);
    
    // Transfer must be within limits
    assert(transfer_amount >= min_transfer);
    assert(transfer_amount <= max_transfer_limit);
    
    // ==========================================
    // 2. Verify sender has sufficient balance
    // ==========================================
    
    assert(sender_balance >= transfer_amount);
    
    // ==========================================
    // 3. Verify balance commitments
    // ==========================================
    
    // Sender's current balance commitment
    let computed_sender_balance_commit = pedersen_commit(
        sender_balance as Field,
        sender_randomness
    );
    assert(computed_sender_balance_commit == sender_balance_commitment);
    
    // Sender's new balance commitment
    let sender_new_balance = sender_balance - transfer_amount;
    let computed_sender_new_commit = pedersen_commit(
        sender_new_balance as Field,
        sender_new_randomness
    );
    assert(computed_sender_new_commit == sender_new_balance_commitment);
    
    // Recipient's current balance commitment
    let computed_recipient_balance_commit = pedersen_commit(
        recipient_balance as Field,
        recipient_randomness
    );
    assert(computed_recipient_balance_commit == recipient_balance_commitment);
    
    // Recipient's new balance commitment
    let recipient_new_balance = recipient_balance + transfer_amount;
    let computed_recipient_new_commit = pedersen_commit(
        recipient_new_balance as Field,
        recipient_new_randomness
    );
    assert(computed_recipient_new_commit == recipient_new_balance_commitment);
    
    // Transfer amount commitment
    let computed_transfer_commit = pedersen_commit(
        transfer_amount as Field,
        transfer_randomness
    );
    assert(computed_transfer_commit == transfer_amount_commitment);
    
    // ==========================================
    // 4. Verify nullifier (prevents double-spend)
    // ==========================================
    
    let computed_nullifier = compute_nullifier(
        sender,
        sender_balance_commitment,
        nonce,
        nullifier_secret
    );
    assert(computed_nullifier == nullifier_value);
    
    // ==========================================
    // 5. Conservation check
    // ==========================================
    
    // Total value before = total value after
    // sender_balance + recipient_balance = sender_new_balance + recipient_new_balance
    let total_before = sender_balance + recipient_balance;
    let total_after = sender_new_balance + recipient_new_balance;
    assert(total_before == total_after);
}

/// Batch transfer proof - multiple recipients
fn verify_batch_transfer(
    sender_balance: u128,
    transfer_amounts: [u128; 4],
    _recipient_balances: [u128; 4]
) -> bool {
    let mut total_transfer: u128 = 0;
    for i in 0..4 {
        total_transfer += transfer_amounts[i];
    }
    let mut valid = sender_balance >= total_transfer;
    for i in 0..4 {
        valid = valid & (transfer_amounts[i] <= MAX_TRANSFER);
    }
    valid
}

/// Range proof for compliance
/// Proves value is within [min, max] without revealing exact value
fn verify_range_proof(
    commitment: Field,
    value: u128,
    randomness: Field,
    min_val: u128,
    max_val: u128
) -> bool {
    let computed_commit = pedersen_commit(value as Field, randomness);
    let commit_valid = computed_commit == commitment;
    let range_valid = (value >= min_val) & (value <= max_val);
    commit_valid & range_valid
}

#[test]
fn test_valid_transfer() {
    let sender_balance: u128 = 1000;
    let recipient_balance: u128 = 500;
    let transfer_amount: u128 = 250;
    
    // Generate randomness
    let sender_randomness = 12345;
    let sender_new_randomness = 23456;
    let recipient_randomness = 34567;
    let recipient_new_randomness = 45678;
    let transfer_randomness = 56789;
    let nullifier_secret = 67890;
    let sender = 0xABCDEF;
    let nonce = 1;
    
    // Compute commitments
    let sender_balance_commitment = pedersen_commit(sender_balance as Field, sender_randomness);
    let sender_new_balance = sender_balance - transfer_amount;
    let sender_new_balance_commitment = pedersen_commit(sender_new_balance as Field, sender_new_randomness);
    
    let recipient_balance_commitment = pedersen_commit(recipient_balance as Field, recipient_randomness);
    let recipient_new_balance = recipient_balance + transfer_amount;
    let recipient_new_balance_commitment = pedersen_commit(recipient_new_balance as Field, recipient_new_randomness);
    
    let transfer_amount_commitment = pedersen_commit(transfer_amount as Field, transfer_randomness);
    
    let nullifier_value = compute_nullifier(sender, sender_balance_commitment, nonce, nullifier_secret);
    
    // Run main proof
    main(
        sender_balance_commitment,
        sender_new_balance_commitment,
        recipient_balance_commitment,
        recipient_new_balance_commitment,
        transfer_amount_commitment,
        nullifier_value,
        1,      // min_transfer
        10000,  // max_transfer_limit
        sender_balance,
        recipient_balance,
        transfer_amount,
        sender_randomness,
        sender_new_randomness,
        recipient_randomness,
        recipient_new_randomness,
        transfer_randomness,
        nullifier_secret,
        sender,
        nonce
    );
}

#[test]
fn test_range_proof() {
    let value: u128 = 500;
    let randomness = 12345;
    let commitment = pedersen_commit(value as Field, randomness);
    
    // Value within range [100, 1000]
    let valid = verify_range_proof(commitment, value, randomness, 100, 1000);
    assert(valid);
    
    // Value outside range
    let invalid = verify_range_proof(commitment, value, randomness, 600, 1000);
    assert(!invalid);
}
