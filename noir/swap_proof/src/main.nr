use std::hash::poseidon;

/// @title SwapProofCircuit
/// @notice Swap Proof Circuit for Soul Exchange AMM
/// 
/// Proves:
/// 1. User has sufficient input tokens
/// 2. Swap calculation is correct (constant product AMM)
/// 3. Slippage protection is satisfied
/// 4. Nullifiers are correctly derived
/// 5. Fee calculation is correct

/// Swap inputs structure
struct SwapInputs {
    // User details (private)
    user_address: Field,
    token_in: Field,
    token_out: Field,
    amount_in: Field,
    amount_out: Field,
    nullifier_secret: Field,
    salt: Field,
    
    // Balance details (private)
    old_balance_in: Field,
    old_balance_out: Field,
    new_balance_in: Field,
    new_balance_out: Field,
}

/// Pool state structure
struct PoolState {
    pool_id: Field,
    reserve_in: Field,
    reserve_out: Field,
    new_reserve_in: Field,
    new_reserve_out: Field,
    fee_rate: Field,  // In basis points (e.g., 30 = 0.3%)
}

/// Compute balance leaf hash
fn compute_balance_leaf(
    user_address: Field,
    token: Field,
    balance: Field
) -> Field {
    poseidon::bn254::hash_4([user_address, token, balance, 0])
}

/// Derive swap nullifier
fn derive_swap_nullifier(
    nullifier_secret: Field,
    user_address: Field,
    pool_id: Field,
    amount_in: Field,
    salt: Field
) -> Field {
    let h1 = poseidon::bn254::hash_4([nullifier_secret, user_address, pool_id, amount_in]);
    poseidon::bn254::hash_2([h1, salt])
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
        assert(path_indices[i] * (1 - path_indices[i]) == 0);
        
        let (left, right) = if path_indices[i] == 0 {
            (current_hash, path_elements[i])
        } else {
            (path_elements[i], current_hash)
        };
        
        current_hash = poseidon::bn254::hash_2([left, right]);
    }
    
    current_hash == root
}

/// Verify constant product invariant (x * y = k)
/// After swap: (x + dx) * (y - dy) >= x * y
fn verify_constant_product(pool: PoolState) -> bool {
    let old_k = pool.reserve_in * pool.reserve_out;
    let new_k = pool.new_reserve_in * pool.new_reserve_out;
    
    // New K should be >= old K (fees increase K)
    new_k as u64 >= old_k as u64
}

/// Verify reserve updates are correct
fn verify_reserve_updates(pool: PoolState, amount_in: Field, amount_out: Field) -> bool {
    let expected_new_reserve_in = pool.reserve_in + amount_in;
    let expected_new_reserve_out = pool.reserve_out - amount_out;
    
    (pool.new_reserve_in == expected_new_reserve_in) & 
    (pool.new_reserve_out == expected_new_reserve_out)
}

/// Verify AMM output calculation
/// amountOut = (amountIn * (10000 - fee) * reserveOut) / (reserveIn * 10000 + amountIn * (10000 - fee))
fn verify_amm_output(
    amount_in: Field,
    amount_out: Field,
    reserve_in: Field,
    reserve_out: Field,
    fee_rate: Field
) -> bool {
    let fee_adjusted = amount_in * (10000 - fee_rate);
    let numerator = fee_adjusted * reserve_out;
    let denominator = reserve_in * 10000 + fee_adjusted;
    
    // amountOut * denominator <= numerator (accounting for integer division)
    (amount_out * denominator) as u64 <= numerator as u64
}

/// Verify slippage protection
fn verify_slippage(amount_out: Field, min_amount_out: Field) -> bool {
    amount_out as u64 >= min_amount_out as u64
}

/// Verify fee calculation
fn verify_fee(amount_in: Field, fee_amount: Field, fee_rate: Field) -> bool {
    let expected_fee = (amount_in * fee_rate) / 10000;
    
    // Allow small rounding error (±1)
    let diff = if fee_amount as u64 >= expected_fee as u64 {
        fee_amount - expected_fee
    } else {
        expected_fee - fee_amount
    };
    
    diff as u64 <= 1
}

/// Verify user balance updates
fn verify_balance_updates(inputs: SwapInputs) -> bool {
    // Input token: new = old - amount_in
    let in_valid = inputs.new_balance_in == inputs.old_balance_in - inputs.amount_in;
    
    // Output token: new = old + amount_out
    let out_valid = inputs.new_balance_out == inputs.old_balance_out + inputs.amount_out;
    
    // Sufficient input balance
    let sufficient = inputs.old_balance_in as u64 >= inputs.amount_in as u64;
    
    in_valid & out_valid & sufficient
}

/// Verify tokens are different
fn verify_different_tokens(token_in: Field, token_out: Field) -> bool {
    token_in != token_out
}

/// Verify amounts are positive
fn verify_positive_amounts(amount_in: Field, amount_out: Field) -> bool {
    (amount_in as u64 > 0) & (amount_out as u64 > 0)
}

/// Verify fee rate is in valid range (0-10000 bps = 0-100%)
fn verify_fee_rate(fee_rate: Field) -> bool {
    fee_rate as u64 <= 10000
}

/// Main entry point for swap proof verification
/// DEPTH = 20 (supports ~1 million balance entries)
fn main(
    // Public inputs
    old_balance_root: pub Field,
    new_balance_root: pub Field,
    pool_id: pub Field,
    nullifier_hash: pub Field,
    min_amount_out: pub Field,
    fee_amount: pub Field,
    
    // Pool state (public)
    reserve_in: pub Field,
    reserve_out: pub Field,
    new_reserve_in: pub Field,
    new_reserve_out: pub Field,
    pool_fee_rate: pub Field,
    
    // Private inputs - Swap details
    user_address: Field,
    token_in: Field,
    token_out: Field,
    amount_in: Field,
    amount_out: Field,
    nullifier_secret: Field,
    salt: Field,
    
    // Private inputs - Balance details
    old_balance_in: Field,
    old_balance_out: Field,
    new_balance_in: Field,
    new_balance_out: Field,
    
    // Private inputs - Merkle proofs
    in_path_elements: [Field; 20],
    in_path_indices: [Field; 20],
    out_path_elements: [Field; 20],
    out_path_indices: [Field; 20]
) {
    // Build structs
    let pool = PoolState {
        pool_id,
        reserve_in,
        reserve_out,
        new_reserve_in,
        new_reserve_out,
        fee_rate: pool_fee_rate
    };
    
    let inputs = SwapInputs {
        user_address,
        token_in,
        token_out,
        amount_in,
        amount_out,
        nullifier_secret,
        salt,
        old_balance_in,
        old_balance_out,
        new_balance_in,
        new_balance_out
    };
    
    // 1. Verify constant product invariant
    assert(verify_constant_product(pool));
    
    // 2. Verify reserve updates
    assert(verify_reserve_updates(pool, amount_in, amount_out));
    
    // 3. Verify AMM output calculation
    assert(verify_amm_output(amount_in, amount_out, reserve_in, reserve_out, pool_fee_rate));
    
    // 4. Verify slippage protection
    assert(verify_slippage(amount_out, min_amount_out));
    
    // 5. Verify fee calculation
    assert(verify_fee(amount_in, fee_amount, pool_fee_rate));
    
    // 6. Verify user balance updates
    assert(verify_balance_updates(inputs));
    
    // 7. Verify nullifier derivation
    let computed_nullifier = derive_swap_nullifier(
        nullifier_secret,
        user_address,
        pool_id,
        amount_in,
        salt
    );
    assert(computed_nullifier == nullifier_hash);
    
    // 8. Verify old input balance Merkle proof
    let old_in_leaf = compute_balance_leaf(user_address, token_in, old_balance_in);
    let old_in_valid = verify_merkle_proof(
        old_in_leaf,
        old_balance_root,
        in_path_elements,
        in_path_indices
    );
    assert(old_in_valid);
    
    // 9. Additional constraints
    assert(verify_different_tokens(token_in, token_out));
    assert(verify_positive_amounts(amount_in, amount_out));
    assert(verify_fee_rate(pool_fee_rate));
}

/// Calculate expected output for a swap
fn calculate_swap_output(
    amount_in: Field,
    reserve_in: Field,
    reserve_out: Field,
    fee_rate: Field
) -> Field {
    let fee_adjusted = amount_in * (10000 - fee_rate);
    let numerator = fee_adjusted * reserve_out;
    let denominator = reserve_in * 10000 + fee_adjusted;
    
    numerator / denominator
}

/// Calculate required input for desired output
fn calculate_swap_input(
    amount_out: Field,
    reserve_in: Field,
    reserve_out: Field,
    fee_rate: Field
) -> Field {
    let numerator = reserve_in * amount_out * 10000;
    let denominator = (reserve_out - amount_out) * (10000 - fee_rate);
    
    // Add 1 to round up
    (numerator / denominator) + 1
}

/// Calculate price impact of a swap
fn calculate_price_impact(
    amount_in: Field,
    reserve_in: Field,
    reserve_out: Field
) -> Field {
    // Spot price = reserve_out / reserve_in
    // Execution price = amount_out / amount_in
    // Price impact = (spot - execution) / spot
    
    let spot_price_scaled = reserve_out * 10000 / reserve_in;
    let amount_out = calculate_swap_output(amount_in, reserve_in, reserve_out, 30); // 0.3% fee
    let execution_price_scaled = amount_out * 10000 / amount_in;
    
    if spot_price_scaled > execution_price_scaled {
        (spot_price_scaled - execution_price_scaled) * 10000 / spot_price_scaled
    } else {
        0
    }
}

#[test]
fn test_constant_product() {
    let pool = PoolState {
        pool_id: 1,
        reserve_in: 1000000,
        reserve_out: 1000000,
        new_reserve_in: 1001000,  // +1000 in
        new_reserve_out: 999001,   // -999 out (includes fee)
        fee_rate: 30
    };
    
    let valid = verify_constant_product(pool);
    assert(valid);
}

#[test]
fn test_reserve_updates() {
    let pool = PoolState {
        pool_id: 1,
        reserve_in: 1000000,
        reserve_out: 1000000,
        new_reserve_in: 1001000,
        new_reserve_out: 999000,
        fee_rate: 30
    };
    
    let valid = verify_reserve_updates(pool, 1000, 1000);
    assert(valid);
}

#[test]
fn test_slippage() {
    // Should pass when output >= minimum
    let valid = verify_slippage(1000, 900);
    assert(valid);
    
    // Should pass when output == minimum
    let valid2 = verify_slippage(900, 900);
    assert(valid2);
}

#[test]
fn test_fee_rate() {
    // 0.3% = 30 bps
    let valid = verify_fee_rate(30);
    assert(valid);
    
    // 100% = 10000 bps (edge case)
    let valid2 = verify_fee_rate(10000);
    assert(valid2);
}

#[test]
fn test_different_tokens() {
    let valid = verify_different_tokens(1, 2);
    assert(valid);
}

#[test]
fn test_swap_nullifier() {
    let nullifier = derive_swap_nullifier(12345, 0xabcd, 1, 1000, 99999);
    assert(nullifier != 0);
    
    // Same inputs should give same nullifier
    let nullifier2 = derive_swap_nullifier(12345, 0xabcd, 1, 1000, 99999);
    assert(nullifier == nullifier2);
}

#[test]
fn test_calculate_output() {
    // 1000 in with 1M/1M reserves and 0.3% fee
    let output = calculate_swap_output(1000, 1000000, 1000000, 30);
    // Should be approximately 997 (due to fee)
    assert(output as u64 > 990);
    assert(output as u64 < 1000);
}
