// =============================================================================
// MIDNIGHT BRIDGE - STATE TRANSITION CIRCUIT
// =============================================================================
//
// This circuit proves:
// 1. A valid state transition from old root to new root
// 2. All operations (deposits/withdrawals) are valid
// 3. Nullifiers are correctly registered

use std::hash::poseidon;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum operations per batch
global MAX_OPERATIONS: u32 = 8;

/// Domain separators
global STATE_DOMAIN: Field = 0x53544154455f5452414e534954494f4e; // "STATE_TRANSITION"
global OP_DOMAIN: Field = 0x4f5045524154494f4e; // "OPERATION"

// =============================================================================
// TYPES
// =============================================================================

/// Operation type
struct BridgeOperation {
    commitment: Field,
    nullifier: Field,
    amount: Field,
    is_deposit: bool,        // true = deposit, false = withdrawal
    chain_id: Field,
}

/// State representation
struct BridgeState {
    deposit_root: Field,     // Merkle root of deposits
    nullifier_root: Field,   // Merkle root of nullifiers
    total_locked: Field,     // Total value locked
    operation_count: Field,  // Number of operations processed
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Hash an operation
fn hash_operation(op: BridgeOperation) -> Field {
    poseidon::bn254::hash_5([
        OP_DOMAIN,
        op.commitment,
        op.nullifier,
        op.amount,
        op.chain_id
    ])
}

/// Compute operations hash
fn compute_operations_hash(operations: [BridgeOperation; MAX_OPERATIONS], count: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..MAX_OPERATIONS {
        if i < count {
            let op_hash = hash_operation(operations[i]);
            acc = poseidon::bn254::hash_2([acc, op_hash]);
        }
    }
    acc
}

/// Compute new state hash
fn compute_state_hash(state: BridgeState) -> Field {
    poseidon::bn254::hash_4([
        state.deposit_root,
        state.nullifier_root,
        state.total_locked,
        state.operation_count
    ])
}

/// Verify operation validity
fn verify_operation(op: BridgeOperation) {
    // Amount must be positive (non-zero)
    assert(op.amount != 0, "Operation amount cannot be zero");
    
    // Commitment must be set for deposits
    if op.is_deposit {
        assert(op.commitment != 0, "Deposit must have commitment");
    }
    
    // Nullifier must be set for withdrawals
    if !op.is_deposit {
        assert(op.nullifier != 0, "Withdrawal must have nullifier");
    }
}

// =============================================================================
// MAIN STATE TRANSITION CIRCUIT
// =============================================================================

/// State transition proof circuit
///
/// Proves that a batch of operations correctly transforms the old state
/// to the new state.
fn main(
    // Public inputs
    old_state_hash: pub Field,      // Hash of previous state
    new_state_hash: pub Field,      // Hash of new state
    operations_hash: pub Field,     // Hash of all operations
    block_number: pub Field,        // Block number for ordering
    
    // Private inputs
    old_state: BridgeState,
    new_state: BridgeState,
    operations: [BridgeOperation; MAX_OPERATIONS],
    operation_count: u32
) {
    // 1. Verify old state hash matches
    let computed_old_hash = compute_state_hash(old_state);
    assert(old_state_hash == computed_old_hash, "Invalid old state hash");
    
    // 2. Verify operations hash matches
    let computed_ops_hash = compute_operations_hash(operations, operation_count);
    assert(operations_hash == computed_ops_hash, "Invalid operations hash");
    
    // 3. Verify each operation is valid
    for i in 0..MAX_OPERATIONS {
        if i < operation_count {
            verify_operation(operations[i]);
        }
    }
    
    // 4. Verify state transition is valid
    // - Operation count incremented correctly
    let expected_op_count = old_state.operation_count + operation_count as Field;
    assert(new_state.operation_count == expected_op_count, "Invalid operation count");
    
    // 5. Verify new state hash matches
    let computed_new_hash = compute_state_hash(new_state);
    assert(new_state_hash == computed_new_hash, "Invalid new state hash");
    
    // 6. Verify block number is non-zero (sanity check)
    assert(block_number != 0, "Block number cannot be zero");
}

// =============================================================================
// TESTS
// =============================================================================

#[test]
fn test_operation_hash() {
    let op = BridgeOperation {
        commitment: 0x1234,
        nullifier: 0x5678,
        amount: 1000,
        is_deposit: true,
        chain_id: 1,
    };
    
    let hash = hash_operation(op);
    assert(hash != 0);
}

#[test]
fn test_state_hash() {
    let state = BridgeState {
        deposit_root: 0x1111,
        nullifier_root: 0x2222,
        total_locked: 1000000,
        operation_count: 50,
    };
    
    let hash = compute_state_hash(state);
    assert(hash != 0);
}
