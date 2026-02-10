use std::hash::poseidon::bn254;

/// @title ContainerValidity
/// @notice PC3 Container Validity Circuit
/// 
/// Proves that a container is valid without revealing its contents.
/// This circuit validates:
/// 1. The encrypted payload matches the commitment
/// 2. The state commitment is correctly formed
/// 3. The nullifier is derived correctly from secret values
/// 4. The container hasn't expired

struct ContainerInputs<let PAYLOAD_CHUNKS: u32> {
    payload_chunks: [Field; PAYLOAD_CHUNKS],
    nullifier_secret: Field,
    salt: Field,
    secret_key: Field,
}

struct ContainerPublicInputs {
    state_commitment: Field,
    nullifier_hash: Field,
    current_timestamp: Field,
    expiry_timestamp: Field,
}

/// Compute payload commitment
fn compute_payload_commitment<let N: u32>(
    payload_chunks: [Field; N],
    salt: Field
) -> Field {
    // Hash payload chunks
    let payload_hash = if N <= 4 {
        bn254::hash_4([payload_chunks[0], payload_chunks[1], payload_chunks[2], payload_chunks[3]])
    } else {
        let h1 = bn254::hash_4([payload_chunks[0], payload_chunks[1], payload_chunks[2], payload_chunks[3]]);
        let h2 = bn254::hash_4([payload_chunks[4], payload_chunks[5], payload_chunks[6], payload_chunks[7]]);
        bn254::hash_2([h1, h2])
    };
    
    // Include salt
    bn254::hash_2([payload_hash, salt])
}

/// Compute state commitment from payload
fn compute_state_commitment(
    payload_commitment: Field,
    secret_key: Field,
    salt: Field
) -> Field {
    bn254::hash_4([payload_commitment, secret_key, salt, 0])
}

/// Compute nullifier hash
fn compute_nullifier(nullifier_secret: Field, secret_key: Field) -> Field {
    bn254::hash_2([nullifier_secret, secret_key])
}

/// Check if container has expired
fn is_not_expired(current: Field, expiry: Field) -> bool {
    let current_ts: u64 = current as u64;
    let expiry_ts: u64 = expiry as u64;
    current_ts < expiry_ts
}

/// Verify container validity
fn verify_container<let PAYLOAD_CHUNKS: u32>(
    inputs: ContainerInputs<PAYLOAD_CHUNKS>,
    public_inputs: ContainerPublicInputs
) -> bool {
    // Step 1: Verify payload commitment
    let payload_commitment = compute_payload_commitment(inputs.payload_chunks, inputs.salt);
    
    // Step 2: Verify state commitment includes payload
    let computed_state = compute_state_commitment(
        payload_commitment,
        inputs.secret_key,
        inputs.salt
    );
    let state_valid = computed_state == public_inputs.state_commitment;
    
    // Step 3: Verify nullifier derivation
    let computed_nullifier = compute_nullifier(inputs.nullifier_secret, inputs.secret_key);
    let nullifier_valid = computed_nullifier == public_inputs.nullifier_hash;
    
    // Step 4: Check expiry
    let not_expired = is_not_expired(public_inputs.current_timestamp, public_inputs.expiry_timestamp);
    
    state_valid & nullifier_valid & not_expired
}

/// Container transfer verification
struct TransferInputs {
    sender_secret_key: Field,
    sender_balance: Field,
    transfer_amount: Field,
    recipient_public_key: Field,
    sender_nullifier_secret: Field,
    recipient_salt: Field,
}

struct TransferPublicInputs {
    sender_nullifier_hash: Field,
    recipient_commitment: Field,
    transfer_hash: Field,
}

/// Verify container transfer
fn verify_transfer(inputs: TransferInputs, public_inputs: TransferPublicInputs) -> bool {
    // Step 1: Verify sender has sufficient balance
    let sender_bal: u64 = inputs.sender_balance as u64;
    let transfer_amt: u64 = inputs.transfer_amount as u64;
    let has_balance = sender_bal >= transfer_amt;
    
    // Step 2: Verify sender's nullifier
    let computed_nullifier = compute_nullifier(inputs.sender_nullifier_secret, inputs.sender_secret_key);
    let nullifier_valid = computed_nullifier == public_inputs.sender_nullifier_hash;
    
    // Step 3: Compute recipient's commitment
    let computed_recipient = bn254::hash_4([
        inputs.transfer_amount,
        inputs.recipient_public_key,
        inputs.recipient_salt,
        0
    ]);
    let commitment_valid = computed_recipient == public_inputs.recipient_commitment;
    
    // Step 4: Verify transfer hash
    let computed_transfer = bn254::hash_4([
        public_inputs.sender_nullifier_hash,
        public_inputs.recipient_commitment,
        inputs.transfer_amount,
        0
    ]);
    let transfer_valid = computed_transfer == public_inputs.transfer_hash;
    
    has_balance & nullifier_valid & commitment_valid & transfer_valid
}

/// Main entry point - 4 payload chunks
fn main(
    // Public inputs
    state_commitment: pub Field,
    nullifier_hash: pub Field,
    current_timestamp: pub Field,
    expiry_timestamp: pub Field,
    // Private inputs
    payload_chunks: [Field; 4],
    nullifier_secret: Field,
    salt: Field,
    secret_key: Field
) -> pub bool {
    let inputs = ContainerInputs {
        payload_chunks,
        nullifier_secret,
        salt,
        secret_key
    };
    
    let public_inputs = ContainerPublicInputs {
        state_commitment,
        nullifier_hash,
        current_timestamp,
        expiry_timestamp
    };
    
    verify_container(inputs, public_inputs)
}

#[test]
fn test_container_validity() {
    let payload: [Field; 4] = [1, 2, 3, 4];
    let salt = 0x1234;
    let secret_key = 0x5678;
    let nullifier_secret = 0xabcd;
    
    let payload_commitment = compute_payload_commitment(payload, salt);
    let state_commitment = compute_state_commitment(payload_commitment, secret_key, salt);
    let nullifier_hash = compute_nullifier(nullifier_secret, secret_key);
    
    let inputs = ContainerInputs {
        payload_chunks: payload,
        nullifier_secret,
        salt,
        secret_key
    };
    
    let public_inputs = ContainerPublicInputs {
        state_commitment,
        nullifier_hash,
        current_timestamp: 1000,
        expiry_timestamp: 2000
    };
    
    assert(verify_container(inputs, public_inputs));
}

#[test]
fn test_expired_container() {
    let current: Field = 3000;
    let expiry: Field = 2000;
    
    assert(!is_not_expired(current, expiry));
}
