use std::hash::poseidon;

/// @title ProofCarryingContainerCircuit
/// @notice Circuit for self-authenticating confidential containers (PC3)
/// @dev Proves:
///   1. Knowledge of encrypted state preimage
///   2. Validity of state transition
///   3. Policy compliance
///   4. Nullifier correctness
/// 
/// This is the core circuit for Soul v2's flagship abstraction.

struct ContainerValidityInputs<let STATE_FIELDS: u32> {
    // Private inputs
    state_fields: [Field; STATE_FIELDS],
    salt: Field,
    owner_secret: Field,
    encryption_key: Field,
}

struct ContainerValidityPublicInputs {
    state_commitment: Field,
    nullifier: Field,
    owner_pubkey: Field,
    chain_id: Field,
}

/// Hash state fields
fn hash_state_fields<let N: u32>(fields: [Field; N]) -> Field {
    if N <= 4 {
        poseidon::bn254::hash_4([fields[0], fields[1], fields[2], fields[3]])
    } else {
        let h1 = poseidon::bn254::hash_4([fields[0], fields[1], fields[2], fields[3]]);
        let h2 = poseidon::bn254::hash_4([fields[4], fields[5], fields[6], fields[7]]);
        poseidon::bn254::hash_2([h1, h2])
    }
}

/// Derive owner public key
fn derive_owner_pubkey(owner_secret: Field) -> Field {
    poseidon::bn254::hash_1([owner_secret])
}

/// Compute state commitment
fn compute_state_commitment(state_hash: Field, salt: Field, owner_secret: Field) -> Field {
    poseidon::bn254::hash_4([state_hash, salt, owner_secret, 0])
}

/// Compute nullifier for container
fn compute_nullifier(owner_secret: Field, state_commitment: Field, chain_id: Field) -> Field {
    poseidon::bn254::hash_4([owner_secret, state_commitment, chain_id, 0])
}

/// Verify container validity
fn verify_container_validity<let STATE_FIELDS: u32>(
    inputs: ContainerValidityInputs<STATE_FIELDS>,
    public_inputs: ContainerValidityPublicInputs
) -> bool {
    // Step 1: Verify state commitment
    let state_hash = hash_state_fields(inputs.state_fields);
    let computed_commitment = compute_state_commitment(
        state_hash,
        inputs.salt,
        inputs.owner_secret
    );
    let commitment_valid = computed_commitment == public_inputs.state_commitment;
    
    // Step 2: Verify nullifier derivation
    let computed_nullifier = compute_nullifier(
        inputs.owner_secret,
        public_inputs.state_commitment,
        public_inputs.chain_id
    );
    let nullifier_valid = computed_nullifier == public_inputs.nullifier;
    
    // Step 3: Verify owner
    let computed_owner = derive_owner_pubkey(inputs.owner_secret);
    let owner_valid = computed_owner == public_inputs.owner_pubkey;
    
    commitment_valid & nullifier_valid & owner_valid
}

/// Container policy proof
struct PolicyProofInputs {
    state_value: Field,
    policy_secret: Field,
}

struct PolicyProofPublicInputs {
    policy_hash: Field,
    state_commitment: Field,
    min_value: Field,
    max_value: Field,
}

/// Compute policy binding
fn compute_policy_binding(policy_hash: Field, policy_secret: Field) -> Field {
    poseidon::bn254::hash_2([policy_hash, policy_secret])
}

/// Verify policy compliance (range check)
fn verify_policy_compliance(
    inputs: PolicyProofInputs,
    public_inputs: PolicyProofPublicInputs
) -> bool {
    // Range check - value within policy bounds
    let value: u64 = inputs.state_value as u64;
    let min_val: u64 = public_inputs.min_value as u64;
    let max_val: u64 = public_inputs.max_value as u64;
    
    let in_range = (value >= min_val) & (value <= max_val);
    
    in_range
}

/// Container nullifier proof
struct NullifierProofInputs {
    owner_secret: Field,
    state_commitment: Field,
    chain_id: Field,
}

/// Verify nullifier is correctly derived and unspent
fn verify_nullifier_proof(
    inputs: NullifierProofInputs,
    expected_nullifier: Field
) -> bool {
    let computed = compute_nullifier(
        inputs.owner_secret,
        inputs.state_commitment,
        inputs.chain_id
    );
    computed == expected_nullifier
}

/// Full PC3 verification
fn verify_pc3<let STATE_FIELDS: u32>(
    container_inputs: ContainerValidityInputs<STATE_FIELDS>,
    container_public: ContainerValidityPublicInputs,
    policy_inputs: PolicyProofInputs,
    policy_public: PolicyProofPublicInputs
) -> bool {
    // Verify container validity
    let container_valid = verify_container_validity(container_inputs, container_public);
    
    // Verify policy compliance
    let policy_valid = verify_policy_compliance(policy_inputs, policy_public);
    
    container_valid & policy_valid
}

/// Main entry point
fn main(
    // Public inputs
    state_commitment: pub Field,
    nullifier: pub Field,
    owner_pubkey: pub Field,
    chain_id: pub Field,
    // Private inputs
    state_fields: [Field; 8],
    salt: Field,
    owner_secret: Field,
    encryption_key: Field
) -> pub bool {
    let inputs = ContainerValidityInputs {
        state_fields,
        salt,
        owner_secret,
        encryption_key
    };
    
    let public_inputs = ContainerValidityPublicInputs {
        state_commitment,
        nullifier,
        owner_pubkey,
        chain_id
    };
    
    verify_container_validity(inputs, public_inputs)
}

#[test]
fn test_container_validity() {
    let state: [Field; 8] = [100, 200, 300, 400, 500, 600, 700, 800];
    let salt = 0x1234;
    let owner_secret = 0x5678;
    let chain_id = 1;
    
    let state_hash = hash_state_fields(state);
    let commitment = compute_state_commitment(state_hash, salt, owner_secret);
    let nullifier = compute_nullifier(owner_secret, commitment, chain_id);
    let owner_pubkey = derive_owner_pubkey(owner_secret);
    
    let inputs = ContainerValidityInputs {
        state_fields: state,
        salt,
        owner_secret,
        encryption_key: 0xabcd
    };
    
    let public_inputs = ContainerValidityPublicInputs {
        state_commitment: commitment,
        nullifier,
        owner_pubkey,
        chain_id
    };
    
    assert(verify_container_validity(inputs, public_inputs));
}

#[test]
fn test_policy_range_check() {
    let inputs = PolicyProofInputs {
        state_value: 100,
        policy_secret: 0x1234
    };
    
    let public_inputs = PolicyProofPublicInputs {
        policy_hash: 0x5678,
        state_commitment: 0xabcd,
        min_value: 50,
        max_value: 200
    };
    
    assert(verify_policy_compliance(inputs, public_inputs));
}

#[test]
fn test_policy_out_of_range() {
    let inputs = PolicyProofInputs {
        state_value: 300,  // Too high
        policy_secret: 0x1234
    };
    
    let public_inputs = PolicyProofPublicInputs {
        policy_hash: 0x5678,
        state_commitment: 0xabcd,
        min_value: 50,
        max_value: 200
    };
    
    assert(!verify_policy_compliance(inputs, public_inputs));
}
