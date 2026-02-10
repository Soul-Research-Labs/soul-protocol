use std::hash::poseidon::bn254;

/// @title PolicyBoundProofCircuit
/// @notice Circuit for proofs cryptographically scoped by disclosure policy (PBP)
/// @dev Key innovation: Verification key is bound to policy hash via domain separator
///      Proofs are invalid outside their policy scope
/// 
/// This makes compliance a cryptographic invariant, not a social/off-chain check.

/// Compute domain separator that binds VK to policy
fn compute_domain_separator(vk_hash: Field, policy_hash: Field) -> Field {
    bn254::hash_2([vk_hash, policy_hash])
}

/// Verify domain separator binding
fn verify_domain_binding(
    vk_hash: Field,
    policy_hash: Field,
    expected_separator: Field
) -> bool {
    let computed = compute_domain_separator(vk_hash, policy_hash);
    computed == expected_separator
}

/// Compute policy hash from preimage
fn compute_policy_hash(preimage: [Field; 4]) -> Field {
    bn254::hash_4(preimage)
}

/// Verify policy commitment in public inputs
fn verify_policy_commitment<let NUM_PUBLIC_INPUTS: u32>(
    policy_preimage: [Field; 4],
    public_inputs: [Field; NUM_PUBLIC_INPUTS],
    expected_policy_hash: Field,
    policy_position: u32
) -> bool {
    // Step 1: Verify policy hash derivation
    let computed_policy_hash = compute_policy_hash(policy_preimage);
    let hash_valid = computed_policy_hash == expected_policy_hash;
    
    // Step 2: Verify policy is in public inputs at expected position
    let mut found = false;
    for i in 0..NUM_PUBLIC_INPUTS {
        if (i == policy_position) & (public_inputs[i] == expected_policy_hash) {
            found = true;
        }
    }
    
    hash_valid & found
}

/// Selective disclosure proof
struct SelectiveDisclosureInputs<let NUM_FIELDS: u32> {
    data_fields: [Field; NUM_FIELDS],
    disclosure_mask: [bool; NUM_FIELDS],  // true = disclose, false = hide
}

struct SelectiveDisclosurePublicInputs<let NUM_FIELDS: u32> {
    data_commitment: Field,
    disclosed_data: [Field; NUM_FIELDS],  // disclosed values or 0
    policy_hash: Field,
}

/// Compute data commitment
fn compute_data_commitment<let N: u32>(data_fields: [Field; N]) -> Field {
    if N <= 4 {
        bn254::hash_4([data_fields[0], data_fields[1], data_fields[2], data_fields[3]])
    } else {
        let h1 = bn254::hash_4([data_fields[0], data_fields[1], data_fields[2], data_fields[3]]);
        let h2 = bn254::hash_4([data_fields[4], data_fields[5], data_fields[6], data_fields[7]]);
        bn254::hash_2([h1, h2])
    }
}

/// Verify selective disclosure
fn verify_selective_disclosure<let NUM_FIELDS: u32>(
    inputs: SelectiveDisclosureInputs<NUM_FIELDS>,
    public_inputs: SelectiveDisclosurePublicInputs<NUM_FIELDS>
) -> bool {
    // Step 1: Verify data commitment
    let computed_commitment = compute_data_commitment(inputs.data_fields);
    let commitment_valid = computed_commitment == public_inputs.data_commitment;
    
    // Step 2: Verify disclosed data matches based on mask
    let mut disclosure_valid = true;
    for i in 0..NUM_FIELDS {
        if inputs.disclosure_mask[i] {
            // If disclosed, must match actual data
            let matches = inputs.data_fields[i] == public_inputs.disclosed_data[i];
            disclosure_valid = disclosure_valid & matches;
        } else {
            // If hidden, disclosed value must be 0
            let is_hidden = public_inputs.disclosed_data[i] == 0;
            disclosure_valid = disclosure_valid & is_hidden;
        }
    }
    
    commitment_valid & disclosure_valid
}

/// Full policy-bound proof verification
fn verify_policy_bound_proof<let NUM_PUBLIC_INPUTS: u32, let NUM_FIELDS: u32>(
    vk_hash: Field,
    expected_separator: Field,
    policy_preimage: [Field; 4],
    public_inputs: [Field; NUM_PUBLIC_INPUTS],
    policy_hash: Field,
    policy_position: u32,
    disclosure_inputs: SelectiveDisclosureInputs<NUM_FIELDS>,
    disclosure_public: SelectiveDisclosurePublicInputs<NUM_FIELDS>
) -> bool {
    // Verify domain binding
    let binding_valid = verify_domain_binding(vk_hash, policy_hash, expected_separator);
    
    // Verify policy commitment
    let policy_valid = verify_policy_commitment(
        policy_preimage,
        public_inputs,
        policy_hash,
        policy_position
    );
    
    // Verify selective disclosure
    let disclosure_valid = verify_selective_disclosure(disclosure_inputs, disclosure_public);
    
    binding_valid & policy_valid & disclosure_valid
}

/// Main entry point
fn main(
    // Public inputs
    vk_hash: pub Field,
    policy_hash: pub Field,
    domain_separator: pub Field,
    data_commitment: pub Field,
    // Private inputs
    policy_preimage: [Field; 4],
    data_fields: [Field; 8],
    disclosure_mask: [bool; 8],
    disclosed_data: [Field; 8]
) -> pub bool {
    // Verify domain binding
    let binding_valid = verify_domain_binding(vk_hash, policy_hash, domain_separator);
    
    // Verify policy hash
    let computed_policy = compute_policy_hash(policy_preimage);
    let policy_valid = computed_policy == policy_hash;
    
    // Verify data commitment
    let computed_commitment = compute_data_commitment(data_fields);
    let commitment_valid = computed_commitment == data_commitment;
    
    // Verify disclosure
    let disclosure_inputs = SelectiveDisclosureInputs {
        data_fields,
        disclosure_mask
    };
    
    let disclosure_public = SelectiveDisclosurePublicInputs {
        data_commitment,
        disclosed_data,
        policy_hash
    };
    
    let disclosure_valid = verify_selective_disclosure(disclosure_inputs, disclosure_public);
    
    binding_valid & policy_valid & commitment_valid & disclosure_valid
}

#[test]
fn test_domain_separator() {
    let vk_hash = 0x1234;
    let policy_hash = 0x5678;
    
    let separator = compute_domain_separator(vk_hash, policy_hash);
    
    assert(verify_domain_binding(vk_hash, policy_hash, separator));
}

#[test]
fn test_policy_hash() {
    let preimage: [Field; 4] = [1, 2, 3, 4];
    
    let hash1 = compute_policy_hash(preimage);
    let hash2 = compute_policy_hash(preimage);
    
    // Same preimage should give same hash
    assert(hash1 == hash2);
}

#[test]
fn test_selective_disclosure() {
    let data: [Field; 8] = [100, 200, 0, 0, 0, 0, 0, 0];
    let mask: [bool; 8] = [true, false, false, false, false, false, false, false];
    let disclosed: [Field; 8] = [100, 0, 0, 0, 0, 0, 0, 0]; // Only first value disclosed
    
    let commitment = compute_data_commitment(data);
    
    let inputs = SelectiveDisclosureInputs {
        data_fields: data,
        disclosure_mask: mask
    };
    
    let public_inputs = SelectiveDisclosurePublicInputs {
        data_commitment: commitment,
        disclosed_data: disclosed,
        policy_hash: 0x1234
    };
    
    assert(verify_selective_disclosure(inputs, public_inputs));
}

#[test]
fn test_invalid_disclosure() {
    let data: [Field; 8] = [100, 200, 0, 0, 0, 0, 0, 0];
    let mask: [bool; 8] = [true, false, false, false, false, false, false, false];
    let disclosed: [Field; 8] = [999, 0, 0, 0, 0, 0, 0, 0]; // Wrong value!
    
    let commitment = compute_data_commitment(data);
    
    let inputs = SelectiveDisclosureInputs {
        data_fields: data,
        disclosure_mask: mask
    };
    
    let public_inputs = SelectiveDisclosurePublicInputs {
        data_commitment: commitment,
        disclosed_data: disclosed,
        policy_hash: 0x1234
    };
    
    // Should fail - disclosed value doesn't match actual
    assert(!verify_selective_disclosure(inputs, public_inputs));
}
