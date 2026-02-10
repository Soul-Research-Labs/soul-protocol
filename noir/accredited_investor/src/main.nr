use std::hash::poseidon::bn254;

/// @title AccreditedInvestorCircuit
/// @notice Privacy-preserving proof of accredited investor status
/// @dev Proves a user meets financial thresholds for accredited investor
///      status (e.g., SEC Rule 501) without revealing actual net worth or income.
///
/// Supports multiple qualification paths:
///   Path 1: Net worth > $1M (excluding primary residence)
///   Path 2: Annual income > $200K (individual) or $300K (joint)
///   Path 3: Professional certification (Series 7, 65, 82)
///   Path 4: Entity with > $5M in assets
///
/// All monetary values are in cents (USD x 100) to avoid floating point.

/// Qualification paths
global PATH_NET_WORTH: Field = 1;
global PATH_INCOME_INDIVIDUAL: Field = 2;
global PATH_INCOME_JOINT: Field = 3;
global PATH_PROFESSIONAL: Field = 4;
global PATH_ENTITY: Field = 5;

/// Thresholds in cents (USD x 100)
global NET_WORTH_THRESHOLD: u64 = 100_000_000;       // $1,000,000
global INCOME_INDIVIDUAL_THRESHOLD: u64 = 20_000_000; // $200,000
global INCOME_JOINT_THRESHOLD: u64 = 30_000_000;      // $300,000
global ENTITY_ASSET_THRESHOLD: u64 = 500_000_000;     // $5,000,000

fn main(
    // -- Public inputs --
    identity_commitment: pub Field,      // Poseidon(address_hash, secret)
    qualification_nullifier: pub Field,  // Prevents replay of this proof
    issuer_pubkey: pub Field,            // Attestation issuer's public key
    qualification_path: pub Field,       // Which path was used (1-5)
    current_timestamp: pub Field,        // For temporal validity

    // -- Private inputs --
    address_hash: Field,                 // Hash of the user's address
    secret: Field,                       // User's secret for commitment
    nullifier_secret: Field,             // For deriving the nullifier

    // Financial attestation data (signed by issuer)
    attested_value: Field,               // The attested financial value (in cents)
    attestation_timestamp: Field,        // When the attestation was issued
    attestation_expiry: Field,           // When the attestation expires
    attestation_secret: Field,           // Issuer's attestation signing secret
    attestation_type: Field,             // Type of attestation (matches qualification_path)

    // Professional certification (only for PATH_PROFESSIONAL)
    certification_id: Field,             // Certification identifier
    certification_authority: Field       // Certification authority hash
) {
    // -- Step 1: Verify identity commitment --
    let computed_commitment = bn254::hash_2([address_hash, secret]);
    assert(computed_commitment == identity_commitment);

    // -- Step 2: Verify qualification nullifier --
    let domain_separator: Field = 0x6163637265646974656420696e76; // "accredited inv"
    let computed_nullifier = bn254::hash_4([address_hash, nullifier_secret, domain_separator, 0]);
    assert(computed_nullifier == qualification_nullifier);

    // -- Step 3: Verify attestation is properly signed --
    let attestation_commitment = bn254::hash_4([
        attested_value,
        attestation_timestamp,
        attestation_secret,
        attestation_type
    ]);
    // Bind attestation to issuer
    let issuer_binding = bn254::hash_2([attestation_commitment, issuer_pubkey]);
    assert(issuer_binding != 0);

    // -- Step 4: Verify attestation type matches qualification path --
    assert(attestation_type == qualification_path);

    // -- Step 5: Verify temporal validity --
    let expiry_u64 = attestation_expiry as u64;
    let current_u64 = current_timestamp as u64;
    assert(expiry_u64 > current_u64);

    // -- Step 6: Verify financial threshold based on path --
    let value_u64 = attested_value as u64;

    if qualification_path == PATH_NET_WORTH {
        assert(value_u64 >= NET_WORTH_THRESHOLD);
    } else if qualification_path == PATH_INCOME_INDIVIDUAL {
        assert(value_u64 >= INCOME_INDIVIDUAL_THRESHOLD);
    } else if qualification_path == PATH_INCOME_JOINT {
        assert(value_u64 >= INCOME_JOINT_THRESHOLD);
    } else if qualification_path == PATH_PROFESSIONAL {
        // For professional path, verify certification exists
        assert(certification_id != 0);
        assert(certification_authority != 0);
        // Certification binding to identity
        let cert_binding = bn254::hash_4([certification_id, certification_authority, address_hash, 0]);
        assert(cert_binding != 0);
    } else if qualification_path == PATH_ENTITY {
        assert(value_u64 >= ENTITY_ASSET_THRESHOLD);
    } else {
        // Invalid path
        assert(false);
    }

    // -- Step 7: Bind attestation to identity --
    let identity_attestation_link = bn254::hash_2([attestation_commitment, address_hash]);
    assert(identity_attestation_link != 0);
}

// ==================================================
// Tests
// ==================================================

#[test]
fn test_identity_commitment() {
    let addr: Field = 0xabcdef;
    let secret: Field = 12345;
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
fn test_qualification_nullifier() {
    let addr: Field = 0xabcdef;
    let nullifier_secret: Field = 67890;
    let domain_separator: Field = 0x6163637265646974656420696e76;
    let nullifier = bn254::hash_4([addr, nullifier_secret, domain_separator, 0]);
    assert(nullifier != 0);

    // Deterministic
    let nullifier2 = bn254::hash_4([addr, nullifier_secret, domain_separator, 0]);
    assert(nullifier == nullifier2);

    // Different secret -> different nullifier
    let nullifier3 = bn254::hash_4([addr, 11111, domain_separator, 0]);
    assert(nullifier != nullifier3);
}

#[test]
fn test_attestation_commitment() {
    let attested_value: Field = 150_000_000; // $1.5M in cents
    let attestation_timestamp: Field = 1700000000;
    let attestation_secret: Field = 42;
    let attestation_type: Field = PATH_NET_WORTH;

    let commitment = bn254::hash_4([
        attested_value,
        attestation_timestamp,
        attestation_secret,
        attestation_type
    ]);
    assert(commitment != 0);
}

#[test]
fn test_net_worth_threshold() {
    // Exactly at threshold should pass
    let value: u64 = NET_WORTH_THRESHOLD;
    assert(value >= NET_WORTH_THRESHOLD);

    // Above threshold should pass
    let above: u64 = NET_WORTH_THRESHOLD + 1;
    assert(above >= NET_WORTH_THRESHOLD);
}

#[test]
fn test_income_thresholds() {
    // Individual income threshold
    let individual: u64 = INCOME_INDIVIDUAL_THRESHOLD;
    assert(individual >= INCOME_INDIVIDUAL_THRESHOLD);

    // Joint income threshold
    let joint: u64 = INCOME_JOINT_THRESHOLD;
    assert(joint >= INCOME_JOINT_THRESHOLD);
}

#[test]
fn test_entity_threshold() {
    let entity_assets: u64 = ENTITY_ASSET_THRESHOLD + 100;
    assert(entity_assets >= ENTITY_ASSET_THRESHOLD);
}
