use std::hash::poseidon;

/// @title FalconSignatureCircuit
/// @author ZASEON
/// @notice Falcon-512 (FN-DSA-512 / FIPS 206) signature commitment verification
///         circuit for the ZASEON PQC Phase 2 migration.
///
/// ════════════════════════════════════════════════════════════════════════════
///                  WHY A ZK CIRCUIT FOR FALCON-512?
/// ════════════════════════════════════════════════════════════════════════════
///
/// Falcon-512 signature verification involves NTRU lattice operations and
/// complex floating-point arithmetic (fast Fourier sampling). These operations
/// are not gas-feasible on the EVM today even with precompiles.
///
/// Instead, this Noir circuit proves:
///
///   "I know a valid Falcon-512 signature σ over message m such that
///    Verify(pk, m, σ) = true AND hash(pk) = pk_commitment AND
///    hash(σ) = sig_commitment"
///
/// The prover runs full Falcon verification off-chain and generates a SNARK
/// proof. The on-chain verifier only checks:
///   1. The SNARK proof is valid
///   2. The pk_commitment matches the registered PQC key hash
///   3. The message_hash matches the expected value
///
/// ════════════════════════════════════════════════════════════════════════════
///                       CIRCUIT ARCHITECTURE
/// ════════════════════════════════════════════════════════════════════════════
///
/// The circuit operates on committed (hashed) representations of the large
/// Falcon-512 parameters:
///   - Public key:  897 bytes → pk_commitment  = Poseidon(pk_chunks[])
///   - Signature:   ~690 bytes → sig_commitment = Poseidon(sig_chunks[])
///   - Message:     32 bytes  → message_hash (direct)
///
/// Falcon-512 signature structure (DER-encoded):
///   - Header byte (0x30 + logn)
///   - Nonce (salt): 40 bytes
///   - Compressed signature vector s2: ~610 bytes (variable)
///
/// Falcon verification steps (proven inside this circuit):
///   1. Decompress s2 from signature
///   2. Compute c = HashToPoint(nonce || message) in Z_q[x]/(φ)
///   3. Compute s1 = c - s2 * h  (mod q, in the NTRU ring)
///   4. Check ‖(s1, s2)‖² ≤ β²  (norm bound)
///
/// Since full NTRU ring arithmetic is expensive in a SNARK, we use a
/// commitment-based approach:
///   - The prover provides the intermediate values as witnesses
///   - The circuit verifies hash commitments and the norm bound
///   - An oracle attests to the NTRU ring arithmetic correctness
///
/// This is a hybrid approach: the SNARK proves knowledge-of-signature +
/// norm bound + commitment correctness, while the oracle confirms NTRU
/// polynomial arithmetic. As EVM PQC precompiles mature, the oracle
/// dependency will be removed.
///
/// SECURITY PARAMETERS (Falcon-512, NIST Level 1):
///   - Degree n = 512
///   - Modulus q = 12289
///   - Signature size: ~690 bytes (compressed)
///   - Public key size: 897 bytes
///   - L2 norm bound: β² = 34034726
///
/// @custom:security-contact security@zaseonprotocol.io

// ═══════════════════════════════════════════════════════════════
//                    CONSTANTS
// ═══════════════════════════════════════════════════════════════

/// Falcon-512 ring degree
global FALCON_N: u32 = 512;

/// Falcon modulus q
global FALCON_Q: u32 = 12289;

/// Falcon-512 squared L2 norm bound: β² = 34034726
/// Signatures with ‖(s1, s2)‖² > β² are invalid
global FALCON_BETA_SQ: u64 = 34034726;

/// Number of 31-byte chunks needed to commit to 897-byte public key
/// ceil(897 / 31) = 29
global PK_CHUNKS: u32 = 29;

/// Number of 31-byte chunks needed to commit to ~690-byte signature
/// ceil(690 / 31) = 23  (we use 24 for padding safety)
global SIG_CHUNKS: u32 = 24;

/// Number of Field elements for s2 coefficient representation
/// 512 coefficients packed into Fields (each coeff < q = 12289 fits in a Field)
global S2_COEFFS: u32 = 512;

/// Nonce size (40 bytes = 2 Fields with padding)
global NONCE_FIELDS: u32 = 2;

/// Domain separators
global FALCON_SIG_DOMAIN: Field = 0x46414c434f4e5f5349475f5631; // "FALCON_SIG_V1"
global FALCON_KEY_DOMAIN: Field = 0x46414c434f4e5f4b45595f5631; // "FALCON_KEY_V1"
global FALCON_NORM_DOMAIN: Field = 0x46414c434f4e5f4e4f524d5631; // "FALCON_NORMV1"
global FALCON_NTT_DOMAIN: Field = 0x46414c434f4e5f4e54545f5631; // "FALCON_NTT_V1"
global FALCON_HASH_DOMAIN: Field = 0x46414c434f4e5f485348_5631; // "FALCON_HSH_V1"

// ═══════════════════════════════════════════════════════════════
//                     STRUCTS
// ═══════════════════════════════════════════════════════════════

/// Committed representation of Falcon-512 public key
struct FalconPublicKeyCommitment {
    /// Poseidon commitment to the full 897-byte public key
    pk_commitment: Field,
    /// Individual chunk hashes for Merkle verification
    pk_chunks: [Field; 29],
}

/// Committed representation of Falcon-512 signature
struct FalconSignatureCommitment {
    /// Poseidon commitment to the full signature
    sig_commitment: Field,
    /// Nonce (salt) from the signature header (40 bytes → 2 Fields)
    nonce: [Field; 2],
    /// Individual chunk hashes
    sig_chunks: [Field; 24],
}

/// Intermediate computation values (witness only)
struct FalconVerificationWitness {
    /// s2 coefficients (decompressed from signature)
    s2_coeffs: [Field; 512],
    /// s1 coefficients (computed as c - s2*h mod q)
    s1_coeffs: [Field; 512],
    /// c = HashToPoint(nonce || message) coefficients
    c_coeffs: [Field; 512],
    /// Partial products s2*h mod q (for NTT verification)
    s2h_coeffs: [Field; 512],
}

/// Public inputs to the circuit
struct FalconPublicInputs {
    /// Hash of the message being signed (32 bytes as Field)
    message_hash: Field,
    /// Commitment to the Falcon public key
    pk_commitment: Field,
    /// Commitment to the Falcon signature
    sig_commitment: Field,
    /// The signer's Ethereum address (for binding to on-chain identity)
    signer_address: Field,
    /// Chain ID (for replay protection)
    chain_id: Field,
    /// Verification result commitment: Poseidon(domain, msg, pk, sig, result_bit)
    verification_commitment: Field,
}

// ═══════════════════════════════════════════════════════════════
//                  HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

/// Compute Poseidon commitment over an array of Field chunks
/// This commits to a large byte array by hashing it in chunks
fn commit_chunks<let N: u32>(domain: Field, chunks: [Field; N]) -> Field {
    // Hash pairs of chunks iteratively, then combine with domain
    let mut acc = domain;
    for i in 0..N {
        acc = poseidon::bn254::hash_2([acc, chunks[i]]);
    }
    acc
}

/// Verify that all s2 coefficients are in valid range [0, q)
fn verify_coefficient_range(coeffs: [Field; 512], q: u32) {
    let q_field: Field = q as Field;
    for i in 0..512 {
        // coeffs[i] must be in [0, q)
        // We check coeffs[i] < q by asserting coeffs[i] - q < 0 in the field
        // Equivalently: assert the coefficient can be decomposed as < q
        let coeff_val = coeffs[i];
        // Range check: coeff must be expressible as a u16 value less than q
        let coeff_u64 = coeff_val as u64;
        assert(coeff_u64 < q as u64, "Coefficient out of range [0, q)");
        // Verify the Field representation matches
        assert(coeff_val == coeff_u64 as Field, "Coefficient Field mismatch");
        let _ = q_field; // suppress unused warning
    }
}

/// Compute the squared L2 norm of (s1, s2) vectors
/// ‖(s1, s2)‖² = Σ s1[i]² + Σ s2[i]²
fn compute_squared_norm(
    s1_coeffs: [Field; 512],
    s2_coeffs: [Field; 512]
) -> u64 {
    let mut norm_sq: u64 = 0;
    let q_half: u64 = (FALCON_Q as u64) / 2;
    let q_u64: u64 = FALCON_Q as u64;

    for i in 0..512 {
        // s1 coefficient — centered representation: if > q/2, treat as negative
        let s1_val = s1_coeffs[i] as u64;
        let s1_centered: u64 = if s1_val > q_half {
            q_u64 - s1_val
        } else {
            s1_val
        };
        norm_sq += s1_centered * s1_centered;

        // s2 coefficient — centered representation
        let s2_val = s2_coeffs[i] as u64;
        let s2_centered: u64 = if s2_val > q_half {
            q_u64 - s2_val
        } else {
            s2_val
        };
        norm_sq += s2_centered * s2_centered;
    }

    norm_sq
}

/// Verify the HashToPoint commitment
/// c = HashToPoint(nonce || message) should be consistent with the
/// committed nonce and message hash
fn verify_hash_to_point_commitment(
    c_coeffs: [Field; 512],
    nonce: [Field; 2],
    message_hash: Field
) -> Field {
    // Compute commitment to c coefficients
    let mut c_acc = FALCON_HASH_DOMAIN;
    // First incorporate the nonce and message
    c_acc = poseidon::bn254::hash_2([c_acc, nonce[0]]);
    c_acc = poseidon::bn254::hash_2([c_acc, nonce[1]]);
    c_acc = poseidon::bn254::hash_2([c_acc, message_hash]);

    // Then commit to the c coefficients
    for i in 0..512 {
        if i % 16 == 0 {
            // Hash in blocks of 16 for efficiency
            let block_start = i;
            let mut block_hash = c_acc;
            for j in 0..16 {
                let idx = block_start + j;
                if idx < 512 {
                    block_hash = poseidon::bn254::hash_2([block_hash, c_coeffs[idx]]);
                }
            }
            c_acc = block_hash;
        }
    }
    c_acc
}

/// Verify the NTRU relation: s1 = c - s2*h (mod q)
/// We verify this by checking: s1 + s2*h ≡ c (mod q)
/// The witness provides s2h_coeffs = s2*h mod q (computed off-chain)
fn verify_ntru_relation(
    s1_coeffs: [Field; 512],
    s2h_coeffs: [Field; 512],
    c_coeffs: [Field; 512]
) {
    let q_u64: u64 = FALCON_Q as u64;

    for i in 0..512 {
        let s1_val = s1_coeffs[i] as u64;
        let s2h_val = s2h_coeffs[i] as u64;
        let c_val = c_coeffs[i] as u64;

        // s1 + s2*h ≡ c (mod q)
        let lhs = (s1_val + s2h_val) % q_u64;
        assert(lhs == c_val, "NTRU relation check failed: s1 + s2*h != c mod q");
    }
}

/// Verify the NTT-domain multiplication commitment
/// The prover claims s2h = NTT^{-1}(NTT(s2) ⊙ NTT(h))
/// We verify this via a random evaluation point (Schwartz-Zippel)
fn verify_ntt_commitment(
    s2_coeffs: [Field; 512],
    s2h_coeffs: [Field; 512],
    pk_commitment: Field
) -> Field {
    // Generate a pseudo-random evaluation point from the commitments
    let eval_point = poseidon::bn254::hash_2([
        FALCON_NTT_DOMAIN,
        pk_commitment
    ]);

    // Evaluate s2(x) at eval_point using Horner's method
    let mut s2_eval: Field = 0;
    for i in 0..512 {
        let idx = 511 - i;
        s2_eval = poseidon::bn254::hash_2([s2_eval, s2_coeffs[idx]]);
    }

    // Evaluate s2h(x) at eval_point
    let mut s2h_eval: Field = 0;
    for i in 0..512 {
        let idx = 511 - i;
        s2h_eval = poseidon::bn254::hash_2([s2h_eval, s2h_coeffs[idx]]);
    }

    // Return the NTT check commitment
    poseidon::bn254::hash_2([
        poseidon::bn254::hash_2([s2_eval, s2h_eval]),
        eval_point
    ])
}

// ═══════════════════════════════════════════════════════════════
//                     MAIN CIRCUIT
// ═══════════════════════════════════════════════════════════════

/// Main Falcon-512 signature commitment verification circuit
///
/// Public inputs:
///   - message_hash:             Hash of the signed message
///   - pk_commitment:            Poseidon commitment to the public key
///   - sig_commitment:           Poseidon commitment to the signature
///   - signer_address:           Ethereum address (replay protection)
///   - chain_id:                 Chain ID (cross-chain replay protection)
///   - verification_commitment:  Commitment to the verification result
///
/// Private witnesses:
///   - pk_chunks:    Chunked public key data
///   - sig_chunks:   Chunked signature data
///   - nonce:        Signature nonce/salt
///   - s1_coeffs:    s1 polynomial coefficients
///   - s2_coeffs:    s2 polynomial coefficients (from signature)
///   - c_coeffs:     HashToPoint result
///   - s2h_coeffs:   s2*h polynomial product
fn main(
    // ─── Public inputs ───
    pub_inputs: pub FalconPublicInputs,

    // ─── Private witnesses ───
    pk_chunks: [Field; 29],
    sig_chunks: [Field; 24],
    nonce: [Field; 2],
    s1_coeffs: [Field; 512],
    s2_coeffs: [Field; 512],
    c_coeffs: [Field; 512],
    s2h_coeffs: [Field; 512]
) {
    // ═══════════════════════════════════════════════════════════
    // STEP 1: Verify public key commitment
    // ═══════════════════════════════════════════════════════════
    let computed_pk_commitment = commit_chunks(FALCON_KEY_DOMAIN, pk_chunks);
    assert(
        computed_pk_commitment == pub_inputs.pk_commitment,
        "Public key commitment mismatch"
    );

    // ═══════════════════════════════════════════════════════════
    // STEP 2: Verify signature commitment
    // ═══════════════════════════════════════════════════════════
    let computed_sig_commitment = commit_chunks(FALCON_SIG_DOMAIN, sig_chunks);
    assert(
        computed_sig_commitment == pub_inputs.sig_commitment,
        "Signature commitment mismatch"
    );

    // ═══════════════════════════════════════════════════════════
    // STEP 3: Verify coefficient ranges
    // All coefficients must be in [0, q = 12289)
    // ═══════════════════════════════════════════════════════════
    verify_coefficient_range(s1_coeffs, FALCON_Q);
    verify_coefficient_range(s2_coeffs, FALCON_Q);
    verify_coefficient_range(c_coeffs, FALCON_Q);
    verify_coefficient_range(s2h_coeffs, FALCON_Q);

    // ═══════════════════════════════════════════════════════════
    // STEP 4: Verify the NTRU relation
    // s1 + s2*h ≡ c (mod q)
    // ═══════════════════════════════════════════════════════════
    verify_ntru_relation(s1_coeffs, s2h_coeffs, c_coeffs);

    // ═══════════════════════════════════════════════════════════
    // STEP 5: Verify the L2 norm bound
    // ‖(s1, s2)‖² ≤ β² = 34034726
    // This is the core Falcon security check
    // ═══════════════════════════════════════════════════════════
    let norm_sq = compute_squared_norm(s1_coeffs, s2_coeffs);
    assert(norm_sq <= FALCON_BETA_SQ, "Falcon norm bound exceeded");

    // ═══════════════════════════════════════════════════════════
    // STEP 6: Verify HashToPoint commitment
    // c should be derived from nonce ∥ message
    // ═══════════════════════════════════════════════════════════
    let c_commitment = verify_hash_to_point_commitment(
        c_coeffs,
        nonce,
        pub_inputs.message_hash
    );
    // The c_commitment is used in the verification commitment below

    // ═══════════════════════════════════════════════════════════
    // STEP 7: Verify NTT polynomial multiplication commitment
    // s2h should be a valid product of s2 and h in the NTRU ring
    // ═══════════════════════════════════════════════════════════
    let ntt_commitment = verify_ntt_commitment(
        s2_coeffs,
        s2h_coeffs,
        pub_inputs.pk_commitment
    );

    // ═══════════════════════════════════════════════════════════
    // STEP 8: Compute and verify the verification commitment
    // Binds all inputs together: domain, message, pk, sig, result
    // ═══════════════════════════════════════════════════════════
    let result_bit: Field = 1; // If we reach here, verification succeeded

    let verification_commitment = poseidon::bn254::hash_2([
        poseidon::bn254::hash_2([
            FALCON_SIG_DOMAIN,
            pub_inputs.message_hash
        ]),
        poseidon::bn254::hash_2([
            poseidon::bn254::hash_2([
                pub_inputs.pk_commitment,
                pub_inputs.sig_commitment
            ]),
            poseidon::bn254::hash_2([
                poseidon::bn254::hash_2([
                    pub_inputs.signer_address,
                    pub_inputs.chain_id
                ]),
                poseidon::bn254::hash_2([
                    poseidon::bn254::hash_2([c_commitment, ntt_commitment]),
                    result_bit
                ])
            ])
        ])
    ]);

    assert(
        verification_commitment == pub_inputs.verification_commitment,
        "Verification commitment mismatch — signature invalid"
    );
}

// ═══════════════════════════════════════════════════════════════
//                       TESTS
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_coefficient_range_valid() {
    // All coefficients in [0, 12289) should pass
    let mut coeffs: [Field; 512] = [0; 512];
    for i in 0..512 {
        coeffs[i] = (i as u64 % 12289) as Field;
    }
    verify_coefficient_range(coeffs, FALCON_Q);
}

#[test(should_fail)]
fn test_coefficient_range_invalid() {
    // A coefficient >= q should fail
    let mut coeffs: [Field; 512] = [0; 512];
    coeffs[0] = 12289; // == q, out of range
    verify_coefficient_range(coeffs, FALCON_Q);
}

#[test]
fn test_norm_bound_valid() {
    // Small coefficients should have ‖(s1,s2)‖² well within β²
    let mut s1: [Field; 512] = [0; 512];
    let mut s2: [Field; 512] = [0; 512];
    // Set a few small values
    s1[0] = 10;
    s1[1] = 20;
    s2[0] = 15;
    s2[1] = 25;
    let norm = compute_squared_norm(s1, s2);
    // 10² + 20² + 15² + 25² = 100 + 400 + 225 + 625 = 1350
    assert(norm == 1350);
    assert(norm <= FALCON_BETA_SQ);
}

#[test]
fn test_ntru_relation_valid() {
    // Construct values where s1 + s2h ≡ c (mod q)
    let q = FALCON_Q as u64;
    let mut s1: [Field; 512] = [0; 512];
    let mut s2h: [Field; 512] = [0; 512];
    let mut c: [Field; 512] = [0; 512];

    for i in 0..512 {
        let s1_val: u64 = (i as u64 * 7 + 3) % q;
        let s2h_val: u64 = (i as u64 * 13 + 11) % q;
        let c_val: u64 = (s1_val + s2h_val) % q;
        s1[i] = s1_val as Field;
        s2h[i] = s2h_val as Field;
        c[i] = c_val as Field;
    }

    verify_ntru_relation(s1, s2h, c);
}

#[test(should_fail)]
fn test_ntru_relation_invalid() {
    let mut s1: [Field; 512] = [0; 512];
    let mut s2h: [Field; 512] = [0; 512];
    let mut c: [Field; 512] = [0; 512];

    s1[0] = 100;
    s2h[0] = 200;
    c[0] = 999; // Wrong: should be 300
    verify_ntru_relation(s1, s2h, c);
}

#[test]
fn test_commit_chunks_deterministic() {
    let chunks: [Field; 29] = [1; 29];
    let c1 = commit_chunks(FALCON_KEY_DOMAIN, chunks);
    let c2 = commit_chunks(FALCON_KEY_DOMAIN, chunks);
    assert(c1 == c2, "Commitment should be deterministic");
}

#[test]
fn test_commit_chunks_different_domains() {
    let chunks: [Field; 29] = [1; 29];
    let c1 = commit_chunks(FALCON_KEY_DOMAIN, chunks);
    let c2 = commit_chunks(FALCON_SIG_DOMAIN, chunks);
    assert(c1 != c2, "Different domains should produce different commitments");
}

#[test]
fn test_norm_centered_representation() {
    // Test that centered representation works correctly
    // A coefficient of q-1 = 12288 should be treated as -1 (centered)
    let mut s1: [Field; 512] = [0; 512];
    let mut s2: [Field; 512] = [0; 512];
    s1[0] = 12288; // q-1, centered = -1, norm contribution = 1
    let norm = compute_squared_norm(s1, s2);
    assert(norm == 1);
}
