// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PQCLib
 * @author Soul Protocol
 * @notice Library for Post-Quantum Cryptography types, utilities, and hybrid signatures
 * @dev Implements NIST PQC standards: ML-DSA (Dilithium), SLH-DSA (SPHINCS+), ML-KEM (Kyber)
 *
 * SUPPORTED ALGORITHMS:
 * ┌──────────────────┬─────────────────┬───────────────────┬────────────────────┐
 * │ Algorithm        │ Type            │ NIST Level        │ Status             │
 * ├──────────────────┼─────────────────┼───────────────────┼────────────────────┤
 * │ ML-DSA-65        │ Digital Sig     │ Level 3 (128-bit) │ FIPS 204 Final     │
 * │ ML-DSA-87        │ Digital Sig     │ Level 5 (192-bit) │ FIPS 204 Final     │
 * │ SLH-DSA-128s     │ Digital Sig     │ Level 1           │ FIPS 205 Final     │
 * │ SLH-DSA-256s     │ Digital Sig     │ Level 5           │ FIPS 205 Final     │
 * │ ML-KEM-768       │ KEM             │ Level 3 (128-bit) │ FIPS 203 Final     │
 * │ ML-KEM-1024      │ KEM             │ Level 5 (192-bit) │ FIPS 203 Final     │
 * └──────────────────┴─────────────────┴───────────────────┴────────────────────┘
 *
 * @custom:security-contact security@soulprotocol.io
 */
library PQCLib {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Magic bytes for hybrid signature identification
    bytes4 public constant HYBRID_SIG_MAGIC = 0x50514331; // "PQC1"

    /// @notice Current format version
    uint8 public constant VERSION = 1;

    /// @notice ECDSA signature size (r, s, v)
    uint256 public constant ECDSA_SIG_SIZE = 65;

    // ML-DSA (Dilithium) sizes
    uint256 public constant DILITHIUM3_PK_SIZE = 1952;
    uint256 public constant DILITHIUM3_SIG_SIZE = 3293;
    uint256 public constant DILITHIUM5_PK_SIZE = 2592;
    uint256 public constant DILITHIUM5_SIG_SIZE = 4595;

    // SLH-DSA (SPHINCS+) sizes
    uint256 public constant SPHINCS_128S_PK_SIZE = 32;
    uint256 public constant SPHINCS_128S_SIG_SIZE = 7856;
    uint256 public constant SPHINCS_128F_SIG_SIZE = 17088;
    uint256 public constant SPHINCS_256S_PK_SIZE = 64;
    uint256 public constant SPHINCS_256S_SIG_SIZE = 29792;
    uint256 public constant SPHINCS_256F_SIG_SIZE = 49856;

    // ML-KEM (Kyber) sizes
    uint256 public constant KYBER512_PK_SIZE = 800;
    uint256 public constant KYBER512_CT_SIZE = 768;
    uint256 public constant KYBER768_PK_SIZE = 1184;
    uint256 public constant KYBER768_CT_SIZE = 1088;
    uint256 public constant KYBER1024_PK_SIZE = 1568;
    uint256 public constant KYBER1024_CT_SIZE = 1568;
    uint256 public constant SHARED_SECRET_SIZE = 32;

    // Domain separators
    bytes32 public constant DILITHIUM_DOMAIN = keccak256("SOUL_DILITHIUM_V1");
    bytes32 public constant SPHINCS_DOMAIN = keccak256("SOUL_SPHINCS_V1");
    bytes32 public constant KYBER_DOMAIN = keccak256("SOUL_KYBER_V1");
    bytes32 public constant HYBRID_DOMAIN = keccak256("SOUL_HYBRID_PQC_V1");

    // =============================================================================
    // ENUMS
    // =============================================================================

    /// @notice Post-quantum signature algorithms
    enum SignatureAlgorithm {
        None,
        Dilithium3, // ML-DSA-65 (NIST Level 3)
        Dilithium5, // ML-DSA-87 (NIST Level 5)
        SPHINCSPlus128s, // SLH-DSA-128s (hash-based, small)
        SPHINCSPlus128f, // SLH-DSA-128f (hash-based, fast)
        SPHINCSPlus256s, // SLH-DSA-256s (hash-based, small, high security)
        SPHINCSPlus256f // SLH-DSA-256f (hash-based, fast, high security)
    }

    /// @notice Key encapsulation mechanisms
    enum KEMAlgorithm {
        None,
        Kyber512, // ML-KEM-512 (NIST Level 1)
        Kyber768, // ML-KEM-768 (NIST Level 3, recommended)
        Kyber1024 // ML-KEM-1024 (NIST Level 5)
    }

    /// @notice Verification modes for gradual transition
    enum VerificationMode {
        Mock, // Testing only - DO NOT USE IN PRODUCTION
        PureSolidity, // Full Solidity verification (~5-10M gas)
        OffchainZK, // ZK proof of off-chain verification (~300K gas)
        Precompile // Future EIP precompile (~50K gas)
    }

    /// @notice Transition phases for PQC adoption
    enum TransitionPhase {
        ClassicalOnly, // Only classical crypto (ECDSA)
        HybridOptional, // Hybrid available but optional
        HybridMandatory, // Hybrid required for new operations
        PQPreferred, // PQ preferred, classical still accepted
        PQOnly // Only PQ accepted (post-quantum era)
    }

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /// @notice Hybrid signature combining classical and post-quantum
    struct HybridSignature {
        bytes4 magic; // Magic bytes for identification
        uint8 version; // Format version
        SignatureAlgorithm algorithm; // PQ algorithm used
        bytes ecdsaSig; // Classical ECDSA signature (65 bytes)
        bytes pqSignature; // Post-quantum signature
        bytes pqPublicKey; // Post-quantum public key
    }

    /// @notice Compact hybrid signature (for storage efficiency)
    struct CompactHybridSignature {
        bytes4 magic;
        uint8 version;
        SignatureAlgorithm algorithm;
        bytes32 ecdsaR;
        bytes32 ecdsaS;
        uint8 ecdsaV;
        bytes pqSignature;
        bytes32 pqPublicKeyHash; // Hash only, lookup key separately
    }

    /// @notice PQC account configuration
    struct AccountConfig {
        bytes32 signatureKeyHash; // Hash of signature public key
        bytes32 kemKeyHash; // Hash of KEM public key
        SignatureAlgorithm sigAlgorithm;
        KEMAlgorithm kemAlgorithm;
        uint64 registeredAt;
        bool hybridEnabled;
        bool isActive;
    }

    /// @notice Verification request
    struct VerificationRequest {
        SignatureAlgorithm algorithm;
        bytes publicKey;
        bytes message;
        bytes signature;
    }

    /// @notice Verification result
    struct VerificationResult {
        bool isValid;
        VerificationMode modeUsed;
        uint256 gasUsed;
        bytes32 resultHash;
    }

    /// @notice ZK verification proof for off-chain verification
    struct ZKVerificationProof {
        bytes32 publicKeyHash;
        bytes32 messageHash;
        bytes32 signatureHash;
        bytes zkProof;
        bytes32 proofCommitment;
    }

    /// @notice Key exchange encapsulation
    struct Encapsulation {
        bytes ciphertext;
        bytes32 sharedSecretHash;
        KEMAlgorithm algorithm;
        uint64 timestamp;
    }

    /// @notice PQC lock configuration
    struct PQCLockConfig {
        bytes32 pqPublicKeyHash;
        SignatureAlgorithm algorithm;
        bool requireHybrid;
        bool requirePQOnly;
        uint64 configuredAt;
        uint256 recoveryDelay;
    }

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 expected, uint256 actual);
    error InvalidCiphertextSize(uint256 expected, uint256 actual);
    error UnsupportedAlgorithm();
    error VerificationFailed();
    error InvalidHybridSignature();
    error MockModeNotAllowed();
    error DecapsulationFailed();
    error SignatureTooShort();
    error InvalidMagic();
    error UnsupportedVersion();

    // =============================================================================
    // HYBRID SIGNATURE ENCODING
    // =============================================================================

    /**
     * @notice Encode a hybrid signature to bytes
     * @param sig The hybrid signature struct
     * @return encoded The encoded signature bytes
     */
    function encodeHybridSignature(
        HybridSignature memory sig
    ) internal pure returns (bytes memory encoded) {
        return
            abi.encodePacked(
                sig.magic,
                sig.version,
                uint8(sig.algorithm),
                uint16(sig.ecdsaSig.length),
                sig.ecdsaSig,
                uint16(sig.pqSignature.length),
                sig.pqSignature,
                uint16(sig.pqPublicKey.length),
                sig.pqPublicKey
            );
    }

    /**
     * @notice Decode hybrid signature from bytes
     * @param encoded The encoded signature bytes
     * @return sig The decoded hybrid signature
     */
    function decodeHybridSignature(
        bytes memory encoded
    ) internal pure returns (HybridSignature memory sig) {
        if (encoded.length < 10) revert SignatureTooShort();

        uint256 offset = 0;

        // Read magic bytes
        sig.magic = bytes4(bytes32(encoded[offset]) >> 224);
        offset += 4;

        if (sig.magic != HYBRID_SIG_MAGIC) revert InvalidMagic();

        // Read version
        sig.version = uint8(encoded[offset]);
        offset += 1;

        if (sig.version != VERSION) revert UnsupportedVersion();

        // Read algorithm
        sig.algorithm = SignatureAlgorithm(uint8(encoded[offset]));
        offset += 1;

        // Read ECDSA signature length and data
        uint16 ecdsaLen = (uint16(uint8(encoded[offset])) << 8) |
            uint16(uint8(encoded[offset + 1]));
        offset += 2;

        sig.ecdsaSig = new bytes(ecdsaLen);
        for (uint256 i = 0; i < ecdsaLen; i++) {
            sig.ecdsaSig[i] = encoded[offset + i];
        }
        offset += ecdsaLen;

        // Read PQ signature length and data
        uint16 pqSigLen = (uint16(uint8(encoded[offset])) << 8) |
            uint16(uint8(encoded[offset + 1]));
        offset += 2;

        sig.pqSignature = new bytes(pqSigLen);
        for (uint256 i = 0; i < pqSigLen; i++) {
            sig.pqSignature[i] = encoded[offset + i];
        }
        offset += pqSigLen;

        // Read PQ public key length and data
        uint16 pqPkLen = (uint16(uint8(encoded[offset])) << 8) |
            uint16(uint8(encoded[offset + 1]));
        offset += 2;

        sig.pqPublicKey = new bytes(pqPkLen);
        for (uint256 i = 0; i < pqPkLen; i++) {
            sig.pqPublicKey[i] = encoded[offset + i];
        }
    }

    /**
     * @notice Encode compact hybrid signature
     * @param sig The compact signature struct
     * @return The encoded bytes
     */
    function encodeCompactHybridSignature(
        CompactHybridSignature memory sig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                sig.magic,
                sig.version,
                uint8(sig.algorithm),
                sig.ecdsaR,
                sig.ecdsaS,
                sig.ecdsaV,
                sig.pqPublicKeyHash,
                uint16(sig.pqSignature.length),
                sig.pqSignature
            );
    }

    // =============================================================================
    // SIZE VALIDATION
    // =============================================================================

    /**
     * @notice Get expected public key size for a signature algorithm
     */
    function getExpectedPublicKeySize(
        SignatureAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (algorithm == SignatureAlgorithm.Dilithium3) {
            return DILITHIUM3_PK_SIZE;
        } else if (algorithm == SignatureAlgorithm.Dilithium5) {
            return DILITHIUM5_PK_SIZE;
        } else if (
            algorithm == SignatureAlgorithm.SPHINCSPlus128s ||
            algorithm == SignatureAlgorithm.SPHINCSPlus128f
        ) {
            return SPHINCS_128S_PK_SIZE;
        } else if (
            algorithm == SignatureAlgorithm.SPHINCSPlus256s ||
            algorithm == SignatureAlgorithm.SPHINCSPlus256f
        ) {
            return SPHINCS_256S_PK_SIZE;
        }
        return 0;
    }

    /**
     * @notice Get expected signature size for a signature algorithm
     */
    function getExpectedSignatureSize(
        SignatureAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (algorithm == SignatureAlgorithm.Dilithium3) {
            return DILITHIUM3_SIG_SIZE;
        } else if (algorithm == SignatureAlgorithm.Dilithium5) {
            return DILITHIUM5_SIG_SIZE;
        } else if (algorithm == SignatureAlgorithm.SPHINCSPlus128s) {
            return SPHINCS_128S_SIG_SIZE;
        } else if (algorithm == SignatureAlgorithm.SPHINCSPlus128f) {
            return SPHINCS_128F_SIG_SIZE;
        } else if (algorithm == SignatureAlgorithm.SPHINCSPlus256s) {
            return SPHINCS_256S_SIG_SIZE;
        } else if (algorithm == SignatureAlgorithm.SPHINCSPlus256f) {
            return SPHINCS_256F_SIG_SIZE;
        }
        return 0;
    }

    /**
     * @notice Get expected ciphertext size for KEM algorithm
     */
    function getExpectedCiphertextSize(
        KEMAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (algorithm == KEMAlgorithm.Kyber512) {
            return KYBER512_CT_SIZE;
        } else if (algorithm == KEMAlgorithm.Kyber768) {
            return KYBER768_CT_SIZE;
        } else if (algorithm == KEMAlgorithm.Kyber1024) {
            return KYBER1024_CT_SIZE;
        }
        return 0;
    }

    /**
     * @notice Validate public key size for algorithm
     */
    function validatePublicKeySize(
        bytes memory publicKey,
        SignatureAlgorithm algorithm
    ) internal pure {
        uint256 expected = getExpectedPublicKeySize(algorithm);
        if (expected > 0 && publicKey.length != expected) {
            revert InvalidPublicKeySize(expected, publicKey.length);
        }
    }

    /**
     * @notice Validate signature size for algorithm
     */
    function validateSignatureSize(
        bytes memory signature,
        SignatureAlgorithm algorithm
    ) internal pure {
        uint256 expected = getExpectedSignatureSize(algorithm);
        if (expected > 0 && signature.length != expected) {
            revert InvalidSignatureSize(expected, signature.length);
        }
    }

    // =============================================================================
    // HASHING UTILITIES
    // =============================================================================

    /**
     * @notice Compute public key hash with domain separation
     */
    function hashPublicKey(
        bytes memory publicKey,
        SignatureAlgorithm algorithm
    ) internal pure returns (bytes32) {
        bytes32 domain;
        if (
            algorithm == SignatureAlgorithm.Dilithium3 ||
            algorithm == SignatureAlgorithm.Dilithium5
        ) {
            domain = DILITHIUM_DOMAIN;
        } else if (algorithm >= SignatureAlgorithm.SPHINCSPlus128s) {
            domain = SPHINCS_DOMAIN;
        } else {
            domain = HYBRID_DOMAIN;
        }
        return keccak256(abi.encodePacked(domain, publicKey));
    }

    /**
     * @notice Compute verification request hash
     */
    function hashVerificationRequest(
        VerificationRequest memory request
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    request.algorithm,
                    keccak256(request.publicKey),
                    keccak256(request.message),
                    keccak256(request.signature)
                )
            );
    }

    /**
     * @notice Compute hybrid signature commitment
     */
    function computeHybridCommitment(
        bytes32 messageHash,
        bytes memory ecdsaSig,
        bytes memory pqSignature,
        bytes memory pqPublicKey
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    HYBRID_DOMAIN,
                    messageHash,
                    keccak256(ecdsaSig),
                    keccak256(pqSignature),
                    keccak256(pqPublicKey)
                )
            );
    }

    // =============================================================================
    // SECURITY LEVEL UTILITIES
    // =============================================================================

    /**
     * @notice Get NIST security level for signature algorithm
     * @return level The security level (1, 3, or 5)
     */
    function getSecurityLevel(
        SignatureAlgorithm algorithm
    ) internal pure returns (uint8 level) {
        if (algorithm == SignatureAlgorithm.Dilithium3) {
            return 3;
        } else if (algorithm == SignatureAlgorithm.Dilithium5) {
            return 5;
        } else if (
            algorithm == SignatureAlgorithm.SPHINCSPlus128s ||
            algorithm == SignatureAlgorithm.SPHINCSPlus128f
        ) {
            return 1;
        } else if (
            algorithm == SignatureAlgorithm.SPHINCSPlus256s ||
            algorithm == SignatureAlgorithm.SPHINCSPlus256f
        ) {
            return 5;
        }
        return 0;
    }

    /**
     * @notice Check if algorithm is lattice-based
     */
    function isLatticeBased(
        SignatureAlgorithm algorithm
    ) internal pure returns (bool) {
        return
            algorithm == SignatureAlgorithm.Dilithium3 ||
            algorithm == SignatureAlgorithm.Dilithium5;
    }

    /**
     * @notice Check if algorithm is hash-based
     */
    function isHashBased(
        SignatureAlgorithm algorithm
    ) internal pure returns (bool) {
        return algorithm >= SignatureAlgorithm.SPHINCSPlus128s;
    }

    /**
     * @notice Estimate gas cost for verification mode
     */
    function estimateVerificationGas(
        VerificationMode mode,
        SignatureAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (mode == VerificationMode.Mock) {
            return 5_000;
        } else if (mode == VerificationMode.Precompile) {
            return 50_000;
        } else if (mode == VerificationMode.OffchainZK) {
            return 300_000;
        } else if (mode == VerificationMode.PureSolidity) {
            if (isLatticeBased(algorithm)) {
                return 10_000_000;
            } else if (isHashBased(algorithm)) {
                return 5_000_000;
            }
        }
        return 1_000_000;
    }
}
