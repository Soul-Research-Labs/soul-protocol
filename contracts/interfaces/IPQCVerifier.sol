// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPQCVerifier
 * @author ZASEON
 * @notice Standard interface for Post-Quantum Cryptographic (PQC) verifiers
 * @dev Defines the verification interface for NIST PQC standard algorithms:
 *
 * SUPPORTED ALGORITHMS (NIST FIPS 203/204/205):
 *   - ML-DSA (CRYSTALS-Dilithium): Lattice-based digital signatures
 *   - ML-KEM (CRYSTALS-Kyber): Lattice-based key encapsulation
 *   - SLH-DSA (SPHINCS+): Hash-based digital signatures (stateless)
 *   - FN-DSA (FALCON): Lattice-based compact signatures (NTRU)
 *
 * SECURITY LEVELS (NIST Categories):
 *   - Level 1: ~AES-128 equivalent (128-bit classical / 64-bit quantum)
 *   - Level 3: ~AES-192 equivalent (192-bit classical / 96-bit quantum)
 *   - Level 5: ~AES-256 equivalent (256-bit classical / 128-bit quantum)
 *
 * HYBRID MODE:
 *   The interface supports hybrid verification where both a classical
 *   (ECDSA/Ed25519) and PQC signature must be valid. This provides
 *   defense-in-depth during the migration period.
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
interface IPQCVerifier {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice NIST Post-Quantum Cryptographic algorithms
    enum PQCAlgorithm {
        ML_DSA_44, // 0 - CRYSTALS-Dilithium Level 2 (2420 byte sig)
        ML_DSA_65, // 1 - CRYSTALS-Dilithium Level 3 (3293 byte sig)
        ML_DSA_87, // 2 - CRYSTALS-Dilithium Level 5 (4595 byte sig)
        FN_DSA_512, // 3 - FALCON-512 Level 1 (~690 byte sig)
        FN_DSA_1024, // 4 - FALCON-1024 Level 5 (~1280 byte sig)
        SLH_DSA_128S, // 5 - SPHINCS+-128s Level 1 (7856 byte sig)
        SLH_DSA_128F, // 6 - SPHINCS+-128f Level 1 (17088 byte sig, fast)
        SLH_DSA_256S, // 7 - SPHINCS+-256s Level 5 (29792 byte sig)
        ML_KEM_512, // 8 - CRYSTALS-Kyber-512 KEM Level 1
        ML_KEM_768, // 9 - CRYSTALS-Kyber-768 KEM Level 3
        ML_KEM_1024 // 10 - CRYSTALS-Kyber-1024 KEM Level 5
    }

    /// @notice NIST security category
    enum SecurityLevel {
        LEVEL_1, // 128-bit classical / 64-bit quantum
        LEVEL_3, // 192-bit classical / 96-bit quantum
        LEVEL_5 // 256-bit classical / 128-bit quantum
    }

    /// @notice Verification mode
    enum VerificationMode {
        PQC_ONLY, // Only PQC signature verified
        CLASSICAL_ONLY, // Only classical signature verified (fallback)
        HYBRID // Both classical + PQC must be valid
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC public key with metadata
    struct PQCPublicKey {
        bytes keyData; // Raw public key bytes
        PQCAlgorithm algorithm; // Algorithm identifier
        SecurityLevel level; // NIST security level
        bytes32 keyHash; // keccak256 of keyData for quick lookup
        uint256 registeredAt; // Registration timestamp
        bool revoked; // Whether key has been revoked
    }

    /// @notice Hybrid signature combining classical + PQC
    struct HybridSignature {
        bytes classicalSig; // ECDSA/Ed25519 signature
        bytes pqcSig; // PQC signature
        PQCAlgorithm algorithm; // PQC algorithm used
        VerificationMode mode; // Verification mode
    }

    /// @notice KEM encapsulation result
    struct KEMEncapsulation {
        bytes ciphertext; // Encapsulated ciphertext
        bytes32 sharedSecret; // Derived shared secret (on sender side)
        PQCAlgorithm algorithm; // KEM algorithm used
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PQCKeyRegistered(
        address indexed owner,
        PQCAlgorithm algorithm,
        bytes32 keyHash,
        SecurityLevel level
    );

    event PQCKeyRevoked(
        address indexed owner,
        bytes32 keyHash,
        uint256 revokedAt
    );

    event PQCSignatureVerified(
        address indexed signer,
        PQCAlgorithm algorithm,
        VerificationMode mode,
        bool valid
    );

    event HybridVerificationCompleted(
        address indexed signer,
        bool classicalValid,
        bool pqcValid,
        bool overallValid
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error UnsupportedAlgorithm(PQCAlgorithm algorithm);
    error InvalidPublicKey(PQCAlgorithm algorithm, uint256 keyLength);
    error InvalidSignature(PQCAlgorithm algorithm, uint256 sigLength);
    error KeyNotRegistered(address owner);
    error KeyRevoked(address owner, bytes32 keyHash);
    error HybridVerificationFailed(bool classicalResult, bool pqcResult);
    error SecurityLevelTooLow(SecurityLevel required, SecurityLevel provided);
    error AlgorithmMismatch(PQCAlgorithm expected, PQCAlgorithm provided);

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a PQC signature
     * @param message The message that was signed (or its hash)
     * @param signature The PQC signature bytes
     * @param publicKey The PQC public key bytes
     * @param algorithm The PQC algorithm used
     * @return valid True if the signature is valid
     */
    function verifyPQCSignature(
        bytes calldata message,
        bytes calldata signature,
        bytes calldata publicKey,
        PQCAlgorithm algorithm
    ) external view returns (bool valid);

    /**
     * @notice Verify a hybrid (classical + PQC) signature
     * @param message The original message
     * @param hybridSig The hybrid signature struct
     * @param classicalPubKey The classical public key (ECDSA/Ed25519)
     * @param pqcPubKey The PQC public key
     * @return valid True if verification passes according to mode
     */
    function verifyHybridSignature(
        bytes calldata message,
        HybridSignature calldata hybridSig,
        bytes calldata classicalPubKey,
        bytes calldata pqcPubKey
    ) external view returns (bool valid);

    /**
     * @notice Get expected signature size for an algorithm
     * @param algorithm The PQC algorithm
     * @return size Expected signature size in bytes
     */
    function getSignatureSize(
        PQCAlgorithm algorithm
    ) external pure returns (uint256 size);

    /**
     * @notice Get expected public key size for an algorithm
     * @param algorithm The PQC algorithm
     * @return size Expected public key size in bytes
     */
    function getPublicKeySize(
        PQCAlgorithm algorithm
    ) external pure returns (uint256 size);

    /**
     * @notice Get the NIST security level for an algorithm
     * @param algorithm The PQC algorithm
     * @return level The security level
     */
    function getSecurityLevel(
        PQCAlgorithm algorithm
    ) external pure returns (SecurityLevel level);

    /**
     * @notice Check if an algorithm is a signature scheme (vs KEM)
     * @param algorithm The PQC algorithm
     * @return isSignature True if signature scheme, false if KEM
     */
    function isSignatureAlgorithm(
        PQCAlgorithm algorithm
    ) external pure returns (bool isSignature);
}
