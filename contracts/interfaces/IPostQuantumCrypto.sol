// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPostQuantumCrypto
 * @author Soul Protocol - Soul v2
 * @notice Interface for Post-Quantum Cryptographic operations
 * @dev Defines standard interfaces for NIST PQC algorithms:
 *      - CRYSTALS-Dilithium (Digital Signatures)
 *      - CRYSTALS-Kyber (Key Encapsulation)
 *      - SPHINCS+ (Hash-based Signatures)
 *      - FALCON (Compact Signatures)
 *
 * These algorithms are designed to be secure against attacks by quantum computers
 * using Shor's algorithm (which breaks RSA/ECC) and Grover's algorithm.
 */

/**
 * @notice Supported post-quantum signature algorithms
 */
enum PQSignatureAlgorithm {
    DILITHIUM2, // NIST Level 2 (128-bit classical, 64-bit quantum)
    DILITHIUM3, // NIST Level 3 (192-bit classical, 96-bit quantum)
    DILITHIUM5, // NIST Level 5 (256-bit classical, 128-bit quantum)
    SPHINCS_SHA2_128F, // SPHINCS+ SHA2 128-bit fast
    SPHINCS_SHA2_128S, // SPHINCS+ SHA2 128-bit small
    SPHINCS_SHA2_256F, // SPHINCS+ SHA2 256-bit fast
    SPHINCS_SHAKE_128F, // SPHINCS+ SHAKE 128-bit fast
    FALCON512, // Falcon-512 (NIST Level 1)
    FALCON1024 // Falcon-1024 (NIST Level 5)
}

/**
 * @notice Supported post-quantum key encapsulation mechanisms
 */
enum PQKEMAlgorithm {
    KYBER512, // NIST Level 1 (128-bit security)
    KYBER768, // NIST Level 3 (192-bit security)
    KYBER1024, // NIST Level 5 (256-bit security)
    MCELIECE348864, // Classic McEliece 348864
    MCELIECE460896, // Classic McEliece 460896
    BIKE_L1, // BIKE Level 1
    BIKE_L3, // BIKE Level 3
    HQC128, // HQC-128
    HQC192, // HQC-192
    HQC256 // HQC-256
}

/**
 * @notice Post-quantum signature data structure
 */
struct PQSignature {
    PQSignatureAlgorithm algorithm;
    bytes signature;
    bytes32 publicKeyHash;
    uint256 timestamp;
}

/**
 * @notice Post-quantum public key structure
 */
struct PQPublicKey {
    PQSignatureAlgorithm algorithm;
    bytes keyData;
    bytes32 keyHash;
    uint64 createdAt;
    uint64 expiresAt;
}

/**
 * @notice KEM encapsulated key structure
 */
struct KEMCiphertext {
    PQKEMAlgorithm algorithm;
    bytes ciphertext;
    bytes32 sharedSecretHash; // Hash of shared secret for verification
}

/**
 * @notice Hybrid signature combining classical + PQC
 */
struct HybridSignature {
    bytes classicalSignature; // ECDSA/EdDSA signature
    PQSignature pqSignature; // Post-quantum signature
    bytes32 combinedHash; // Hash binding both signatures
}

/**
 * @title IPostQuantumSignatureVerifier
 * @notice Interface for verifying post-quantum signatures on-chain
 */
interface IPostQuantumSignatureVerifier {
    /**
     * @notice Verify a post-quantum signature
     * @param message The message that was signed (or its hash)
     * @param signature The PQ signature to verify
     * @param publicKey The signer's PQ public key
     * @return valid True if signature is valid
     */
    function verifyPQSignature(
        bytes32 message,
        PQSignature calldata signature,
        PQPublicKey calldata publicKey
    ) external view returns (bool valid);

    /**
     * @notice Verify a Dilithium signature specifically
     * @param message Message hash
     * @param signature Raw Dilithium signature bytes
     * @param publicKey Raw Dilithium public key bytes
     * @param level Security level (2, 3, or 5)
     * @return valid True if valid
     */
    function verifyDilithium(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint8 level
    ) external view returns (bool valid);

    /**
     * @notice Verify a SPHINCS+ signature
     * @param message Message hash
     * @param signature Raw SPHINCS+ signature bytes
     * @param publicKey Raw SPHINCS+ public key bytes
     * @param variant The SPHINCS+ variant identifier
     * @return valid True if valid
     */
    function verifySPHINCS(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint8 variant
    ) external view returns (bool valid);

    /**
     * @notice Verify a Falcon signature
     * @param message Message hash
     * @param signature Raw Falcon signature bytes
     * @param publicKey Raw Falcon public key bytes
     * @param level Security level (512 or 1024)
     * @return valid True if valid
     */
    function verifyFalcon(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint16 level
    ) external view returns (bool valid);

    /**
     * @notice Get the expected signature size for an algorithm
     * @param algorithm The signature algorithm
     * @return size Expected signature size in bytes
     */
    function getSignatureSize(
        PQSignatureAlgorithm algorithm
    ) external pure returns (uint256 size);

    /**
     * @notice Get the expected public key size for an algorithm
     * @param algorithm The signature algorithm
     * @return size Expected public key size in bytes
     */
    function getPublicKeySize(
        PQSignatureAlgorithm algorithm
    ) external pure returns (uint256 size);

    /**
     * @notice Check if an algorithm is supported
     * @param algorithm The algorithm to check
     * @return supported True if the algorithm is supported
     */
    function isAlgorithmSupported(
        PQSignatureAlgorithm algorithm
    ) external view returns (bool supported);
}

/**
 * @title IPostQuantumKEM
 * @notice Interface for post-quantum key encapsulation mechanisms
 */
interface IPostQuantumKEM {
    /**
     * @notice Verify a KEM decapsulation was performed correctly
     * @dev Used to verify off-chain KEM operations on-chain
     * @param ciphertext The encapsulated ciphertext
     * @param sharedSecretCommitment Commitment to the shared secret
     * @param publicKey The recipient's public key
     * @return valid True if the commitment matches expected shared secret
     */
    function verifyDecapsulation(
        KEMCiphertext calldata ciphertext,
        bytes32 sharedSecretCommitment,
        bytes calldata publicKey
    ) external view returns (bool valid);

    /**
     * @notice Get expected ciphertext size for an algorithm
     * @param algorithm The KEM algorithm
     * @return size Expected ciphertext size in bytes
     */
    function getCiphertextSize(
        PQKEMAlgorithm algorithm
    ) external pure returns (uint256 size);

    /**
     * @notice Get expected shared secret size for an algorithm
     * @param algorithm The KEM algorithm
     * @return size Expected shared secret size in bytes
     */
    function getSharedSecretSize(
        PQKEMAlgorithm algorithm
    ) external pure returns (uint256 size);
}

/**
 * @title IHybridCrypto
 * @notice Interface for hybrid classical + post-quantum cryptography
 * @dev Hybrid schemes provide security against both classical and quantum attacks
 */
interface IHybridCrypto {
    /**
     * @notice Verify a hybrid signature (classical + PQC)
     * @param message The message hash
     * @param hybridSig The hybrid signature structure
     * @param classicalPubKey Classical public key (ECDSA/EdDSA)
     * @param pqPubKey Post-quantum public key
     * @return valid True if BOTH signatures are valid
     */
    function verifyHybridSignature(
        bytes32 message,
        HybridSignature calldata hybridSig,
        bytes calldata classicalPubKey,
        PQPublicKey calldata pqPubKey
    ) external view returns (bool valid);

    /**
     * @notice Compute a hybrid key derivation
     * @param classicalSharedSecret Classical ECDH shared secret
     * @param pqSharedSecret Post-quantum KEM shared secret
     * @param context Additional context for domain separation
     * @return hybridKey The combined hybrid key
     */
    function deriveHybridKey(
        bytes32 classicalSharedSecret,
        bytes32 pqSharedSecret,
        bytes calldata context
    ) external pure returns (bytes32 hybridKey);

    /**
     * @notice Get the hybrid scheme identifier
     * @return scheme The hybrid scheme name
     */
    function hybridScheme() external pure returns (string memory scheme);
}

/**
 * @title IPQCKeyRegistry
 * @notice Registry for post-quantum public keys
 */
interface IPQCKeyRegistry {
    /**
     * @notice Register a post-quantum public key
     * @param keyType The signature algorithm
     * @param publicKey The raw public key bytes
     * @param expiresAt Expiration timestamp
     * @return keyHash The hash identifier for the registered key
     */
    function registerKey(
        PQSignatureAlgorithm keyType,
        bytes calldata publicKey,
        uint64 expiresAt
    ) external returns (bytes32 keyHash);

    /**
     * @notice Revoke a previously registered key
     * @param keyHash The key to revoke
     */
    function revokeKey(bytes32 keyHash) external;

    /**
     * @notice Get a registered public key
     * @param keyHash The key identifier
     * @return key The public key structure
     */
    function getKey(
        bytes32 keyHash
    ) external view returns (PQPublicKey memory key);

    /**
     * @notice Check if a key is valid (registered, not revoked, not expired)
     * @param keyHash The key to check
     * @return valid True if the key is valid
     */
    function isKeyValid(bytes32 keyHash) external view returns (bool valid);

    /**
     * @notice Get all active keys for an owner
     * @param owner The key owner address
     * @return keyHashes Array of active key hashes
     */
    function getOwnerKeys(
        address owner
    ) external view returns (bytes32[] memory keyHashes);

    /**
     * @notice Emitted when a key is registered
     */
    event KeyRegistered(
        bytes32 indexed keyHash,
        address indexed owner,
        PQSignatureAlgorithm algorithm,
        uint64 expiresAt
    );

    /**
     * @notice Emitted when a key is revoked
     */
    event KeyRevoked(bytes32 indexed keyHash, address indexed owner);
}
