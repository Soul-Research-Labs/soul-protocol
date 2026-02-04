// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {PQCLib} from "../../libraries/PQCLib.sol";

/**
 * @title ISPHINCSPlusVerifier
 * @notice Interface for SPHINCS+ (SLH-DSA) hash-based signature verification
 * @dev SPHINCS+ is stateless and relies only on hash function security,
 *      making it the most conservative post-quantum signature scheme.
 *
 * NIST FIPS 205 (SLH-DSA) - Finalized August 2024
 * Variants:
 * - SPHINCS+-128s: Security Level 1, 7856 byte signatures (small)
 * - SPHINCS+-128f: Security Level 1, 17088 byte signatures (fast)
 * - SPHINCS+-256s: Security Level 5, 29792 byte signatures (small)
 * - SPHINCS+-256f: Security Level 5, 49856 byte signatures (fast)
 */
interface ISPHINCSPlusVerifier {
    // ============ Events ============

    /**
     * @notice Emitted when a SPHINCS+ signature is verified
     * @param publicKeyHash Hash of the public key
     * @param messageHash Hash of the message
     * @param variant SPHINCS+ variant used
     * @param valid Verification result
     */
    event SPHINCSVerified(
        bytes32 indexed publicKeyHash,
        bytes32 indexed messageHash,
        SPHINCSVariant variant,
        bool valid
    );

    /**
     * @notice Emitted when a cached result is used
     * @param cacheKey The cache key
     * @param valid Cached result
     */
    event CacheHit(bytes32 indexed cacheKey, bool valid);

    /**
     * @notice Emitted when verification mode changes
     * @param oldMode Previous mode
     * @param newMode New mode
     */
    event ModeChanged(
        PQCLib.VerificationMode indexed oldMode,
        PQCLib.VerificationMode indexed newMode
    );

    // ============ Errors ============

    /// @notice Invalid SPHINCS+ public key size
    error InvalidPublicKeySize(uint256 provided, SPHINCSVariant variant);

    /// @notice Invalid SPHINCS+ signature size
    error InvalidSignatureSize(uint256 provided, SPHINCSVariant variant);

    /// @notice SPHINCS+ verification failed
    error VerificationFailed();

    /// @notice ZK proof verification failed
    error ZKProofFailed();

    /// @notice Unsupported SPHINCS+ variant
    error UnsupportedVariant(SPHINCSVariant variant);

    /// @notice Verification mode not available
    error ModeNotAvailable(PQCLib.VerificationMode mode);

    // ============ Enums ============

    /**
     * @notice SPHINCS+ variant enumeration
     */
    enum SPHINCSVariant {
        NONE, // 0: Invalid
        SPHINCS_128s, // 1: 128-bit security, small signatures
        SPHINCS_128f, // 2: 128-bit security, fast signing
        SPHINCS_256s, // 3: 256-bit security, small signatures
        SPHINCS_256f // 4: 256-bit security, fast signing
    }

    // ============ Structs ============

    /**
     * @notice Verification request for batch operations
     */
    struct SPHINCSRequest {
        bytes publicKey;
        bytes signature;
        bytes32 messageHash;
        SPHINCSVariant variant;
    }

    /**
     * @notice Verification result
     */
    struct SPHINCSResult {
        bool valid;
        bytes32 publicKeyHash;
        uint256 gasUsed;
        SPHINCSVariant variant;
    }

    /**
     * @notice Variant configuration
     */
    struct VariantConfig {
        uint256 publicKeySize;
        uint256 signatureSize;
        uint256 securityLevel;
        bool supported;
    }

    // ============ View Functions ============

    /**
     * @notice Get current verification mode
     * @return mode Current mode
     */
    function getVerificationMode()
        external
        view
        returns (PQCLib.VerificationMode mode);

    /**
     * @notice Get configuration for a SPHINCS+ variant
     * @param variant The variant to query
     * @return config Variant configuration
     */
    function getVariantConfig(
        SPHINCSVariant variant
    ) external view returns (VariantConfig memory config);

    /**
     * @notice Get expected sizes for a variant
     * @param variant The variant
     * @return pkSize Public key size
     * @return sigSize Signature size
     */
    function getExpectedSizes(
        SPHINCSVariant variant
    ) external pure returns (uint256 pkSize, uint256 sigSize);

    /**
     * @notice Check if a result is cached
     * @param cacheKey The cache key
     * @return cached Whether result is cached
     * @return valid The cached result
     */
    function getCachedResult(
        bytes32 cacheKey
    ) external view returns (bool cached, bool valid);

    /**
     * @notice Estimate gas for verification
     * @param variant SPHINCS+ variant
     * @param mode Verification mode
     * @return gasEstimate Estimated gas
     */
    function estimateGas(
        SPHINCSVariant variant,
        PQCLib.VerificationMode mode
    ) external view returns (uint256 gasEstimate);

    /**
     * @notice Get verification statistics
     * @return total Total verifications
     * @return successful Successful verifications
     * @return cached Cache hits
     */
    function getStats()
        external
        view
        returns (uint256 total, uint256 successful, uint256 cached);

    // ============ Verification Functions ============

    /**
     * @notice Verify a SPHINCS+ signature
     * @param publicKey Public key bytes
     * @param signature Signature bytes
     * @param messageHash Message hash
     * @param variant SPHINCS+ variant
     * @return valid True if valid
     */
    function verify(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash,
        SPHINCSVariant variant
    ) external returns (bool valid);

    /**
     * @notice Verify SPHINCS+-128s signature
     * @param publicKey Public key (32 bytes)
     * @param signature Signature (7856 bytes)
     * @param messageHash Message hash
     * @return valid True if valid
     */
    function verifySPHINCS128s(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify SPHINCS+-128f signature
     * @param publicKey Public key (32 bytes)
     * @param signature Signature (17088 bytes)
     * @param messageHash Message hash
     * @return valid True if valid
     */
    function verifySPHINCS128f(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify SPHINCS+-256s signature
     * @param publicKey Public key (64 bytes)
     * @param signature Signature (29792 bytes)
     * @param messageHash Message hash
     * @return valid True if valid
     */
    function verifySPHINCS256s(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify SPHINCS+-256f signature
     * @param publicKey Public key (64 bytes)
     * @param signature Signature (49856 bytes)
     * @param messageHash Message hash
     * @return valid True if valid
     */
    function verifySPHINCS256f(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify with ZK proof
     * @param publicKey Public key
     * @param signature Signature
     * @param messageHash Message hash
     * @param zkProof ZK proof of correct verification
     * @param variant SPHINCS+ variant
     * @return valid True if proof valid
     */
    function verifyWithZKProof(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash,
        bytes calldata zkProof,
        SPHINCSVariant variant
    ) external returns (bool valid);

    /**
     * @notice Batch verify multiple signatures
     * @param requests Array of verification requests
     * @return results Array of verification results
     */
    function batchVerify(
        SPHINCSRequest[] calldata requests
    ) external returns (SPHINCSResult[] memory results);

    // ============ Admin Functions ============

    /**
     * @notice Set verification mode
     * @param mode New mode
     */
    function setVerificationMode(PQCLib.VerificationMode mode) external;

    /**
     * @notice Enable or disable a variant
     * @param variant The variant
     * @param enabled Whether to enable
     */
    function setVariantEnabled(SPHINCSVariant variant, bool enabled) external;

    /**
     * @notice Set ZK verifier contract
     * @param verifier Verifier address
     */
    function setZKVerifier(address verifier) external;

    /**
     * @notice Clear verification cache
     */
    function clearCache() external;

    /**
     * @notice Emergency pause
     */
    function pause() external;

    /**
     * @notice Unpause
     */
    function unpause() external;
}
