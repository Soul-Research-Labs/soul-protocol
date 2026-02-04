// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {PQCLib} from "../../libraries/PQCLib.sol";

/**
 * @title IDilithiumVerifier
 * @notice Interface for CRYSTALS-Dilithium (ML-DSA) signature verification
 * @dev Supports both Dilithium3 (NIST Level 3) and Dilithium5 (NIST Level 5)
 *      with multiple verification modes for gradual EVM integration
 *
 * NIST FIPS 204 (ML-DSA) - Finalized August 2024
 * - Dilithium3 (ML-DSA-65): 1952 byte public key, 3293 byte signature
 * - Dilithium5 (ML-DSA-87): 2592 byte public key, 4595 byte signature
 */
interface IDilithiumVerifier {
    // ============ Events ============

    /**
     * @notice Emitted when a signature is verified
     * @param publicKeyHash Hash of the public key used
     * @param messageHash Hash of the message signed
     * @param algorithm Dilithium variant used
     * @param mode Verification mode used
     * @param valid Whether verification succeeded
     */
    event SignatureVerified(
        bytes32 indexed publicKeyHash,
        bytes32 indexed messageHash,
        PQCLib.SignatureAlgorithm algorithm,
        PQCLib.VerificationMode mode,
        bool valid
    );

    /**
     * @notice Emitted when verification mode is changed
     * @param oldMode Previous verification mode
     * @param newMode New verification mode
     */
    event VerificationModeChanged(
        PQCLib.VerificationMode indexed oldMode,
        PQCLib.VerificationMode indexed newMode
    );

    /**
     * @notice Emitted when a public key is registered as trusted
     * @param publicKeyHash Hash of the trusted public key
     * @param registrar Address that registered the key
     */
    event TrustedKeyAdded(
        bytes32 indexed publicKeyHash,
        address indexed registrar
    );

    /**
     * @notice Emitted when a trusted public key is removed
     * @param publicKeyHash Hash of the removed key
     */
    event TrustedKeyRemoved(bytes32 indexed publicKeyHash);

    // ============ Errors ============

    /// @notice Invalid Dilithium public key size
    error InvalidPublicKeySize(uint256 provided, uint256 expected);

    /// @notice Invalid Dilithium signature size
    error InvalidSignatureSize(uint256 provided, uint256 expected);

    /// @notice Signature verification failed
    error SignatureVerificationFailed();

    /// @notice ZK proof verification failed
    error ZKProofVerificationFailed();

    /// @notice Verification mode not supported
    error UnsupportedVerificationMode(PQCLib.VerificationMode mode);

    /// @notice Algorithm not supported by this verifier
    error UnsupportedAlgorithm(PQCLib.SignatureAlgorithm algorithm);

    /// @notice Public key is not trusted
    error UntrustedPublicKey(bytes32 publicKeyHash);

    /// @notice Batch size mismatch
    error BatchSizeMismatch();

    // ============ Structs ============

    /**
     * @notice Verification request for batch operations
     */
    struct VerificationRequest {
        bytes publicKey;
        bytes signature;
        bytes32 messageHash;
        PQCLib.SignatureAlgorithm algorithm;
    }

    /**
     * @notice Verification result for batch operations
     */
    struct VerificationResult {
        bool valid;
        bytes32 publicKeyHash;
        uint256 gasUsed;
    }

    // ============ View Functions ============

    /**
     * @notice Get current verification mode
     * @return mode Current verification mode
     */
    function getVerificationMode()
        external
        view
        returns (PQCLib.VerificationMode mode);

    /**
     * @notice Check if a public key is trusted
     * @param publicKeyHash Hash of the public key to check
     * @return trusted True if the key is trusted
     */
    function isTrustedKey(
        bytes32 publicKeyHash
    ) external view returns (bool trusted);

    /**
     * @notice Check if a signature result is cached
     * @param cacheKey The cache key (hash of pk, sig, msg)
     * @return cached True if result is cached
     * @return valid Cached verification result
     */
    function getCachedResult(
        bytes32 cacheKey
    ) external view returns (bool cached, bool valid);

    /**
     * @notice Estimate gas for verification
     * @param algorithm Dilithium variant
     * @param mode Verification mode
     * @return gasEstimate Estimated gas cost
     */
    function estimateVerificationGas(
        PQCLib.SignatureAlgorithm algorithm,
        PQCLib.VerificationMode mode
    ) external view returns (uint256 gasEstimate);

    /**
     * @notice Get verification statistics
     * @return totalVerifications Total number of verifications
     * @return successfulVerifications Number of successful verifications
     * @return failedVerifications Number of failed verifications
     */
    function getStats()
        external
        view
        returns (
            uint256 totalVerifications,
            uint256 successfulVerifications,
            uint256 failedVerifications
        );

    // ============ Verification Functions ============

    /**
     * @notice Verify a Dilithium3 signature
     * @param publicKey Dilithium3 public key (1952 bytes)
     * @param signature Dilithium3 signature (3293 bytes)
     * @param messageHash 32-byte message hash
     * @return valid True if signature is valid
     */
    function verifyDilithium3(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify a Dilithium5 signature
     * @param publicKey Dilithium5 public key (2592 bytes)
     * @param signature Dilithium5 signature (4595 bytes)
     * @param messageHash 32-byte message hash
     * @return valid True if signature is valid
     */
    function verifyDilithium5(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify with ZK proof (for off-chain verification mode)
     * @param publicKey Dilithium public key
     * @param signature Dilithium signature
     * @param messageHash Message hash
     * @param zkProof ZK proof of correct verification
     * @param algorithm Dilithium variant (3 or 5)
     * @return valid True if proof is valid
     */
    function verifyWithZKProof(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash,
        bytes calldata zkProof,
        PQCLib.SignatureAlgorithm algorithm
    ) external returns (bool valid);

    /**
     * @notice Batch verify multiple signatures
     * @param requests Array of verification requests
     * @return results Array of verification results
     */
    function batchVerify(
        VerificationRequest[] calldata requests
    ) external returns (VerificationResult[] memory results);

    /**
     * @notice Generic verify function
     * @param publicKey Public key bytes
     * @param signature Signature bytes
     * @param messageHash Message hash
     * @param algorithm Dilithium variant
     * @return valid True if signature is valid
     */
    function verify(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash,
        PQCLib.SignatureAlgorithm algorithm
    ) external returns (bool valid);

    // ============ Admin Functions ============

    /**
     * @notice Set the verification mode
     * @param mode New verification mode
     */
    function setVerificationMode(PQCLib.VerificationMode mode) external;

    /**
     * @notice Add a trusted public key
     * @param publicKeyHash Hash of the public key to trust
     */
    function addTrustedKey(bytes32 publicKeyHash) external;

    /**
     * @notice Remove a trusted public key
     * @param publicKeyHash Hash of the public key to remove
     */
    function removeTrustedKey(bytes32 publicKeyHash) external;

    /**
     * @notice Set the ZK verifier contract address
     * @param verifier Address of the ZK verifier
     */
    function setZKVerifier(address verifier) external;

    /**
     * @notice Clear verification cache (for testing/emergency)
     */
    function clearCache() external;
}
