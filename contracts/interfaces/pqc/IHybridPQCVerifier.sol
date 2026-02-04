// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {PQCLib} from "../../libraries/PQCLib.sol";

/**
 * @title IHybridPQCVerifier
 * @notice Interface for hybrid classical + post-quantum signature verification
 * @dev Provides defense-in-depth by requiring both ECDSA and PQC signatures.
 *      If either cryptosystem is compromised, the other provides protection.
 *
 * Security Model:
 * - Both signatures must be valid in HybridMandatory/PQPreferred phases
 * - Either signature validates in ClassicalOnly/HybridOptional phases
 * - PQC-only in PQOnly phase (for full quantum resistance)
 */
interface IHybridPQCVerifier {
    // ============ Events ============

    /**
     * @notice Emitted when a hybrid signature is verified
     * @param signer ECDSA signer address
     * @param pqcKeyHash Hash of the PQC public key
     * @param messageHash Hash of signed message
     * @param mode Verification mode used
     * @param result Verification result
     */
    event HybridSignatureVerified(
        address indexed signer,
        bytes32 indexed pqcKeyHash,
        bytes32 indexed messageHash,
        HybridMode mode,
        HybridResult result
    );

    /**
     * @notice Emitted when ECDSA-only verification is performed
     * @param signer Recovered signer address
     * @param messageHash Message hash
     * @param valid Whether signature was valid
     */
    event ECDSAVerified(
        address indexed signer,
        bytes32 indexed messageHash,
        bool valid
    );

    /**
     * @notice Emitted when PQC-only verification is performed
     * @param pqcKeyHash Hash of PQC public key
     * @param messageHash Message hash
     * @param algorithm PQC algorithm used
     * @param valid Whether signature was valid
     */
    event PQCVerified(
        bytes32 indexed pqcKeyHash,
        bytes32 indexed messageHash,
        PQCLib.SignatureAlgorithm algorithm,
        bool valid
    );

    /**
     * @notice Emitted when hybrid mode changes
     * @param oldMode Previous mode
     * @param newMode New mode
     */
    event HybridModeChanged(
        HybridMode indexed oldMode,
        HybridMode indexed newMode
    );

    // ============ Errors ============

    /// @notice Invalid ECDSA signature
    error InvalidECDSASignature();

    /// @notice ECDSA signer mismatch
    error ECDSASignerMismatch(address recovered, address expected);

    /// @notice Invalid PQC signature
    error InvalidPQCSignature();

    /// @notice PQC key mismatch
    error PQCKeyMismatch(bytes32 provided, bytes32 expected);

    /// @notice Hybrid signature required but only one component provided
    error HybridSignatureRequired();

    /// @notice Classical signature required but not provided
    error ClassicalSignatureRequired();

    /// @notice PQC signature required but not provided
    error PQCSignatureRequired();

    /// @notice Invalid hybrid signature encoding
    error InvalidHybridEncoding();

    /// @notice Mode not supported for this operation
    error UnsupportedMode(HybridMode mode);

    /// @notice Signature malleability detected
    error SignatureMalleabilityDetected();

    // ============ Enums ============

    /**
     * @notice Hybrid verification mode
     */
    enum HybridMode {
        CLASSICAL_ONLY, // 0: Only ECDSA required
        HYBRID_OPTIONAL, // 1: ECDSA required, PQC optional
        HYBRID_MANDATORY, // 2: Both required
        PQC_PREFERRED, // 3: Both required, PQC verification first
        PQC_ONLY // 4: Only PQC required
    }

    /**
     * @notice Verification result details
     */
    enum HybridResult {
        INVALID, // 0: Both failed
        ECDSA_ONLY, // 1: Only ECDSA valid
        PQC_ONLY, // 2: Only PQC valid
        HYBRID_VALID // 3: Both valid
    }

    // ============ Structs ============

    /**
     * @notice Hybrid signature components
     */
    struct HybridSignatureData {
        // ECDSA component
        bytes32 r;
        bytes32 s;
        uint8 v;
        // PQC component
        bytes pqcSignature;
        bytes pqcPublicKey;
        PQCLib.SignatureAlgorithm pqcAlgorithm;
    }

    /**
     * @notice Verification request for batch operations
     */
    struct HybridRequest {
        address expectedSigner;
        bytes32 expectedPQCKeyHash;
        bytes32 messageHash;
        bytes hybridSignature;
    }

    /**
     * @notice Verification result details
     */
    struct HybridVerificationResult {
        bool valid;
        HybridResult result;
        address recoveredSigner;
        bytes32 pqcKeyHash;
        uint256 gasUsed;
    }

    // ============ View Functions ============

    /**
     * @notice Get current hybrid verification mode
     * @return mode Current mode
     */
    function getHybridMode() external view returns (HybridMode mode);

    /**
     * @notice Check if both components are required in current mode
     * @return required True if both ECDSA and PQC are required
     */
    function isBothRequired() external view returns (bool required);

    /**
     * @notice Check if PQC is required in current mode
     * @return required True if PQC signature is required
     */
    function isPQCRequired() external view returns (bool required);

    /**
     * @notice Check if ECDSA is required in current mode
     * @return required True if ECDSA signature is required
     */
    function isECDSARequired() external view returns (bool required);

    /**
     * @notice Get Dilithium verifier address
     * @return verifier Address of DilithiumVerifier contract
     */
    function getDilithiumVerifier() external view returns (address verifier);

    /**
     * @notice Get SPHINCS+ verifier address
     * @return verifier Address of SPHINCSPlusVerifier contract
     */
    function getSPHINCSVerifier() external view returns (address verifier);

    /**
     * @notice Decode a hybrid signature
     * @param encoded Encoded hybrid signature bytes
     * @return data Decoded signature components
     */
    function decodeHybridSignature(
        bytes calldata encoded
    ) external pure returns (HybridSignatureData memory data);

    /**
     * @notice Estimate gas for hybrid verification
     * @param pqcAlgorithm PQC algorithm used
     * @param mode Hybrid mode
     * @return gasEstimate Estimated gas cost
     */
    function estimateGas(
        PQCLib.SignatureAlgorithm pqcAlgorithm,
        HybridMode mode
    ) external view returns (uint256 gasEstimate);

    // ============ Verification Functions ============

    /**
     * @notice Verify a hybrid signature
     * @param hybridSignature Encoded hybrid signature
     * @param messageHash Message hash
     * @param expectedSigner Expected ECDSA signer
     * @param expectedPQCKeyHash Expected PQC public key hash
     * @return valid True if verification passes per current mode
     */
    function verifyHybrid(
        bytes calldata hybridSignature,
        bytes32 messageHash,
        address expectedSigner,
        bytes32 expectedPQCKeyHash
    ) external returns (bool valid);

    /**
     * @notice Verify hybrid with detailed result
     * @param hybridSignature Encoded hybrid signature
     * @param messageHash Message hash
     * @param expectedSigner Expected ECDSA signer
     * @param expectedPQCKeyHash Expected PQC public key hash
     * @return result Detailed verification result
     */
    function verifyHybridDetailed(
        bytes calldata hybridSignature,
        bytes32 messageHash,
        address expectedSigner,
        bytes32 expectedPQCKeyHash
    ) external returns (HybridVerificationResult memory result);

    /**
     * @notice Verify each component separately
     * @param ecdsaR ECDSA r component
     * @param ecdsaS ECDSA s component
     * @param ecdsaV ECDSA v component
     * @param pqcSignature PQC signature bytes
     * @param pqcPublicKey PQC public key bytes
     * @param pqcAlgorithm PQC algorithm
     * @param messageHash Message hash
     * @return ecdsaValid True if ECDSA valid
     * @return pqcValid True if PQC valid
     * @return recoveredSigner Recovered ECDSA signer
     */
    function verifyHybridComponents(
        bytes32 ecdsaR,
        bytes32 ecdsaS,
        uint8 ecdsaV,
        bytes calldata pqcSignature,
        bytes calldata pqcPublicKey,
        PQCLib.SignatureAlgorithm pqcAlgorithm,
        bytes32 messageHash
    )
        external
        returns (bool ecdsaValid, bool pqcValid, address recoveredSigner);

    /**
     * @notice Verify ECDSA signature only
     * @param signature ECDSA signature bytes (65 bytes)
     * @param messageHash Message hash
     * @param expectedSigner Expected signer address
     * @return valid True if valid and matches expected signer
     */
    function verifyECDSAOnly(
        bytes calldata signature,
        bytes32 messageHash,
        address expectedSigner
    ) external returns (bool valid);

    /**
     * @notice Verify PQC signature only
     * @param signature PQC signature bytes
     * @param publicKey PQC public key bytes
     * @param messageHash Message hash
     * @param algorithm PQC algorithm
     * @return valid True if signature is valid
     */
    function verifyPQCOnly(
        bytes calldata signature,
        bytes calldata publicKey,
        bytes32 messageHash,
        PQCLib.SignatureAlgorithm algorithm
    ) external returns (bool valid);

    /**
     * @notice Batch verify hybrid signatures
     * @param requests Array of verification requests
     * @return results Array of verification results
     */
    function batchVerifyHybrid(
        HybridRequest[] calldata requests
    ) external returns (HybridVerificationResult[] memory results);

    /**
     * @notice Verify a compact hybrid signature (for gas efficiency)
     * @param compactSig Compact encoded hybrid signature
     * @param messageHash Message hash
     * @param hints Verification hints for gas optimization
     * @return valid True if valid
     */
    function verifyCompactHybrid(
        bytes calldata compactSig,
        bytes32 messageHash,
        bytes32 hints
    ) external returns (bool valid);

    // ============ Admin Functions ============

    /**
     * @notice Set hybrid verification mode
     * @param mode New mode
     */
    function setHybridMode(HybridMode mode) external;

    /**
     * @notice Set Dilithium verifier contract
     * @param verifier Address of DilithiumVerifier
     */
    function setDilithiumVerifier(address verifier) external;

    /**
     * @notice Set SPHINCS+ verifier contract
     * @param verifier Address of SPHINCSPlusVerifier
     */
    function setSPHINCSVerifier(address verifier) external;

    /**
     * @notice Enable/disable signature malleability checks
     * @param enabled True to enable strict checks
     */
    function setMalleabilityCheckEnabled(bool enabled) external;

    /**
     * @notice Emergency pause
     */
    function pause() external;

    /**
     * @notice Unpause
     */
    function unpause() external;
}
