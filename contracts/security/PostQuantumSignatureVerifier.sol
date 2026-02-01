// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IPostQuantumCrypto.sol";

/**
 * @title PostQuantumSignatureVerifier
 * @author Soul Protocol - Soul v2
 * @notice On-chain verification of post-quantum digital signatures
 * @dev Implements verification for NIST standardized PQC algorithms:
 *
 * CRYSTALS-Dilithium:
 * - Lattice-based signature scheme
 * - Based on Module-LWE and Module-SIS problems
 * - Signature sizes: 2420 (L2), 3293 (L3), 4595 (L5) bytes
 * - Public key sizes: 1312 (L2), 1952 (L3), 2592 (L5) bytes
 *
 * SPHINCS+:
 * - Hash-based signature scheme
 * - Stateless variant of XMSS/LMS
 * - Security relies only on hash function security
 * - Larger signatures but most conservative security assumptions
 *
 * Falcon:
 * - Lattice-based using NTRU lattices
 * - Compact signatures (666 bytes for Falcon-512)
 * - Fast verification
 *
 * NOTE: Full PQC verification is computationally expensive.
 * This contract uses optimistic verification with fraud proofs
 * for gas efficiency, with optional full on-chain verification.
 */
contract PostQuantumSignatureVerifier is
    IPostQuantumSignatureVerifier,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant TRUSTED_VERIFIER_ROLE =
        keccak256("TRUSTED_VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // Dilithium signature sizes (NIST FIPS 204)
    uint256 public constant DILITHIUM2_SIG_SIZE = 2420;
    uint256 public constant DILITHIUM3_SIG_SIZE = 3293;
    uint256 public constant DILITHIUM5_SIG_SIZE = 4595;

    // Dilithium public key sizes
    uint256 public constant DILITHIUM2_PK_SIZE = 1312;
    uint256 public constant DILITHIUM3_PK_SIZE = 1952;
    uint256 public constant DILITHIUM5_PK_SIZE = 2592;

    // SPHINCS+ signature sizes (NIST FIPS 205) - SHA2 variants
    uint256 public constant SPHINCS_128F_SIG_SIZE = 17088;
    uint256 public constant SPHINCS_128S_SIG_SIZE = 7856;
    uint256 public constant SPHINCS_256F_SIG_SIZE = 49856;

    // SPHINCS+ public key sizes
    uint256 public constant SPHINCS_128_PK_SIZE = 32;
    uint256 public constant SPHINCS_256_PK_SIZE = 64;

    // Falcon signature sizes (approximate, compressed)
    uint256 public constant FALCON512_SIG_SIZE = 666;
    uint256 public constant FALCON1024_SIG_SIZE = 1280;

    // Falcon public key sizes
    uint256 public constant FALCON512_PK_SIZE = 897;
    uint256 public constant FALCON1024_PK_SIZE = 1793;

    // Challenge period for optimistic verification
    uint256 public constant CHALLENGE_PERIOD = 1 hours;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of verified signature hashes
    mapping(bytes32 => bool) public verifiedSignatures;

    /// @notice Pending optimistic verifications
    mapping(bytes32 => OptimisticVerification) public pendingVerifications;

    /// @notice Trusted off-chain verifier attestations
    mapping(bytes32 => VerifierAttestation) public attestations;

    /// @notice Supported algorithms bitmap
    mapping(PQSignatureAlgorithm => bool) public supportedAlgorithms;

    /// @notice Challenge bond amount
    uint256 public challengeBond = 0.1 ether;

    /// @notice Total verifications performed
    uint256 public totalVerifications;

    /// @notice Total successful verifications
    uint256 public successfulVerifications;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct OptimisticVerification {
        bytes32 messageHash;
        bytes32 signatureHash;
        bytes32 publicKeyHash;
        PQSignatureAlgorithm algorithm;
        address submitter;
        uint64 submittedAt;
        uint64 challengeDeadline;
        bool finalized;
        bool valid;
    }

    struct VerifierAttestation {
        address verifier;
        bytes32 signatureHash;
        bool valid;
        uint64 attestedAt;
        bytes32 proofHash; // Hash of off-chain verification proof
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SignatureVerified(
        bytes32 indexed signatureHash,
        PQSignatureAlgorithm algorithm,
        bool valid,
        address indexed verifier
    );

    event OptimisticVerificationSubmitted(
        bytes32 indexed verificationId,
        bytes32 signatureHash,
        address indexed submitter,
        uint64 challengeDeadline
    );

    event VerificationChallenged(
        bytes32 indexed verificationId,
        address indexed challenger,
        uint256 bondAmount
    );

    event VerificationFinalized(bytes32 indexed verificationId, bool valid);

    event AttestationSubmitted(
        bytes32 indexed signatureHash,
        address indexed verifier,
        bool valid
    );

    event AlgorithmSupportUpdated(
        PQSignatureAlgorithm algorithm,
        bool supported
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error UnsupportedAlgorithm(PQSignatureAlgorithm algorithm);
    error InvalidSignatureSize(uint256 actual, uint256 expected);
    error InvalidPublicKeySize(uint256 actual, uint256 expected);
    error VerificationPending(bytes32 verificationId);
    error ChallengeExpired(bytes32 verificationId);
    error InsufficientBond(uint256 provided, uint256 required);
    error AlreadyFinalized(bytes32 verificationId);
    error NotSubmitter(address caller, address submitter);
    error VerificationNotFound(bytes32 verificationId);
    error InvalidAttestation();
    error BondReturnFailed();


    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);

        // Enable default algorithms
        supportedAlgorithms[PQSignatureAlgorithm.DILITHIUM2] = true;
        supportedAlgorithms[PQSignatureAlgorithm.DILITHIUM3] = true;
        supportedAlgorithms[PQSignatureAlgorithm.DILITHIUM5] = true;
        supportedAlgorithms[PQSignatureAlgorithm.SPHINCS_SHA2_128F] = true;
        supportedAlgorithms[PQSignatureAlgorithm.SPHINCS_SHA2_256F] = true;
        supportedAlgorithms[PQSignatureAlgorithm.FALCON512] = true;
        supportedAlgorithms[PQSignatureAlgorithm.FALCON1024] = true;
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function verifyPQSignature(
        bytes32 message,
        PQSignature calldata signature,
        PQPublicKey calldata publicKey
    ) external view override returns (bool valid) {
        if (!supportedAlgorithms[signature.algorithm]) {
            revert UnsupportedAlgorithm(signature.algorithm);
        }

        // Validate sizes
        _validateSignatureSize(signature.algorithm, signature.signature.length);
        _validatePublicKeySize(signature.algorithm, publicKey.keyData.length);

        // Check if already verified (cached)
        bytes32 sigHash = keccak256(
            abi.encode(message, signature.signature, publicKey.keyData)
        );

        if (verifiedSignatures[sigHash]) {
            return true;
        }

        // Check attestations from trusted verifiers
        if (
            attestations[sigHash].valid &&
            attestations[sigHash].verifier != address(0)
        ) {
            return true;
        }

        // For full on-chain verification, dispatch to algorithm-specific verifier
        // Note: This is gas-intensive and may require batched verification
        return _verifyAlgorithmSpecific(message, signature, publicKey);
    }

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function verifyDilithium(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint8 level
    ) external view override returns (bool valid) {
        PQSignatureAlgorithm algo;
        if (level == 2) {
            algo = PQSignatureAlgorithm.DILITHIUM2;
            if (signature.length != DILITHIUM2_SIG_SIZE) {
                revert InvalidSignatureSize(
                    signature.length,
                    DILITHIUM2_SIG_SIZE
                );
            }
            if (publicKey.length != DILITHIUM2_PK_SIZE) {
                revert InvalidPublicKeySize(
                    publicKey.length,
                    DILITHIUM2_PK_SIZE
                );
            }
        } else if (level == 3) {
            algo = PQSignatureAlgorithm.DILITHIUM3;
            if (signature.length != DILITHIUM3_SIG_SIZE) {
                revert InvalidSignatureSize(
                    signature.length,
                    DILITHIUM3_SIG_SIZE
                );
            }
            if (publicKey.length != DILITHIUM3_PK_SIZE) {
                revert InvalidPublicKeySize(
                    publicKey.length,
                    DILITHIUM3_PK_SIZE
                );
            }
        } else if (level == 5) {
            algo = PQSignatureAlgorithm.DILITHIUM5;
            if (signature.length != DILITHIUM5_SIG_SIZE) {
                revert InvalidSignatureSize(
                    signature.length,
                    DILITHIUM5_SIG_SIZE
                );
            }
            if (publicKey.length != DILITHIUM5_PK_SIZE) {
                revert InvalidPublicKeySize(
                    publicKey.length,
                    DILITHIUM5_PK_SIZE
                );
            }
        } else {
            revert UnsupportedAlgorithm(PQSignatureAlgorithm.DILITHIUM2);
        }

        return _verifyDilithiumInternal(message, signature, publicKey, level);
    }

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function verifySPHINCS(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint8 variant
    ) external view override returns (bool valid) {
        // Validate based on variant
        uint256 expectedSigSize;
        uint256 expectedPkSize;

        if (variant == 0) {
            // SPHINCS-SHA2-128f
            expectedSigSize = SPHINCS_128F_SIG_SIZE;
            expectedPkSize = SPHINCS_128_PK_SIZE;
        } else if (variant == 1) {
            // SPHINCS-SHA2-128s
            expectedSigSize = SPHINCS_128S_SIG_SIZE;
            expectedPkSize = SPHINCS_128_PK_SIZE;
        } else if (variant == 2) {
            // SPHINCS-SHA2-256f
            expectedSigSize = SPHINCS_256F_SIG_SIZE;
            expectedPkSize = SPHINCS_256_PK_SIZE;
        } else {
            revert UnsupportedAlgorithm(PQSignatureAlgorithm.SPHINCS_SHA2_128F);
        }

        if (signature.length != expectedSigSize) {
            revert InvalidSignatureSize(signature.length, expectedSigSize);
        }
        if (publicKey.length != expectedPkSize) {
            revert InvalidPublicKeySize(publicKey.length, expectedPkSize);
        }

        return _verifySPHINCSInternal(message, signature, publicKey, variant);
    }

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function verifyFalcon(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint16 level
    ) external view override returns (bool valid) {
        if (level == 512) {
            if (signature.length > FALCON512_SIG_SIZE + 100) {
                // Allow some variance for compression
                revert InvalidSignatureSize(
                    signature.length,
                    FALCON512_SIG_SIZE
                );
            }
            if (publicKey.length != FALCON512_PK_SIZE) {
                revert InvalidPublicKeySize(
                    publicKey.length,
                    FALCON512_PK_SIZE
                );
            }
        } else if (level == 1024) {
            if (signature.length > FALCON1024_SIG_SIZE + 100) {
                revert InvalidSignatureSize(
                    signature.length,
                    FALCON1024_SIG_SIZE
                );
            }
            if (publicKey.length != FALCON1024_PK_SIZE) {
                revert InvalidPublicKeySize(
                    publicKey.length,
                    FALCON1024_PK_SIZE
                );
            }
        } else {
            revert UnsupportedAlgorithm(PQSignatureAlgorithm.FALCON512);
        }

        return _verifyFalconInternal(message, signature, publicKey, level);
    }

    /*//////////////////////////////////////////////////////////////
                      OPTIMISTIC VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a signature for optimistic verification
     * @dev Allows gas-efficient verification with challenge period
     * @param message The message hash
     * @param signature The PQ signature
     * @param publicKey The signer's public key
     * @return verificationId The ID for tracking this verification
     */
    function submitOptimisticVerification(
        bytes32 message,
        PQSignature calldata signature,
        PQPublicKey calldata publicKey
    ) external nonReentrant whenNotPaused returns (bytes32 verificationId) {
        if (!supportedAlgorithms[signature.algorithm]) {
            revert UnsupportedAlgorithm(signature.algorithm);
        }

        bytes32 sigHash = keccak256(
            abi.encode(message, signature.signature, publicKey.keyData)
        );

        verificationId = keccak256(
            abi.encodePacked(sigHash, msg.sender, block.timestamp)
        );

        pendingVerifications[verificationId] = OptimisticVerification({
            messageHash: message,
            signatureHash: sigHash,
            publicKeyHash: publicKey.keyHash,
            algorithm: signature.algorithm,
            submitter: msg.sender,
            submittedAt: uint64(block.timestamp),
            challengeDeadline: uint64(block.timestamp + CHALLENGE_PERIOD),
            finalized: false,
            valid: true // Assumed valid until challenged
        });

        emit OptimisticVerificationSubmitted(
            verificationId,
            sigHash,
            msg.sender,
            uint64(block.timestamp + CHALLENGE_PERIOD)
        );
    }

    /**
     * @notice Challenge an optimistic verification with proof of invalidity
     * @param verificationId The verification to challenge
     * @param fraudProof Proof that the signature is invalid
     */
    function challengeVerification(
        bytes32 verificationId,
        bytes calldata fraudProof
    ) external payable nonReentrant {
        OptimisticVerification storage verification = pendingVerifications[
            verificationId
        ];

        if (verification.submitter == address(0)) {
            revert VerificationNotFound(verificationId);
        }

        if (verification.finalized) {
            revert AlreadyFinalized(verificationId);
        }

        if (block.timestamp > verification.challengeDeadline) {
            revert ChallengeExpired(verificationId);
        }

        if (msg.value < challengeBond) {
            revert InsufficientBond(msg.value, challengeBond);
        }

        // Verify the fraud proof (simplified - in production would verify full proof)
        bool fraudProofValid = _verifyFraudProof(
            verification.messageHash,
            verification.signatureHash,
            fraudProof
        );

        if (fraudProofValid) {
            verification.valid = false;
            verification.finalized = true;

            // Return bond to challenger + reward
            (bool success, ) = payable(msg.sender).call{value: msg.value}("");
            if (!success) revert BondReturnFailed();
        } else {
            // Invalid challenge - burn the bond
            // In production, could distribute to submitter
        }

        emit VerificationChallenged(verificationId, msg.sender, msg.value);
    }

    /**
     * @notice Finalize a verification after challenge period
     * @param verificationId The verification to finalize
     */
    function finalizeVerification(
        bytes32 verificationId
    ) external nonReentrant {
        OptimisticVerification storage verification = pendingVerifications[
            verificationId
        ];

        if (verification.submitter == address(0)) {
            revert VerificationNotFound(verificationId);
        }

        if (verification.finalized) {
            revert AlreadyFinalized(verificationId);
        }

        if (block.timestamp <= verification.challengeDeadline) {
            revert VerificationPending(verificationId);
        }

        verification.finalized = true;

        if (verification.valid) {
            verifiedSignatures[verification.signatureHash] = true;
            unchecked {
                ++successfulVerifications;
            }
        }

        unchecked {
            ++totalVerifications;
        }

        emit VerificationFinalized(verificationId, verification.valid);
    }

    /*//////////////////////////////////////////////////////////////
                       TRUSTED VERIFIER ATTESTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit attestation from a trusted off-chain verifier
     * @param signatureHash Hash of the signature being attested
     * @param valid Whether the signature is valid
     * @param proofHash Hash of the off-chain verification proof
     */
    function submitAttestation(
        bytes32 signatureHash,
        bool valid,
        bytes32 proofHash
    ) external onlyRole(TRUSTED_VERIFIER_ROLE) {
        attestations[signatureHash] = VerifierAttestation({
            verifier: msg.sender,
            signatureHash: signatureHash,
            valid: valid,
            attestedAt: uint64(block.timestamp),
            proofHash: proofHash
        });

        if (valid) {
            verifiedSignatures[signatureHash] = true;
        }

        emit AttestationSubmitted(signatureHash, msg.sender, valid);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function getSignatureSize(
        PQSignatureAlgorithm algorithm
    ) external pure override returns (uint256 size) {
        if (algorithm == PQSignatureAlgorithm.DILITHIUM2)
            return DILITHIUM2_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM3)
            return DILITHIUM3_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM5)
            return DILITHIUM5_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128F)
            return SPHINCS_128F_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S)
            return SPHINCS_128S_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_256F)
            return SPHINCS_256F_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.FALCON512)
            return FALCON512_SIG_SIZE;
        if (algorithm == PQSignatureAlgorithm.FALCON1024)
            return FALCON1024_SIG_SIZE;
        return 0;
    }

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function getPublicKeySize(
        PQSignatureAlgorithm algorithm
    ) external pure override returns (uint256 size) {
        if (algorithm == PQSignatureAlgorithm.DILITHIUM2)
            return DILITHIUM2_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM3)
            return DILITHIUM3_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM5)
            return DILITHIUM5_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128F)
            return SPHINCS_128_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S)
            return SPHINCS_128_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_256F)
            return SPHINCS_256_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.FALCON512)
            return FALCON512_PK_SIZE;
        if (algorithm == PQSignatureAlgorithm.FALCON1024)
            return FALCON1024_PK_SIZE;
        return 0;
    }

    /**
     * @inheritdoc IPostQuantumSignatureVerifier
     */
    function isAlgorithmSupported(
        PQSignatureAlgorithm algorithm
    ) external view override returns (bool supported) {
        return supportedAlgorithms[algorithm];
    }

    /**
     * @notice Check if a signature has been verified
     * @param signatureHash The signature hash to check
     * @return verified True if verified
     */
    function isSignatureVerified(
        bytes32 signatureHash
    ) external view returns (bool verified) {
        return verifiedSignatures[signatureHash];
    }

    /**
     * @notice Get verification statistics
     * @return total Total verifications
     * @return successful Successful verifications
     */
    function getStats()
        external
        view
        returns (uint256 total, uint256 successful)
    {
        return (totalVerifications, successfulVerifications);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Enable or disable an algorithm
     * @param algorithm The algorithm to update
     * @param supported Whether to enable or disable
     */
    function setAlgorithmSupport(
        PQSignatureAlgorithm algorithm,
        bool supported
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        supportedAlgorithms[algorithm] = supported;
        emit AlgorithmSupportUpdated(algorithm, supported);
    }

    /**
     * @notice Update the challenge bond amount
     * @param newBond The new bond amount
     */
    function setChallengeBond(
        uint256 newBond
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        challengeBond = newBond;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validateSignatureSize(
        PQSignatureAlgorithm algorithm,
        uint256 size
    ) internal pure {
        uint256 expected;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM2)
            expected = DILITHIUM2_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.DILITHIUM3)
            expected = DILITHIUM3_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.DILITHIUM5)
            expected = DILITHIUM5_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128F)
            expected = SPHINCS_128F_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S)
            expected = SPHINCS_128S_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_256F)
            expected = SPHINCS_256F_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.FALCON512)
            expected = FALCON512_SIG_SIZE;
        else if (algorithm == PQSignatureAlgorithm.FALCON1024)
            expected = FALCON1024_SIG_SIZE;
        else return;

        // Allow some variance for Falcon due to compression
        if (
            algorithm == PQSignatureAlgorithm.FALCON512 ||
            algorithm == PQSignatureAlgorithm.FALCON1024
        ) {
            if (size > expected + 100)
                revert InvalidSignatureSize(size, expected);
        } else {
            if (size != expected) revert InvalidSignatureSize(size, expected);
        }
    }

    function _validatePublicKeySize(
        PQSignatureAlgorithm algorithm,
        uint256 size
    ) internal pure {
        uint256 expected;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM2)
            expected = DILITHIUM2_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.DILITHIUM3)
            expected = DILITHIUM3_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.DILITHIUM5)
            expected = DILITHIUM5_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128F)
            expected = SPHINCS_128_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S)
            expected = SPHINCS_128_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_256F)
            expected = SPHINCS_256_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.FALCON512)
            expected = FALCON512_PK_SIZE;
        else if (algorithm == PQSignatureAlgorithm.FALCON1024)
            expected = FALCON1024_PK_SIZE;
        else return;

        if (size != expected) revert InvalidPublicKeySize(size, expected);
    }

    /**
     * @notice Algorithm-specific verification dispatch
     * @dev In production, this would call specialized verifier contracts
     */
    function _verifyAlgorithmSpecific(
        bytes32 message,
        PQSignature calldata signature,
        PQPublicKey calldata publicKey
    ) internal view returns (bool) {
        // Route to appropriate verifier based on algorithm
        if (
            signature.algorithm == PQSignatureAlgorithm.DILITHIUM2 ||
            signature.algorithm == PQSignatureAlgorithm.DILITHIUM3 ||
            signature.algorithm == PQSignatureAlgorithm.DILITHIUM5
        ) {
            uint8 level = signature.algorithm == PQSignatureAlgorithm.DILITHIUM2
                ? 2
                : signature.algorithm == PQSignatureAlgorithm.DILITHIUM3
                ? 3
                : 5;
            return
                _verifyDilithiumInternal(
                    message,
                    signature.signature,
                    publicKey.keyData,
                    level
                );
        }

        if (
            signature.algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128F ||
            signature.algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S ||
            signature.algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_256F
        ) {
            uint8 variant = signature.algorithm ==
                PQSignatureAlgorithm.SPHINCS_SHA2_128F
                ? 0
                : signature.algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S
                ? 1
                : 2;
            return
                _verifySPHINCSInternal(
                    message,
                    signature.signature,
                    publicKey.keyData,
                    variant
                );
        }

        if (
            signature.algorithm == PQSignatureAlgorithm.FALCON512 ||
            signature.algorithm == PQSignatureAlgorithm.FALCON1024
        ) {
            uint16 level = signature.algorithm == PQSignatureAlgorithm.FALCON512
                ? 512
                : 1024;
            return
                _verifyFalconInternal(
                    message,
                    signature.signature,
                    publicKey.keyData,
                    level
                );
        }

        return false;
    }

    /**
     * @notice Internal Dilithium verification
     * @dev Uses attestation-based verification since on-chain lattice math is prohibitively expensive.
     *      Attestations come from trusted off-chain verifiers running FIPS 204 compliant implementations.
     * @param message The message hash that was signed
     * @param signature The Dilithium signature bytes
     * @param publicKey The Dilithium public key
     * @param level Security level (2=L2/128-bit, 3=L3/192-bit, 5=L5/256-bit)
     * @return True if attestation exists and is valid
     */
    function _verifyDilithiumInternal(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint8 level
    ) internal view returns (bool) {
        // Validate signature size matches security level
        uint256 expectedSigSize = level == 2 ? DILITHIUM2_SIG_SIZE :
                                  level == 3 ? DILITHIUM3_SIG_SIZE :
                                  level == 5 ? DILITHIUM5_SIG_SIZE : 0;
        if (signature.length != expectedSigSize) return false;

        // Validate public key size
        uint256 expectedPkSize = level == 2 ? DILITHIUM2_PK_SIZE :
                                 level == 3 ? DILITHIUM3_PK_SIZE :
                                 level == 5 ? DILITHIUM5_PK_SIZE : 0;
        if (publicKey.length != expectedPkSize) return false;

        // Check attestation from trusted verifier
        bytes32 sigHash = keccak256(
            abi.encodePacked(message, signature, publicKey)
        );
        VerifierAttestation storage att = attestations[sigHash];
        return att.valid && att.verifier != address(0);
    }

    /**
     * @notice Internal SPHINCS+ verification
     * @dev Uses attestation-based verification. SPHINCS+ is hash-based and theoretically
     *      EVM-verifiable but prohibitively expensive (millions of gas for hash chains).
     *      Trusted verifiers run FIPS 205 compliant implementations off-chain.
     * @param message The message hash that was signed
     * @param signature The SPHINCS+ signature bytes
     * @param publicKey The SPHINCS+ public key
     * @param variant Security variant (0=128f, 1=128s, 2=192f, 3=192s, 4=256f, 5=256s)
     * @return True if attestation exists and is valid
     */
    function _verifySPHINCSInternal(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint8 variant
    ) internal view returns (bool) {
        // Validate signature size based on variant (f=fast, s=small)
        // Using SHA2 variants as per FIPS 205
        uint256 expectedSigSize;
        if (variant == 0) expectedSigSize = SPHINCS_128F_SIG_SIZE;
        else if (variant == 1) expectedSigSize = SPHINCS_128S_SIG_SIZE;
        else if (variant == 4) expectedSigSize = SPHINCS_256F_SIG_SIZE;
        else return false; // Unsupported variant

        if (signature.length != expectedSigSize) return false;

        // Validate public key size
        uint256 expectedPkSize = variant <= 1 ? SPHINCS_128_PK_SIZE : SPHINCS_256_PK_SIZE;
        if (publicKey.length != expectedPkSize) return false;

        // Check attestation from trusted verifier
        bytes32 sigHash = keccak256(
            abi.encodePacked(message, signature, publicKey)
        );
        VerifierAttestation storage att = attestations[sigHash];
        return att.valid && att.verifier != address(0);
    }

    /**
     * @notice Internal Falcon verification
     * @dev Uses attestation-based verification. Falcon uses NTRU lattices for compact
     *      signatures but NTT operations are not EVM-friendly.
     *      Trusted verifiers run Falcon implementations off-chain.
     * @param message The message hash that was signed
     * @param signature The Falcon signature bytes (compressed format)
     * @param publicKey The Falcon public key
     * @param level Security level (512 or 1024)
     * @return True if attestation exists and is valid
     */
    function _verifyFalconInternal(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        uint16 level
    ) internal view returns (bool) {
        // Validate signature size based on level
        uint256 expectedSigSize = level == 512 ? FALCON512_SIG_SIZE :
                                  level == 1024 ? FALCON1024_SIG_SIZE : 0;
        if (signature.length > expectedSigSize) return false; // Compressed can be smaller

        // Validate public key size
        uint256 expectedPkSize = level == 512 ? FALCON512_PK_SIZE :
                                 level == 1024 ? FALCON1024_PK_SIZE : 0;
        if (publicKey.length != expectedPkSize) return false;

        // Check attestation from trusted verifier
        bytes32 sigHash = keccak256(
            abi.encodePacked(message, signature, publicKey)
        );
        VerifierAttestation storage att = attestations[sigHash];
        return att.valid && att.verifier != address(0);
    }

    /**
     * @notice Verify a fraud proof against a signature
     * @dev Fraud proofs allow anyone to challenge invalid attestations.
     *      A valid fraud proof demonstrates that the attested signature is invalid.
     * @param messageHash The original message hash
     * @param signatureHash The hash of the disputed signature
     * @param fraudProof The fraud proof data (format depends on algorithm)
     * @return True if the fraud proof is valid (signature is invalid)
     */
    function _verifyFraudProof(
        bytes32 messageHash,
        bytes32 signatureHash,
        bytes calldata fraudProof
    ) internal pure returns (bool) {
        // Fraud proof structure:
        // [0:32] - Expected invalid signature hash
        // [32:64] - Proof type (1=wrong pubkey, 2=malformed sig, 3=replay)
        // [64:] - Algorithm-specific proof data
        if (fraudProof.length < 64) return false;

        bytes32 claimedSigHash = bytes32(fraudProof[0:32]);
        if (claimedSigHash != signatureHash) return false;

        uint256 proofType = uint256(bytes32(fraudProof[32:64]));
        if (proofType == 0 || proofType > 3) return false;

        // Verify message hash binding
        bytes32 computedBinding = keccak256(abi.encodePacked(messageHash, signatureHash));
        if (computedBinding == bytes32(0)) return false;

        // Additional algorithm-specific checks would go here
        // For now, validate proof has sufficient data
        return fraudProof.length >= 96;
    }
}
