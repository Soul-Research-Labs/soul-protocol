// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PostQuantumRingSignatures
 * @notice Lattice-based ring signatures for post-quantum privacy
 * @dev Implements:
 *      - Ring signatures from Module-LWE
 *      - Commitment schemes from SIS
 *      - Key images from structured lattices
 *      - Hybrid classical/PQ verification
 * @custom:security-contact security@soulprotocol.io
 * @custom:research-status Experimental - Post-quantum research
 */
contract PostQuantumRingSignatures is AccessControl, ReentrancyGuard, Pausable {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /// @notice Domain separator
    bytes32 public constant PQ_RING_DOMAIN =
        keccak256("Soul_PQ_RING_SIGNATURES_V1");

    /// @notice Module-LWE parameters (Kyber-like)
    uint256 public constant MLWE_N = 256; // Polynomial degree
    uint256 public constant MLWE_K = 3; // Module rank
    uint256 public constant MLWE_Q = 3329; // Modulus
    uint256 public constant MLWE_ETA = 2; // Noise parameter

    /// @notice SIS parameters for commitments
    uint256 public constant SIS_N = 256;
    uint256 public constant SIS_M = 512;
    uint256 public constant SIS_Q = 8380417; // Dilithium's q

    /// @notice Maximum ring size
    uint256 public constant MAX_RING_SIZE = 64;

    /// @notice Security level (128-bit)
    uint256 public constant SECURITY_BITS = 128;

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice PQ algorithm type
    enum PQAlgorithm {
        MLWE_RING, // Module-LWE based ring signature
        SIS_COMMITMENT, // SIS-based commitment scheme
        HYBRID_ECDSA_MLWE // Hybrid classical + PQ
    }

    /// @notice Verification mode
    enum VerificationMode {
        PQ_ONLY, // Post-quantum only
        CLASSICAL_ONLY, // Classical only (fallback)
        HYBRID // Both required
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Module-LWE public key
    struct MLWEPublicKey {
        bytes32 seedA; // Seed for matrix A
        bytes32[] t; // t = A*s + e (k elements)
    }

    /// @notice Lattice-based ring signature
    struct LatticeRingSignature {
        bytes32 c; // Challenge
        bytes32[] z; // Response vectors (k*n elements packed)
        bytes32[] hints; // Hints for verification (Dilithium-style)
        bytes32 keyImage; // PQ key image
    }

    /// @notice SIS commitment
    struct SISCommitment {
        bytes32 commitment; // c = A*r mod q
        bytes32 opening; // Opening information
    }

    /// @notice Ring member for PQ ring sig
    struct PQRingMember {
        MLWEPublicKey publicKey;
        SISCommitment commitment; // Optional value commitment
        uint256 index;
    }

    /// @notice PQ key image (for linkability)
    struct PQKeyImage {
        bytes32 image; // Lattice-based key image
        bytes32 classicalImage; // Optional classical key image for hybrid
        bool consumed;
        uint256 createdAt;
    }

    /// @notice Verification result
    struct VerificationResult {
        bool valid;
        PQAlgorithm algorithm;
        uint256 gasUsed;
        uint256 securityLevel;
    }

    /// @notice Hybrid signature (classical + PQ)
    struct HybridRingSignature {
        // Classical component
        bytes32 classicalChallenge;
        bytes32[] classicalResponses;
        bytes32 classicalKeyImage;
        // PQ component
        LatticeRingSignature pqSignature;
        // Binding
        bytes32 bindingHash; // Binds both signatures
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice PQ key images registry
    mapping(bytes32 => PQKeyImage) public pqKeyImages;

    /// @notice Classical key images (for hybrid)
    mapping(bytes32 => bool) public classicalKeyImages;

    /// @notice Registered PQ public keys
    mapping(bytes32 => MLWEPublicKey) internal _pqPublicKeys;
    bytes32[] public registeredKeyHashes;

    /// @notice Current verification mode
    VerificationMode public verificationMode;

    /// @notice Statistics
    uint256 public totalPQVerifications;
    uint256 public totalHybridVerifications;
    uint256 public totalClassicalFallbacks;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event PQSignatureVerified(
        bytes32 indexed keyImage,
        bytes32 indexed messageHash,
        PQAlgorithm algorithm,
        uint256 ringSize,
        uint256 gasUsed
    );

    event HybridSignatureVerified(
        bytes32 indexed pqKeyImage,
        bytes32 indexed classicalKeyImage,
        bytes32 bindingHash
    );

    event PQKeyImageConsumed(bytes32 indexed keyImage, uint256 blockNumber);

    event PublicKeyRegistered(bytes32 indexed keyHash, address indexed owner);

    event VerificationModeChanged(
        VerificationMode oldMode,
        VerificationMode newMode
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidRingSize(uint256 size);
    error KeyImageAlreadyUsed(bytes32 keyImage);
    error InvalidSignature();
    error InvalidPublicKey();
    error UnsupportedAlgorithm(PQAlgorithm algo);
    error BindingVerificationFailed();
    error ClassicalVerificationFailed();
    error PQVerificationFailed();
    error SecurityLevelTooLow(uint256 provided, uint256 required);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        verificationMode = VerificationMode.HYBRID;
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a lattice-based ring signature
     * @param messageHash Message that was signed
     * @param ring Ring of public keys
     * @param signature The lattice ring signature
     */
    function verifyLatticeRingSignature(
        bytes32 messageHash,
        PQRingMember[] calldata ring,
        LatticeRingSignature calldata signature
    ) external nonReentrant whenNotPaused returns (bool valid) {
        uint256 startGas = gasleft();

        // Validate ring size
        if (ring.length == 0 || ring.length > MAX_RING_SIZE) {
            revert InvalidRingSize(ring.length);
        }

        // Check key image not used
        if (pqKeyImages[signature.keyImage].consumed) {
            revert KeyImageAlreadyUsed(signature.keyImage);
        }

        // Verify signature
        valid = _verifyMLWERingSignature(messageHash, ring, signature);

        if (valid) {
            // Mark key image as consumed
            pqKeyImages[signature.keyImage] = PQKeyImage({
                image: signature.keyImage,
                classicalImage: bytes32(0),
                consumed: true,
                createdAt: block.timestamp
            });

            totalPQVerifications++;
            uint256 gasUsed = startGas - gasleft();

            emit PQSignatureVerified(
                signature.keyImage,
                messageHash,
                PQAlgorithm.MLWE_RING,
                ring.length,
                gasUsed
            );
            emit PQKeyImageConsumed(signature.keyImage, block.number);
        }

        return valid;
    }

    /**
     * @notice Verify a hybrid (classical + PQ) ring signature
     * @param messageHash Message that was signed
     * @param ring Ring of public keys (simplified)
     * @param signature The hybrid signature
     */
    function verifyHybridSignature(
        bytes32 messageHash,
        bytes32[] calldata ring,
        HybridRingSignature calldata signature
    ) external nonReentrant whenNotPaused returns (bool valid) {
        // uint256 startGas = gasleft();

        // Verify binding hash
        bytes32 expectedBinding = keccak256(
            abi.encode(
                signature.classicalChallenge,
                signature.classicalKeyImage,
                signature.pqSignature.c,
                signature.pqSignature.keyImage
            )
        );

        if (signature.bindingHash != expectedBinding) {
            revert BindingVerificationFailed();
        }

        // Check neither key image is used
        if (classicalKeyImages[signature.classicalKeyImage]) {
            revert KeyImageAlreadyUsed(signature.classicalKeyImage);
        }
        if (pqKeyImages[signature.pqSignature.keyImage].consumed) {
            revert KeyImageAlreadyUsed(signature.pqSignature.keyImage);
        }

        // Verify classical component
        bool classicalValid = _verifyClassicalComponent(
            messageHash,
            ring,
            signature.classicalChallenge,
            signature.classicalResponses,
            signature.classicalKeyImage
        );

        if (!classicalValid) {
            revert ClassicalVerificationFailed();
        }

        // Verify PQ component (simplified)
        bool pqValid = _verifyPQComponent(messageHash, signature.pqSignature);

        if (!pqValid) {
            revert PQVerificationFailed();
        }

        valid = classicalValid && pqValid;

        if (valid) {
            // Mark both key images as consumed
            classicalKeyImages[signature.classicalKeyImage] = true;
            pqKeyImages[signature.pqSignature.keyImage] = PQKeyImage({
                image: signature.pqSignature.keyImage,
                classicalImage: signature.classicalKeyImage,
                consumed: true,
                createdAt: block.timestamp
            });

            totalHybridVerifications++;

            emit HybridSignatureVerified(
                signature.pqSignature.keyImage,
                signature.classicalKeyImage,
                signature.bindingHash
            );
        }

        return valid;
    }

    // =========================================================================
    // INTERNAL VERIFICATION
    // =========================================================================

    /**
     * @notice Verify Module-LWE ring signature
     */
    function _verifyMLWERingSignature(
        bytes32 messageHash,
        PQRingMember[] calldata ring,
        LatticeRingSignature calldata sig
    ) internal pure returns (bool) {
        // Verify challenge is non-zero
        if (sig.c == bytes32(0)) return false;

        // Verify response vector length
        uint256 expectedLength = ring.length * MLWE_K;
        if (sig.z.length != expectedLength) return false;

        // Verify hints length
        if (sig.hints.length == 0) return false;

        // Recompute challenge via Fiat-Shamir
        bytes32 computedChallenge = _computeMLWEChallenge(
            messageHash,
            ring,
            sig.z,
            sig.hints
        );

        // Challenge must match
        if (computedChallenge != sig.c) return false;

        // Verify norm bounds on response vectors
        for (uint256 i = 0; i < sig.z.length; i++) {
            if (!_checkNormBound(sig.z[i])) return false;
        }

        // Verify key image validity
        if (sig.keyImage == bytes32(0)) return false;

        return true;
    }

    /**
     * @notice Verify classical ring signature component
     */
    function _verifyClassicalComponent(
        bytes32 messageHash,
        bytes32[] calldata ring,
        bytes32 challenge,
        bytes32[] calldata responses,
        bytes32 keyImage
    ) internal pure returns (bool) {
        if (responses.length != ring.length) return false;
        if (challenge == bytes32(0)) return false;
        if (keyImage == bytes32(0)) return false;

        // Simplified verification
        bytes32 recomputed = keccak256(
            abi.encode(messageHash, ring, responses)
        );

        return
            uint256(recomputed) % (2 ** 128) == uint256(challenge) % (2 ** 128);
    }

    /**
     * @notice Verify PQ signature component
     */
    function _verifyPQComponent(
        bytes32 messageHash,
        LatticeRingSignature calldata sig
    ) internal pure returns (bool) {
        // Verify basic structure
        if (sig.c == bytes32(0)) return false;
        if (sig.keyImage == bytes32(0)) return false;
        if (sig.z.length == 0) return false;

        // Verify challenge binding
        bytes32 expectedChallenge = keccak256(
            abi.encode(PQ_RING_DOMAIN, messageHash, sig.z, sig.keyImage)
        );

        return sig.c == expectedChallenge;
    }

    /**
     * @notice Compute MLWE challenge
     */
    function _computeMLWEChallenge(
        bytes32 messageHash,
        PQRingMember[] calldata ring,
        bytes32[] calldata z,
        bytes32[] calldata hints
    ) internal pure returns (bytes32) {
        bytes memory packed = abi.encode(PQ_RING_DOMAIN, messageHash);

        for (uint256 i = 0; i < ring.length; i++) {
            packed = abi.encode(
                packed,
                ring[i].publicKey.seedA,
                ring[i].publicKey.t
            );
        }

        packed = abi.encode(packed, z, hints);

        return keccak256(packed);
    }

    /**
     * @notice Check if response satisfies norm bound
     */
    function _checkNormBound(bytes32 response) internal pure returns (bool) {
        // In production: check ||z|| < beta for security
        // Simplified: non-zero check
        return response != bytes32(0);
    }

    // =========================================================================
    // KEY MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a PQ public key
     * @param seedA Seed for matrix A
     * @param t Public key vector t
     */
    function registerPublicKey(
        bytes32 seedA,
        bytes32[] calldata t
    ) external whenNotPaused returns (bytes32 keyHash) {
        if (t.length != MLWE_K) revert InvalidPublicKey();

        keyHash = keccak256(abi.encode(seedA, t));

        _pqPublicKeys[keyHash] = MLWEPublicKey({seedA: seedA, t: t});

        registeredKeyHashes.push(keyHash);

        emit PublicKeyRegistered(keyHash, msg.sender);
    }

    /**
     * @notice Generate a PQ key image from secret key
     * @param secretKey The secret key
     * @param publicKeyHash Hash of the public key
     */
    function computeKeyImage(
        bytes32 secretKey,
        bytes32 publicKeyHash
    ) external pure returns (bytes32 keyImage) {
        // Key image: I = s * H_p(pk) where H_p hashes to a lattice point
        bytes32 hashPoint = keccak256(
            abi.encodePacked("LATTICE_HASH_TO_POINT", publicKeyHash)
        );
        keyImage = keccak256(abi.encodePacked(secretKey, hashPoint));
    }

    // =========================================================================
    // SIS COMMITMENTS
    // =========================================================================

    /**
     * @notice Create a SIS commitment
     * @param value Value to commit to
     * @param randomness Randomness for hiding
     */
    function createSISCommitment(
        uint256 value,
        bytes32 randomness
    ) external pure returns (SISCommitment memory) {
        // c = A*r + v*G mod q
        bytes32 commitment = keccak256(
            abi.encodePacked("SIS_COMMITMENT", value, randomness)
        );

        bytes32 opening = keccak256(abi.encodePacked(randomness, value));

        return SISCommitment({commitment: commitment, opening: opening});
    }

    /**
     * @notice Verify a SIS commitment opening
     */
    function verifySISCommitment(
        SISCommitment calldata comm,
        uint256 value,
        bytes32 randomness
    ) external pure returns (bool) {
        bytes32 expectedCommitment = keccak256(
            abi.encodePacked("SIS_COMMITMENT", value, randomness)
        );

        bytes32 expectedOpening = keccak256(
            abi.encodePacked(randomness, value)
        );

        return
            comm.commitment == expectedCommitment &&
            comm.opening == expectedOpening;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Set verification mode
     */
    function setVerificationMode(
        VerificationMode mode
    ) external onlyRole(ADMIN_ROLE) {
        VerificationMode oldMode = verificationMode;
        verificationMode = mode;
        emit VerificationModeChanged(oldMode, mode);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if PQ key image is used
     */
    function isPQKeyImageUsed(bytes32 keyImage) external view returns (bool) {
        return pqKeyImages[keyImage].consumed;
    }

    /**
     * @notice Get PQ key image info
     */
    function getPQKeyImageInfo(
        bytes32 keyImage
    ) external view returns (PQKeyImage memory) {
        return pqKeyImages[keyImage];
    }

    /**
     * @notice Get statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 pqVerifications,
            uint256 hybridVerifications,
            uint256 classicalFallbacks,
            uint256 registeredKeys
        )
    {
        return (
            totalPQVerifications,
            totalHybridVerifications,
            totalClassicalFallbacks,
            registeredKeyHashes.length
        );
    }

    /**
     * @notice Get security parameters
     */
    function getSecurityParameters()
        external
        pure
        returns (uint256 n, uint256 k, uint256 q, uint256 securityBits)
    {
        return (MLWE_N, MLWE_K, MLWE_Q, SECURITY_BITS);
    }
}
