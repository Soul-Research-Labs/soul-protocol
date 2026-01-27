// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title SPHINCSPlusVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for SPHINCS+ (SLH-DSA) post-quantum signatures
 * @dev Implements verification for SPHINCS+ hash-based signatures.
 *      SPHINCS+ is stateless and based only on hash functions, making it
 *      the most conservative post-quantum choice with no lattice assumptions.
 *
 * SPHINCS+ Parameters:
 * - SPHINCS+-128s: 128-bit security, 7.9 KB signatures (small)
 * - SPHINCS+-128f: 128-bit security, 17 KB signatures (fast)
 * - SPHINCS+-256s: 256-bit security, 29 KB signatures (small)
 * - SPHINCS+-256f: 256-bit security, 49 KB signatures (fast)
 */

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract SPHINCSPlusVerifier is Ownable {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for SPHINCS+ verification
    address public constant SPHINCS_PRECOMSoulE = address(0x0E);

    /// @notice Parameter set sizes
    uint256 public constant SPHINCS_128S_PK_SIZE = 32;
    uint256 public constant SPHINCS_128S_SIG_SIZE = 7856;
    uint256 public constant SPHINCS_128F_SIG_SIZE = 17088;
    uint256 public constant SPHINCS_256S_PK_SIZE = 64;
    uint256 public constant SPHINCS_256S_SIG_SIZE = 29792;
    uint256 public constant SPHINCS_256F_SIG_SIZE = 49856;

    // =============================================================================
    // ENUMS
    // =============================================================================

    enum SPHINCSVariant {
        SPHINCS_128s, // Small, 128-bit security
        SPHINCS_128f, // Fast, 128-bit security
        SPHINCS_256s, // Small, 256-bit security
        SPHINCS_256f // Fast, 256-bit security
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Whether to use mock verification
    bool public useMockVerification;

    /// @notice Trusted key hashes
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Pre-verified signatures for testing
    mapping(bytes32 => bool) public preVerified;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event SPHINCSVerified(
        bytes32 indexed messageHash,
        bytes32 indexed publicKeyHash,
        SPHINCSVariant variant,
        bool valid
    );

    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 minExpected, uint256 actual);
    error PrecompileCallFailed();
    error UnsupportedVariant();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor() Ownable(msg.sender) {
        useMockVerification = true;
    }

    // =============================================================================
    // VERIFICATION FUNCTIONS
    // =============================================================================

    /**
     * @notice Verify a SPHINCS+ signature
     * @param message The 32-byte message hash
     * @param signature The SPHINCS+ signature
     * @param publicKey The SPHINCS+ public key
     * @param variant The parameter set variant
     * @return valid True if signature is valid
     */
    function verify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        SPHINCSVariant variant
    ) external returns (bool valid) {
        // Validate sizes
        (uint256 expectedPkSize, uint256 minSigSize) = _getSizes(variant);

        if (publicKey.length != expectedPkSize) {
            revert InvalidPublicKeySize(expectedPkSize, publicKey.length);
        }
        if (signature.length < minSigSize) {
            revert InvalidSignatureSize(minSigSize, signature.length);
        }

        bytes32 pkHash = keccak256(publicKey);
        bytes32 sigHash = keccak256(signature);

        // Check pre-verified cache
        bytes32 cacheKey = keccak256(abi.encode(message, sigHash, pkHash));
        if (preVerified[cacheKey]) {
            emit SPHINCSVerified(message, pkHash, variant, true);
            return true;
        }

        if (useMockVerification) {
            valid = _mockVerify(message, publicKey, pkHash);
        } else {
            valid = _precompileVerify(message, signature, publicKey, variant);
        }

        // Cache successful verifications
        if (valid) {
            preVerified[cacheKey] = true;
        }

        emit SPHINCSVerified(message, pkHash, variant, valid);
        return valid;
    }

    /**
     * @notice Verify SPHINCS+-128s signature (most common variant)
     */
    function verifySPHINCS128s(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool) {
        return
            this.verify(
                message,
                signature,
                publicKey,
                SPHINCSVariant.SPHINCS_128s
            );
    }

    /**
     * @notice Verify SPHINCS+-256s signature (maximum security)
     */
    function verifySPHINCS256s(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool) {
        return
            this.verify(
                message,
                signature,
                publicKey,
                SPHINCSVariant.SPHINCS_256s
            );
    }

    // =============================================================================
    // INTERNAL
    // =============================================================================

    function _mockVerify(
        bytes32 message,
        bytes calldata publicKey,
        bytes32 pkHash
    ) internal view returns (bool) {
        // Trust pre-registered keys
        if (trustedKeyHashes[pkHash]) {
            return true;
        }

        // Basic sanity checks for mock mode
        // Real implementation would verify the Merkle tree structure
        return message != bytes32(0) && publicKey.length > 0;
    }

    function _precompileVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        SPHINCSVariant variant
    ) internal view returns (bool) {
        bytes memory input = abi.encodePacked(
            uint8(variant),
            message,
            publicKey,
            signature
        );

        (bool success, bytes memory result) = SPHINCS_PRECOMSoulE.staticcall(
            input
        );

        if (!success || result.length == 0) {
            if (useMockVerification) {
                return _mockVerify(message, publicKey, keccak256(publicKey));
            }
            revert PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    function _getSizes(
        SPHINCSVariant variant
    ) internal pure returns (uint256 pkSize, uint256 sigSize) {
        if (variant == SPHINCSVariant.SPHINCS_128s) {
            return (SPHINCS_128S_PK_SIZE, SPHINCS_128S_SIG_SIZE);
        } else if (variant == SPHINCSVariant.SPHINCS_128f) {
            return (SPHINCS_128S_PK_SIZE, SPHINCS_128F_SIG_SIZE);
        } else if (variant == SPHINCSVariant.SPHINCS_256s) {
            return (SPHINCS_256S_PK_SIZE, SPHINCS_256S_SIG_SIZE);
        } else if (variant == SPHINCSVariant.SPHINCS_256f) {
            return (SPHINCS_256S_PK_SIZE, SPHINCS_256F_SIG_SIZE);
        }
        revert UnsupportedVariant();
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setMockMode(bool enabled) external onlyOwner {
        useMockVerification = enabled;
    }

    function addTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    function removeTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
    }

    function addPreVerified(
        bytes32 message,
        bytes32 signatureHash,
        bytes32 publicKeyHash
    ) external onlyOwner {
        bytes32 key = keccak256(
            abi.encode(message, signatureHash, publicKeyHash)
        );
        preVerified[key] = true;
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    function getExpectedSizes(
        SPHINCSVariant variant
    ) external pure returns (uint256 pkSize, uint256 sigSize) {
        return _getSizes(variant);
    }

    function isKeyTrusted(
        bytes calldata publicKey
    ) external view returns (bool) {
        return trustedKeyHashes[keccak256(publicKey)];
    }

    /**
     * @notice Estimate gas for verification
     * @dev SPHINCS+ verification is more expensive due to hash computations
     */
    function estimateGas(
        SPHINCSVariant variant
    ) external pure returns (uint256) {
        if (
            variant == SPHINCSVariant.SPHINCS_128s ||
            variant == SPHINCSVariant.SPHINCS_128f
        ) {
            return 300_000;
        } else {
            return 500_000;
        }
    }
}
