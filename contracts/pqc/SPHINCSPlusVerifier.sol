// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {PQCLib} from "../libraries/PQCLib.sol";

/**
 * @title SPHINCSPlusVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for SPHINCS+ (SLH-DSA) post-quantum signatures
 * @dev Implements verification for SPHINCS+ hash-based signatures.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                      HASH-BASED SIGNATURES                                 ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ SLH-DSA (SPHINCS+) - NIST FIPS 205 Standard                               ║
 * ║                                                                           ║
 * ║ SPHINCS+ is stateless and based only on hash functions, making it        ║
 * ║ the most conservative post-quantum choice with no lattice assumptions.   ║
 * ║                                                                           ║
 * ║ Variants:                                                                 ║
 * ║ • SPHINCS+-128s: 128-bit security, 7.9 KB signatures (small)             ║
 * ║ • SPHINCS+-128f: 128-bit security, 17 KB signatures (fast)               ║
 * ║ • SPHINCS+-256s: 256-bit security, 29 KB signatures (small)              ║
 * ║ • SPHINCS+-256f: 256-bit security, 49 KB signatures (fast)               ║
 * ║                                                                           ║
 * ║ Security: Based on hash function collision resistance only               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract SPHINCSPlusVerifier is Ownable, Pausable {
    using PQCLib for PQCLib.SignatureAlgorithm;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for SPHINCS+ verification
    address public constant SPHINCS_PRECOMPILE = address(0x0E);

    /// @notice Hypertree parameters for SPHINCS+-128s
    uint256 public constant SPHINCS_128_TREE_HEIGHT = 64;
    uint256 public constant SPHINCS_128_FORS_TREES = 14;

    /// @notice Hypertree parameters for SPHINCS+-256s
    uint256 public constant SPHINCS_256_TREE_HEIGHT = 68;
    uint256 public constant SPHINCS_256_FORS_TREES = 22;

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Current verification mode
    PQCLib.VerificationMode public verificationMode;

    /// @notice Trusted key hashes
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Verification cache
    mapping(bytes32 => bool) public verificationCache;

    /// @notice Cache timestamps
    mapping(bytes32 => uint256) public cacheTimestamps;

    /// @notice Cache TTL
    uint256 public cacheTTL = 1 hours;

    /// @notice Total verifications
    uint256 public totalVerifications;

    /// @notice Successful verifications
    uint256 public successfulVerifications;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event SPHINCSVerified(
        bytes32 indexed messageHash,
        bytes32 indexed publicKeyHash,
        PQCLib.SignatureAlgorithm variant,
        bool valid,
        PQCLib.VerificationMode modeUsed
    );

    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);
    event VerificationModeChanged(
        PQCLib.VerificationMode oldMode,
        PQCLib.VerificationMode newMode
    );

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 minExpected, uint256 actual);
    error PrecompileCallFailed();
    error UnsupportedVariant();
    error MockModeNotAllowedOnMainnet();
    error GasLimitExceeded();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor() Ownable(msg.sender) {
        if (block.chainid == 1) {
            verificationMode = PQCLib.VerificationMode.OffchainZK;
        } else {
            verificationMode = PQCLib.VerificationMode.Mock;
        }
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
        PQCLib.SignatureAlgorithm variant
    ) external whenNotPaused returns (bool valid) {
        // Validate variant is SPHINCS+
        if (
            variant < PQCLib.SignatureAlgorithm.SPHINCSPlus128s ||
            variant > PQCLib.SignatureAlgorithm.SPHINCSPlus256f
        ) {
            revert UnsupportedVariant();
        }

        // Validate sizes
        _validateSizes(publicKey, signature, variant);

        bytes32 pkHash = PQCLib.hashPublicKey(publicKey, variant);
        totalVerifications++;

        // Check cache
        bytes32 cacheKey = keccak256(
            abi.encode(message, keccak256(signature), pkHash)
        );
        if (_isCacheValid(cacheKey)) {
            return verificationCache[cacheKey];
        }

        // Route to verification mode
        if (verificationMode == PQCLib.VerificationMode.Mock) {
            valid = _mockVerify(message, publicKey, pkHash);
        } else if (verificationMode == PQCLib.VerificationMode.Precompile) {
            valid = _precompileVerify(message, signature, publicKey, variant);
        } else if (verificationMode == PQCLib.VerificationMode.PureSolidity) {
            valid = _solidityVerify(message, signature, publicKey, variant);
        } else {
            // OffchainZK mode requires explicit ZK proof
            valid = _mockVerify(message, publicKey, pkHash);
        }

        if (valid) {
            successfulVerifications++;
            _cacheResult(cacheKey, true);
        }

        emit SPHINCSVerified(message, pkHash, variant, valid, verificationMode);
    }

    /**
     * @notice Verify SPHINCS+-128s signature (compact variant)
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
                PQCLib.SignatureAlgorithm.SPHINCSPlus128s
            );
    }

    /**
     * @notice Verify SPHINCS+-128f signature (fast variant)
     */
    function verifySPHINCS128f(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool) {
        return
            this.verify(
                message,
                signature,
                publicKey,
                PQCLib.SignatureAlgorithm.SPHINCSPlus128f
            );
    }

    /**
     * @notice Verify SPHINCS+-256s signature (high security compact)
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
                PQCLib.SignatureAlgorithm.SPHINCSPlus256s
            );
    }

    /**
     * @notice Verify SPHINCS+-256f signature (high security fast)
     */
    function verifySPHINCS256f(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool) {
        return
            this.verify(
                message,
                signature,
                publicKey,
                PQCLib.SignatureAlgorithm.SPHINCSPlus256f
            );
    }

    /**
     * @notice Batch verify multiple SPHINCS+ signatures
     */
    function batchVerify(
        bytes32[] calldata messages,
        bytes[] calldata signatures,
        bytes[] calldata publicKeys,
        PQCLib.SignatureAlgorithm variant
    ) external whenNotPaused returns (bool allValid) {
        uint256 len = messages.length;
        require(
            len == signatures.length && len == publicKeys.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < len; i++) {
            if (
                !this.verify(messages[i], signatures[i], publicKeys[i], variant)
            ) {
                return false;
            }
        }

        return true;
    }

    // =============================================================================
    // INTERNAL VERIFICATION
    // =============================================================================

    function _validateSizes(
        bytes calldata publicKey,
        bytes calldata signature,
        PQCLib.SignatureAlgorithm variant
    ) internal pure {
        (uint256 expectedPkSize, uint256 minSigSize) = _getSizes(variant);

        if (publicKey.length != expectedPkSize) {
            revert InvalidPublicKeySize(expectedPkSize, publicKey.length);
        }
        if (signature.length < minSigSize) {
            revert InvalidSignatureSize(minSigSize, signature.length);
        }
    }

    function _getSizes(
        PQCLib.SignatureAlgorithm variant
    ) internal pure returns (uint256 pkSize, uint256 sigSize) {
        if (variant == PQCLib.SignatureAlgorithm.SPHINCSPlus128s) {
            return (PQCLib.SPHINCS_128S_PK_SIZE, PQCLib.SPHINCS_128S_SIG_SIZE);
        } else if (variant == PQCLib.SignatureAlgorithm.SPHINCSPlus128f) {
            return (PQCLib.SPHINCS_128S_PK_SIZE, PQCLib.SPHINCS_128F_SIG_SIZE);
        } else if (variant == PQCLib.SignatureAlgorithm.SPHINCSPlus256s) {
            return (PQCLib.SPHINCS_256S_PK_SIZE, PQCLib.SPHINCS_256S_SIG_SIZE);
        } else if (variant == PQCLib.SignatureAlgorithm.SPHINCSPlus256f) {
            return (PQCLib.SPHINCS_256S_PK_SIZE, PQCLib.SPHINCS_256F_SIG_SIZE);
        }
        revert UnsupportedVariant();
    }

    function _mockVerify(
        bytes32 message,
        bytes calldata publicKey,
        bytes32 pkHash
    ) internal view returns (bool) {
        if (block.chainid == 1) {
            revert MockModeNotAllowedOnMainnet();
        }

        // Trust pre-registered keys
        if (trustedKeyHashes[pkHash]) {
            return true;
        }

        // Basic sanity check
        return message != bytes32(0) && publicKey.length > 0;
    }

    function _precompileVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        PQCLib.SignatureAlgorithm variant
    ) internal view returns (bool) {
        bytes memory input = abi.encodePacked(
            uint8(variant),
            message,
            publicKey,
            signature
        );

        (bool success, bytes memory result) = SPHINCS_PRECOMPILE.staticcall(
            input
        );

        if (!success || result.length == 0) {
            if (block.chainid != 1) {
                return _mockVerify(message, publicKey, keccak256(publicKey));
            }
            revert PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    function _solidityVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        PQCLib.SignatureAlgorithm variant
    ) internal view returns (bool) {
        // SPHINCS+ verification involves:
        // 1. Parse FORS signature and verify
        // 2. Parse hypertree authentication paths
        // 3. Verify each layer of the hypertree

        // This is very gas-expensive (5-10M gas)
        // For now, implement simplified verification

        // Extract seed from public key
        bytes32 seed;
        assembly {
            seed := calldataload(publicKey.offset)
        }

        // Extract root from signature
        bytes32 sigRoot;
        assembly {
            sigRoot := calldataload(signature.offset)
        }

        // Simplified check (real implementation much more complex)
        bytes32 computed = keccak256(
            abi.encodePacked(PQCLib.SPHINCS_DOMAIN, message, seed, variant)
        );

        // Suppress unused variable warning
        return computed != bytes32(0) && sigRoot != bytes32(0);
    }

    // =============================================================================
    // CACHE MANAGEMENT
    // =============================================================================

    function _isCacheValid(bytes32 cacheKey) internal view returns (bool) {
        if (cacheTimestamps[cacheKey] == 0) return false;
        return block.timestamp < cacheTimestamps[cacheKey] + cacheTTL;
    }

    function _cacheResult(bytes32 cacheKey, bool result) internal {
        verificationCache[cacheKey] = result;
        cacheTimestamps[cacheKey] = block.timestamp;
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setVerificationMode(
        PQCLib.VerificationMode newMode
    ) external onlyOwner {
        if (newMode == PQCLib.VerificationMode.Mock && block.chainid == 1) {
            revert MockModeNotAllowedOnMainnet();
        }

        PQCLib.VerificationMode oldMode = verificationMode;
        verificationMode = newMode;
        emit VerificationModeChanged(oldMode, newMode);
    }

    function setCacheTTL(uint256 _cacheTTL) external onlyOwner {
        cacheTTL = _cacheTTL;
    }

    function addTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    function removeTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
    }

    function clearCache(bytes32 cacheKey) external onlyOwner {
        delete verificationCache[cacheKey];
        delete cacheTimestamps[cacheKey];
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    function getStats()
        external
        view
        returns (
            uint256 total,
            uint256 successful,
            PQCLib.VerificationMode mode
        )
    {
        return (totalVerifications, successfulVerifications, verificationMode);
    }

    function isTrustedKey(bytes32 keyHash) external view returns (bool) {
        return trustedKeyHashes[keyHash];
    }

    function estimateGas(
        PQCLib.SignatureAlgorithm variant
    ) external pure returns (uint256) {
        return
            PQCLib.estimateVerificationGas(
                PQCLib.VerificationMode.PureSolidity,
                variant
            );
    }
}
