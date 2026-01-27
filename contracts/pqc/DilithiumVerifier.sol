// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title DilithiumVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for NIST ML-DSA (Dilithium) post-quantum signatures
 * @dev Implements verification for Dilithium3 and Dilithium5 parameter sets.
 *      This is a placeholder implementation that uses a precompile address.
 *      In production, this would call an EIP-proposed precompile for PQ verification.
 *
 * Dilithium Parameters:
 * - Dilithium3: 128-bit quantum security, 3.3 KB signatures, 1.9 KB public keys
 * - Dilithium5: 192-bit quantum security, 4.6 KB signatures, 2.6 KB public keys
 */

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract DilithiumVerifier is Ownable {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for Dilithium verification
    /// @dev This would be assigned by an EIP in the future
    address public constant DILITHIUM_PRECOMSoulE = address(0x0D);

    /// @notice Dilithium3 public key size (bytes)
    uint256 public constant DILITHIUM3_PK_SIZE = 1952;

    /// @notice Dilithium3 signature size (bytes)
    uint256 public constant DILITHIUM3_SIG_SIZE = 3293;

    /// @notice Dilithium5 public key size (bytes)
    uint256 public constant DILITHIUM5_PK_SIZE = 2592;

    /// @notice Dilithium5 signature size (bytes)
    uint256 public constant DILITHIUM5_SIG_SIZE = 4595;

    // =============================================================================
    // ENUMS
    // =============================================================================

    enum DilithiumLevel {
        Level3, // NIST Security Level 3 (128-bit quantum)
        Level5 // NIST Security Level 5 (192-bit quantum)
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Whether to use mock verification (for testing)
    bool public useMockVerification;

    /// @notice Mapping of mock verification results for testing
    mapping(bytes32 => bool) public mockResults;

    /// @notice Trusted public key hashes that have been pre-verified
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Gas cost override for verification (0 = use actual)
    uint256 public gasOverride;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event DilithiumVerified(
        bytes32 indexed messageHash,
        bytes32 indexed publicKeyHash,
        DilithiumLevel level,
        bool valid
    );

    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);
    event MockModeChanged(bool enabled);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 expected, uint256 actual);
    error PrecompileCallFailed();
    error InvalidSecurityLevel();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor() Ownable(msg.sender) {
        useMockVerification = true; // Start in mock mode until precompiles exist
    }

    // =============================================================================
    // VERIFICATION FUNCTIONS
    // =============================================================================

    /**
     * @notice Verify a Dilithium3 signature
     * @param message The 32-byte message hash that was signed
     * @param signature The Dilithium3 signature (3293 bytes)
     * @param publicKey The Dilithium3 public key (1952 bytes)
     * @return valid True if the signature is valid
     */
    function verifyDilithium3(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool valid) {
        return _verify(message, signature, publicKey, DilithiumLevel.Level3);
    }

    /**
     * @notice Verify a Dilithium5 signature
     * @param message The 32-byte message hash that was signed
     * @param signature The Dilithium5 signature (4595 bytes)
     * @param publicKey The Dilithium5 public key (2592 bytes)
     * @return valid True if the signature is valid
     */
    function verifyDilithium5(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool valid) {
        return _verify(message, signature, publicKey, DilithiumLevel.Level5);
    }

    /**
     * @notice Unified verification for any Dilithium level
     * @param message The message hash
     * @param signature The signature bytes
     * @param publicKey The public key bytes
     * @param level The security level
     * @return valid True if valid
     */
    function verify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        DilithiumLevel level
    ) external returns (bool valid) {
        return _verify(message, signature, publicKey, level);
    }

    /**
     * @notice Batch verify multiple signatures
     * @param messages Array of message hashes
     * @param signatures Array of signatures
     * @param publicKeys Array of public keys
     * @param levels Array of security levels
     * @return allValid True if all signatures are valid
     */
    function batchVerify(
        bytes32[] calldata messages,
        bytes[] calldata signatures,
        bytes[] calldata publicKeys,
        DilithiumLevel[] calldata levels
    ) external returns (bool allValid) {
        require(
            messages.length == signatures.length &&
                signatures.length == publicKeys.length &&
                publicKeys.length == levels.length,
            "Array length mismatch"
        );

        uint256 len = messages.length;
        for (uint256 i; i < len; ) {
            if (
                !_verify(messages[i], signatures[i], publicKeys[i], levels[i])
            ) {
                return false;
            }
            unchecked {
                ++i;
            }
        }
        return true;
    }

    // =============================================================================
    // INTERNAL VERIFICATION
    // =============================================================================

    function _verify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        DilithiumLevel level
    ) internal returns (bool valid) {
        // Validate sizes based on level - use inline check for gas efficiency
        uint256 pkLen = publicKey.length;
        uint256 sigLen = signature.length;

        if (level == DilithiumLevel.Level3) {
            if (pkLen != DILITHIUM3_PK_SIZE)
                revert InvalidPublicKeySize(DILITHIUM3_PK_SIZE, pkLen);
            if (sigLen != DILITHIUM3_SIG_SIZE)
                revert InvalidSignatureSize(DILITHIUM3_SIG_SIZE, sigLen);
        } else {
            if (pkLen != DILITHIUM5_PK_SIZE)
                revert InvalidPublicKeySize(DILITHIUM5_PK_SIZE, pkLen);
            if (sigLen != DILITHIUM5_SIG_SIZE)
                revert InvalidSignatureSize(DILITHIUM5_SIG_SIZE, sigLen);
        }

        bytes32 pkHash = keccak256(publicKey);

        // Cache storage read for gas efficiency
        bool mockMode = useMockVerification;
        if (mockMode) {
            valid = _mockVerify(message, signature, publicKey, pkHash);
        } else {
            valid = _precompileVerify(message, signature, publicKey, level);
        }

        emit DilithiumVerified(message, pkHash, level, valid);
    }

    function _mockVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        bytes32 pkHash
    ) internal view returns (bool) {
        // Check if there's a preset mock result
        bytes32 verifyKey = keccak256(
            abi.encode(message, keccak256(signature), pkHash)
        );
        if (mockResults[verifyKey]) {
            return true;
        }

        // Check if public key is in trusted set
        if (trustedKeyHashes[pkHash]) {
            // For trusted keys, perform a simplified check
            // In reality, this would verify the signature mathematically
            return signature.length > 0 && publicKey.length > 0;
        }

        // Default mock behavior: verify signature format is plausible
        // First 32 bytes should not be all zeros (basic sanity check)
        bytes32 sigPrefix;
        assembly {
            sigPrefix := calldataload(signature.offset)
        }
        return sigPrefix != bytes32(0);
    }

    function _precompileVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        DilithiumLevel level
    ) internal view returns (bool) {
        // Encode call data for precompile
        bytes memory input = abi.encodePacked(
            uint8(level),
            message,
            publicKey,
            signature
        );

        uint256 gasToUse = gasOverride > 0 ? gasOverride : gasleft();

        // Call precompile
        (bool success, bytes memory result) = DILITHIUM_PRECOMSoulE.staticcall{
            gas: gasToUse
        }(input);

        if (!success || result.length == 0) {
            // Fallback to mock if precompile not available
            if (useMockVerification) {
                return
                    _mockVerify(
                        message,
                        signature,
                        publicKey,
                        keccak256(publicKey)
                    );
            }
            revert PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    function _getSizes(
        DilithiumLevel level
    ) internal pure returns (uint256 pkSize, uint256 sigSize) {
        if (level == DilithiumLevel.Level3) {
            return (DILITHIUM3_PK_SIZE, DILITHIUM3_SIG_SIZE);
        } else if (level == DilithiumLevel.Level5) {
            return (DILITHIUM5_PK_SIZE, DILITHIUM5_SIG_SIZE);
        }
        revert InvalidSecurityLevel();
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    /**
     * @notice Set mock verification mode
     * @param enabled True to enable mock mode
     */
    function setMockMode(bool enabled) external onlyOwner {
        useMockVerification = enabled;
        emit MockModeChanged(enabled);
    }

    /**
     * @notice Add a mock verification result
     * @param message The message hash
     * @param signatureHash Hash of the signature
     * @param publicKeyHash Hash of the public key
     * @param result The verification result to return
     */
    function setMockResult(
        bytes32 message,
        bytes32 signatureHash,
        bytes32 publicKeyHash,
        bool result
    ) external onlyOwner {
        bytes32 key = keccak256(
            abi.encode(message, signatureHash, publicKeyHash)
        );
        mockResults[key] = result;
    }

    /**
     * @notice Add a trusted public key hash
     * @param keyHash The keccak256 hash of the public key
     */
    function addTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    /**
     * @notice Remove a trusted public key hash
     * @param keyHash The key hash to remove
     */
    function removeTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
    }

    /**
     * @notice Set gas override for precompile calls
     * @param gas Gas amount (0 = use remaining gas)
     */
    function setGasOverride(uint256 gas) external onlyOwner {
        gasOverride = gas;
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    /**
     * @notice Get expected sizes for a security level
     * @param level The Dilithium level
     * @return pkSize Public key size in bytes
     * @return sigSize Signature size in bytes
     */
    function getExpectedSizes(
        DilithiumLevel level
    ) external pure returns (uint256 pkSize, uint256 sigSize) {
        return _getSizes(level);
    }

    /**
     * @notice Check if a public key is trusted
     * @param publicKey The public key bytes
     * @return trusted True if the key hash is in the trusted set
     */
    function isKeyTrusted(
        bytes calldata publicKey
    ) external view returns (bool trusted) {
        return trustedKeyHashes[keccak256(publicKey)];
    }

    /**
     * @notice Estimate gas cost for verification
     * @param level The security level
     * @return gas Estimated gas cost
     */
    function estimateGas(
        DilithiumLevel level
    ) external pure returns (uint256 gas) {
        // Estimated costs (will be defined by EIP)
        if (level == DilithiumLevel.Level3) {
            return 150_000;
        } else {
            return 200_000;
        }
    }
}
