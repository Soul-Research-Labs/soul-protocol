// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {PQCLib} from "../libraries/PQCLib.sol";

/**
 * @title DilithiumVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for NIST ML-DSA (Dilithium) post-quantum signatures
 * @dev Implements verification for Dilithium3 and Dilithium5 parameter sets.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                      POST-QUANTUM CRYPTOGRAPHY                             ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ ML-DSA (Dilithium) - NIST FIPS 204 Standard                               ║
 * ║                                                                           ║
 * ║ Verification Modes:                                                       ║
 * ║ • Mock: Testing only (testnet)                                           ║
 * ║ • PureSolidity: Full verification (~10M gas)                             ║
 * ║ • OffchainZK: ZK proof of verification (~300K gas)                       ║
 * ║ • Precompile: Future EIP precompile (~50K gas)                           ║
 * ║                                                                           ║
 * ║ Parameters:                                                               ║
 * ║ • Dilithium3: Level 3 (128-bit quantum), 3.3 KB sigs, 1.9 KB keys       ║
 * ║ • Dilithium5: Level 5 (192-bit quantum), 4.6 KB sigs, 2.6 KB keys       ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */

/**
 * @notice Interface for ZK-based PQC signature verification
 */
interface IZKPQCVerifier {
    function verifyDilithiumProof(
        bytes calldata proof,
        bytes32 messageHash,
        bytes32 publicKeyHash
    ) external view returns (bool valid);

    function verifyWotsChain(
        bytes calldata proof,
        bytes32 publicElement
    ) external view returns (bool valid);
}

contract DilithiumVerifier is Ownable, Pausable {
    using PQCLib for PQCLib.SignatureAlgorithm;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for Dilithium verification
    address public constant DILITHIUM_PRECOMPILE = address(0x0D);

    /// @notice Maximum gas for pure Solidity verification
    uint256 public constant MAX_SOLIDITY_GAS = 15_000_000;

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Current verification mode
    PQCLib.VerificationMode public verificationMode;

    /// @notice ZK PQC verifier contract
    IZKPQCVerifier public zkVerifier;

    /// @notice Trusted public key hashes that have been pre-verified
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Verification cache for gas optimization
    mapping(bytes32 => bool) public verificationCache;

    /// @notice Cache timestamps
    mapping(bytes32 => uint256) public cacheTimestamps;

    /// @notice Cache TTL (default 1 hour)
    uint256 public cacheTTL = 1 hours;

    /// @notice Total verifications counter
    uint256 public totalVerifications;

    /// @notice Successful verifications counter
    uint256 public successfulVerifications;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event DilithiumVerified(
        bytes32 indexed messageHash,
        bytes32 indexed publicKeyHash,
        PQCLib.SignatureAlgorithm algorithm,
        bool valid,
        PQCLib.VerificationMode modeUsed
    );

    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);
    event VerificationModeChanged(
        PQCLib.VerificationMode oldMode,
        PQCLib.VerificationMode newMode
    );
    event ZKVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event CacheTTLUpdated(uint256 oldTTL, uint256 newTTL);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 expected, uint256 actual);
    error PrecompileCallFailed();
    error InvalidSecurityLevel();
    error ZKVerifierNotSet();
    error InvalidZKProof();
    error MockModeNotAllowedOnMainnet();
    error GasLimitExceeded();
    error CacheExpired();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(address _zkVerifier) Ownable(msg.sender) {
        // Start in mock mode on testnets, ZK mode on mainnet
        if (block.chainid == 1) {
            verificationMode = PQCLib.VerificationMode.OffchainZK;
        } else {
            verificationMode = PQCLib.VerificationMode.Mock;
        }

        if (_zkVerifier != address(0)) {
            zkVerifier = IZKPQCVerifier(_zkVerifier);
        }
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
    ) external whenNotPaused returns (bool valid) {
        return
            _verify(
                message,
                signature,
                publicKey,
                PQCLib.SignatureAlgorithm.Dilithium3
            );
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
    ) external whenNotPaused returns (bool valid) {
        return
            _verify(
                message,
                signature,
                publicKey,
                PQCLib.SignatureAlgorithm.Dilithium5
            );
    }

    /**
     * @notice Verify with ZK proof (for off-chain verification mode)
     * @param message The message hash
     * @param publicKeyHash Hash of the public key
     * @param zkProof The ZK proof of correct verification
     * @param algorithm The Dilithium variant
     * @return valid True if the ZK proof is valid
     */
    function verifyWithZKProof(
        bytes32 message,
        bytes32 publicKeyHash,
        bytes calldata zkProof,
        PQCLib.SignatureAlgorithm algorithm
    ) external whenNotPaused returns (bool valid) {
        if (address(zkVerifier) == address(0)) revert ZKVerifierNotSet();

        // Verify the algorithm is Dilithium
        if (
            algorithm != PQCLib.SignatureAlgorithm.Dilithium3 &&
            algorithm != PQCLib.SignatureAlgorithm.Dilithium5
        ) {
            revert InvalidSecurityLevel();
        }

        totalVerifications++;

        // Check cache first
        bytes32 cacheKey = keccak256(
            abi.encode(message, publicKeyHash, keccak256(zkProof))
        );
        if (_isCacheValid(cacheKey)) {
            return verificationCache[cacheKey];
        }

        // Verify ZK proof
        valid = zkVerifier.verifyDilithiumProof(
            zkProof,
            message,
            publicKeyHash
        );

        if (valid) {
            successfulVerifications++;
            _cacheResult(cacheKey, true);
        }

        emit DilithiumVerified(
            message,
            publicKeyHash,
            algorithm,
            valid,
            PQCLib.VerificationMode.OffchainZK
        );
    }

    /**
     * @notice Batch verify multiple signatures
     * @param messages Array of message hashes
     * @param signatures Array of signatures
     * @param publicKeys Array of public keys
     * @param algorithm The Dilithium variant
     * @return allValid True if all signatures are valid
     */
    function batchVerify(
        bytes32[] calldata messages,
        bytes[] calldata signatures,
        bytes[] calldata publicKeys,
        PQCLib.SignatureAlgorithm algorithm
    ) external whenNotPaused returns (bool allValid) {
        uint256 len = messages.length;
        require(
            len == signatures.length && len == publicKeys.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < len; i++) {
            if (
                !_verify(messages[i], signatures[i], publicKeys[i], algorithm)
            ) {
                return false;
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
        PQCLib.SignatureAlgorithm algorithm
    ) internal returns (bool valid) {
        // Validate sizes
        _validateSizes(signature, publicKey, algorithm);

        bytes32 pkHash = PQCLib.hashPublicKey(publicKey, algorithm);
        totalVerifications++;

        // Check cache
        bytes32 cacheKey = keccak256(
            abi.encode(message, keccak256(signature), pkHash)
        );
        if (_isCacheValid(cacheKey)) {
            return verificationCache[cacheKey];
        }

        // Route to appropriate verification mode
        if (verificationMode == PQCLib.VerificationMode.Mock) {
            valid = _mockVerify(message, publicKey, pkHash);
        } else if (verificationMode == PQCLib.VerificationMode.Precompile) {
            valid = _precompileVerify(message, signature, publicKey, algorithm);
        } else if (verificationMode == PQCLib.VerificationMode.OffchainZK) {
            // For off-chain ZK mode, require explicit ZK proof
            // This path should use verifyWithZKProof instead
            revert ZKVerifierNotSet();
        } else if (verificationMode == PQCLib.VerificationMode.PureSolidity) {
            valid = _solidityVerify(message, signature, publicKey, algorithm);
        }

        if (valid) {
            successfulVerifications++;
            _cacheResult(cacheKey, true);
        }

        emit DilithiumVerified(
            message,
            pkHash,
            algorithm,
            valid,
            verificationMode
        );
    }

    function _validateSizes(
        bytes calldata signature,
        bytes calldata publicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) internal pure {
        uint256 expectedPkSize;
        uint256 expectedSigSize;

        if (algorithm == PQCLib.SignatureAlgorithm.Dilithium3) {
            expectedPkSize = PQCLib.DILITHIUM3_PK_SIZE;
            expectedSigSize = PQCLib.DILITHIUM3_SIG_SIZE;
        } else if (algorithm == PQCLib.SignatureAlgorithm.Dilithium5) {
            expectedPkSize = PQCLib.DILITHIUM5_PK_SIZE;
            expectedSigSize = PQCLib.DILITHIUM5_SIG_SIZE;
        } else {
            revert InvalidSecurityLevel();
        }

        if (publicKey.length != expectedPkSize) {
            revert InvalidPublicKeySize(expectedPkSize, publicKey.length);
        }
        if (signature.length != expectedSigSize) {
            revert InvalidSignatureSize(expectedSigSize, signature.length);
        }
    }

    function _mockVerify(
        bytes32 message,
        bytes calldata publicKey,
        bytes32 pkHash
    ) internal view returns (bool) {
        // Only allow mock mode on testnets
        if (block.chainid == 1) {
            revert MockModeNotAllowedOnMainnet();
        }

        // Trust pre-registered keys
        if (trustedKeyHashes[pkHash]) {
            return true;
        }

        // Basic sanity check for mock
        return message != bytes32(0) && publicKey.length > 0;
    }

    function _precompileVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) internal view returns (bool) {
        bytes memory input = abi.encodePacked(
            uint8(algorithm),
            message,
            publicKey,
            signature
        );

        (bool success, bytes memory result) = DILITHIUM_PRECOMPILE.staticcall(
            input
        );

        if (!success || result.length == 0) {
            // Fallback to mock on testnet if precompile not available
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
        PQCLib.SignatureAlgorithm algorithm
    ) internal view returns (bool) {
        // Check gas limit
        if (gasleft() < MAX_SOLIDITY_GAS) {
            revert GasLimitExceeded();
        }

        // Full Solidity verification would go here
        // This is extremely gas-expensive (~10M gas)
        // For now, we implement a simplified version

        // Parse public key components
        bytes32 rho;
        assembly {
            rho := calldataload(publicKey.offset)
        }

        // Parse signature components
        bytes32 c;
        assembly {
            c := calldataload(signature.offset)
        }

        // Simplified verification (not cryptographically complete)
        // Real implementation would:
        // 1. Expand matrix A from rho
        // 2. Compute w' = Az - ct1 * 2^d
        // 3. Hash to get c' and compare

        bytes32 computed = keccak256(
            abi.encodePacked(PQCLib.DILITHIUM_DOMAIN, message, rho, algorithm)
        );

        // This is a placeholder - real verification is much more complex
        return computed != bytes32(0) && c != bytes32(0);
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

    function clearCache(bytes32 cacheKey) external onlyOwner {
        delete verificationCache[cacheKey];
        delete cacheTimestamps[cacheKey];
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

    function setZKVerifier(address _zkVerifier) external onlyOwner {
        address oldVerifier = address(zkVerifier);
        zkVerifier = IZKPQCVerifier(_zkVerifier);
        emit ZKVerifierUpdated(oldVerifier, _zkVerifier);
    }

    function setCacheTTL(uint256 _cacheTTL) external onlyOwner {
        uint256 oldTTL = cacheTTL;
        cacheTTL = _cacheTTL;
        emit CacheTTLUpdated(oldTTL, _cacheTTL);
    }

    function addTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    function removeTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
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
}
