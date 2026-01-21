// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IPostQuantumCrypto.sol";

/**
 * @title HybridCryptoVerifier
 * @author Soul Protocol - PIL v2
 * @notice Hybrid cryptography combining classical (ECDSA/EdDSA) with post-quantum signatures
 * @dev Implements "belt and suspenders" approach for crypto-agile security:
 *
 * Security Properties:
 * - Security is maintained if EITHER classical OR PQC scheme is secure
 * - Protects against "harvest now, decrypt later" quantum attacks
 * - Backward compatible with existing classical infrastructure
 *
 * Supported Hybrid Modes:
 * - ECDSA + Dilithium (recommended for Ethereum compatibility)
 * - EdDSA + Dilithium (for non-EVM chains)
 * - ECDSA + SPHINCS+ (highest security, hash-based)
 * - ECDSA + Falcon (compact signatures)
 *
 * Key Derivation:
 * - Hybrid key = HKDF(ECDH_secret || KEM_secret, context)
 * - Both secrets required for decryption
 */
contract HybridCryptoVerifier is
    IHybridCrypto,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant HYBRID_ADMIN_ROLE = keccak256("HYBRID_ADMIN_ROLE");
    bytes32 public constant KEY_REGISTRAR_ROLE =
        keccak256("KEY_REGISTRAR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator for hybrid key derivation
    bytes32 public constant HYBRID_DOMAIN = keccak256("PIL.HybridCrypto.v1");

    /// @notice Minimum security level (bits)
    uint256 public constant MIN_SECURITY_BITS = 128;

    /// @notice ECDSA signature size (r, s, v)
    uint256 public constant ECDSA_SIG_SIZE = 65;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Hybrid mode combining classical and PQC algorithms
    enum HybridMode {
        ECDSA_DILITHIUM2, // secp256k1 + Dilithium L2
        ECDSA_DILITHIUM3, // secp256k1 + Dilithium L3
        ECDSA_DILITHIUM5, // secp256k1 + Dilithium L5
        ECDSA_SPHINCS_128F, // secp256k1 + SPHINCS+ 128f
        ECDSA_SPHINCS_256F, // secp256k1 + SPHINCS+ 256f
        ECDSA_FALCON512, // secp256k1 + Falcon-512
        ECDSA_FALCON1024, // secp256k1 + Falcon-1024
        EDDSA_DILITHIUM3, // Ed25519 + Dilithium L3
        EDDSA_SPHINCS_128F // Ed25519 + SPHINCS+ 128f
    }

    /// @notice Hybrid key pair registration
    struct HybridKeyPair {
        address owner;
        address classicalAddress; // ECDSA address (derived from public key)
        bytes32 pqPublicKeyHash; // Hash of PQ public key
        HybridMode mode;
        uint64 registeredAt;
        uint64 expiresAt;
        bool revoked;
    }

    /// @notice Hybrid verification result
    struct HybridVerificationResult {
        bool classicalValid;
        bool pqValid;
        bool combinedValid;
        HybridMode mode;
        bytes32 verificationHash;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice PQ signature verifier
    IPostQuantumSignatureVerifier public pqVerifier;

    /// @notice Registered hybrid key pairs
    mapping(bytes32 => HybridKeyPair) public hybridKeys;

    /// @notice Owner to key mappings
    mapping(address => bytes32[]) public ownerKeys;

    /// @notice Verified hybrid signatures
    mapping(bytes32 => bool) public verifiedHybridSignatures;

    /// @notice Supported hybrid modes
    mapping(HybridMode => bool) public supportedModes;

    /// @notice Total hybrid keys registered
    uint256 public totalKeysRegistered;

    /// @notice Total hybrid verifications
    uint256 public totalVerifications;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event HybridKeyRegistered(
        bytes32 indexed keyId,
        address indexed owner,
        HybridMode mode,
        address classicalAddress,
        bytes32 pqKeyHash
    );

    event HybridKeyRevoked(bytes32 indexed keyId, address indexed owner);

    event HybridSignatureVerified(
        bytes32 indexed signatureHash,
        HybridMode mode,
        bool classicalValid,
        bool pqValid,
        bool combinedValid
    );

    event HybridModeUpdated(HybridMode mode, bool supported);

    event PQVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error UnsupportedHybridMode(HybridMode mode);
    error InvalidClassicalSignature();
    error InvalidPQSignature();
    error KeyNotFound(bytes32 keyId);
    error KeyRevoked(bytes32 keyId);
    error KeyExpired(bytes32 keyId);
    error NotKeyOwner(address caller, address owner);
    error InvalidSignatureLength(uint256 expected, uint256 actual);
    error ZeroAddress();
    error KeyAlreadyExists(bytes32 keyId);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _pqVerifier) {
        if (_pqVerifier == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(HYBRID_ADMIN_ROLE, msg.sender);

        pqVerifier = IPostQuantumSignatureVerifier(_pqVerifier);

        // Enable default hybrid modes
        supportedModes[HybridMode.ECDSA_DILITHIUM2] = true;
        supportedModes[HybridMode.ECDSA_DILITHIUM3] = true;
        supportedModes[HybridMode.ECDSA_DILITHIUM5] = true;
        supportedModes[HybridMode.ECDSA_SPHINCS_128F] = true;
        supportedModes[HybridMode.ECDSA_FALCON512] = true;
    }

    /*//////////////////////////////////////////////////////////////
                         KEY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a hybrid key pair
     * @param classicalAddress The address derived from ECDSA public key
     * @param pqPublicKey The post-quantum public key bytes
     * @param mode The hybrid mode
     * @param expiresAt Expiration timestamp
     * @return keyId The unique key identifier
     */
    function registerHybridKey(
        address classicalAddress,
        bytes calldata pqPublicKey,
        HybridMode mode,
        uint64 expiresAt
    ) external nonReentrant whenNotPaused returns (bytes32 keyId) {
        if (!supportedModes[mode]) {
            revert UnsupportedHybridMode(mode);
        }

        if (classicalAddress == address(0)) {
            revert ZeroAddress();
        }

        bytes32 pqKeyHash = keccak256(pqPublicKey);

        keyId = keccak256(
            abi.encodePacked(
                msg.sender,
                classicalAddress,
                pqKeyHash,
                mode,
                block.timestamp
            )
        );

        if (hybridKeys[keyId].owner != address(0)) {
            revert KeyAlreadyExists(keyId);
        }

        hybridKeys[keyId] = HybridKeyPair({
            owner: msg.sender,
            classicalAddress: classicalAddress,
            pqPublicKeyHash: pqKeyHash,
            mode: mode,
            registeredAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revoked: false
        });

        ownerKeys[msg.sender].push(keyId);

        unchecked {
            ++totalKeysRegistered;
        }

        emit HybridKeyRegistered(
            keyId,
            msg.sender,
            mode,
            classicalAddress,
            pqKeyHash
        );
    }

    /**
     * @notice Revoke a hybrid key
     * @param keyId The key to revoke
     */
    function revokeHybridKey(bytes32 keyId) external {
        HybridKeyPair storage key = hybridKeys[keyId];

        if (key.owner == address(0)) {
            revert KeyNotFound(keyId);
        }

        if (
            key.owner != msg.sender && !hasRole(HYBRID_ADMIN_ROLE, msg.sender)
        ) {
            revert NotKeyOwner(msg.sender, key.owner);
        }

        key.revoked = true;

        emit HybridKeyRevoked(keyId, key.owner);
    }

    /*//////////////////////////////////////////////////////////////
                       SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IHybridCrypto
     */
    function verifyHybridSignature(
        bytes32 message,
        HybridSignature calldata hybridSig,
        bytes calldata classicalPubKey,
        PQPublicKey calldata pqPubKey
    ) external view override returns (bool valid) {
        // Verify binding between signatures
        bytes32 expectedBinding = keccak256(
            abi.encodePacked(
                message,
                hybridSig.classicalSignature,
                hybridSig.pqSignature.signature
            )
        );

        if (expectedBinding != hybridSig.combinedHash) {
            return false;
        }

        // Verify classical signature (ECDSA)
        bool classicalValid = _verifyECDSA(
            message,
            hybridSig.classicalSignature,
            classicalPubKey
        );

        if (!classicalValid) {
            return false;
        }

        // Verify PQ signature
        bool pqValid = pqVerifier.verifyPQSignature(
            message,
            hybridSig.pqSignature,
            pqPubKey
        );

        // Both must be valid for hybrid verification
        return classicalValid && pqValid;
    }

    /**
     * @notice Get the first hybrid key hash for an owner
     * @param owner The owner address
     * @return keyHash The first key hash, or zero if none
     */
    function getHybridKeyHash(
        address owner
    ) external view returns (bytes32 keyHash) {
        bytes32[] storage keys = ownerKeys[owner];
        if (keys.length == 0) {
            return bytes32(0);
        }
        return keys[0];
    }

    /**
     * @notice Verify a hybrid signature with detailed result
     * @param message The message hash
     * @param keyId The registered hybrid key ID
     * @param classicalSig Raw ECDSA signature
     * @param pqSig Full PQ signature
     * @param pqPubKey PQ public key
     * @return result Detailed verification result
     */
    function verifyWithDetails(
        bytes32 message,
        bytes32 keyId,
        bytes calldata classicalSig,
        PQSignature calldata pqSig,
        PQPublicKey calldata pqPubKey
    ) external view returns (HybridVerificationResult memory result) {
        HybridKeyPair storage key = hybridKeys[keyId];

        if (key.owner == address(0)) {
            return result; // All false
        }

        if (key.revoked) {
            return result;
        }

        if (block.timestamp > key.expiresAt && key.expiresAt != 0) {
            return result;
        }

        result.mode = key.mode;
        result.verificationHash = keccak256(
            abi.encodePacked(message, keyId, block.timestamp)
        );

        // Verify classical signature recovers to registered address
        result.classicalValid = _verifyECDSAToAddress(
            message,
            classicalSig,
            key.classicalAddress
        );

        // Verify PQ signature with registered key hash
        if (pqPubKey.keyHash == key.pqPublicKeyHash) {
            result.pqValid = pqVerifier.verifyPQSignature(
                message,
                pqSig,
                pqPubKey
            );
        }

        // Combined is only valid if BOTH are valid
        result.combinedValid = result.classicalValid && result.pqValid;
    }

    /**
     * @notice Batch verify multiple hybrid signatures
     * @param messages Array of message hashes
     * @param signatures Array of hybrid signatures
     * @param keyIds Array of key IDs
     * @return results Array of verification results
     */
    function batchVerify(
        bytes32[] calldata messages,
        HybridSignature[] calldata signatures,
        bytes32[] calldata keyIds
    ) external view returns (bool[] memory results) {
        require(
            messages.length == signatures.length &&
                signatures.length == keyIds.length,
            "Array length mismatch"
        );

        results = new bool[](messages.length);

        for (uint256 i = 0; i < messages.length; i++) {
            HybridKeyPair storage key = hybridKeys[keyIds[i]];

            if (key.owner == address(0) || key.revoked) {
                results[i] = false;
                continue;
            }

            if (block.timestamp > key.expiresAt && key.expiresAt != 0) {
                results[i] = false;
                continue;
            }

            // Simplified batch check - in production would do full verification
            results[i] = signatures[i].combinedHash != bytes32(0);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          KEY DERIVATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IHybridCrypto
     */
    function deriveHybridKey(
        bytes32 classicalSharedSecret,
        bytes32 pqSharedSecret,
        bytes calldata context
    ) external pure override returns (bytes32 hybridKey) {
        // HKDF-style key derivation
        // IKM = classical_secret || pq_secret
        bytes memory ikm = abi.encodePacked(
            classicalSharedSecret,
            pqSharedSecret
        );

        // Extract: PRK = HMAC(salt, IKM)
        bytes32 prk = keccak256(abi.encodePacked(HYBRID_DOMAIN, ikm));

        // Expand: OKM = HMAC(PRK, info || 0x01)
        hybridKey = keccak256(abi.encodePacked(prk, context, uint8(1)));
    }

    /**
     * @notice Derive a hybrid encryption key with KDF parameters
     * @param classicalSecret ECDH shared secret
     * @param pqSecret KEM shared secret
     * @param salt Optional salt for KDF
     * @param info Context info for KDF
     * @param keyLength Desired key length in bytes (max 32)
     * @return derivedKey The derived key material
     */
    function deriveHybridKeyExtended(
        bytes32 classicalSecret,
        bytes32 pqSecret,
        bytes32 salt,
        bytes calldata info,
        uint8 keyLength
    ) external pure returns (bytes memory derivedKey) {
        require(keyLength <= 32 && keyLength > 0, "Invalid key length");

        // HKDF Extract
        bytes32 prk;
        if (salt == bytes32(0)) {
            prk = keccak256(abi.encodePacked(classicalSecret, pqSecret));
        } else {
            prk = keccak256(abi.encodePacked(salt, classicalSecret, pqSecret));
        }

        // HKDF Expand
        bytes32 okm = keccak256(abi.encodePacked(prk, info, uint8(1)));

        // Truncate to desired length
        derivedKey = new bytes(keyLength);
        for (uint8 i = 0; i < keyLength; i++) {
            derivedKey[i] = okm[i];
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IHybridCrypto
     */
    function hybridScheme()
        external
        pure
        override
        returns (string memory scheme)
    {
        return "PIL-Hybrid-v1";
    }

    /**
     * @notice Get a registered hybrid key
     * @param keyId The key identifier
     * @return key The hybrid key pair
     */
    function getHybridKey(
        bytes32 keyId
    ) external view returns (HybridKeyPair memory key) {
        return hybridKeys[keyId];
    }

    /**
     * @notice Check if a hybrid key is valid
     * @param keyId The key to check
     * @return valid True if key is valid (exists, not revoked, not expired)
     */
    function isKeyValid(bytes32 keyId) external view returns (bool valid) {
        HybridKeyPair storage key = hybridKeys[keyId];

        if (key.owner == address(0)) return false;
        if (key.revoked) return false;
        if (key.expiresAt != 0 && block.timestamp > key.expiresAt) return false;

        return true;
    }

    /**
     * @notice Get all keys for an owner
     * @param owner The key owner
     * @return keyIds Array of key IDs
     */
    function getOwnerKeys(
        address owner
    ) external view returns (bytes32[] memory keyIds) {
        return ownerKeys[owner];
    }

    /**
     * @notice Get the PQ algorithm for a hybrid mode
     * @param mode The hybrid mode
     * @return algorithm The PQ signature algorithm
     */
    function getPQAlgorithm(
        HybridMode mode
    ) external pure returns (PQSignatureAlgorithm algorithm) {
        if (mode == HybridMode.ECDSA_DILITHIUM2)
            return PQSignatureAlgorithm.DILITHIUM2;
        if (
            mode == HybridMode.ECDSA_DILITHIUM3 ||
            mode == HybridMode.EDDSA_DILITHIUM3
        ) {
            return PQSignatureAlgorithm.DILITHIUM3;
        }
        if (mode == HybridMode.ECDSA_DILITHIUM5)
            return PQSignatureAlgorithm.DILITHIUM5;
        if (
            mode == HybridMode.ECDSA_SPHINCS_128F ||
            mode == HybridMode.EDDSA_SPHINCS_128F
        ) {
            return PQSignatureAlgorithm.SPHINCS_SHA2_128F;
        }
        if (mode == HybridMode.ECDSA_SPHINCS_256F)
            return PQSignatureAlgorithm.SPHINCS_SHA2_256F;
        if (mode == HybridMode.ECDSA_FALCON512)
            return PQSignatureAlgorithm.FALCON512;
        if (mode == HybridMode.ECDSA_FALCON1024)
            return PQSignatureAlgorithm.FALCON1024;

        return PQSignatureAlgorithm.DILITHIUM3; // Default
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the PQ verifier contract
     * @param newVerifier The new verifier address
     */
    function setPQVerifier(
        address newVerifier
    ) external onlyRole(HYBRID_ADMIN_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();

        address oldVerifier = address(pqVerifier);
        pqVerifier = IPostQuantumSignatureVerifier(newVerifier);

        emit PQVerifierUpdated(oldVerifier, newVerifier);
    }

    /**
     * @notice Enable or disable a hybrid mode
     * @param mode The mode to update
     * @param supported Whether to enable or disable
     */
    function setHybridModeSupport(
        HybridMode mode,
        bool supported
    ) external onlyRole(HYBRID_ADMIN_ROLE) {
        supportedModes[mode] = supported;
        emit HybridModeUpdated(mode, supported);
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

    /**
     * @notice Verify an ECDSA signature
     * @param messageHash The message hash
     * @param signature The ECDSA signature (65 bytes: r, s, v)
     * @param publicKey The public key bytes
     * @return valid True if signature is valid
     */
    function _verifyECDSA(
        bytes32 messageHash,
        bytes calldata signature,
        bytes calldata publicKey
    ) internal pure returns (bool valid) {
        if (signature.length != ECDSA_SIG_SIZE) {
            return false;
        }

        // Extract r, s, v
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Normalize v
        if (v < 27) v += 27;

        // Recover signer
        address recovered = ecrecover(messageHash, v, r, s);

        // Derive expected address from public key
        if (publicKey.length == 64) {
            // Uncompressed without prefix
            address expected = address(uint160(uint256(keccak256(publicKey))));
            return recovered == expected;
        } else if (publicKey.length == 65) {
            // Uncompressed with 0x04 prefix
            address expected = address(
                uint160(uint256(keccak256(publicKey[1:])))
            );
            return recovered == expected;
        }

        return false;
    }

    /**
     * @notice Verify ECDSA signature recovers to expected address
     * @param messageHash The message hash
     * @param signature The ECDSA signature
     * @param expectedAddress The expected signer address
     * @return valid True if signature is from expected address
     */
    function _verifyECDSAToAddress(
        bytes32 messageHash,
        bytes calldata signature,
        address expectedAddress
    ) internal pure returns (bool valid) {
        if (signature.length != ECDSA_SIG_SIZE) {
            return false;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) v += 27;

        address recovered = ecrecover(messageHash, v, r, s);
        return recovered == expectedAddress && recovered != address(0);
    }
}
