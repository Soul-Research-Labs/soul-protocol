// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title KyberKEM
 * @author Soul Protocol
 * @notice On-chain Key Encapsulation Mechanism using NIST ML-KEM (Kyber)
 * @dev Implements Kyber key encapsulation for post-quantum key exchange.
 *      Used for privacy pool key exchanges and cross-chain secure channels.
 *
 * Kyber Parameters:
 * - Kyber512: 128-bit security, fast
 * - Kyber768: 192-bit security (recommended)
 * - Kyber1024: 256-bit security, most secure
 */

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract KyberKEM is Ownable {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for Kyber
    address public constant KYBER_PRECOMSoulE = address(0x0F);

    /// @notice Kyber512 sizes
    uint256 public constant KYBER512_PK_SIZE = 800;
    uint256 public constant KYBER512_SK_SIZE = 1632;
    uint256 public constant KYBER512_CT_SIZE = 768;

    /// @notice Kyber768 sizes (recommended)
    uint256 public constant KYBER768_PK_SIZE = 1184;
    uint256 public constant KYBER768_SK_SIZE = 2400;
    uint256 public constant KYBER768_CT_SIZE = 1088;

    /// @notice Kyber1024 sizes
    uint256 public constant KYBER1024_PK_SIZE = 1568;
    uint256 public constant KYBER1024_SK_SIZE = 3168;
    uint256 public constant KYBER1024_CT_SIZE = 1568;

    /// @notice Shared secret size (all variants)
    uint256 public constant SHARED_SECRET_SIZE = 32;

    // =============================================================================
    // ENUMS
    // =============================================================================

    enum KyberVariant {
        Kyber512,
        Kyber768,
        Kyber1024
    }

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice Encapsulated key material
     */
    struct Encapsulation {
        bytes ciphertext; // The encapsulated ciphertext
        bytes32 sharedSecretHash; // Hash of the shared secret (for verification)
        KyberVariant variant; // Which variant was used
        uint64 timestamp; // When encapsulation occurred
    }

    /**
     * @notice Registered public key for an address
     */
    struct KyberKeyPair {
        bytes32 publicKeyHash; // Hash of the full public key
        KyberVariant variant; // Which variant
        uint64 registeredAt; // Registration time
        bool isActive; // Whether key is active
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Mock mode for testing
    bool public useMockMode;

    /// @notice Registered Kyber public keys
    mapping(address => KyberKeyPair) public registeredKeys;

    /// @notice Full public keys stored by hash
    mapping(bytes32 => bytes) public publicKeyStorage;

    /// @notice Pending encapsulations awaiting decapsulation
    mapping(bytes32 => Encapsulation) public pendingEncapsulations;

    /// @notice Completed key exchanges
    mapping(bytes32 => bool) public completedExchanges;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event KeyPairRegistered(
        address indexed owner,
        bytes32 indexed publicKeyHash,
        KyberVariant variant
    );

    event KeyEncapsulated(
        bytes32 indexed exchangeId,
        address indexed sender,
        address indexed recipient,
        KyberVariant variant
    );

    event KeyDecapsulated(
        bytes32 indexed exchangeId,
        address indexed recipient,
        bytes32 sharedSecretHash
    );

    event KeyPairRevoked(address indexed owner);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidCiphertextSize(uint256 expected, uint256 actual);
    error KeyNotRegistered();
    error KeyAlreadyRegistered();
    error ExchangeNotFound();
    error ExchangeAlreadyCompleted();
    error PrecompileCallFailed();

    error SharedSecretMismatch();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor() Ownable(msg.sender) {
        useMockMode = true;
    }

    // =============================================================================
    // KEY REGISTRATION
    // =============================================================================

    /**
     * @notice Register a Kyber public key
     * @param publicKey The full Kyber public key
     * @param variant The Kyber variant
     */
    function registerPublicKey(
        bytes calldata publicKey,
        KyberVariant variant
    ) external {
        if (registeredKeys[msg.sender].isActive) {
            revert KeyAlreadyRegistered();
        }

        uint256 expectedSize = _getPublicKeySize(variant);
        if (publicKey.length != expectedSize) {
            revert InvalidPublicKeySize(expectedSize, publicKey.length);
        }

        bytes32 pkHash = keccak256(publicKey);

        registeredKeys[msg.sender] = KyberKeyPair({
            publicKeyHash: pkHash,
            variant: variant,
            registeredAt: uint64(block.timestamp),
            isActive: true
        });

        // Store full public key
        publicKeyStorage[pkHash] = publicKey;

        emit KeyPairRegistered(msg.sender, pkHash, variant);
    }

    /**
     * @notice Revoke a registered key
     */
    function revokeKey() external {
        if (!registeredKeys[msg.sender].isActive) {
            revert KeyNotRegistered();
        }

        bytes32 pkHash = registeredKeys[msg.sender].publicKeyHash;
        delete publicKeyStorage[pkHash];
        delete registeredKeys[msg.sender];

        emit KeyPairRevoked(msg.sender);
    }

    // =============================================================================
    // KEY ENCAPSULATION
    // =============================================================================

    /**
     * @notice Encapsulate a shared secret for a recipient
     * @param recipient The recipient address
     * @param randomness Optional randomness for deterministic encapsulation
     * @return exchangeId Unique identifier for this exchange
     * @return ciphertext The encapsulated ciphertext to send to recipient
     * @return sharedSecretHash Hash of the shared secret (for verification)
     */
    function encapsulate(
        address recipient,
        bytes32 randomness
    )
        external
        returns (
            bytes32 exchangeId,
            bytes memory ciphertext,
            bytes32 sharedSecretHash
        )
    {
        // Cache storage reads for gas efficiency
        KyberKeyPair memory recipientKey = registeredKeys[recipient];
        if (!recipientKey.isActive) {
            revert KeyNotRegistered();
        }

        bytes memory publicKey = publicKeyStorage[recipientKey.publicKeyHash];
        KyberVariant variant = recipientKey.variant;

        // Generate exchange ID
        exchangeId = keccak256(
            abi.encode(msg.sender, recipient, block.timestamp, randomness)
        );

        // Cache storage read
        bool mockMode = useMockMode;
        if (mockMode) {
            // Mock encapsulation for testing
            (ciphertext, sharedSecretHash) = _mockEncapsulate(
                publicKey,
                variant,
                randomness
            );
        } else {
            (ciphertext, sharedSecretHash) = _precompileEncapsulate(
                publicKey,
                variant,
                randomness
            );
        }

        // Store pending encapsulation
        pendingEncapsulations[exchangeId] = Encapsulation({
            ciphertext: ciphertext,
            sharedSecretHash: sharedSecretHash,
            variant: variant,
            timestamp: uint64(block.timestamp)
        });

        emit KeyEncapsulated(exchangeId, msg.sender, recipient, variant);
    }

    /**
     * @notice Decapsulate a shared secret (off-chain operation, on-chain verification)
     * @param exchangeId The exchange identifier
     * @param sharedSecretHash Hash of the decapsulated secret (for verification)
     */
    function confirmDecapsulation(
        bytes32 exchangeId,
        bytes32 sharedSecretHash
    ) external {
        Encapsulation storage encap = pendingEncapsulations[exchangeId];
        if (encap.timestamp == 0) {
            revert ExchangeNotFound();
        }
        if (completedExchanges[exchangeId]) {
            revert ExchangeAlreadyCompleted();
        }

        // Verify the shared secret matches
        if (encap.sharedSecretHash != sharedSecretHash) {
            revert SharedSecretMismatch();
        }

        completedExchanges[exchangeId] = true;

        emit KeyDecapsulated(exchangeId, msg.sender, sharedSecretHash);
    }

    // =============================================================================
    // INTERNAL FUNCTIONS
    // =============================================================================

    function _mockEncapsulate(
        bytes memory publicKey,
        KyberVariant variant,
        bytes32 randomness
    )
        internal
        view
        returns (bytes memory ciphertext, bytes32 sharedSecretHash)
    {
        // Generate deterministic mock ciphertext
        uint256 ctSize = _getCiphertextSize(variant);
        ciphertext = new bytes(ctSize);

        // Fill with pseudo-random data
        bytes32 seed = keccak256(
            abi.encode(publicKey, randomness, block.timestamp)
        );
        for (uint256 i = 0; i < ctSize; i += 32) {
            seed = keccak256(abi.encode(seed, i));
            uint256 remaining = ctSize - i;
            uint256 copyLen = remaining < 32 ? remaining : 32;
            for (uint256 j = 0; j < copyLen; j++) {
                ciphertext[i + j] = bytes1(
                    uint8(uint256(seed) >> (8 * (31 - j)))
                );
            }
        }

        // Generate mock shared secret hash
        sharedSecretHash = keccak256(
            abi.encode(publicKey, ciphertext, randomness)
        );
    }

    function _precompileEncapsulate(
        bytes memory publicKey,
        KyberVariant variant,
        bytes32 randomness
    ) internal returns (bytes memory ciphertext, bytes32 sharedSecretHash) {
        bytes memory input = abi.encodePacked(
            uint8(0), // Operation: Encapsulate
            uint8(variant),
            randomness,
            publicKey
        );

        (bool success, bytes memory result) = KYBER_PRECOMSoulE.call(input);

        if (!success || result.length == 0) {
            if (useMockMode) {
                return _mockEncapsulate(publicKey, variant, randomness);
            }
            revert PrecompileCallFailed();
        }

        // Decode result: ciphertext length (32) + ciphertext + shared secret (32)
        uint256 ctSize = _getCiphertextSize(variant);
        ciphertext = new bytes(ctSize);
        for (uint256 i; i < ctSize; ) {
            ciphertext[i] = result[i];
            unchecked {
                ++i;
            }
        }
        // Extract shared secret hash from result
        assembly {
            sharedSecretHash := mload(add(add(result, 32), ctSize))
        }
    }

    function _getPublicKeySize(
        KyberVariant variant
    ) internal pure returns (uint256) {
        if (variant == KyberVariant.Kyber512) return KYBER512_PK_SIZE;
        if (variant == KyberVariant.Kyber768) return KYBER768_PK_SIZE;
        return KYBER1024_PK_SIZE;
    }

    function _getCiphertextSize(
        KyberVariant variant
    ) internal pure returns (uint256) {
        if (variant == KyberVariant.Kyber512) return KYBER512_CT_SIZE;
        if (variant == KyberVariant.Kyber768) return KYBER768_CT_SIZE;
        return KYBER1024_CT_SIZE;
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setMockMode(bool enabled) external onlyOwner {
        useMockMode = enabled;
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    /**
     * @notice Get registered key info for an address
     */
    function getKeyInfo(
        address owner
    ) external view returns (KyberKeyPair memory) {
        return registeredKeys[owner];
    }

    /**
     * @notice Get stored public key
     */
    function getPublicKey(address owner) external view returns (bytes memory) {
        bytes32 pkHash = registeredKeys[owner].publicKeyHash;
        return publicKeyStorage[pkHash];
    }

    /**
     * @notice Get encapsulation details
     */
    function getEncapsulation(
        bytes32 exchangeId
    ) external view returns (Encapsulation memory) {
        return pendingEncapsulations[exchangeId];
    }

    /**
     * @notice Check if exchange is completed
     */
    function isExchangeCompleted(
        bytes32 exchangeId
    ) external view returns (bool) {
        return completedExchanges[exchangeId];
    }

    /**
     * @notice Get expected sizes for a variant
     */
    function getSizes(
        KyberVariant variant
    ) external pure returns (uint256 pkSize, uint256 skSize, uint256 ctSize) {
        if (variant == KyberVariant.Kyber512) {
            return (KYBER512_PK_SIZE, KYBER512_SK_SIZE, KYBER512_CT_SIZE);
        } else if (variant == KyberVariant.Kyber768) {
            return (KYBER768_PK_SIZE, KYBER768_SK_SIZE, KYBER768_CT_SIZE);
        } else {
            return (KYBER1024_PK_SIZE, KYBER1024_SK_SIZE, KYBER1024_CT_SIZE);
        }
    }
}
