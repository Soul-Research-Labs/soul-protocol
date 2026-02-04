// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {PQCLib} from "../../libraries/PQCLib.sol";

/**
 * @title IKyberKEM
 * @notice Interface for CRYSTALS-Kyber (ML-KEM) key encapsulation mechanism
 * @dev Enables quantum-secure key exchange on-chain
 *
 * NIST FIPS 203 (ML-KEM) - Finalized August 2024
 * - Kyber512: Security Level 1, 800 byte public key, 768 byte ciphertext
 * - Kyber768: Security Level 3, 1184 byte public key, 1088 byte ciphertext
 * - Kyber1024: Security Level 5, 1568 byte public key, 1568 byte ciphertext
 */
interface IKyberKEM {
    // ============ Events ============

    /**
     * @notice Emitted when a public key is registered
     * @param owner Address of the key owner
     * @param publicKeyHash Hash of the public key
     * @param algorithm Kyber variant
     * @param expiresAt Expiration timestamp
     */
    event PublicKeyRegistered(
        address indexed owner,
        bytes32 indexed publicKeyHash,
        PQCLib.KEMAlgorithm algorithm,
        uint256 expiresAt
    );

    /**
     * @notice Emitted when a public key is updated
     * @param owner Address of the key owner
     * @param oldKeyHash Hash of the old public key
     * @param newKeyHash Hash of the new public key
     */
    event PublicKeyUpdated(
        address indexed owner,
        bytes32 indexed oldKeyHash,
        bytes32 indexed newKeyHash
    );

    /**
     * @notice Emitted when a public key is revoked
     * @param owner Address of the key owner
     * @param publicKeyHash Hash of the revoked key
     */
    event PublicKeyRevoked(
        address indexed owner,
        bytes32 indexed publicKeyHash
    );

    /**
     * @notice Emitted when a key exchange is initiated
     * @param exchangeId Unique exchange identifier
     * @param initiator Address initiating the exchange
     * @param recipient Address of the recipient
     * @param ciphertextHash Hash of the encapsulated ciphertext
     */
    event KeyExchangeInitiated(
        bytes32 indexed exchangeId,
        address indexed initiator,
        address indexed recipient,
        bytes32 ciphertextHash
    );

    /**
     * @notice Emitted when a key exchange is completed
     * @param exchangeId Unique exchange identifier
     * @param sharedSecretHash Hash of the derived shared secret
     */
    event KeyExchangeCompleted(
        bytes32 indexed exchangeId,
        bytes32 sharedSecretHash
    );

    /**
     * @notice Emitted when a key exchange expires or is cancelled
     * @param exchangeId Unique exchange identifier
     */
    event KeyExchangeCancelled(bytes32 indexed exchangeId);

    // ============ Errors ============

    /// @notice Invalid Kyber public key size
    error InvalidPublicKeySize(uint256 provided, uint256 expected);

    /// @notice Invalid Kyber ciphertext size
    error InvalidCiphertextSize(uint256 provided, uint256 expected);

    /// @notice Public key not found
    error PublicKeyNotFound(address owner);

    /// @notice Public key has expired
    error PublicKeyExpired(address owner, uint256 expiredAt);

    /// @notice Public key already registered
    error PublicKeyAlreadyRegistered(address owner);

    /// @notice Key exchange not found
    error ExchangeNotFound(bytes32 exchangeId);

    /// @notice Key exchange has expired
    error ExchangeExpired(bytes32 exchangeId);

    /// @notice Not authorized for this operation
    error NotAuthorized(address caller, address expected);

    /// @notice Algorithm mismatch between parties
    error AlgorithmMismatch(
        PQCLib.KEMAlgorithm expected,
        PQCLib.KEMAlgorithm provided
    );

    /// @notice Replay attack detected
    error ReplayDetected(bytes32 ciphertextHash);

    // ============ Structs ============

    /**
     * @notice Registered public key information
     */
    struct RegisteredKey {
        bytes32 publicKeyHash;
        PQCLib.KEMAlgorithm algorithm;
        uint256 registeredAt;
        uint256 expiresAt;
        bool active;
    }

    /**
     * @notice Active key exchange session
     */
    struct KeyExchange {
        address initiator;
        address recipient;
        bytes32 ciphertextHash;
        PQCLib.KEMAlgorithm algorithm;
        uint256 initiatedAt;
        uint256 expiresAt;
        bool completed;
    }

    // ============ View Functions ============

    /**
     * @notice Get registered key for an address
     * @param owner Address of the key owner
     * @return key The registered key info
     */
    function getRegisteredKey(
        address owner
    ) external view returns (RegisteredKey memory key);

    /**
     * @notice Check if an address has a valid (non-expired) key
     * @param owner Address to check
     * @return valid True if key is valid and not expired
     */
    function hasValidKey(address owner) external view returns (bool valid);

    /**
     * @notice Get key exchange details
     * @param exchangeId The exchange identifier
     * @return exchange The exchange details
     */
    function getKeyExchange(
        bytes32 exchangeId
    ) external view returns (KeyExchange memory exchange);

    /**
     * @notice Check if a ciphertext has been used (replay protection)
     * @param ciphertextHash Hash of the ciphertext to check
     * @return used True if ciphertext was already used
     */
    function isCiphertextUsed(
        bytes32 ciphertextHash
    ) external view returns (bool used);

    /**
     * @notice Get recommended Kyber variant based on security requirements
     * @param securityLevel Desired NIST security level (1, 3, or 5)
     * @return algorithm Recommended Kyber variant
     */
    function getRecommendedAlgorithm(
        uint8 securityLevel
    ) external pure returns (PQCLib.KEMAlgorithm algorithm);

    /**
     * @notice Get expected sizes for a Kyber variant
     * @param algorithm Kyber variant
     * @return publicKeySize Expected public key size
     * @return ciphertextSize Expected ciphertext size
     * @return sharedSecretSize Expected shared secret size (32 bytes for all)
     */
    function getSizes(
        PQCLib.KEMAlgorithm algorithm
    )
        external
        pure
        returns (
            uint256 publicKeySize,
            uint256 ciphertextSize,
            uint256 sharedSecretSize
        );

    // ============ Key Registration Functions ============

    /**
     * @notice Register a new Kyber public key
     * @param publicKey The public key bytes
     * @param algorithm Kyber variant
     * @param expirationDays Number of days until key expires
     * @return publicKeyHash Hash of the registered key
     */
    function registerPublicKey(
        bytes calldata publicKey,
        PQCLib.KEMAlgorithm algorithm,
        uint256 expirationDays
    ) external returns (bytes32 publicKeyHash);

    /**
     * @notice Update existing public key (rotation)
     * @param newPublicKey New public key bytes
     * @param algorithm Kyber variant
     * @param expirationDays Days until new key expires
     * @return newKeyHash Hash of the new key
     */
    function updatePublicKey(
        bytes calldata newPublicKey,
        PQCLib.KEMAlgorithm algorithm,
        uint256 expirationDays
    ) external returns (bytes32 newKeyHash);

    /**
     * @notice Revoke current public key
     */
    function revokePublicKey() external;

    // ============ Key Exchange Functions ============

    /**
     * @notice Initiate a key exchange with a recipient
     * @param recipient Address of the recipient
     * @param ciphertext Encapsulated ciphertext
     * @return exchangeId Unique identifier for this exchange
     */
    function initiateExchange(
        address recipient,
        bytes calldata ciphertext
    ) external returns (bytes32 exchangeId);

    /**
     * @notice Complete a key exchange
     * @param exchangeId The exchange to complete
     * @param sharedSecretHash Hash of the derived shared secret (for verification)
     */
    function completeExchange(
        bytes32 exchangeId,
        bytes32 sharedSecretHash
    ) external;

    /**
     * @notice Cancel an expired or unwanted exchange
     * @param exchangeId The exchange to cancel
     */
    function cancelExchange(bytes32 exchangeId) external;

    /**
     * @notice Verify ciphertext format without executing exchange
     * @param ciphertext Ciphertext to verify
     * @param algorithm Expected Kyber variant
     * @return valid True if format is valid
     */
    function verifyCiphertextFormat(
        bytes calldata ciphertext,
        PQCLib.KEMAlgorithm algorithm
    ) external pure returns (bool valid);

    // ============ Admin Functions ============

    /**
     * @notice Set default key expiration period
     * @param daysCount Default expiration in days
     */
    function setDefaultExpiration(uint256 daysCount) external;

    /**
     * @notice Set exchange timeout
     * @param hoursCount Timeout in hours
     */
    function setExchangeTimeout(uint256 hoursCount) external;

    /**
     * @notice Pause the contract
     */
    function pause() external;

    /**
     * @notice Unpause the contract
     */
    function unpause() external;
}
