// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {PQCLib} from "../../libraries/PQCLib.sol";

/**
 * @title IPQCRegistry
 * @notice Interface for the central PQC primitives registry
 * @dev Manages account PQC configurations, signature verification,
 *      key exchanges, and statistics tracking across the protocol.
 */
interface IPQCRegistry {
    // ============ Events ============

    /**
     * @notice Emitted when an account configures PQC
     * @param account The account address
     * @param signatureAlgorithm Signature algorithm chosen
     * @param kemAlgorithm KEM algorithm chosen
     * @param publicKeyHash Hash of the signature public key
     */
    event AccountConfigured(
        address indexed account,
        PQCLib.SignatureAlgorithm signatureAlgorithm,
        PQCLib.KEMAlgorithm kemAlgorithm,
        bytes32 indexed publicKeyHash
    );

    /**
     * @notice Emitted when an account updates PQC configuration
     * @param account The account address
     * @param newPublicKeyHash Hash of the new public key
     */
    event AccountUpdated(
        address indexed account,
        bytes32 indexed newPublicKeyHash
    );

    /**
     * @notice Emitted when an account deactivates PQC
     * @param account The account address
     */
    event AccountDeactivated(address indexed account);

    /**
     * @notice Emitted when signature verification completes
     * @param account The account address
     * @param messageHash Message hash verified
     * @param valid Verification result
     * @param hybrid Whether hybrid verification was used
     */
    event SignatureVerified(
        address indexed account,
        bytes32 indexed messageHash,
        bool valid,
        bool hybrid
    );

    /**
     * @notice Emitted when key exchange is initiated
     * @param exchangeId Unique exchange identifier
     * @param initiator Exchange initiator
     * @param recipient Exchange recipient
     */
    event KeyExchangeInitiated(
        bytes32 indexed exchangeId,
        address indexed initiator,
        address indexed recipient
    );

    /**
     * @notice Emitted when key exchange completes
     * @param exchangeId Exchange identifier
     * @param sharedSecretHash Hash of derived shared secret
     */
    event KeyExchangeCompleted(
        bytes32 indexed exchangeId,
        bytes32 sharedSecretHash
    );

    /**
     * @notice Emitted when a verifier contract is updated
     * @param verifierType Type of verifier
     * @param oldAddress Old verifier address
     * @param newAddress New verifier address
     */
    event VerifierUpdated(
        string verifierType,
        address indexed oldAddress,
        address indexed newAddress
    );

    // ============ Errors ============

    /// @notice Account already configured for PQC
    error AccountAlreadyConfigured(address account);

    /// @notice Account not configured for PQC
    error AccountNotConfigured(address account);

    /// @notice Account configuration is inactive
    error AccountInactive(address account);

    /// @notice Account configuration has expired
    error AccountExpired(address account);

    /// @notice Signature algorithm not supported
    error UnsupportedSignatureAlgorithm(PQCLib.SignatureAlgorithm algorithm);

    /// @notice KEM algorithm not supported
    error UnsupportedKEMAlgorithm(PQCLib.KEMAlgorithm algorithm);

    /// @notice Signature verification failed
    error VerificationFailed();

    /// @notice Hybrid signature required for this account
    error HybridSignatureRequired(address account);

    /// @notice Key exchange not found
    error ExchangeNotFound(bytes32 exchangeId);

    /// @notice Key exchange already exists
    error ExchangeAlreadyExists(bytes32 exchangeId);

    /// @notice Only exchange parties can interact
    error NotExchangeParty(address caller);

    /// @notice Verifier contract not set
    error VerifierNotSet(string verifierType);

    /// @notice Invalid public key
    error InvalidPublicKey();

    /// @notice Invalid signature
    error InvalidSignature();

    // ============ Structs ============

    /**
     * @notice Account PQC configuration
     */
    struct AccountConfig {
        PQCLib.SignatureAlgorithm signatureAlgorithm;
        PQCLib.KEMAlgorithm kemAlgorithm;
        bytes32 signaturePublicKeyHash;
        bytes32 kemPublicKeyHash;
        uint256 configuredAt;
        uint256 expiresAt;
        bool requireHybrid;
        bool active;
    }

    /**
     * @notice Protocol-wide PQC statistics
     */
    struct PQCStats {
        uint256 totalAccounts;
        uint256 activeAccounts;
        uint256 totalVerifications;
        uint256 successfulVerifications;
        uint256 hybridVerifications;
        uint256 keyExchanges;
    }

    /**
     * @notice Key exchange session
     */
    struct KeyExchangeSession {
        address initiator;
        address recipient;
        bytes32 initiatorCiphertextHash;
        bytes32 recipientCiphertextHash;
        PQCLib.KEMAlgorithm algorithm;
        uint256 initiatedAt;
        uint256 expiresAt;
        bool completed;
    }

    // ============ View Functions ============

    /**
     * @notice Get account PQC configuration
     * @param account The account address
     * @return config Account configuration
     */
    function getAccountConfig(
        address account
    ) external view returns (AccountConfig memory config);

    /**
     * @notice Check if account is configured for PQC
     * @param account The account address
     * @return configured True if configured
     */
    function isConfigured(
        address account
    ) external view returns (bool configured);

    /**
     * @notice Check if account configuration is active
     * @param account The account address
     * @return active True if active and not expired
     */
    function isActive(address account) external view returns (bool active);

    /**
     * @notice Check if account requires hybrid signatures
     * @param account The account address
     * @return required True if hybrid required
     */
    function requiresHybrid(
        address account
    ) external view returns (bool required);

    /**
     * @notice Get protocol-wide PQC statistics
     * @return stats Current statistics
     */
    function getStats() external view returns (PQCStats memory stats);

    /**
     * @notice Get key exchange session details
     * @param exchangeId The exchange identifier
     * @return session Exchange session details
     */
    function getKeyExchange(
        bytes32 exchangeId
    ) external view returns (KeyExchangeSession memory session);

    /**
     * @notice Get Dilithium verifier address
     * @return verifier Verifier address
     */
    function getDilithiumVerifier() external view returns (address verifier);

    /**
     * @notice Get SPHINCS+ verifier address
     * @return verifier Verifier address
     */
    function getSPHINCSVerifier() external view returns (address verifier);

    /**
     * @notice Get Kyber KEM address
     * @return kem KEM contract address
     */
    function getKyberKEM() external view returns (address kem);

    /**
     * @notice Get hybrid verifier address
     * @return verifier Verifier address
     */
    function getHybridVerifier() external view returns (address verifier);

    /**
     * @notice Get supported signature algorithms
     * @return algorithms Array of supported algorithms
     */
    function getSupportedSignatureAlgorithms()
        external
        view
        returns (PQCLib.SignatureAlgorithm[] memory algorithms);

    /**
     * @notice Get supported KEM algorithms
     * @return algorithms Array of supported algorithms
     */
    function getSupportedKEMAlgorithms()
        external
        view
        returns (PQCLib.KEMAlgorithm[] memory algorithms);

    // ============ Account Configuration Functions ============

    /**
     * @notice Configure PQC for an account
     * @param signatureAlgorithm Signature algorithm to use
     * @param kemAlgorithm KEM algorithm to use
     * @param signaturePublicKey Signature public key bytes
     * @param kemPublicKey KEM public key bytes
     * @param requireHybrid Whether to require hybrid signatures
     * @param expirationDays Configuration expiration in days
     */
    function configureAccount(
        PQCLib.SignatureAlgorithm signatureAlgorithm,
        PQCLib.KEMAlgorithm kemAlgorithm,
        bytes calldata signaturePublicKey,
        bytes calldata kemPublicKey,
        bool requireHybrid,
        uint256 expirationDays
    ) external;

    /**
     * @notice Update account PQC configuration
     * @param newSignaturePublicKey New signature public key
     * @param newKEMPublicKey New KEM public key
     * @param expirationDays New expiration in days
     */
    function updateAccount(
        bytes calldata newSignaturePublicKey,
        bytes calldata newKEMPublicKey,
        uint256 expirationDays
    ) external;

    /**
     * @notice Deactivate PQC for an account
     */
    function deactivateAccount() external;

    /**
     * @notice Set hybrid requirement for account
     * @param required Whether hybrid is required
     */
    function setHybridRequired(bool required) external;

    // ============ Verification Functions ============

    /**
     * @notice Verify a PQC signature for an account
     * @param account The account address
     * @param signature Signature bytes
     * @param messageHash Message hash
     * @return valid True if signature is valid
     */
    function verifySignature(
        address account,
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify a hybrid signature for an account
     * @param account The account address
     * @param hybridSignature Encoded hybrid signature
     * @param messageHash Message hash
     * @return valid True if signature is valid per account requirements
     */
    function verifyHybridSignature(
        address account,
        bytes calldata hybridSignature,
        bytes32 messageHash
    ) external returns (bool valid);

    /**
     * @notice Verify signature with explicit algorithm
     * @param publicKey Public key bytes
     * @param signature Signature bytes
     * @param messageHash Message hash
     * @param algorithm Signature algorithm
     * @return valid True if valid
     */
    function verifyWithAlgorithm(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes32 messageHash,
        PQCLib.SignatureAlgorithm algorithm
    ) external returns (bool valid);

    // ============ Key Exchange Functions ============

    /**
     * @notice Initiate key exchange with another account
     * @param recipient Recipient address
     * @param ciphertext Encapsulated ciphertext
     * @return exchangeId Unique exchange identifier
     */
    function initiateKeyExchange(
        address recipient,
        bytes calldata ciphertext
    ) external returns (bytes32 exchangeId);

    /**
     * @notice Complete key exchange
     * @param exchangeId Exchange identifier
     * @param ciphertext Response ciphertext
     * @param sharedSecretHash Hash of derived shared secret
     */
    function completeKeyExchange(
        bytes32 exchangeId,
        bytes calldata ciphertext,
        bytes32 sharedSecretHash
    ) external;

    /**
     * @notice Cancel key exchange
     * @param exchangeId Exchange identifier
     */
    function cancelKeyExchange(bytes32 exchangeId) external;

    // ============ Admin Functions ============

    /**
     * @notice Set Dilithium verifier contract
     * @param verifier Verifier address
     */
    function setDilithiumVerifier(address verifier) external;

    /**
     * @notice Set SPHINCS+ verifier contract
     * @param verifier Verifier address
     */
    function setSPHINCSVerifier(address verifier) external;

    /**
     * @notice Set Kyber KEM contract
     * @param kem KEM address
     */
    function setKyberKEM(address kem) external;

    /**
     * @notice Set hybrid verifier contract
     * @param verifier Verifier address
     */
    function setHybridVerifier(address verifier) external;

    /**
     * @notice Enable/disable a signature algorithm
     * @param algorithm Algorithm to configure
     * @param enabled Whether to enable
     */
    function setSignatureAlgorithmEnabled(
        PQCLib.SignatureAlgorithm algorithm,
        bool enabled
    ) external;

    /**
     * @notice Enable/disable a KEM algorithm
     * @param algorithm Algorithm to configure
     * @param enabled Whether to enable
     */
    function setKEMAlgorithmEnabled(
        PQCLib.KEMAlgorithm algorithm,
        bool enabled
    ) external;

    /**
     * @notice Set default configuration expiration
     * @param daysCount Default expiration in days
     */
    function setDefaultExpiration(uint256 daysCount) external;

    /**
     * @notice Pause the registry
     */
    function pause() external;

    /**
     * @notice Unpause the registry
     */
    function unpause() external;

    /**
     * @notice Emergency deactivate an account (admin only)
     * @param account Account to deactivate
     */
    function emergencyDeactivate(address account) external;
}
