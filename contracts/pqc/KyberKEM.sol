// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {PQCLib} from "../libraries/PQCLib.sol";

/**
 * @title KyberKEM
 * @author Soul Protocol
 * @notice On-chain Key Encapsulation Mechanism using NIST ML-KEM (Kyber)
 * @dev Implements Kyber key encapsulation for post-quantum secure key exchange.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                      POST-QUANTUM KEY EXCHANGE                             ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ ML-KEM (Kyber) - NIST FIPS 203 Standard                                   ║
 * ║                                                                           ║
 * ║ Variants:                                                                 ║
 * ║ • Kyber512:  Level 1, 800B PK, 768B CT (fast)                            ║
 * ║ • Kyber768:  Level 3, 1184B PK, 1088B CT (recommended)                   ║
 * ║ • Kyber1024: Level 5, 1568B PK, 1568B CT (high security)                 ║
 * ║                                                                           ║
 * ║ Use Cases:                                                                ║
 * ║ • Privacy pool key exchanges                                             ║
 * ║ • Cross-chain secure channels                                            ║
 * ║ • Encrypted state transfer                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract KyberKEM is Ownable, Pausable, ReentrancyGuard {
    using PQCLib for PQCLib.KEMAlgorithm;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for Kyber
    address public constant KYBER_PRECOMPILE = address(0x0F);

    /// @notice Domain separator
    bytes32 public constant DOMAIN_SEPARATOR = keccak256("SOUL_KYBER_KEM_V1");

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice Registered public key for an address
     */
    struct RegisteredKey {
        bytes32 publicKeyHash;
        PQCLib.KEMAlgorithm algorithm;
        uint64 registeredAt;
        uint64 expiresAt;
        bool isActive;
    }

    /**
     * @notice Key exchange request
     */
    struct KeyExchange {
        address initiator;
        address recipient;
        bytes32 ciphertextHash;
        bytes32 sharedSecretCommitment;
        PQCLib.KEMAlgorithm algorithm;
        uint64 initiatedAt;
        uint64 expiresAt;
        bool isCompleted;
        bool isCancelled;
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Mock mode for testing
    bool public useMockMode;

    /// @notice Registered Kyber public keys
    mapping(address => RegisteredKey) public registeredKeys;

    /// @notice Full public keys stored by hash (for on-chain lookup)
    mapping(bytes32 => bytes) public publicKeyStorage;

    /// @notice Key exchange counter
    uint256 public exchangeCount;

    /// @notice Key exchanges by ID
    mapping(bytes32 => KeyExchange) public exchanges;

    /// @notice Completed exchanges (for replay protection)
    mapping(bytes32 => bool) public completedExchanges;

    /// @notice Exchange expiry duration (default 24 hours)
    uint256 public exchangeExpiry = 24 hours;

    /// @notice Key expiry duration (default 1 year)
    uint256 public keyExpiry = 365 days;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event KeyRegistered(
        address indexed owner,
        bytes32 indexed publicKeyHash,
        PQCLib.KEMAlgorithm algorithm,
        uint64 expiresAt
    );

    event KeyRevoked(address indexed owner, bytes32 indexed publicKeyHash);

    event KeyExchangeInitiated(
        bytes32 indexed exchangeId,
        address indexed initiator,
        address indexed recipient,
        PQCLib.KEMAlgorithm algorithm
    );

    event KeyExchangeCompleted(
        bytes32 indexed exchangeId,
        address indexed recipient,
        bytes32 sharedSecretCommitment
    );

    event KeyExchangeCancelled(bytes32 indexed exchangeId, address cancelledBy);

    event MockModeChanged(bool enabled);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidCiphertextSize(uint256 expected, uint256 actual);
    error KeyNotRegistered();
    error KeyAlreadyRegistered();
    error KeyExpired();
    error ExchangeNotFound();
    error ExchangeExpired();
    error ExchangeAlreadyCompleted();
    error UnauthorizedCaller();
    error PrecompileCallFailed();
    error MockModeNotAllowedOnMainnet();
    error InvalidAlgorithm();
    error SharedSecretMismatch();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor() Ownable(msg.sender) {
        // Only enable mock mode on testnets
        if (block.chainid != 1) {
            useMockMode = true;
        }
    }

    // =============================================================================
    // KEY REGISTRATION
    // =============================================================================

    /**
     * @notice Register a Kyber public key
     * @param publicKey The full Kyber public key
     * @param algorithm The Kyber variant
     */
    function registerPublicKey(
        bytes calldata publicKey,
        PQCLib.KEMAlgorithm algorithm
    ) external whenNotPaused {
        if (registeredKeys[msg.sender].isActive) {
            revert KeyAlreadyRegistered();
        }

        _validatePublicKeySize(publicKey, algorithm);

        bytes32 pkHash = keccak256(
            abi.encodePacked(DOMAIN_SEPARATOR, publicKey)
        );

        registeredKeys[msg.sender] = RegisteredKey({
            publicKeyHash: pkHash,
            algorithm: algorithm,
            registeredAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + keyExpiry),
            isActive: true
        });

        // Store full public key on-chain (expensive but enables trustless verification)
        publicKeyStorage[pkHash] = publicKey;

        emit KeyRegistered(
            msg.sender,
            pkHash,
            algorithm,
            uint64(block.timestamp + keyExpiry)
        );
    }

    /**
     * @notice Update existing public key
     * @param newPublicKey The new public key
     * @param algorithm The Kyber variant
     */
    function updatePublicKey(
        bytes calldata newPublicKey,
        PQCLib.KEMAlgorithm algorithm
    ) external whenNotPaused {
        RegisteredKey storage key = registeredKeys[msg.sender];
        if (!key.isActive) {
            revert KeyNotRegistered();
        }

        _validatePublicKeySize(newPublicKey, algorithm);

        // Remove old key from storage
        delete publicKeyStorage[key.publicKeyHash];

        // Register new key
        bytes32 newPkHash = keccak256(
            abi.encodePacked(DOMAIN_SEPARATOR, newPublicKey)
        );

        key.publicKeyHash = newPkHash;
        key.algorithm = algorithm;
        key.registeredAt = uint64(block.timestamp);
        key.expiresAt = uint64(block.timestamp + keyExpiry);

        publicKeyStorage[newPkHash] = newPublicKey;

        emit KeyRegistered(msg.sender, newPkHash, algorithm, key.expiresAt);
    }

    /**
     * @notice Revoke public key
     */
    function revokePublicKey() external {
        RegisteredKey storage key = registeredKeys[msg.sender];
        if (!key.isActive) {
            revert KeyNotRegistered();
        }

        bytes32 pkHash = key.publicKeyHash;

        delete publicKeyStorage[pkHash];
        delete registeredKeys[msg.sender];

        emit KeyRevoked(msg.sender, pkHash);
    }

    // =============================================================================
    // KEY EXCHANGE
    // =============================================================================

    /**
     * @notice Initiate a key exchange with a recipient
     * @param recipient The recipient address
     * @param ciphertext The encapsulated ciphertext
     * @param sharedSecretCommitment Hash commitment to the shared secret
     * @return exchangeId The unique exchange identifier
     */
    function initiateExchange(
        address recipient,
        bytes calldata ciphertext,
        bytes32 sharedSecretCommitment
    ) external whenNotPaused nonReentrant returns (bytes32 exchangeId) {
        RegisteredKey memory recipientKey = registeredKeys[recipient];
        if (!recipientKey.isActive) {
            revert KeyNotRegistered();
        }
        if (block.timestamp > recipientKey.expiresAt) {
            revert KeyExpired();
        }

        _validateCiphertextSize(ciphertext, recipientKey.algorithm);

        exchangeId = keccak256(
            abi.encodePacked(
                DOMAIN_SEPARATOR,
                msg.sender,
                recipient,
                ++exchangeCount,
                block.timestamp
            )
        );

        exchanges[exchangeId] = KeyExchange({
            initiator: msg.sender,
            recipient: recipient,
            ciphertextHash: keccak256(ciphertext),
            sharedSecretCommitment: sharedSecretCommitment,
            algorithm: recipientKey.algorithm,
            initiatedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + exchangeExpiry),
            isCompleted: false,
            isCancelled: false
        });

        emit KeyExchangeInitiated(
            exchangeId,
            msg.sender,
            recipient,
            recipientKey.algorithm
        );
    }

    /**
     * @notice Complete a key exchange by recipient
     * @param exchangeId The exchange identifier
     * @param sharedSecretCommitment The recipient's shared secret commitment (should match)
     */
    function completeExchange(
        bytes32 exchangeId,
        bytes32 sharedSecretCommitment
    ) external whenNotPaused nonReentrant {
        KeyExchange storage exchange = exchanges[exchangeId];

        if (exchange.initiator == address(0)) {
            revert ExchangeNotFound();
        }
        if (exchange.recipient != msg.sender) {
            revert UnauthorizedCaller();
        }
        if (exchange.isCompleted) {
            revert ExchangeAlreadyCompleted();
        }
        if (block.timestamp > exchange.expiresAt) {
            revert ExchangeExpired();
        }
        if (exchange.sharedSecretCommitment != sharedSecretCommitment) {
            revert SharedSecretMismatch();
        }

        exchange.isCompleted = true;
        completedExchanges[exchangeId] = true;

        emit KeyExchangeCompleted(
            exchangeId,
            msg.sender,
            sharedSecretCommitment
        );
    }

    /**
     * @notice Cancel a key exchange
     * @param exchangeId The exchange identifier
     */
    function cancelExchange(bytes32 exchangeId) external {
        KeyExchange storage exchange = exchanges[exchangeId];

        if (exchange.initiator == address(0)) {
            revert ExchangeNotFound();
        }
        if (
            exchange.initiator != msg.sender && exchange.recipient != msg.sender
        ) {
            revert UnauthorizedCaller();
        }
        if (exchange.isCompleted) {
            revert ExchangeAlreadyCompleted();
        }

        exchange.isCancelled = true;

        emit KeyExchangeCancelled(exchangeId, msg.sender);
    }

    // =============================================================================
    // ENCAPSULATION VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a ciphertext was correctly formed for a public key
     * @param publicKey The recipient's public key
     * @param ciphertext The ciphertext to verify
     * @param algorithm The Kyber variant
     * @return valid True if ciphertext format is valid
     */
    function verifyCiphertextFormat(
        bytes calldata publicKey,
        bytes calldata ciphertext,
        PQCLib.KEMAlgorithm algorithm
    ) external view returns (bool valid) {
        _validatePublicKeySize(publicKey, algorithm);
        _validateCiphertextSize(ciphertext, algorithm);

        if (useMockMode) {
            // Mock mode: basic format validation
            return publicKey.length > 0 && ciphertext.length > 0;
        }

        // Call precompile for verification
        bytes memory input = abi.encode(
            uint8(algorithm),
            publicKey,
            ciphertext
        );

        (bool success, bytes memory result) = KYBER_PRECOMPILE.staticcall(
            input
        );

        if (!success || result.length == 0) {
            if (useMockMode) {
                return true; // Fallback to mock
            }
            return false;
        }

        return abi.decode(result, (bool));
    }

    // =============================================================================
    // INTERNAL FUNCTIONS
    // =============================================================================

    function _validatePublicKeySize(
        bytes calldata publicKey,
        PQCLib.KEMAlgorithm algorithm
    ) internal pure {
        uint256 expected = 0;
        if (algorithm == PQCLib.KEMAlgorithm.Kyber512) {
            expected = PQCLib.KYBER512_PK_SIZE;
        } else if (algorithm == PQCLib.KEMAlgorithm.Kyber768) {
            expected = PQCLib.KYBER768_PK_SIZE;
        } else if (algorithm == PQCLib.KEMAlgorithm.Kyber1024) {
            expected = PQCLib.KYBER1024_PK_SIZE;
        } else {
            revert InvalidAlgorithm();
        }

        if (publicKey.length != expected) {
            revert InvalidPublicKeySize(expected, publicKey.length);
        }
    }

    function _validateCiphertextSize(
        bytes calldata ciphertext,
        PQCLib.KEMAlgorithm algorithm
    ) internal pure {
        uint256 expected = 0;
        if (algorithm == PQCLib.KEMAlgorithm.Kyber512) {
            expected = PQCLib.KYBER512_CT_SIZE;
        } else if (algorithm == PQCLib.KEMAlgorithm.Kyber768) {
            expected = PQCLib.KYBER768_CT_SIZE;
        } else if (algorithm == PQCLib.KEMAlgorithm.Kyber1024) {
            expected = PQCLib.KYBER1024_CT_SIZE;
        } else {
            revert InvalidAlgorithm();
        }

        if (ciphertext.length != expected) {
            revert InvalidCiphertextSize(expected, ciphertext.length);
        }
    }

    function _getExpectedPublicKeySize(
        PQCLib.KEMAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (algorithm == PQCLib.KEMAlgorithm.Kyber512) {
            return PQCLib.KYBER512_PK_SIZE;
        } else if (algorithm == PQCLib.KEMAlgorithm.Kyber768) {
            return PQCLib.KYBER768_PK_SIZE;
        } else if (algorithm == PQCLib.KEMAlgorithm.Kyber1024) {
            return PQCLib.KYBER1024_PK_SIZE;
        }
        return 0;
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setMockMode(bool enabled) external onlyOwner {
        if (enabled && block.chainid == 1) {
            revert MockModeNotAllowedOnMainnet();
        }
        useMockMode = enabled;
        emit MockModeChanged(enabled);
    }

    function setExchangeExpiry(uint256 _expiry) external onlyOwner {
        exchangeExpiry = _expiry;
    }

    function setKeyExpiry(uint256 _expiry) external onlyOwner {
        keyExpiry = _expiry;
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

    function getRegisteredKey(
        address owner
    )
        external
        view
        returns (
            bytes32 publicKeyHash,
            PQCLib.KEMAlgorithm algorithm,
            uint64 registeredAt,
            uint64 expiresAt,
            bool isActive
        )
    {
        RegisteredKey memory key = registeredKeys[owner];
        return (
            key.publicKeyHash,
            key.algorithm,
            key.registeredAt,
            key.expiresAt,
            key.isActive && block.timestamp <= key.expiresAt
        );
    }

    function getPublicKey(bytes32 pkHash) external view returns (bytes memory) {
        return publicKeyStorage[pkHash];
    }

    function getExchange(
        bytes32 exchangeId
    )
        external
        view
        returns (
            address initiator,
            address recipient,
            bytes32 ciphertextHash,
            PQCLib.KEMAlgorithm algorithm,
            bool isCompleted,
            bool isCancelled
        )
    {
        KeyExchange memory exchange = exchanges[exchangeId];
        return (
            exchange.initiator,
            exchange.recipient,
            exchange.ciphertextHash,
            exchange.algorithm,
            exchange.isCompleted,
            exchange.isCancelled
        );
    }

    function isExchangeValid(bytes32 exchangeId) external view returns (bool) {
        KeyExchange memory exchange = exchanges[exchangeId];
        return
            exchange.initiator != address(0) &&
            !exchange.isCompleted &&
            !exchange.isCancelled &&
            block.timestamp <= exchange.expiresAt;
    }
}
