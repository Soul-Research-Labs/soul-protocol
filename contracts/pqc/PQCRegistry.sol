// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title PQCRegistry
 * @author Soul Protocol
 * @notice Central registry for post-quantum cryptography primitives
 * @dev Manages verifiers, KEMs, and hybrid signature schemes for Soul protocol.
 *      Provides a unified interface for post-quantum operations across the protocol.
 *
 * SECURITY ARCHITECTURE:
 * - Supports NIST PQC standards: Dilithium (ML-DSA), SPHINCS+, Kyber (ML-KEM)
 * - Hybrid mode enables graceful transition from classical to post-quantum
 * - Phase-based migration from Optional -> HybridMandatory -> PQCOnly
 * - All operations are access-controlled via OpenZeppelin's AccessControl
 */

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {DilithiumVerifier} from "./DilithiumVerifier.sol";
import {SPHINCSPlusVerifier} from "./SPHINCSPlusVerifier.sol";
import {KyberKEM} from "./KyberKEM.sol";

contract PQCRegistry is AccessControl, Pausable {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // =============================================================================
    // ENUMS
    // =============================================================================

    enum PQCPrimitive {
        None,
        Dilithium3,
        Dilithium5,
        SPHINCSPlus128s,
        SPHINCSPlus128f,
        SPHINCSPlus256s,
        SPHINCSPlus256f,
        Kyber512,
        Kyber768,
        Kyber1024
    }

    enum TransitionPhase {
        ClassicalOnly, // Only classical crypto used
        HybridOptional, // Hybrid available but optional
        HybridMandatory, // Hybrid required for new operations
        PQPreferred, // PQ preferred, classical still accepted
        PQOnly // Only PQ accepted
    }

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice Configuration for a registered account
     * @dev Packed for gas efficiency - booleans grouped at end
     */
    struct AccountPQConfig {
        bytes32 signatureKeyHash; // Hash of signature public key (slot 1)
        bytes32 kemKeyHash; // Hash of KEM public key (slot 2)
        uint64 registeredAt; // Registration timestamp (slot 3 start)
        PQCPrimitive signatureAlgorithm; // 1 byte
        PQCPrimitive kemAlgorithm; // 1 byte
        bool hybridEnabled; // 1 byte
        bool isActive; // 1 byte - slot 3 = 8+1+1+1+1 = 12 bytes
    }

    /**
     * @notice Statistics for PQC usage
     */
    struct PQCStats {
        uint256 totalAccounts;
        uint256 dilithiumAccounts;
        uint256 sphincsAccounts;
        uint256 kyberAccounts;
        uint256 totalSignatureVerifications;
        uint256 totalKeyEncapsulations;
        uint256 hybridVerifications;
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Dilithium verifier contract
    DilithiumVerifier public dilithiumVerifier;

    /// @notice SPHINCS+ verifier contract
    SPHINCSPlusVerifier public sphincsVerifier;

    /// @notice Kyber KEM contract
    KyberKEM public kyberKEM;

    /// @notice Current transition phase
    TransitionPhase public currentPhase;

    /// @notice Account PQC configurations
    mapping(address => AccountPQConfig) public accountConfigs;

    /// @notice Supported primitives
    mapping(PQCPrimitive => bool) public supportedPrimitives;

    /// @notice Statistics
    PQCStats public stats;

    /// @notice Recommended primitives for new registrations
    PQCPrimitive public recommendedSignature;
    PQCPrimitive public recommendedKEM;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event VerifierUpdated(
        string indexed verifierType,
        address indexed newAddress
    );
    event PhaseTransition(
        TransitionPhase indexed oldPhase,
        TransitionPhase indexed newPhase
    );
    event AccountConfigured(
        address indexed account,
        PQCPrimitive signatureAlg,
        PQCPrimitive kemAlg
    );
    event AccountDeactivated(address indexed account);
    event PrimitiveStatusChanged(
        PQCPrimitive indexed primitive,
        bool supported
    );
    event RecommendationUpdated(PQCPrimitive signature, PQCPrimitive kem);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error UnsupportedPrimitive(PQCPrimitive primitive);
    error AccountNotConfigured();
    error AccountAlreadyConfigured();
    error PhaseNotAllowed();
    error VerifierNotSet();
    error HybridRequired();
    error InvalidConfiguration();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(
        address _dilithiumVerifier,
        address _sphincsVerifier,
        address _kyberKEM
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        if (_dilithiumVerifier != address(0)) {
            dilithiumVerifier = DilithiumVerifier(_dilithiumVerifier);
        }
        if (_sphincsVerifier != address(0)) {
            sphincsVerifier = SPHINCSPlusVerifier(_sphincsVerifier);
        }
        if (_kyberKEM != address(0)) {
            kyberKEM = KyberKEM(_kyberKEM);
        }

        currentPhase = TransitionPhase.ClassicalOnly;

        // Enable all primitives by default
        supportedPrimitives[PQCPrimitive.Dilithium3] = true;
        supportedPrimitives[PQCPrimitive.Dilithium5] = true;
        supportedPrimitives[PQCPrimitive.SPHINCSPlus128s] = true;
        supportedPrimitives[PQCPrimitive.SPHINCSPlus256s] = true;
        supportedPrimitives[PQCPrimitive.Kyber768] = true;
        supportedPrimitives[PQCPrimitive.Kyber1024] = true;

        // Set recommended defaults
        recommendedSignature = PQCPrimitive.Dilithium3;
        recommendedKEM = PQCPrimitive.Kyber768;
    }

    // =============================================================================
    // ACCOUNT CONFIGURATION
    // =============================================================================

    /**
     * @notice Configure PQC settings for an account
     * @param signatureAlgorithm Signature algorithm to use
     * @param kemAlgorithm KEM algorithm to use
     * @param signatureKeyHash Hash of signature public key
     * @param kemKeyHash Hash of KEM public key
     * @param enableHybrid Whether to enable hybrid mode
     */
    function configureAccount(
        PQCPrimitive signatureAlgorithm,
        PQCPrimitive kemAlgorithm,
        bytes32 signatureKeyHash,
        bytes32 kemKeyHash,
        bool enableHybrid
    ) external whenNotPaused {
        if (accountConfigs[msg.sender].isActive) {
            revert AccountAlreadyConfigured();
        }
        if (!supportedPrimitives[signatureAlgorithm]) {
            revert UnsupportedPrimitive(signatureAlgorithm);
        }
        if (
            kemAlgorithm != PQCPrimitive.None &&
            !supportedPrimitives[kemAlgorithm]
        ) {
            revert UnsupportedPrimitive(kemAlgorithm);
        }

        // Validate phase requirements
        if (currentPhase == TransitionPhase.HybridMandatory && !enableHybrid) {
            revert HybridRequired();
        }

        accountConfigs[msg.sender] = AccountPQConfig({
            signatureAlgorithm: signatureAlgorithm,
            kemAlgorithm: kemAlgorithm,
            signatureKeyHash: signatureKeyHash,
            kemKeyHash: kemKeyHash,
            registeredAt: uint64(block.timestamp),
            hybridEnabled: enableHybrid,
            isActive: true
        });

        // Update statistics with unchecked for gas savings
        unchecked {
            ++stats.totalAccounts;
            if (
                signatureAlgorithm == PQCPrimitive.Dilithium3 ||
                signatureAlgorithm == PQCPrimitive.Dilithium5
            ) {
                ++stats.dilithiumAccounts;
            } else if (
                uint8(signatureAlgorithm) >= 3 && uint8(signatureAlgorithm) <= 6
            ) {
                ++stats.sphincsAccounts;
            }
            if (kemAlgorithm != PQCPrimitive.None) {
                ++stats.kyberAccounts;
            }
        }

        emit AccountConfigured(msg.sender, signatureAlgorithm, kemAlgorithm);
    }

    /**
     * @notice Update account configuration
     */
    function updateAccount(
        PQCPrimitive signatureAlgorithm,
        PQCPrimitive kemAlgorithm,
        bytes32 signatureKeyHash,
        bytes32 kemKeyHash,
        bool enableHybrid
    ) external whenNotPaused {
        if (!accountConfigs[msg.sender].isActive) {
            revert AccountNotConfigured();
        }
        if (!supportedPrimitives[signatureAlgorithm]) {
            revert UnsupportedPrimitive(signatureAlgorithm);
        }

        AccountPQConfig storage config = accountConfigs[msg.sender];
        config.signatureAlgorithm = signatureAlgorithm;
        config.kemAlgorithm = kemAlgorithm;
        config.signatureKeyHash = signatureKeyHash;
        config.kemKeyHash = kemKeyHash;
        config.hybridEnabled = enableHybrid;

        emit AccountConfigured(msg.sender, signatureAlgorithm, kemAlgorithm);
    }

    /**
     * @notice Deactivate account PQC configuration
     */
    function deactivateAccount() external {
        if (!accountConfigs[msg.sender].isActive) {
            revert AccountNotConfigured();
        }

        accountConfigs[msg.sender].isActive = false;
        stats.totalAccounts--;

        emit AccountDeactivated(msg.sender);
    }

    // =============================================================================
    // SIGNATURE VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a post-quantum signature
     * @param signer The claimed signer address
     * @param message The message hash
     * @param signature The PQ signature
     * @param publicKey The PQ public key
     * @return valid True if signature is valid
     */
    function verifySignature(
        address signer,
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool valid) {
        AccountPQConfig storage config = accountConfigs[signer];
        if (!config.isActive) {
            // If not configured, check phase
            if (currentPhase >= TransitionPhase.PQPreferred) {
                revert AccountNotConfigured();
            }
            return false; // Classical-only account
        }

        // Verify public key matches registered hash
        if (keccak256(publicKey) != config.signatureKeyHash) {
            return false;
        }

        PQCPrimitive alg = config.signatureAlgorithm;

        if (alg == PQCPrimitive.Dilithium3) {
            if (address(dilithiumVerifier) == address(0))
                revert VerifierNotSet();
            valid = dilithiumVerifier.verifyDilithium3(
                message,
                signature,
                publicKey
            );
        } else if (alg == PQCPrimitive.Dilithium5) {
            if (address(dilithiumVerifier) == address(0))
                revert VerifierNotSet();
            valid = dilithiumVerifier.verifyDilithium5(
                message,
                signature,
                publicKey
            );
        } else if (alg == PQCPrimitive.SPHINCSPlus128s) {
            if (address(sphincsVerifier) == address(0)) revert VerifierNotSet();
            valid = sphincsVerifier.verifySPHINCS128s(
                message,
                signature,
                publicKey
            );
        } else if (alg == PQCPrimitive.SPHINCSPlus256s) {
            if (address(sphincsVerifier) == address(0)) revert VerifierNotSet();
            valid = sphincsVerifier.verifySPHINCS256s(
                message,
                signature,
                publicKey
            );
        } else {
            revert UnsupportedPrimitive(alg);
        }

        if (valid) {
            stats.totalSignatureVerifications++;
        }

        return valid;
    }

    /**
     * @notice Verify a hybrid signature (classical + PQ)
     * @param signer The signer address
     * @param message The message hash
     * @param classicalSig ECDSA signature
     * @param pqSignature PQ signature
     * @param pqPublicKey PQ public key
     * @return valid True if both signatures are valid
     */
    function verifyHybridSignature(
        address signer,
        bytes32 message,
        bytes calldata classicalSig,
        bytes calldata pqSignature,
        bytes calldata pqPublicKey
    ) external returns (bool valid) {
        // Verify classical ECDSA
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
        );
        address recovered = _recoverSigner(ethHash, classicalSig);
        if (recovered != signer) {
            return false;
        }

        // Verify PQ signature
        valid = this.verifySignature(signer, message, pqSignature, pqPublicKey);

        if (valid) {
            stats.hybridVerifications++;
        }

        return valid;
    }

    // =============================================================================
    // KEY ENCAPSULATION
    // =============================================================================

    /**
     * @notice Initiate key exchange with a recipient
     * @param recipient The recipient address
     * @return exchangeId The exchange identifier
     * @return ciphertext The encapsulated ciphertext
     */
    function initiateKeyExchange(
        address recipient
    )
        external
        whenNotPaused
        returns (bytes32 exchangeId, bytes memory ciphertext)
    {
        if (address(kyberKEM) == address(0)) revert VerifierNotSet();

        AccountPQConfig storage recipientConfig = accountConfigs[recipient];
        if (
            !recipientConfig.isActive ||
            recipientConfig.kemAlgorithm == PQCPrimitive.None
        ) {
            revert AccountNotConfigured();
        }

        bytes32 sharedSecretHash;
        (exchangeId, ciphertext, sharedSecretHash) = kyberKEM.encapsulate(
            recipient,
            keccak256(abi.encode(msg.sender, block.timestamp, block.prevrandao))
        );

        stats.totalKeyEncapsulations++;

        return (exchangeId, ciphertext);
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    /**
     * @notice Update verifier contracts
     */
    function setDilithiumVerifier(
        address _verifier
    ) external onlyRole(ADMIN_ROLE) {
        dilithiumVerifier = DilithiumVerifier(_verifier);
        emit VerifierUpdated("Dilithium", _verifier);
    }

    function setSPHINCSVerifier(
        address _verifier
    ) external onlyRole(ADMIN_ROLE) {
        sphincsVerifier = SPHINCSPlusVerifier(_verifier);
        emit VerifierUpdated("SPHINCS", _verifier);
    }

    function setKyberKEM(address _kem) external onlyRole(ADMIN_ROLE) {
        kyberKEM = KyberKEM(_kem);
        emit VerifierUpdated("Kyber", _kem);
    }

    /**
     * @notice Transition to a new phase
     */
    function transitionPhase(
        TransitionPhase newPhase
    ) external onlyRole(ADMIN_ROLE) {
        require(uint8(newPhase) >= uint8(currentPhase), "Cannot go backwards");
        TransitionPhase oldPhase = currentPhase;
        currentPhase = newPhase;
        emit PhaseTransition(oldPhase, newPhase);
    }

    /**
     * @notice Enable/disable a primitive
     */
    function setPrimitiveSupport(
        PQCPrimitive primitive,
        bool supported
    ) external onlyRole(ADMIN_ROLE) {
        supportedPrimitives[primitive] = supported;
        emit PrimitiveStatusChanged(primitive, supported);
    }

    /**
     * @notice Update recommended primitives
     */
    function setRecommendations(
        PQCPrimitive signature,
        PQCPrimitive kem
    ) external onlyRole(ADMIN_ROLE) {
        recommendedSignature = signature;
        recommendedKEM = kem;
        emit RecommendationUpdated(signature, kem);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    /**
     * @notice Get account configuration
     */
    function getAccountConfig(
        address account
    ) external view returns (AccountPQConfig memory) {
        return accountConfigs[account];
    }

    /**
     * @notice Check if account has PQC configured
     */
    function isPQCEnabled(address account) external view returns (bool) {
        return accountConfigs[account].isActive;
    }

    /**
     * @notice Get current statistics
     */
    function getStats() external view returns (PQCStats memory) {
        return stats;
    }

    /**
     * @notice Get recommended configuration
     */
    function getRecommendedConfig()
        external
        view
        returns (PQCPrimitive signature, PQCPrimitive kem, bool hybridEnabled)
    {
        return (
            recommendedSignature,
            recommendedKEM,
            currentPhase >= TransitionPhase.HybridOptional
        );
    }

    /**
     * @notice Check if phase allows classical-only
     */
    function allowsClassicalOnly() external view returns (bool) {
        return currentPhase <= TransitionPhase.HybridOptional;
    }

    // =============================================================================
    // INTERNAL FUNCTIONS
    // =============================================================================

    function _recoverSigner(
        bytes32 hash,
        bytes calldata signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) {
            v += 27;
        }

        return ecrecover(hash, v, r, s);
    }
}
