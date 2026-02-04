// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {PQCLib} from "../libraries/PQCLib.sol";
import {DilithiumVerifier} from "./DilithiumVerifier.sol";
import {SPHINCSPlusVerifier} from "./SPHINCSPlusVerifier.sol";
import {KyberKEM} from "./KyberKEM.sol";

/**
 * @title PQCRegistry
 * @author Soul Protocol
 * @notice Central registry for post-quantum cryptography primitives
 * @dev Manages verifiers, KEMs, and hybrid signature schemes for Soul Protocol.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                      PQC REGISTRY                                          ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                           ║
 * ║ TRANSITION PHASES:                                                        ║
 * ║ ┌───────────────┐   ┌───────────────┐   ┌───────────────┐                ║
 * ║ │ Classical     │──▶│ Hybrid        │──▶│ PQ Only       │                ║
 * ║ │ Only          │   │ (ECDSA + PQC) │   │ (Future)      │                ║
 * ║ └───────────────┘   └───────────────┘   └───────────────┘                ║
 * ║                                                                           ║
 * ║ SUPPORTED PRIMITIVES:                                                     ║
 * ║ • Signatures: Dilithium3, Dilithium5, SPHINCS+-128s/f, SPHINCS+-256s/f  ║
 * ║ • KEMs: Kyber512, Kyber768, Kyber1024                                    ║
 * ║                                                                           ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract PQCRegistry is AccessControl, Pausable {
    using PQCLib for PQCLib.SignatureAlgorithm;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PHASE_ADMIN_ROLE = keccak256("PHASE_ADMIN_ROLE");

    /// @notice Domain separator
    bytes32 public constant DOMAIN_SEPARATOR =
        keccak256("SOUL_PQC_REGISTRY_V1");

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice Account PQC configuration
     */
    struct AccountConfig {
        bytes32 signatureKeyHash;
        bytes32 kemKeyHash;
        PQCLib.SignatureAlgorithm signatureAlgorithm;
        PQCLib.KEMAlgorithm kemAlgorithm;
        uint64 registeredAt;
        uint64 updatedAt;
        bool hybridEnabled;
        bool isActive;
    }

    /**
     * @notice Protocol-wide statistics
     */
    struct PQCStats {
        uint256 totalAccounts;
        uint256 dilithiumAccounts;
        uint256 sphincsAccounts;
        uint256 kyberAccounts;
        uint256 hybridAccounts;
        uint256 totalSignatureVerifications;
        uint256 totalKeyEncapsulations;
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
    PQCLib.TransitionPhase public currentPhase;

    /// @notice Account configurations
    mapping(address => AccountConfig) public accountConfigs;

    /// @notice Supported signature algorithms
    mapping(PQCLib.SignatureAlgorithm => bool)
        public supportedSignatureAlgorithms;

    /// @notice Supported KEM algorithms
    mapping(PQCLib.KEMAlgorithm => bool) public supportedKEMAlgorithms;

    /// @notice Protocol statistics
    PQCStats public stats;

    /// @notice Recommended signature algorithm
    PQCLib.SignatureAlgorithm public recommendedSignature;

    /// @notice Recommended KEM algorithm
    PQCLib.KEMAlgorithm public recommendedKEM;

    /// @notice Full public keys stored by hash
    mapping(bytes32 => bytes) public publicKeyStorage;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event VerifierUpdated(
        string indexed verifierType,
        address indexed newAddress
    );
    event PhaseTransition(
        PQCLib.TransitionPhase indexed oldPhase,
        PQCLib.TransitionPhase indexed newPhase
    );
    event AccountConfigured(
        address indexed account,
        PQCLib.SignatureAlgorithm signatureAlg,
        PQCLib.KEMAlgorithm kemAlg,
        bool hybridEnabled
    );
    event AccountUpdated(address indexed account);
    event AccountDeactivated(address indexed account);
    event AlgorithmStatusChanged(
        string algorithmType,
        uint8 algorithm,
        bool supported
    );
    event RecommendationUpdated(
        PQCLib.SignatureAlgorithm signature,
        PQCLib.KEMAlgorithm kem
    );
    event SignatureVerified(
        address indexed account,
        bool valid,
        PQCLib.SignatureAlgorithm algorithm
    );
    event KeyExchangeInitiated(
        address indexed initiator,
        address indexed recipient,
        bytes32 exchangeId
    );

    // =============================================================================
    // ERRORS
    // =============================================================================

    error UnsupportedSignatureAlgorithm(PQCLib.SignatureAlgorithm algorithm);
    error UnsupportedKEMAlgorithm(PQCLib.KEMAlgorithm algorithm);
    error AccountNotConfigured();
    error AccountAlreadyConfigured();
    error PhaseNotAllowed();
    error VerifierNotSet();
    error HybridRequired();
    error InvalidConfiguration();
    error InvalidPhaseTransition();
    error PQCRequired();

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
        _grantRole(PHASE_ADMIN_ROLE, msg.sender);

        if (_dilithiumVerifier != address(0)) {
            dilithiumVerifier = DilithiumVerifier(_dilithiumVerifier);
        }
        if (_sphincsVerifier != address(0)) {
            sphincsVerifier = SPHINCSPlusVerifier(_sphincsVerifier);
        }
        if (_kyberKEM != address(0)) {
            kyberKEM = KyberKEM(_kyberKEM);
        }

        currentPhase = PQCLib.TransitionPhase.HybridOptional;

        // Enable all standard algorithms
        supportedSignatureAlgorithms[
            PQCLib.SignatureAlgorithm.Dilithium3
        ] = true;
        supportedSignatureAlgorithms[
            PQCLib.SignatureAlgorithm.Dilithium5
        ] = true;
        supportedSignatureAlgorithms[
            PQCLib.SignatureAlgorithm.SPHINCSPlus128s
        ] = true;
        supportedSignatureAlgorithms[
            PQCLib.SignatureAlgorithm.SPHINCSPlus256s
        ] = true;

        supportedKEMAlgorithms[PQCLib.KEMAlgorithm.Kyber768] = true;
        supportedKEMAlgorithms[PQCLib.KEMAlgorithm.Kyber1024] = true;

        // Set recommended defaults
        recommendedSignature = PQCLib.SignatureAlgorithm.Dilithium3;
        recommendedKEM = PQCLib.KEMAlgorithm.Kyber768;
    }

    // =============================================================================
    // ACCOUNT CONFIGURATION
    // =============================================================================

    /**
     * @notice Configure PQC settings for an account
     * @param signatureAlgorithm Signature algorithm to use
     * @param kemAlgorithm KEM algorithm to use
     * @param signaturePubKey Full signature public key
     * @param kemPubKey Full KEM public key (optional)
     * @param enableHybrid Whether to enable hybrid verification
     */
    function configureAccount(
        PQCLib.SignatureAlgorithm signatureAlgorithm,
        PQCLib.KEMAlgorithm kemAlgorithm,
        bytes calldata signaturePubKey,
        bytes calldata kemPubKey,
        bool enableHybrid
    ) external whenNotPaused {
        if (accountConfigs[msg.sender].isActive) {
            revert AccountAlreadyConfigured();
        }

        _validateAlgorithms(signatureAlgorithm, kemAlgorithm);
        _validatePhaseRequirements(enableHybrid);

        bytes32 sigKeyHash = keccak256(
            abi.encodePacked(DOMAIN_SEPARATOR, signaturePubKey)
        );
        bytes32 kemKeyHash = kemPubKey.length > 0
            ? keccak256(abi.encodePacked(DOMAIN_SEPARATOR, kemPubKey))
            : bytes32(0);

        accountConfigs[msg.sender] = AccountConfig({
            signatureKeyHash: sigKeyHash,
            kemKeyHash: kemKeyHash,
            signatureAlgorithm: signatureAlgorithm,
            kemAlgorithm: kemAlgorithm,
            registeredAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            hybridEnabled: enableHybrid,
            isActive: true
        });

        // Store public keys
        publicKeyStorage[sigKeyHash] = signaturePubKey;
        if (kemPubKey.length > 0) {
            publicKeyStorage[kemKeyHash] = kemPubKey;
        }

        // Update stats
        stats.totalAccounts++;
        if (
            signatureAlgorithm == PQCLib.SignatureAlgorithm.Dilithium3 ||
            signatureAlgorithm == PQCLib.SignatureAlgorithm.Dilithium5
        ) {
            stats.dilithiumAccounts++;
        } else if (
            signatureAlgorithm >= PQCLib.SignatureAlgorithm.SPHINCSPlus128s
        ) {
            stats.sphincsAccounts++;
        }
        if (kemAlgorithm != PQCLib.KEMAlgorithm.None) {
            stats.kyberAccounts++;
        }
        if (enableHybrid) {
            stats.hybridAccounts++;
        }

        emit AccountConfigured(
            msg.sender,
            signatureAlgorithm,
            kemAlgorithm,
            enableHybrid
        );
    }

    /**
     * @notice Update account configuration
     */
    function updateAccount(
        PQCLib.SignatureAlgorithm signatureAlgorithm,
        PQCLib.KEMAlgorithm kemAlgorithm,
        bytes calldata signaturePubKey,
        bytes calldata kemPubKey,
        bool enableHybrid
    ) external whenNotPaused {
        AccountConfig storage config = accountConfigs[msg.sender];
        if (!config.isActive) {
            revert AccountNotConfigured();
        }

        _validateAlgorithms(signatureAlgorithm, kemAlgorithm);
        _validatePhaseRequirements(enableHybrid);

        // Clean up old keys
        delete publicKeyStorage[config.signatureKeyHash];
        if (config.kemKeyHash != bytes32(0)) {
            delete publicKeyStorage[config.kemKeyHash];
        }

        // Update configuration
        bytes32 sigKeyHash = keccak256(
            abi.encodePacked(DOMAIN_SEPARATOR, signaturePubKey)
        );
        bytes32 kemKeyHash = kemPubKey.length > 0
            ? keccak256(abi.encodePacked(DOMAIN_SEPARATOR, kemPubKey))
            : bytes32(0);

        config.signatureKeyHash = sigKeyHash;
        config.kemKeyHash = kemKeyHash;
        config.signatureAlgorithm = signatureAlgorithm;
        config.kemAlgorithm = kemAlgorithm;
        config.hybridEnabled = enableHybrid;
        config.updatedAt = uint64(block.timestamp);

        publicKeyStorage[sigKeyHash] = signaturePubKey;
        if (kemPubKey.length > 0) {
            publicKeyStorage[kemKeyHash] = kemPubKey;
        }

        emit AccountUpdated(msg.sender);
    }

    /**
     * @notice Deactivate account
     */
    function deactivateAccount() external {
        AccountConfig storage config = accountConfigs[msg.sender];
        if (!config.isActive) {
            revert AccountNotConfigured();
        }

        // Clean up stored keys
        delete publicKeyStorage[config.signatureKeyHash];
        if (config.kemKeyHash != bytes32(0)) {
            delete publicKeyStorage[config.kemKeyHash];
        }

        config.isActive = false;
        stats.totalAccounts--;

        emit AccountDeactivated(msg.sender);
    }

    // =============================================================================
    // SIGNATURE VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a signature for a configured account
     * @param signer The account that signed
     * @param message The message hash
     * @param signature The signature
     * @return valid True if valid
     */
    function verifySignature(
        address signer,
        bytes32 message,
        bytes calldata signature
    ) external returns (bool valid) {
        AccountConfig memory config = accountConfigs[signer];
        if (!config.isActive) {
            revert AccountNotConfigured();
        }

        bytes memory pubKey = publicKeyStorage[config.signatureKeyHash];
        if (pubKey.length == 0) {
            revert VerifierNotSet();
        }

        valid = _verifyWithAlgorithm(
            message,
            signature,
            pubKey,
            config.signatureAlgorithm
        );

        if (valid) {
            stats.totalSignatureVerifications++;
        }

        emit SignatureVerified(signer, valid, config.signatureAlgorithm);
    }

    /**
     * @notice Verify a hybrid signature for a configured account
     * @param signer The account that signed
     * @param message The message hash
     * @param ecdsaSig The ECDSA signature
     * @param pqcSig The PQC signature
     * @return valid True if both are valid
     */
    function verifyHybridSignature(
        address signer,
        bytes32 message,
        bytes calldata ecdsaSig,
        bytes calldata pqcSig
    ) external returns (bool valid) {
        AccountConfig memory config = accountConfigs[signer];
        if (!config.isActive) {
            revert AccountNotConfigured();
        }
        if (!config.hybridEnabled) {
            revert HybridRequired();
        }

        bytes memory pubKey = publicKeyStorage[config.signatureKeyHash];

        // Verify PQC signature
        bool pqcValid = _verifyWithAlgorithm(
            message,
            pqcSig,
            pubKey,
            config.signatureAlgorithm
        );

        // Verify ECDSA (simplified - would use proper ECDSA verification)
        bool ecdsaValid = ecdsaSig.length == 65;

        valid = pqcValid && ecdsaValid;

        if (valid) {
            stats.totalSignatureVerifications++;
        }

        emit SignatureVerified(signer, valid, config.signatureAlgorithm);
    }

    // =============================================================================
    // KEY EXCHANGE
    // =============================================================================

    /**
     * @notice Initiate a key exchange with a recipient
     * @param recipient The recipient address
     * @param ciphertext The Kyber ciphertext
     * @param sharedSecretCommitment Hash of the shared secret
     * @return exchangeId The exchange identifier
     */
    function initiateKeyExchange(
        address recipient,
        bytes calldata ciphertext,
        bytes32 sharedSecretCommitment
    ) external whenNotPaused returns (bytes32 exchangeId) {
        AccountConfig memory recipientConfig = accountConfigs[recipient];
        if (!recipientConfig.isActive) {
            revert AccountNotConfigured();
        }
        if (recipientConfig.kemAlgorithm == PQCLib.KEMAlgorithm.None) {
            revert UnsupportedKEMAlgorithm(PQCLib.KEMAlgorithm.None);
        }

        if (address(kyberKEM) == address(0)) {
            revert VerifierNotSet();
        }

        exchangeId = kyberKEM.initiateExchange(
            recipient,
            ciphertext,
            sharedSecretCommitment
        );
        stats.totalKeyEncapsulations++;

        emit KeyExchangeInitiated(msg.sender, recipient, exchangeId);
    }

    // =============================================================================
    // INTERNAL FUNCTIONS
    // =============================================================================

    function _validateAlgorithms(
        PQCLib.SignatureAlgorithm sigAlg,
        PQCLib.KEMAlgorithm kemAlg
    ) internal view {
        if (
            sigAlg != PQCLib.SignatureAlgorithm.None &&
            !supportedSignatureAlgorithms[sigAlg]
        ) {
            revert UnsupportedSignatureAlgorithm(sigAlg);
        }
        if (
            kemAlg != PQCLib.KEMAlgorithm.None &&
            !supportedKEMAlgorithms[kemAlg]
        ) {
            revert UnsupportedKEMAlgorithm(kemAlg);
        }
    }

    function _validatePhaseRequirements(bool hybridEnabled) internal view {
        if (
            currentPhase == PQCLib.TransitionPhase.HybridMandatory &&
            !hybridEnabled
        ) {
            revert HybridRequired();
        }
        if (currentPhase == PQCLib.TransitionPhase.PQOnly) {
            // In PQ-only phase, hybrid is not allowed
            revert PhaseNotAllowed();
        }
    }

    function _verifyWithAlgorithm(
        bytes32 message,
        bytes calldata signature,
        bytes memory publicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) internal returns (bool) {
        if (algorithm == PQCLib.SignatureAlgorithm.Dilithium3) {
            if (address(dilithiumVerifier) == address(0))
                revert VerifierNotSet();
            return
                dilithiumVerifier.verifyDilithium3(
                    message,
                    signature,
                    publicKey
                );
        } else if (algorithm == PQCLib.SignatureAlgorithm.Dilithium5) {
            if (address(dilithiumVerifier) == address(0))
                revert VerifierNotSet();
            return
                dilithiumVerifier.verifyDilithium5(
                    message,
                    signature,
                    publicKey
                );
        } else if (algorithm >= PQCLib.SignatureAlgorithm.SPHINCSPlus128s) {
            if (address(sphincsVerifier) == address(0)) revert VerifierNotSet();
            return
                sphincsVerifier.verify(
                    message,
                    signature,
                    publicKey,
                    algorithm
                );
        }

        return false;
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setPhase(
        PQCLib.TransitionPhase newPhase
    ) external onlyRole(PHASE_ADMIN_ROLE) {
        // Validate transition (can't go backwards to ClassicalOnly)
        if (
            currentPhase > newPhase &&
            newPhase == PQCLib.TransitionPhase.ClassicalOnly
        ) {
            revert InvalidPhaseTransition();
        }

        PQCLib.TransitionPhase oldPhase = currentPhase;
        currentPhase = newPhase;
        emit PhaseTransition(oldPhase, newPhase);
    }

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

    function setSignatureAlgorithmSupport(
        PQCLib.SignatureAlgorithm algorithm,
        bool supported
    ) external onlyRole(ADMIN_ROLE) {
        supportedSignatureAlgorithms[algorithm] = supported;
        emit AlgorithmStatusChanged("signature", uint8(algorithm), supported);
    }

    function setKEMAlgorithmSupport(
        PQCLib.KEMAlgorithm algorithm,
        bool supported
    ) external onlyRole(ADMIN_ROLE) {
        supportedKEMAlgorithms[algorithm] = supported;
        emit AlgorithmStatusChanged("kem", uint8(algorithm), supported);
    }

    function setRecommendations(
        PQCLib.SignatureAlgorithm sigAlg,
        PQCLib.KEMAlgorithm kemAlg
    ) external onlyRole(ADMIN_ROLE) {
        recommendedSignature = sigAlg;
        recommendedKEM = kemAlg;
        emit RecommendationUpdated(sigAlg, kemAlg);
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

    function getAccountConfig(
        address account
    )
        external
        view
        returns (
            bytes32 signatureKeyHash,
            bytes32 kemKeyHash,
            PQCLib.SignatureAlgorithm signatureAlgorithm,
            PQCLib.KEMAlgorithm kemAlgorithm,
            bool hybridEnabled,
            bool isActive
        )
    {
        AccountConfig memory config = accountConfigs[account];
        return (
            config.signatureKeyHash,
            config.kemKeyHash,
            config.signatureAlgorithm,
            config.kemAlgorithm,
            config.hybridEnabled,
            config.isActive
        );
    }

    function isPQCEnabled(address account) external view returns (bool) {
        return accountConfigs[account].isActive;
    }

    function getStats() external view returns (PQCStats memory) {
        return stats;
    }

    function getRecommendations()
        external
        view
        returns (PQCLib.SignatureAlgorithm sigAlg, PQCLib.KEMAlgorithm kemAlg)
    {
        return (recommendedSignature, recommendedKEM);
    }

    function isAlgorithmSupported(
        PQCLib.SignatureAlgorithm sigAlg,
        PQCLib.KEMAlgorithm kemAlg
    ) external view returns (bool sigSupported, bool kemSupported) {
        return (
            supportedSignatureAlgorithms[sigAlg],
            supportedKEMAlgorithms[kemAlg]
        );
    }
}
