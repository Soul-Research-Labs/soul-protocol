// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PQCLib} from "../libraries/PQCLib.sol";
import {DilithiumVerifier} from "./DilithiumVerifier.sol";
import {SPHINCSPlusVerifier} from "./SPHINCSPlusVerifier.sol";

/**
 * @title HybridPQCVerifier
 * @author Soul Protocol
 * @notice Multi-mode hybrid classical/post-quantum signature verifier
 * @dev Supports multiple verification modes for graceful PQC transition:
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                    HYBRID PQC VERIFICATION                                 ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                           ║
 * ║   MOCK ────────────────┐                                                  ║
 * ║   (testnet only)       │                                                  ║
 * ║                        ▼                                                  ║
 * ║                   PURE_SOLIDITY ◄──────────────────┐                      ║
 * ║                   (~5-10M gas)                     │                      ║
 * ║                        │                           │                      ║
 * ║                        ▼                           │                      ║
 * ║                   OFFCHAIN_ZK ─────────────────────┤                      ║
 * ║                   (~300K gas)      fallback        │                      ║
 * ║                        │                           │                      ║
 * ║                        ▼                           │                      ║
 * ║                   PRECOMPILE ──────────────────────┘                      ║
 * ║                   (future EIP)     fallback                               ║
 * ║                                                                           ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * Hybrid signatures combine ECDSA + PQC for defense-in-depth:
 * - If ECDSA breaks (quantum), PQC still protects
 * - If PQC breaks (unlikely), ECDSA still protects
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract HybridPQCVerifier is AccessControl, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using PQCLib for PQCLib.HybridSignature;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant MODE_ADMIN_ROLE = keccak256("MODE_ADMIN_ROLE");

    /// @notice Domain separator
    bytes32 public constant DOMAIN = keccak256("SOUL_HYBRID_PQC_VERIFIER_V1");

    /// @notice Maximum gas for pure Solidity verification
    uint256 public constant MAX_SOLIDITY_GAS = 15_000_000;

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Current verification mode
    PQCLib.VerificationMode public currentMode;

    /// @notice Fallback mode if primary fails
    PQCLib.VerificationMode public fallbackMode;

    /// @notice Whether mock mode is permanently disabled
    bool public mockModePermanentlyDisabled;

    /// @notice Dilithium verifier contract
    DilithiumVerifier public dilithiumVerifier;

    /// @notice SPHINCS+ verifier contract
    SPHINCSPlusVerifier public sphincsVerifier;

    /// @notice Trusted public key hashes (for caching)
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Verification cache
    mapping(bytes32 => PQCLib.VerificationResult) public verificationCache;

    /// @notice Cache timestamps
    mapping(bytes32 => uint256) public cacheTimestamps;

    /// @notice Cache TTL
    uint256 public cacheTTL = 1 hours;

    /// @notice Total verifications per mode
    mapping(PQCLib.VerificationMode => uint256) public verificationCount;

    /// @notice Gas used per mode
    mapping(PQCLib.VerificationMode => uint256) public totalGasUsed;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event ModeChanged(
        PQCLib.VerificationMode oldMode,
        PQCLib.VerificationMode newMode,
        address changedBy
    );
    event FallbackModeChanged(
        PQCLib.VerificationMode oldMode,
        PQCLib.VerificationMode newMode
    );
    event MockModePermanentlyDisabled(address disabledBy);
    event VerifierUpdated(
        string verifierType,
        address oldAddress,
        address newAddress
    );
    event VerificationCompleted(
        bytes32 indexed requestHash,
        bool isValid,
        PQCLib.VerificationMode modeUsed,
        uint256 gasUsed
    );
    event HybridVerificationCompleted(
        bytes32 indexed messageHash,
        address indexed signer,
        bool ecdsaValid,
        bool pqcValid,
        bool overallValid
    );
    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error MockModeNotAllowed();
    error MockModePermanentlyDisabledError();
    error InvalidZKProof();
    error PrecompileNotAvailable();
    error VerificationFailed(string reason);
    error UnsupportedAlgorithm(PQCLib.SignatureAlgorithm algorithm);
    error GasLimitExceeded(uint256 required, uint256 available);
    error InvalidPublicKey();
    error InvalidSignature();
    error CacheExpired();
    error ECDSAVerificationFailed();
    error PQCVerificationFailed();
    error VerifierNotSet();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(
        address admin,
        address _dilithiumVerifier,
        address _sphincsVerifier,
        PQCLib.VerificationMode initialMode
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(MODE_ADMIN_ROLE, admin);

        if (_dilithiumVerifier != address(0)) {
            dilithiumVerifier = DilithiumVerifier(_dilithiumVerifier);
        }
        if (_sphincsVerifier != address(0)) {
            sphincsVerifier = SPHINCSPlusVerifier(_sphincsVerifier);
        }

        currentMode = initialMode;
        fallbackMode = PQCLib.VerificationMode.PureSolidity;
    }

    // =============================================================================
    // HYBRID VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a hybrid signature (ECDSA + PQC)
     * @param message The message hash that was signed
     * @param signer The expected ECDSA signer address
     * @param hybridSig The encoded hybrid signature
     * @return valid True if both signatures are valid
     */
    function verifyHybrid(
        bytes32 message,
        address signer,
        bytes calldata hybridSig
    ) external whenNotPaused returns (bool valid) {
        // Decode hybrid signature
        PQCLib.HybridSignature memory sig = PQCLib.decodeHybridSignature(
            hybridSig
        );

        // Verify ECDSA
        bool ecdsaValid = _verifyECDSA(message, signer, sig.ecdsaSig);

        // Verify PQC signature
        bool pqcValid = _verifyPQC(
            message,
            sig.pqSignature,
            sig.pqPublicKey,
            sig.algorithm
        );

        valid = ecdsaValid && pqcValid;

        emit HybridVerificationCompleted(
            message,
            signer,
            ecdsaValid,
            pqcValid,
            valid
        );
    }

    /**
     * @notice Verify hybrid signature with components
     * @param message The message hash
     * @param signer The expected ECDSA signer
     * @param ecdsaSig The ECDSA signature (65 bytes)
     * @param pqSignature The PQC signature
     * @param pqPublicKey The PQC public key
     * @param algorithm The PQC algorithm
     * @return valid True if both are valid
     */
    function verifyHybridComponents(
        bytes32 message,
        address signer,
        bytes calldata ecdsaSig,
        bytes calldata pqSignature,
        bytes calldata pqPublicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) external whenNotPaused returns (bool valid) {
        bool ecdsaValid = _verifyECDSA(message, signer, ecdsaSig);
        bool pqcValid = _verifyPQC(
            message,
            pqSignature,
            pqPublicKey,
            algorithm
        );

        valid = ecdsaValid && pqcValid;

        emit HybridVerificationCompleted(
            message,
            signer,
            ecdsaValid,
            pqcValid,
            valid
        );
    }

    /**
     * @notice Verify only ECDSA component
     */
    function verifyECDSAOnly(
        bytes32 message,
        address signer,
        bytes calldata signature
    ) external view returns (bool) {
        return _verifyECDSA(message, signer, signature);
    }

    /**
     * @notice Verify only PQC component
     */
    function verifyPQCOnly(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) external returns (bool) {
        return _verifyPQC(message, signature, publicKey, algorithm);
    }

    // =============================================================================
    // GENERAL VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a post-quantum signature
     * @param request The verification request
     * @return result The verification result
     */
    function verify(
        PQCLib.VerificationRequest calldata request
    ) external whenNotPaused returns (PQCLib.VerificationResult memory result) {
        uint256 gasStart = gasleft();

        // Check cache first
        bytes32 requestHash = PQCLib.hashVerificationRequest(request);
        if (_isCacheValid(requestHash)) {
            result = verificationCache[requestHash];
            emit VerificationCompleted(
                requestHash,
                result.isValid,
                result.modeUsed,
                0
            );
            return result;
        }

        // Route to appropriate verification mode
        result = _verifyWithMode(request, currentMode);

        // If primary mode fails, try fallback
        if (!result.isValid && fallbackMode != currentMode) {
            result = _verifyWithMode(request, fallbackMode);
        }

        // Calculate gas used
        result.gasUsed = gasStart - gasleft();
        result.resultHash = requestHash;

        // Update metrics
        verificationCount[result.modeUsed]++;
        totalGasUsed[result.modeUsed] += result.gasUsed;

        // Cache successful results
        if (result.isValid) {
            verificationCache[requestHash] = result;
            cacheTimestamps[requestHash] = block.timestamp;
        }

        emit VerificationCompleted(
            requestHash,
            result.isValid,
            result.modeUsed,
            result.gasUsed
        );
    }

    // =============================================================================
    // INTERNAL VERIFICATION
    // =============================================================================

    function _verifyECDSA(
        bytes32 message,
        address signer,
        bytes memory signature
    ) internal view returns (bool) {
        if (signature.length != 65) return false;

        bytes32 ethSignedMessage = message.toEthSignedMessageHash();
        address recovered = ethSignedMessage.recover(signature);

        return recovered == signer;
    }

    function _verifyPQC(
        bytes32 message,
        bytes memory signature,
        bytes memory publicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) internal returns (bool) {
        if (
            algorithm == PQCLib.SignatureAlgorithm.Dilithium3 ||
            algorithm == PQCLib.SignatureAlgorithm.Dilithium5
        ) {
            if (address(dilithiumVerifier) == address(0))
                revert VerifierNotSet();

            if (algorithm == PQCLib.SignatureAlgorithm.Dilithium3) {
                return
                    dilithiumVerifier.verifyDilithium3(
                        message,
                        signature,
                        publicKey
                    );
            } else {
                return
                    dilithiumVerifier.verifyDilithium5(
                        message,
                        signature,
                        publicKey
                    );
            }
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

        revert UnsupportedAlgorithm(algorithm);
    }

    function _verifyWithMode(
        PQCLib.VerificationRequest calldata request,
        PQCLib.VerificationMode mode
    ) internal returns (PQCLib.VerificationResult memory result) {
        result.modeUsed = mode;

        if (mode == PQCLib.VerificationMode.Mock) {
            if (block.chainid == 1 || mockModePermanentlyDisabled) {
                revert MockModeNotAllowed();
            }
            result.isValid = _mockVerify(request);
        } else if (mode == PQCLib.VerificationMode.Precompile) {
            result.isValid = _precompileVerify(request);
        } else if (mode == PQCLib.VerificationMode.PureSolidity) {
            result.isValid = _solidityVerify(request);
        } else if (mode == PQCLib.VerificationMode.OffchainZK) {
            result.isValid = _zkVerify(request);
        }
    }

    function _mockVerify(
        PQCLib.VerificationRequest calldata request
    ) internal view returns (bool) {
        bytes32 pkHash = keccak256(request.publicKey);
        if (trustedKeyHashes[pkHash]) return true;
        return request.publicKey.length > 0 && request.signature.length > 0;
    }

    function _precompileVerify(
        PQCLib.VerificationRequest calldata request
    ) internal returns (bool) {
        // Route to appropriate verifier
        return
            _verifyPQC(
                keccak256(request.message),
                request.signature,
                request.publicKey,
                request.algorithm
            );
    }

    function _solidityVerify(
        PQCLib.VerificationRequest calldata request
    ) internal returns (bool) {
        if (gasleft() < MAX_SOLIDITY_GAS) {
            revert GasLimitExceeded(MAX_SOLIDITY_GAS, gasleft());
        }
        return
            _verifyPQC(
                keccak256(request.message),
                request.signature,
                request.publicKey,
                request.algorithm
            );
    }

    function _zkVerify(
        PQCLib.VerificationRequest calldata request
    ) internal returns (bool) {
        // ZK verification would use the ZK verifier in the underlying verifiers
        return
            _verifyPQC(
                keccak256(request.message),
                request.signature,
                request.publicKey,
                request.algorithm
            );
    }

    // =============================================================================
    // CACHE MANAGEMENT
    // =============================================================================

    function _isCacheValid(bytes32 requestHash) internal view returns (bool) {
        if (cacheTimestamps[requestHash] == 0) return false;
        return block.timestamp < cacheTimestamps[requestHash] + cacheTTL;
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setMode(
        PQCLib.VerificationMode newMode
    ) external onlyRole(MODE_ADMIN_ROLE) {
        if (newMode == PQCLib.VerificationMode.Mock) {
            if (block.chainid == 1 || mockModePermanentlyDisabled) {
                revert MockModeNotAllowed();
            }
        }

        PQCLib.VerificationMode oldMode = currentMode;
        currentMode = newMode;
        emit ModeChanged(oldMode, newMode, msg.sender);
    }

    function setFallbackMode(
        PQCLib.VerificationMode newMode
    ) external onlyRole(MODE_ADMIN_ROLE) {
        PQCLib.VerificationMode oldMode = fallbackMode;
        fallbackMode = newMode;
        emit FallbackModeChanged(oldMode, newMode);
    }

    function permanentlyDisableMockMode() external onlyRole(ADMIN_ROLE) {
        mockModePermanentlyDisabled = true;
        if (currentMode == PQCLib.VerificationMode.Mock) {
            currentMode = PQCLib.VerificationMode.OffchainZK;
        }
        emit MockModePermanentlyDisabled(msg.sender);
    }

    function setDilithiumVerifier(
        address _verifier
    ) external onlyRole(ADMIN_ROLE) {
        address old = address(dilithiumVerifier);
        dilithiumVerifier = DilithiumVerifier(_verifier);
        emit VerifierUpdated("Dilithium", old, _verifier);
    }

    function setSPHINCSVerifier(
        address _verifier
    ) external onlyRole(ADMIN_ROLE) {
        address old = address(sphincsVerifier);
        sphincsVerifier = SPHINCSPlusVerifier(_verifier);
        emit VerifierUpdated("SPHINCS", old, _verifier);
    }

    function setCacheTTL(uint256 _cacheTTL) external onlyRole(ADMIN_ROLE) {
        cacheTTL = _cacheTTL;
    }

    function addTrustedKey(bytes32 keyHash) external onlyRole(ADMIN_ROLE) {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    function removeTrustedKey(bytes32 keyHash) external onlyRole(ADMIN_ROLE) {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
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

    function getStats(
        PQCLib.VerificationMode mode
    ) external view returns (uint256 count, uint256 gasUsed) {
        return (verificationCount[mode], totalGasUsed[mode]);
    }

    function getCurrentConfig()
        external
        view
        returns (
            PQCLib.VerificationMode mode,
            PQCLib.VerificationMode fallback_,
            bool mockDisabled,
            address dilithium,
            address sphincs
        )
    {
        return (
            currentMode,
            fallbackMode,
            mockModePermanentlyDisabled,
            address(dilithiumVerifier),
            address(sphincsVerifier)
        );
    }
}
