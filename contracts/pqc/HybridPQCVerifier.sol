// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {DilithiumCore} from "./lib/DilithiumCore.sol";
import {KyberCore} from "./lib/KyberCore.sol";

/**
 * @title HybridPQCVerifier
 * @author Soul Protocol
 * @notice Multi-mode post-quantum cryptography verifier
 * @dev Supports multiple verification modes for graceful transition:
 *      - MOCK: Testing only, accepts all signatures (DO NOT USE IN PRODUCTION)
 *      - PURE_SOLIDITY: Full verification in Solidity (expensive but functional)
 *      - OFFCHAIN_ZK: Verify ZK proof that off-chain verification passed
 *      - PRECOMPILE: Future EIP precompile (when available)
 *
 * MODE TRANSITION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    PQC Verification Mode Transition                      │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │   MOCK ────────────────┐                                               │
 * │   (testnet only)       │                                               │
 * │                        ▼                                               │
 * │                   PURE_SOLIDITY ◄──────────────────┐                   │
 * │                   (~5-10M gas)                     │                   │
 * │                        │                           │                   │
 * │                        ▼                           │                   │
 * │                   OFFCHAIN_ZK ─────────────────────┤                   │
 * │                   (~300K gas)      fallback        │                   │
 * │                        │                           │                   │
 * │                        ▼                           │                   │
 * │                   PRECOMPILE ──────────────────────┘                   │
 * │                   (future EIP)     fallback                            │
 * │                                                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@soul.network
 */
contract HybridPQCVerifier is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verification modes
    enum VerificationMode {
        MOCK, // Testing only - accepts all
        PURE_SOLIDITY, // Full Solidity verification
        OFFCHAIN_ZK, // ZK proof of off-chain verification
        PRECOMPILE // Future EIP precompile
    }

    /// @notice Signature algorithm types
    enum SignatureAlgorithm {
        DILITHIUM3, // 128-bit quantum security
        DILITHIUM5, // 192-bit quantum security
        SPHINCS_SHA256, // Hash-based (conservative)
        SPHINCS_SHAKE // Hash-based (fast)
    }

    /// @notice KEM algorithm types
    enum KEMAlgorithm {
        KYBER512, // Level 1
        KYBER768, // Level 3 (recommended)
        KYBER1024 // Level 5
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verification request
    struct VerificationRequest {
        SignatureAlgorithm algorithm;
        bytes publicKey;
        bytes message;
        bytes signature;
    }

    /// @notice ZK verification data (for OFFCHAIN_ZK mode)
    struct ZKVerificationProof {
        bytes32 publicKeyHash;
        bytes32 messageHash;
        bytes32 signatureHash;
        bytes zkProof; // SNARK/STARK proof of correct verification
        bytes32 proofCommitment;
    }

    /// @notice Verification result
    struct VerificationResult {
        bool isValid;
        VerificationMode modeUsed;
        uint256 gasUsed;
        bytes32 resultHash;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant MODE_ADMIN_ROLE = keccak256("MODE_ADMIN_ROLE");

    /// @notice Domain separator
    bytes32 public constant DOMAIN = keccak256("Soul_HYBRID_PQC_VERIFIER_V1");

    /// @notice Maximum gas for pure Solidity verification
    uint256 public constant MAX_SOLIDITY_GAS = 15_000_000;

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current verification mode
    VerificationMode public currentMode;

    /// @notice Fallback mode if primary fails
    VerificationMode public fallbackMode;

    /// @notice Whether mock mode is permanently disabled
    bool public mockModePermanentlyDisabled;

    /// @notice ZK verifier contract for OFFCHAIN_ZK mode
    address public zkVerifier;

    /// @notice Precompile address for PRECOMPILE mode (future)
    address public precompileAddress;

    /// @notice Trusted public key hashes (for caching)
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Verification cache (for gas optimization)
    mapping(bytes32 => VerificationResult) public verificationCache;

    /// @notice Cache TTL
    uint256 public cacheTTL = 1 hours;

    /// @notice Cache timestamps
    mapping(bytes32 => uint256) public cacheTimestamps;

    /// @notice Total verifications per mode (for metrics)
    mapping(VerificationMode => uint256) public verificationCount;

    /// @notice Gas used per mode (for metrics)
    mapping(VerificationMode => uint256) public totalGasUsed;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ModeChanged(
        VerificationMode oldMode,
        VerificationMode newMode,
        address changedBy
    );
    event FallbackModeChanged(
        VerificationMode oldMode,
        VerificationMode newMode
    );
    event MockModePermanentlyDisabled(address disabledBy);
    event ZKVerifierUpdated(address oldVerifier, address newVerifier);
    event VerificationCompleted(
        bytes32 indexed requestHash,
        bool isValid,
        VerificationMode modeUsed,
        uint256 gasUsed
    );
    event VerificationCached(bytes32 indexed requestHash, uint256 expiresAt);
    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);

    /*//////////////////////////////////////////////////////////////
                             CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error MockModeNotAllowed();
    error MockModePermanentlyDisabledError();
    error InvalidZKProof();
    error PrecompileNotAvailable();
    error VerificationFailed(string reason);
    error UnsupportedAlgorithm(SignatureAlgorithm algorithm);
    error GasLimitExceeded(uint256 required, uint256 available);
    error InvalidPublicKey();
    error InvalidSignature();
    error CacheExpired();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes the hybrid verifier
     * @param admin Admin address for role management
     * @param initialMode Initial verification mode
     */
    constructor(address admin, VerificationMode initialMode) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(MODE_ADMIN_ROLE, admin);

        currentMode = initialMode;
        fallbackMode = VerificationMode.PURE_SOLIDITY;

        // Mock mode should only be used on testnets
        if (initialMode == VerificationMode.MOCK) {
            // Warning: Mock mode provides no security
        }
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verifies a post-quantum signature
     * @param request The verification request
     * @return result The verification result
     */
    function verify(
        VerificationRequest calldata request
    ) external whenNotPaused returns (VerificationResult memory result) {
        uint256 gasStart = gasleft();

        // Check cache first
        bytes32 requestHash = hashRequest(request);
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

        // Cache result
        _cacheResult(requestHash, result);

        // Update metrics
        verificationCount[result.modeUsed]++;
        totalGasUsed[result.modeUsed] += result.gasUsed;

        emit VerificationCompleted(
            requestHash,
            result.isValid,
            result.modeUsed,
            result.gasUsed
        );
    }

    /**
     * @notice Verifies using ZK proof (for OFFCHAIN_ZK mode)
     * @param zkProof The ZK verification proof
     * @return isValid True if ZK proof is valid
     */
    function verifyWithZKProof(
        ZKVerificationProof calldata zkProof
    ) external whenNotPaused returns (bool isValid) {
        require(currentMode == VerificationMode.OFFCHAIN_ZK, "Not in ZK mode");
        require(zkVerifier != address(0), "ZK verifier not set");

        // Verify the ZK proof
        isValid = _verifyZKProof(zkProof);

        emit VerificationCompleted(
            zkProof.proofCommitment,
            isValid,
            VerificationMode.OFFCHAIN_ZK,
            gasleft()
        );
    }

    /*//////////////////////////////////////////////////////////////
                           MODE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Changes the verification mode
     * @param newMode New verification mode
     */
    function setMode(
        VerificationMode newMode
    ) external onlyRole(MODE_ADMIN_ROLE) {
        // Cannot switch to mock if permanently disabled
        if (newMode == VerificationMode.MOCK && mockModePermanentlyDisabled) {
            revert MockModePermanentlyDisabledError();
        }

        // Validate mode requirements
        if (newMode == VerificationMode.OFFCHAIN_ZK) {
            require(zkVerifier != address(0), "ZK verifier not set");
        }
        if (newMode == VerificationMode.PRECOMPILE) {
            require(_isPrecompileAvailable(), "Precompile not available");
        }

        VerificationMode oldMode = currentMode;
        currentMode = newMode;

        emit ModeChanged(oldMode, newMode, msg.sender);
    }

    /**
     * @notice Sets the fallback mode
     * @param newFallbackMode New fallback mode
     */
    function setFallbackMode(
        VerificationMode newFallbackMode
    ) external onlyRole(MODE_ADMIN_ROLE) {
        require(
            newFallbackMode != VerificationMode.MOCK,
            "Mock cannot be fallback"
        );

        VerificationMode oldMode = fallbackMode;
        fallbackMode = newFallbackMode;

        emit FallbackModeChanged(oldMode, newFallbackMode);
    }

    /**
     * @notice Permanently disables mock mode
     * @dev Cannot be undone - use with caution
     */
    function permanentlyDisableMockMode() external onlyRole(ADMIN_ROLE) {
        require(!mockModePermanentlyDisabled, "Already disabled");

        // If currently in mock mode, switch to fallback
        if (currentMode == VerificationMode.MOCK) {
            currentMode = fallbackMode;
        }

        mockModePermanentlyDisabled = true;
        emit MockModePermanentlyDisabled(msg.sender);
    }

    /**
     * @notice Sets the ZK verifier contract
     * @param newZKVerifier New ZK verifier address
     */
    function setZKVerifier(
        address newZKVerifier
    ) external onlyRole(ADMIN_ROLE) {
        address oldVerifier = zkVerifier;
        zkVerifier = newZKVerifier;
        emit ZKVerifierUpdated(oldVerifier, newZKVerifier);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Routes verification to appropriate mode
     */
    function _verifyWithMode(
        VerificationRequest calldata request,
        VerificationMode mode
    ) internal view returns (VerificationResult memory result) {
        result.modeUsed = mode;

        if (mode == VerificationMode.MOCK) {
            result.isValid = true; // DANGER: Accepts everything
            return result;
        }

        if (mode == VerificationMode.PURE_SOLIDITY) {
            result.isValid = _verifySolidity(request);
            return result;
        }

        if (mode == VerificationMode.OFFCHAIN_ZK) {
            // For direct calls, require ZK proof separately
            result.isValid = false;
            return result;
        }

        if (mode == VerificationMode.PRECOMPILE) {
            result.isValid = _verifyPrecompile(request);
            return result;
        }
    }

    /**
     * @notice Verifies signature using pure Solidity
     */
    function _verifySolidity(
        VerificationRequest calldata request
    ) internal view returns (bool isValid) {
        if (request.algorithm == SignatureAlgorithm.DILITHIUM3) {
            (isValid, ) = DilithiumCore.verifyDilithium3(
                request.publicKey,
                request.message,
                request.signature
            );
        } else if (request.algorithm == SignatureAlgorithm.DILITHIUM5) {
            (isValid, ) = DilithiumCore.verifyDilithium5(
                request.publicKey,
                request.message,
                request.signature
            );
        } else {
            revert UnsupportedAlgorithm(request.algorithm);
        }
    }

    /**
     * @notice Verifies using precompile (future)
     * @dev Commented out request parameter until precompile is available
     */
    function _verifyPrecompile(
        VerificationRequest calldata /* request */
    ) internal view returns (bool isValid) {
        if (!_isPrecompileAvailable()) {
            revert PrecompileNotAvailable();
        }

        // Future: Call precompile
        // (bool success, bytes memory result) = precompileAddress.staticcall(
        //     abi.encode(request)
        // );
        // return success && abi.decode(result, (bool));

        return false;
    }

    /**
     * @notice Verifies ZK proof
     */
    function _verifyZKProof(
        ZKVerificationProof calldata zkProof
    ) internal view returns (bool isValid) {
        // Call ZK verifier contract
        (bool success, bytes memory result) = zkVerifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes32,bytes32,bytes32,bytes)",
                zkProof.publicKeyHash,
                zkProof.messageHash,
                zkProof.signatureHash,
                zkProof.zkProof
            )
        );

        if (!success) {
            return false;
        }

        return abi.decode(result, (bool));
    }

    /**
     * @notice Checks if precompile is available
     */
    function _isPrecompileAvailable() internal view returns (bool) {
        if (precompileAddress == address(0)) {
            return false;
        }
        // Check if precompile has code
        uint256 size;
        assembly {
            size := extcodesize(sload(precompileAddress.slot))
        }
        return size > 0;
    }

    /**
     * @notice Checks if cache entry is valid
     */
    function _isCacheValid(bytes32 requestHash) internal view returns (bool) {
        uint256 cachedAt = cacheTimestamps[requestHash];
        if (cachedAt == 0) {
            return false;
        }
        return block.timestamp < cachedAt + cacheTTL;
    }

    /**
     * @notice Caches verification result
     */
    function _cacheResult(
        bytes32 requestHash,
        VerificationResult memory result
    ) internal {
        verificationCache[requestHash] = result;
        cacheTimestamps[requestHash] = block.timestamp;
        emit VerificationCached(requestHash, block.timestamp + cacheTTL);
    }

    /**
     * @notice Computes request hash
     */
    function hashRequest(
        VerificationRequest calldata request
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    DOMAIN,
                    request.algorithm,
                    keccak256(request.publicKey),
                    keccak256(request.message),
                    keccak256(request.signature)
                )
            );
    }

    /*//////////////////////////////////////////////////////////////
                          TRUSTED KEYS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Adds a trusted public key hash
     * @param keyHash Hash of the public key
     */
    function addTrustedKey(bytes32 keyHash) external onlyRole(ADMIN_ROLE) {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    /**
     * @notice Removes a trusted public key hash
     * @param keyHash Hash of the public key
     */
    function removeTrustedKey(bytes32 keyHash) external onlyRole(ADMIN_ROLE) {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gets verification statistics
     * @return mockCount Verifications in mock mode
     * @return solidityCount Verifications in Solidity mode
     * @return zkCount Verifications in ZK mode
     * @return precompileCount Verifications in precompile mode
     */
    function getStats()
        external
        view
        returns (
            uint256 mockCount,
            uint256 solidityCount,
            uint256 zkCount,
            uint256 precompileCount
        )
    {
        mockCount = verificationCount[VerificationMode.MOCK];
        solidityCount = verificationCount[VerificationMode.PURE_SOLIDITY];
        zkCount = verificationCount[VerificationMode.OFFCHAIN_ZK];
        precompileCount = verificationCount[VerificationMode.PRECOMPILE];
    }

    /**
     * @notice Estimates gas for verification
     * @param algorithm Signature algorithm
     * @param mode Verification mode
     * @return estimatedGas Estimated gas cost
     */
    function estimateGas(
        SignatureAlgorithm algorithm,
        VerificationMode mode
    ) external pure returns (uint256 estimatedGas) {
        if (mode == VerificationMode.MOCK) {
            return 50_000;
        }
        if (mode == VerificationMode.PURE_SOLIDITY) {
            if (algorithm == SignatureAlgorithm.DILITHIUM3) {
                return DilithiumCore.estimateGas(false);
            } else if (algorithm == SignatureAlgorithm.DILITHIUM5) {
                return DilithiumCore.estimateGas(true);
            }
        }
        if (mode == VerificationMode.OFFCHAIN_ZK) {
            return 300_000; // ZK proof verification
        }
        if (mode == VerificationMode.PRECOMPILE) {
            return 100_000; // Estimated precompile cost
        }
        return MAX_SOLIDITY_GAS;
    }
}
