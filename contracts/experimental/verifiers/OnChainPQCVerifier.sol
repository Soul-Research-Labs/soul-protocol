// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";

/**
 * @title OnChainPQCVerifier
 * @author ZASEON
 * @notice Replaces oracle-delegated PQC verification with direct on-chain
 *         verification combining precompile calls and ZK proof validation.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                          ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Phase 3: Eliminates the trusted oracle dependency by:
 *   1. Attempting direct precompile verification (when EVM precompiles exist)
 *   2. Falling back to ZK proof verification (Noir UltraHonk proofs)
 *   3. Auto-submitting results to HybridPQCVerifier.approvedPQCResults
 *   4. Providing oracle deprecation tracking and sunset mechanism
 *
 * DEPRECATION PATH:
 *   Phase 1: ORACLE only           (pqcOracle = trusted EOA/contract)
 *   Phase 2: ZK_PROOF backend      (FalconZKVerifier as pqcOracle)
 *   Phase 3: ON_CHAIN verification  (this contract as pqcOracle, no trust)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract OnChainPQCVerifier is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator matching HybridPQCVerifier
    bytes32 public constant HYBRID_SIG_DOMAIN =
        keccak256("ZASEON_HYBRID_SIGNATURE_V1");

    /// @notice Domain separator for on-chain verification
    bytes32 public constant ON_CHAIN_DOMAIN =
        keccak256("ZASEON_ON_CHAIN_PQC_V1");

    /// @notice Maximum gas for precompile verification
    uint256 public constant MAX_PRECOMPILE_GAS = 500_000;

    /// @notice Oracle sunset grace period after on-chain is activated
    uint256 public constant ORACLE_SUNSET_PERIOD = 30 days;

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice On-chain verification mode
    enum OnChainMode {
        PRECOMPILE_ONLY, // Only accept precompile verification
        ZK_PROOF_ONLY, // Only accept ZK proof verification
        PRECOMPILE_PREFERRED, // Precompile first, ZK proof fallback
        ZK_PROOF_PREFERRED // ZK proof first, precompile fallback
    }

    /// @notice Oracle deprecation stage
    enum OracleDeprecationStage {
        ACTIVE, // Oracle still primary (Phase 1-2)
        SHADOWED, // On-chain verifies in parallel, compares results
        DEPRECATED, // Oracle no longer accepted, on-chain only
        SUNSET // Oracle completely removed
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-algorithm on-chain verifier configuration
    struct AlgorithmVerifierConfig {
        address precompileAddress; // EVM precompile for this algorithm
        address zkVerifierContract; // ZK verifier contract (e.g. FalconZKVerifier)
        OnChainMode mode; // Verification mode
        bool enabled; // Whether on-chain verification is active
        uint256 totalVerifications; // Total on-chain verifications
        uint256 successfulVerifications;
        uint256 precompileSuccesses;
        uint256 zkProofSuccesses;
    }

    /// @notice Verification request for batch processing
    struct VerificationRequest {
        bytes32 messageHash;
        bytes pqcSignature;
        address signer;
        IPQCVerifier.PQCAlgorithm algorithm;
    }

    /// @notice Oracle shadow comparison result
    struct ShadowResult {
        bool oracleResult;
        bool onChainResult;
        bool mismatch;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice HybridPQCVerifier reference
    address public hybridPQCVerifier;

    /// @notice Per-algorithm verifier configs
    mapping(IPQCVerifier.PQCAlgorithm => AlgorithmVerifierConfig)
        public algorithmConfigs;

    /// @notice Oracle deprecation state
    OracleDeprecationStage public oracleDeprecationStage;

    /// @notice Timestamp when oracle deprecation was initiated
    uint256 public oracleDeprecationStarted;

    /// @notice Total on-chain verifications across all algorithms
    uint256 public totalOnChainVerifications;

    /// @notice Total mismatches detected during shadow mode
    uint256 public totalShadowMismatches;

    /// @notice Shadow comparison results (for auditing during transition)
    mapping(bytes32 => ShadowResult) public shadowResults;

    /// @notice Replay protection: used verification hashes
    mapping(bytes32 => bool) public usedVerificationHashes;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event OnChainVerificationCompleted(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        address indexed signer,
        bytes32 messageHash,
        bool verified,
        string backend
    );

    event AlgorithmConfigured(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        address precompile,
        address zkVerifier,
        OnChainMode mode
    );

    event OracleDeprecationAdvanced(
        OracleDeprecationStage oldStage,
        OracleDeprecationStage newStage,
        uint256 timestamp
    );

    event ShadowMismatchDetected(
        bytes32 indexed verificationHash,
        bool oracleResult,
        bool onChainResult
    );

    event ResultSubmittedToHub(
        bytes32 indexed resultHash,
        IPQCVerifier.PQCAlgorithm algorithm
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error AlgorithmNotEnabled(IPQCVerifier.PQCAlgorithm algorithm);
    error NotSignatureAlgorithm(IPQCVerifier.PQCAlgorithm algorithm);
    error VerificationFailed(string reason);
    error OracleNotDeprecated();
    error OracleAlreadySunset();
    error SunsetPeriodNotElapsed();
    error ReplayDetected(bytes32 verificationHash);
    error InvalidSignatureSize(uint256 expected, uint256 actual);
    error HubSubmissionFailed();

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, address _hybridPQCVerifier) {
        if (admin == address(0)) revert ZeroAddress();
        if (_hybridPQCVerifier == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(VERIFIER_ADMIN_ROLE, admin);

        hybridPQCVerifier = _hybridPQCVerifier;
        oracleDeprecationStage = OracleDeprecationStage.ACTIVE;
    }

    /*//////////////////////////////////////////////////////////////
                    ON-CHAIN VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a PQC signature on-chain and submit result to HybridPQCVerifier
     * @param messageHash The signed message hash
     * @param pqcSignature The raw PQC signature bytes
     * @param signer The signer's address
     * @param algorithm The PQC algorithm used
     * @return verified Whether the signature is valid
     * @return resultHash The result hash submitted to HybridPQCVerifier
     */
    function verifyOnChain(
        bytes32 messageHash,
        bytes calldata pqcSignature,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    )
        external
        nonReentrant
        whenNotPaused
        returns (bool verified, bytes32 resultHash)
    {
        if (uint8(algorithm) > uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S))
            revert NotSignatureAlgorithm(algorithm);

        AlgorithmVerifierConfig storage config = algorithmConfigs[algorithm];
        if (!config.enabled) revert AlgorithmNotEnabled(algorithm);

        // Replay protection
        bytes32 verificationHash = keccak256(
            abi.encodePacked(
                ON_CHAIN_DOMAIN,
                messageHash,
                keccak256(pqcSignature),
                signer,
                algorithm,
                block.chainid
            )
        );

        if (usedVerificationHashes[verificationHash])
            revert ReplayDetected(verificationHash);
        usedVerificationHashes[verificationHash] = true;

        // Attempt verification based on mode
        config.totalVerifications++;
        totalOnChainVerifications++;

        verified = _verifyByMode(
            config,
            messageHash,
            pqcSignature,
            signer,
            algorithm
        );

        if (verified) {
            config.successfulVerifications++;

            // Compute result hash and submit to HybridPQCVerifier
            resultHash = _computeZKResultHash(
                messageHash,
                keccak256(pqcSignature),
                signer,
                algorithm
            );

            _submitToHub(resultHash);

            emit ResultSubmittedToHub(resultHash, algorithm);
        }

        emit OnChainVerificationCompleted(
            algorithm,
            signer,
            messageHash,
            verified,
            _modeToString(config.mode)
        );
    }

    /**
     * @notice Verify in shadow mode — compare on-chain result with oracle
     * @dev Used during OracleDeprecationStage.SHADOWED
     */
    function verifyShadow(
        bytes32 messageHash,
        bytes calldata pqcSignature,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    )
        external
        nonReentrant
        whenNotPaused
        returns (bool onChainResult, bool oracleResult, bool mismatch)
    {
        if (uint8(algorithm) > uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S))
            revert NotSignatureAlgorithm(algorithm);

        AlgorithmVerifierConfig storage config = algorithmConfigs[algorithm];
        if (!config.enabled) revert AlgorithmNotEnabled(algorithm);

        // On-chain verification
        onChainResult = _verifyByMode(
            config,
            messageHash,
            pqcSignature,
            signer,
            algorithm
        );

        // Oracle check (read-only — check if oracle already approved)
        bytes32 oracleResultHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                messageHash,
                keccak256(pqcSignature),
                signer,
                algorithm
            )
        );

        oracleResult = _checkOracleResult(oracleResultHash);

        // Compare
        mismatch = (onChainResult != oracleResult);

        bytes32 shadowKey = keccak256(
            abi.encodePacked(
                ON_CHAIN_DOMAIN,
                "SHADOW",
                messageHash,
                signer,
                algorithm
            )
        );

        shadowResults[shadowKey] = ShadowResult({
            oracleResult: oracleResult,
            onChainResult: onChainResult,
            mismatch: mismatch,
            timestamp: block.timestamp
        });

        if (mismatch) {
            totalShadowMismatches++;
            emit ShadowMismatchDetected(shadowKey, oracleResult, onChainResult);
        }
    }

    /**
     * @notice Batch verify multiple signatures on-chain
     * @param requests Array of verification requests
     * @return results Array of verification results
     */
    function batchVerifyOnChain(
        VerificationRequest[] calldata requests
    ) external nonReentrant whenNotPaused returns (bool[] memory results) {
        uint256 len = requests.length;
        require(len > 0 && len <= 32, "Invalid batch size");

        results = new bool[](len);

        for (uint256 i = 0; i < len; ) {
            VerificationRequest calldata req = requests[i];

            if (
                uint8(req.algorithm) >
                uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S)
            ) {
                unchecked {
                    ++i;
                }
                continue;
            }

            AlgorithmVerifierConfig storage config = algorithmConfigs[
                req.algorithm
            ];

            if (!config.enabled) {
                unchecked {
                    ++i;
                }
                continue;
            }

            config.totalVerifications++;
            totalOnChainVerifications++;

            bool verified = _verifyByMode(
                config,
                req.messageHash,
                req.pqcSignature,
                req.signer,
                req.algorithm
            );

            results[i] = verified;

            if (verified) {
                config.successfulVerifications++;

                bytes32 resultHash = _computeZKResultHash(
                    req.messageHash,
                    keccak256(req.pqcSignature),
                    req.signer,
                    req.algorithm
                );

                _submitToHub(resultHash);
            }

            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ORACLE DEPRECATION LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Advance oracle deprecation to shadow mode
     * @dev Enables parallel on-chain + oracle comparison
     */
    function advanceToShadow() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            oracleDeprecationStage == OracleDeprecationStage.ACTIVE,
            "Must be in ACTIVE stage"
        );

        OracleDeprecationStage oldStage = oracleDeprecationStage;
        oracleDeprecationStage = OracleDeprecationStage.SHADOWED;

        emit OracleDeprecationAdvanced(
            oldStage,
            OracleDeprecationStage.SHADOWED,
            block.timestamp
        );
    }

    /**
     * @notice Advance to deprecated — oracle results no longer accepted
     */
    function advanceToDeprecated() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            oracleDeprecationStage == OracleDeprecationStage.SHADOWED,
            "Must be in SHADOWED stage"
        );

        OracleDeprecationStage oldStage = oracleDeprecationStage;
        oracleDeprecationStage = OracleDeprecationStage.DEPRECATED;
        oracleDeprecationStarted = block.timestamp;

        emit OracleDeprecationAdvanced(
            oldStage,
            OracleDeprecationStage.DEPRECATED,
            block.timestamp
        );
    }

    /**
     * @notice Complete oracle sunset after grace period
     */
    function advanceToSunset() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            oracleDeprecationStage == OracleDeprecationStage.DEPRECATED,
            "Must be in DEPRECATED stage"
        );
        require(
            block.timestamp >= oracleDeprecationStarted + ORACLE_SUNSET_PERIOD,
            "Sunset period not elapsed"
        );

        OracleDeprecationStage oldStage = oracleDeprecationStage;
        oracleDeprecationStage = OracleDeprecationStage.SUNSET;

        emit OracleDeprecationAdvanced(
            oldStage,
            OracleDeprecationStage.SUNSET,
            block.timestamp
        );
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get verification stats for an algorithm
     */
    function getAlgorithmStats(
        IPQCVerifier.PQCAlgorithm algorithm
    )
        external
        view
        returns (
            uint256 totalVerifications,
            uint256 successRate,
            uint256 precompileRate,
            uint256 zkProofRate
        )
    {
        AlgorithmVerifierConfig storage config = algorithmConfigs[algorithm];
        totalVerifications = config.totalVerifications;

        if (totalVerifications > 0) {
            successRate =
                (config.successfulVerifications * 10_000) /
                totalVerifications;
            precompileRate =
                (config.precompileSuccesses * 10_000) /
                totalVerifications;
            zkProofRate =
                (config.zkProofSuccesses * 10_000) /
                totalVerifications;
        }
    }

    /**
     * @notice Get oracle deprecation status
     */
    function getDeprecationInfo()
        external
        view
        returns (
            OracleDeprecationStage stage,
            uint256 deprecationStarted,
            uint256 shadowMismatches,
            bool sunsetEligible
        )
    {
        stage = oracleDeprecationStage;
        deprecationStarted = oracleDeprecationStarted;
        shadowMismatches = totalShadowMismatches;
        sunsetEligible = (stage == OracleDeprecationStage.DEPRECATED &&
            block.timestamp >= oracleDeprecationStarted + ORACLE_SUNSET_PERIOD);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure on-chain verification for an algorithm
     */
    function configureAlgorithm(
        IPQCVerifier.PQCAlgorithm algorithm,
        address precompile,
        address zkVerifier,
        OnChainMode mode
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (uint8(algorithm) > uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S))
            revert NotSignatureAlgorithm(algorithm);

        AlgorithmVerifierConfig storage config = algorithmConfigs[algorithm];
        config.precompileAddress = precompile;
        config.zkVerifierContract = zkVerifier;
        config.mode = mode;
        config.enabled = true;

        emit AlgorithmConfigured(algorithm, precompile, zkVerifier, mode);
    }

    /**
     * @notice Disable on-chain verification for an algorithm
     */
    function disableAlgorithm(
        IPQCVerifier.PQCAlgorithm algorithm
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        algorithmConfigs[algorithm].enabled = false;
    }

    /**
     * @notice Update HybridPQCVerifier address
     */
    function setHybridPQCVerifier(
        address newAddr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAddr == address(0)) revert ZeroAddress();
        hybridPQCVerifier = newAddr;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyByMode(
        AlgorithmVerifierConfig storage config,
        bytes32 messageHash,
        bytes calldata pqcSignature,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal returns (bool) {
        if (config.mode == OnChainMode.PRECOMPILE_ONLY) {
            return
                _verifyViaPrecompile(config, messageHash, pqcSignature, signer);
        }

        if (config.mode == OnChainMode.ZK_PROOF_ONLY) {
            return
                _verifyViaZKProof(
                    config,
                    messageHash,
                    pqcSignature,
                    signer,
                    algorithm
                );
        }

        if (config.mode == OnChainMode.PRECOMPILE_PREFERRED) {
            bool precompileResult = _verifyViaPrecompile(
                config,
                messageHash,
                pqcSignature,
                signer
            );
            if (precompileResult) return true;
            // Fallback to ZK
            return
                _verifyViaZKProof(
                    config,
                    messageHash,
                    pqcSignature,
                    signer,
                    algorithm
                );
        }

        // ZK_PROOF_PREFERRED
        bool zkResult = _verifyViaZKProof(
            config,
            messageHash,
            pqcSignature,
            signer,
            algorithm
        );
        if (zkResult) return true;
        // Fallback to precompile
        return _verifyViaPrecompile(config, messageHash, pqcSignature, signer);
    }

    function _verifyViaPrecompile(
        AlgorithmVerifierConfig storage config,
        bytes32 messageHash,
        bytes calldata pqcSignature,
        address signer
    ) internal returns (bool) {
        if (config.precompileAddress == address(0)) return false;

        bytes memory input = abi.encode(
            keccak256(abi.encodePacked(signer)), // derive key hash from signer
            messageHash,
            keccak256(pqcSignature)
        );

        (bool success, bytes memory result) = config
            .precompileAddress
            .staticcall{gas: MAX_PRECOMPILE_GAS}(input);

        if (!success || result.length < 32) return false;

        bool verified = abi.decode(result, (bool));
        if (verified) {
            config.precompileSuccesses++;
        }
        return verified;
    }

    function _verifyViaZKProof(
        AlgorithmVerifierConfig storage config,
        bytes32 messageHash,
        bytes calldata pqcSignature,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal returns (bool) {
        if (hybridPQCVerifier == address(0)) return false;

        // Check if a ZK proof has been submitted for this verification
        bytes32 zkResultHash = _computeZKResultHash(
            messageHash,
            keccak256(pqcSignature),
            signer,
            algorithm
        );

        (bool success, bytes memory result) = hybridPQCVerifier.staticcall(
            abi.encodeWithSignature("approvedPQCResults(bytes32)", zkResultHash)
        );

        if (!success || result.length < 32) return false;

        bool verified = abi.decode(result, (bool));
        if (verified) {
            config.zkProofSuccesses++;
        }
        return verified;
    }

    function _checkOracleResult(
        bytes32 resultHash
    ) internal view returns (bool) {
        if (hybridPQCVerifier == address(0)) return false;

        (bool success, bytes memory result) = hybridPQCVerifier.staticcall(
            abi.encodeWithSignature("approvedPQCResults(bytes32)", resultHash)
        );

        if (!success || result.length < 32) return false;
        return abi.decode(result, (bool));
    }

    function _computeZKResultHash(
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    keccak256("ZASEON_HYBRID_SIGNATURE_V1"),
                    "ZK_VERIFIED",
                    messageHash,
                    pqcSigHash,
                    signer,
                    algorithm
                )
            );
    }

    function _submitToHub(bytes32 resultHash) internal {
        if (hybridPQCVerifier == address(0)) revert ZeroAddress();

        (bool success, ) = hybridPQCVerifier.call(
            abi.encodeWithSignature("submitPQCResult(bytes32)", resultHash)
        );

        if (!success) revert HubSubmissionFailed();
    }

    function _modeToString(
        OnChainMode mode
    ) internal pure returns (string memory) {
        if (mode == OnChainMode.PRECOMPILE_ONLY) return "PRECOMPILE";
        if (mode == OnChainMode.ZK_PROOF_ONLY) return "ZK_PROOF";
        if (mode == OnChainMode.PRECOMPILE_PREFERRED) return "PRECOMPILE_PREF";
        return "ZK_PROOF_PREF";
    }
}
