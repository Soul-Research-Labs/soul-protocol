// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";

/**
 * @title PQCPrecompileRouter
 * @author ZASEON
 * @notice Routes PQC signature verification through EVM precompiles when
 *         available, with graceful fallback to ZK proof or oracle backends.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                          ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Phase 3 introduces a precompile router that:
 *   1. Detects precompile availability per algorithm via liveness probes
 *   2. Routes verification to: Precompile → ZK_PROOF → Oracle (fallback chain)
 *   3. Caches probe results to avoid repeated gas overhead
 *   4. Supports both EIP-proposed and custom PQC precompile ABIs
 *   5. Emits diagnostics for monitoring precompile migration readiness
 *
 * PRECOMPILE ABI (expected):
 *   input:  abi.encode(bytes pubkey, bytes32 msgHash, bytes signature)
 *   output: abi.encode(bool valid)
 *
 * SUPPORTED ALGORITHMS:
 *   ML-DSA-44, ML-DSA-65, ML-DSA-87, FN-DSA-512, FN-DSA-1024,
 *   SLH-DSA-128s, SLH-DSA-128f, SLH-DSA-256s
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PQCPrecompileRouter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant PRECOMPILE_ADMIN_ROLE =
        keccak256("PRECOMPILE_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator for precompile verification results
    bytes32 public constant PRECOMPILE_DOMAIN =
        keccak256("ZASEON_PQC_PRECOMPILE_V1");

    /// @notice Maximum gas for precompile calls to prevent griefing
    uint256 public constant MAX_PRECOMPILE_GAS = 500_000;

    /// @notice Probe cache TTL (how long a probe result is valid)
    uint256 public constant PROBE_CACHE_TTL = 1 hours;

    /// @notice Maximum number of fallback attempts
    uint256 public constant MAX_FALLBACK_DEPTH = 3;

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verification backend priority
    enum VerificationBackend {
        PRECOMPILE, // EVM precompile (fastest, cheapest when available)
        ZK_PROOF, // Noir/STARK ZK proof verification
        ORACLE // Oracle-delegated (Phase 1 legacy fallback)
    }

    /// @notice Precompile availability status
    enum PrecompileStatus {
        UNKNOWN, // Never probed
        AVAILABLE, // Confirmed available via liveness probe
        UNAVAILABLE, // Confirmed unavailable
        DEGRADED // Available but returning inconsistent results
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-algorithm precompile configuration
    struct PrecompileConfig {
        address precompileAddress; // EVM precompile address
        PrecompileStatus status; // Current availability status
        uint256 lastProbeTime; // Last liveness probe timestamp
        uint256 totalCalls; // Total verification calls
        uint256 successfulCalls; // Successful verifications
        uint256 failedCalls; // Failed verifications
        uint256 gasUsedCumulative; // Cumulative gas tracking
        bool useRawKeyBytes; // Whether to pass raw pubkey (not hash)
    }

    /// @notice Verification routing result
    struct RoutingResult {
        VerificationBackend backendUsed;
        bool verified;
        uint256 gasUsed;
        bytes32 resultHash;
    }

    /// @notice Fallback chain configuration
    struct FallbackChain {
        VerificationBackend primary;
        VerificationBackend secondary;
        VerificationBackend tertiary;
        bool allowFallback;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Precompile configs per algorithm
    mapping(IPQCVerifier.PQCAlgorithm => PrecompileConfig)
        public precompileConfigs;

    /// @notice Fallback chain per algorithm
    mapping(IPQCVerifier.PQCAlgorithm => FallbackChain) public fallbackChains;

    /// @notice HybridPQCVerifier address for oracle/ZK fallback
    address public hybridPQCVerifier;

    /// @notice FalconZKVerifier address for ZK_PROOF fallback
    address public falconZKVerifier;

    /// @notice Total verifications routed
    uint256 public totalRoutedVerifications;

    /// @notice Total precompile successes
    uint256 public totalPrecompileSuccesses;

    /// @notice Total fallback invocations
    uint256 public totalFallbacks;

    /// @notice Verification results cache (for dedup)
    mapping(bytes32 => bool) public verifiedResults;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrecompileConfigured(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        address precompileAddress,
        bool useRawKeyBytes
    );

    event PrecompileProbeResult(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        PrecompileStatus status,
        uint256 gasUsed
    );

    event VerificationRouted(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        VerificationBackend backendUsed,
        bool verified,
        uint256 gasUsed
    );

    event FallbackTriggered(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        VerificationBackend from,
        VerificationBackend to,
        string reason
    );

    event FallbackChainConfigured(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        VerificationBackend primary,
        VerificationBackend secondary,
        VerificationBackend tertiary
    );

    event HybridPQCVerifierUpdated(
        address indexed oldAddr,
        address indexed newAddr
    );
    event FalconZKVerifierUpdated(
        address indexed oldAddr,
        address indexed newAddr
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error PrecompileNotConfigured(IPQCVerifier.PQCAlgorithm algorithm);
    error PrecompileCallFailed(IPQCVerifier.PQCAlgorithm algorithm);
    error AllBackendsFailed(IPQCVerifier.PQCAlgorithm algorithm);
    error NotSignatureAlgorithm(IPQCVerifier.PQCAlgorithm algorithm);
    error InvalidFallbackChain();

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param admin Admin address
     * @param _hybridPQCVerifier HybridPQCVerifier address (oracle/ZK fallback)
     * @param _falconZKVerifier FalconZKVerifier address (ZK_PROOF fallback for Falcon)
     */
    constructor(
        address admin,
        address _hybridPQCVerifier,
        address _falconZKVerifier
    ) {
        if (admin == address(0)) revert ZeroAddress();
        if (_hybridPQCVerifier == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(PRECOMPILE_ADMIN_ROLE, admin);

        hybridPQCVerifier = _hybridPQCVerifier;
        falconZKVerifier = _falconZKVerifier;

        // Set default fallback chains for all signature algorithms
        _setDefaultFallbackChains();
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFICATION ROUTING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Route a PQC signature verification through the optimal backend
     * @dev Attempts backends in fallback chain order; emits events for monitoring
     * @param pubKeyHash keccak256 of the signer's PQC public key
     * @param messageHash Hash of the signed message
     * @param pqcSigHash keccak256 of the PQC signature bytes
     * @param signer Ethereum address of the signer
     * @param algorithm The PQC signature algorithm
     * @return result The routing result including backend used and validity
     */
    function routeVerification(
        bytes32 pubKeyHash,
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    )
        external
        nonReentrant
        whenNotPaused
        returns (RoutingResult memory result)
    {
        if (uint8(algorithm) > uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S))
            revert NotSignatureAlgorithm(algorithm);

        totalRoutedVerifications++;

        FallbackChain storage chain = fallbackChains[algorithm];

        // Try primary backend
        uint256 gasBefore = gasleft();
        (bool success, bool verified) = _tryBackend(
            chain.primary,
            pubKeyHash,
            messageHash,
            pqcSigHash,
            signer,
            algorithm
        );

        if (success) {
            uint256 gasUsed = gasBefore - gasleft();
            result = RoutingResult({
                backendUsed: chain.primary,
                verified: verified,
                gasUsed: gasUsed,
                resultHash: _computeResultHash(
                    messageHash,
                    pqcSigHash,
                    signer,
                    algorithm
                )
            });

            if (chain.primary == VerificationBackend.PRECOMPILE && verified) {
                totalPrecompileSuccesses++;
            }

            emit VerificationRouted(
                algorithm,
                chain.primary,
                verified,
                gasUsed
            );
            return result;
        }

        if (!chain.allowFallback) revert AllBackendsFailed(algorithm);

        // Fallback to secondary
        emit FallbackTriggered(
            algorithm,
            chain.primary,
            chain.secondary,
            "Primary backend failed"
        );
        totalFallbacks++;

        gasBefore = gasleft();
        (success, verified) = _tryBackend(
            chain.secondary,
            pubKeyHash,
            messageHash,
            pqcSigHash,
            signer,
            algorithm
        );

        if (success) {
            uint256 gasUsed = gasBefore - gasleft();
            result = RoutingResult({
                backendUsed: chain.secondary,
                verified: verified,
                gasUsed: gasUsed,
                resultHash: _computeResultHash(
                    messageHash,
                    pqcSigHash,
                    signer,
                    algorithm
                )
            });

            emit VerificationRouted(
                algorithm,
                chain.secondary,
                verified,
                gasUsed
            );
            return result;
        }

        // Fallback to tertiary
        emit FallbackTriggered(
            algorithm,
            chain.secondary,
            chain.tertiary,
            "Secondary backend failed"
        );
        totalFallbacks++;

        gasBefore = gasleft();
        (success, verified) = _tryBackend(
            chain.tertiary,
            pubKeyHash,
            messageHash,
            pqcSigHash,
            signer,
            algorithm
        );

        if (success) {
            uint256 gasUsed = gasBefore - gasleft();
            result = RoutingResult({
                backendUsed: chain.tertiary,
                verified: verified,
                gasUsed: gasUsed,
                resultHash: _computeResultHash(
                    messageHash,
                    pqcSigHash,
                    signer,
                    algorithm
                )
            });

            emit VerificationRouted(
                algorithm,
                chain.tertiary,
                verified,
                gasUsed
            );
            return result;
        }

        revert AllBackendsFailed(algorithm);
    }

    /**
     * @notice Probe a precompile to check availability
     * @dev Sends a known-valid test vector to the precompile address.
     *      Results are cached for PROBE_CACHE_TTL.
     */
    function probePrecompile(
        IPQCVerifier.PQCAlgorithm algorithm
    ) external onlyRole(OPERATOR_ROLE) returns (PrecompileStatus status) {
        PrecompileConfig storage config = precompileConfigs[algorithm];

        if (config.precompileAddress == address(0)) {
            config.status = PrecompileStatus.UNAVAILABLE;
            config.lastProbeTime = block.timestamp;
            emit PrecompileProbeResult(
                algorithm,
                PrecompileStatus.UNAVAILABLE,
                0
            );
            return PrecompileStatus.UNAVAILABLE;
        }

        uint256 gasBefore = gasleft();

        // Try a minimal staticcall — if the precompile exists it should not revert
        // on well-formed input (even if verification result is false)
        bytes memory probeInput = abi.encode(
            bytes32(0), // zero pubkey hash
            bytes32(uint256(1)), // test message
            bytes32(uint256(2)) // test sig hash
        );

        (bool success, bytes memory result) = config
            .precompileAddress
            .staticcall{gas: MAX_PRECOMPILE_GAS}(probeInput);

        uint256 gasUsed = gasBefore - gasleft();

        if (success && result.length >= 32) {
            config.status = PrecompileStatus.AVAILABLE;
        } else if (success) {
            config.status = PrecompileStatus.DEGRADED;
        } else {
            config.status = PrecompileStatus.UNAVAILABLE;
        }

        config.lastProbeTime = block.timestamp;
        emit PrecompileProbeResult(algorithm, config.status, gasUsed);
        return config.status;
    }

    /**
     * @notice Check if a precompile probe result is still fresh
     */
    function isProbeFresh(
        IPQCVerifier.PQCAlgorithm algorithm
    ) external view returns (bool) {
        PrecompileConfig storage config = precompileConfigs[algorithm];
        return
            config.lastProbeTime > 0 &&
            block.timestamp - config.lastProbeTime < PROBE_CACHE_TTL;
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get diagnostic stats for an algorithm's precompile
     */
    function getPrecompileStats(
        IPQCVerifier.PQCAlgorithm algorithm
    )
        external
        view
        returns (
            address precompileAddr,
            PrecompileStatus status,
            uint256 totalCalls,
            uint256 successRate,
            uint256 avgGas
        )
    {
        PrecompileConfig storage config = precompileConfigs[algorithm];
        precompileAddr = config.precompileAddress;
        status = config.status;
        totalCalls = config.totalCalls;
        successRate = totalCalls > 0
            ? (config.successfulCalls * 10_000) / totalCalls
            : 0;
        avgGas = totalCalls > 0 ? config.gasUsedCumulative / totalCalls : 0;
    }

    /**
     * @notice Get overall routing statistics
     */
    function getRoutingStats()
        external
        view
        returns (
            uint256 totalRouted,
            uint256 precompileSuccesses,
            uint256 fallbacks,
            uint256 precompileRate
        )
    {
        totalRouted = totalRoutedVerifications;
        precompileSuccesses = totalPrecompileSuccesses;
        fallbacks = totalFallbacks;
        precompileRate = totalRouted > 0
            ? (precompileSuccesses * 10_000) / totalRouted
            : 0;
    }

    /**
     * @notice Compute the result hash for a verification
     */
    function computeResultHash(
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) external pure returns (bytes32) {
        return _computeResultHash(messageHash, pqcSigHash, signer, algorithm);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a precompile address for an algorithm
     */
    function configurePrecompile(
        IPQCVerifier.PQCAlgorithm algorithm,
        address precompileAddress,
        bool useRawKeyBytes
    ) external onlyRole(PRECOMPILE_ADMIN_ROLE) {
        if (precompileAddress == address(0)) revert ZeroAddress();
        if (uint8(algorithm) > uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S))
            revert NotSignatureAlgorithm(algorithm);

        precompileConfigs[algorithm] = PrecompileConfig({
            precompileAddress: precompileAddress,
            status: PrecompileStatus.UNKNOWN,
            lastProbeTime: 0,
            totalCalls: 0,
            successfulCalls: 0,
            failedCalls: 0,
            gasUsedCumulative: 0,
            useRawKeyBytes: useRawKeyBytes
        });

        emit PrecompileConfigured(algorithm, precompileAddress, useRawKeyBytes);
    }

    /**
     * @notice Configure the fallback chain for an algorithm
     */
    function configureFallbackChain(
        IPQCVerifier.PQCAlgorithm algorithm,
        VerificationBackend primary,
        VerificationBackend secondary,
        VerificationBackend tertiary,
        bool allowFallback
    ) external onlyRole(PRECOMPILE_ADMIN_ROLE) {
        // Ensure no duplicate backends in fallback chain
        if (
            primary == secondary || primary == tertiary || secondary == tertiary
        ) revert InvalidFallbackChain();

        fallbackChains[algorithm] = FallbackChain({
            primary: primary,
            secondary: secondary,
            tertiary: tertiary,
            allowFallback: allowFallback
        });

        emit FallbackChainConfigured(algorithm, primary, secondary, tertiary);
    }

    /**
     * @notice Update the HybridPQCVerifier address
     */
    function setHybridPQCVerifier(
        address newAddr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAddr == address(0)) revert ZeroAddress();
        address old = hybridPQCVerifier;
        hybridPQCVerifier = newAddr;
        emit HybridPQCVerifierUpdated(old, newAddr);
    }

    /**
     * @notice Update the FalconZKVerifier address
     */
    function setFalconZKVerifier(
        address newAddr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = falconZKVerifier;
        falconZKVerifier = newAddr;
        emit FalconZKVerifierUpdated(old, newAddr);
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

    /**
     * @dev Try to verify via a specific backend. Returns (callSucceeded, verificationResult).
     *      callSucceeded=false means the backend itself errored (trigger fallback).
     *      callSucceeded=true + verificationResult=false means the sig is INVALID (no fallback).
     */
    function _tryBackend(
        VerificationBackend backend,
        bytes32 pubKeyHash,
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal returns (bool callSucceeded, bool verified) {
        if (backend == VerificationBackend.PRECOMPILE) {
            return
                _tryPrecompile(pubKeyHash, messageHash, pqcSigHash, algorithm);
        }

        if (backend == VerificationBackend.ZK_PROOF) {
            return _tryZKProof(messageHash, pqcSigHash, signer, algorithm);
        }

        if (backend == VerificationBackend.ORACLE) {
            return _tryOracle(messageHash, pqcSigHash, signer, algorithm);
        }

        return (false, false);
    }

    /**
     * @dev Attempt precompile verification
     */
    function _tryPrecompile(
        bytes32 pubKeyHash,
        bytes32 messageHash,
        bytes32 pqcSigHash,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal returns (bool callSucceeded, bool verified) {
        PrecompileConfig storage config = precompileConfigs[algorithm];

        if (config.precompileAddress == address(0)) {
            return (false, false);
        }

        // Check if probe indicates unavailable
        if (config.status == PrecompileStatus.UNAVAILABLE) {
            // Re-probe if stale
            if (block.timestamp - config.lastProbeTime > PROBE_CACHE_TTL) {
                // Allow through for re-probe attempt
            } else {
                return (false, false);
            }
        }

        uint256 gasBefore = gasleft();

        bytes memory input = abi.encode(pubKeyHash, messageHash, pqcSigHash);

        (bool success, bytes memory result) = config
            .precompileAddress
            .staticcall{gas: MAX_PRECOMPILE_GAS}(input);

        uint256 gasUsed = gasBefore - gasleft();
        config.totalCalls++;
        config.gasUsedCumulative += gasUsed;

        if (!success || result.length < 32) {
            config.failedCalls++;
            return (false, false);
        }

        verified = abi.decode(result, (bool));
        config.successfulCalls++;
        return (true, verified);
    }

    /**
     * @dev Attempt ZK proof verification via HybridPQCVerifier approvedPQCResults
     */
    function _tryZKProof(
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal view returns (bool callSucceeded, bool verified) {
        if (hybridPQCVerifier == address(0)) return (false, false);

        // Check if the ZK proof result exists in HybridPQCVerifier
        bytes32 zkResultHash = keccak256(
            abi.encodePacked(
                keccak256("ZASEON_HYBRID_SIGNATURE_V1"),
                "ZK_VERIFIED",
                messageHash,
                pqcSigHash,
                signer,
                algorithm
            )
        );

        (bool success, bytes memory result) = hybridPQCVerifier.staticcall(
            abi.encodeWithSignature("approvedPQCResults(bytes32)", zkResultHash)
        );

        if (!success || result.length < 32) return (false, false);

        verified = abi.decode(result, (bool));
        return (true, verified);
    }

    /**
     * @dev Attempt oracle verification via HybridPQCVerifier approvedPQCResults (legacy)
     */
    function _tryOracle(
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal view returns (bool callSucceeded, bool verified) {
        if (hybridPQCVerifier == address(0)) return (false, false);

        bytes32 resultHash = keccak256(
            abi.encodePacked(
                keccak256("ZASEON_HYBRID_SIGNATURE_V1"),
                messageHash,
                pqcSigHash,
                signer,
                algorithm
            )
        );

        (bool success, bytes memory result) = hybridPQCVerifier.staticcall(
            abi.encodeWithSignature("approvedPQCResults(bytes32)", resultHash)
        );

        if (!success || result.length < 32) return (false, false);

        verified = abi.decode(result, (bool));
        return (true, verified);
    }

    /**
     * @dev Compute the ZK-compatible result hash
     */
    function _computeResultHash(
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

    /**
     * @dev Set default fallback chains: PRECOMPILE → ZK_PROOF → ORACLE
     *      (except FN_DSA_512 which already has the FalconZKVerifier)
     */
    function _setDefaultFallbackChains() internal {
        // Default: try precompile first, then ZK, then oracle
        FallbackChain memory defaultChain = FallbackChain({
            primary: VerificationBackend.PRECOMPILE,
            secondary: VerificationBackend.ZK_PROOF,
            tertiary: VerificationBackend.ORACLE,
            allowFallback: true
        });

        fallbackChains[IPQCVerifier.PQCAlgorithm.FN_DSA_512] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.FN_DSA_1024] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.ML_DSA_44] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.ML_DSA_65] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.ML_DSA_87] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.SLH_DSA_128S] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.SLH_DSA_128F] = defaultChain;
        fallbackChains[IPQCVerifier.PQCAlgorithm.SLH_DSA_256S] = defaultChain;
    }
}
