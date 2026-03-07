// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {IUniversalChainAdapter} from "../interfaces/IUniversalChainAdapter.sol";
import {UniversalChainRegistry} from "../libraries/UniversalChainRegistry.sol";

/**
 * @title UniversalProofTranslator
 * @author ZASEON
 * @notice Translates ZK proofs between compatible proof systems for cross-chain interop
 *
 * @dev SCOPE & LIMITATIONS:
 *
 *      SUPPORTED (same-family, no recursion required):
 *        - PLONK <-> UltraPlonk <-> HONK (Noir/Aztec family)
 *        - Groth16 <-> Groth16 (same system cross-chain relay)
 *        - STARK <-> STARK (same system cross-chain relay)
 *
 *      NOT SUPPORTED (requires recursive wrapper circuits):
 *        - Groth16 <-> PLONK (cross-family — needs proof-of-verification circuit)
 *        - STARK <-> Groth16 (cross-family — extremely expensive on EVM)
 *        - Any cross-family translation
 *
 *      Cross-family translation would require embedding a verifier circuit for system A
 *      inside a proof for system B (recursive proof wrapping). This is:
 *        1. Extremely gas-intensive on EVM (~500k-2M gas per recursive verification)
 *        2. Requires per-pair circuit compilation (N² circuits for N proof systems)
 *        3. An active research area — not production-ready
 *
 *      The protocol handles cross-family cases by verifying the source proof directly
 *      using the appropriate verifier adapter from VerifierRegistryV2, rather than
 *      attempting translation. This is functionally equivalent when the destination
 *      chain supports the source proof system's verifier.
 *
 *      ARCHITECTURE:
 *      ┌──────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
 *      │  Source Chain     │     │  UniversalProof      │     │  Dest Chain      │
 *      │  (HONK proof)    │────>│  Translator          │────>│  (PLONK verifier)│
 *      └──────────────────┘     │                      │     └──────────────────┘
 *                               │  1. Check compat     │
 *                               │  2. Validate source  │
 *                               │  3. Dispatch/relay   │
 *                               └──────────────────────┘
 */
contract UniversalProofTranslator is AccessControl, Pausable {
    using UniversalChainRegistry for *;

    // =========================================================================
    // TYPE ALIASES
    // =========================================================================

    /// @dev Alias for readability
    type ProofSystem is uint8;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Registered verifier for a proof system
    struct SystemVerifier {
        address verifier; // IProofVerifier implementation
        bool active;
        uint256 registeredAt;
    }

    /// @notice Result of a translation attempt
    struct TranslationResult {
        bool success;
        bool nativeCompatible; // True if no translation needed
        bytes translatedProof; // Same as input if natively compatible
        IUniversalChainAdapter.ProofSystem targetSystem;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// @notice Verifier per proof system
    mapping(IUniversalChainAdapter.ProofSystem => SystemVerifier)
        public systemVerifiers;

    /// @notice Translation statistics
    uint256 public totalTranslations;
    uint256 public totalNativeRelays;
    uint256 public totalUnsupportedRequests;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event VerifierRegistered(
        IUniversalChainAdapter.ProofSystem indexed system,
        address indexed verifier
    );

    event VerifierDeactivated(
        IUniversalChainAdapter.ProofSystem indexed system
    );

    event ProofTranslated(
        IUniversalChainAdapter.ProofSystem indexed sourceSystem,
        IUniversalChainAdapter.ProofSystem indexed targetSystem,
        bool nativeCompatible,
        bytes32 proofHash
    );

    event TranslationUnsupported(
        IUniversalChainAdapter.ProofSystem indexed sourceSystem,
        IUniversalChainAdapter.ProofSystem indexed targetSystem
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error UnsupportedTranslation(
        IUniversalChainAdapter.ProofSystem source,
        IUniversalChainAdapter.ProofSystem target
    );
    error VerifierNotRegistered(IUniversalChainAdapter.ProofSystem system);
    error VerifierInactive(IUniversalChainAdapter.ProofSystem system);
    error ProofVerificationFailed();
    error EmptyProof();
    error ZeroAddress();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address _admin, address _operator) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_operator == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _operator);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    // =========================================================================
    // TRANSLATION
    // =========================================================================

    /**
     * @notice Check whether a translation path exists between two proof systems
     * @param source Source proof system
     * @param target Target proof system
     * @return supported True if translation is supported
     * @return nativeCompat True if systems are natively compatible (no translation needed)
     */
    function isTranslationSupported(
        IUniversalChainAdapter.ProofSystem source,
        IUniversalChainAdapter.ProofSystem target
    ) external view returns (bool supported, bool nativeCompat) {
        // Same system always supported
        if (source == target) {
            return (true, true);
        }

        // Check native compatibility (same family)
        if (UniversalChainRegistry.areProofSystemsCompatible(source, target)) {
            // Need verifier for the source to validate the proof
            bool hasVerifier = systemVerifiers[source].active;
            return (hasVerifier, true);
        }

        // Cross-family: not supported
        return (false, false);
    }

    /**
     * @notice Translate (or relay) a proof from one system to another
     * @dev For same-family systems, validates the proof with the source verifier
     *      and returns it as-is (native compatibility). For cross-family, reverts.
     * @param proof The proof bytes
     * @param publicInputs Public inputs for verification
     * @param sourceSystem The proof system that generated the proof
     * @param targetSystem The proof system expected by the destination
     * @return result The translation result
     */
    function translateProof(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        IUniversalChainAdapter.ProofSystem sourceSystem,
        IUniversalChainAdapter.ProofSystem targetSystem
    ) external whenNotPaused returns (TranslationResult memory result) {
        if (proof.length == 0) revert EmptyProof();

        // Case 1: Same system — relay directly after verification
        if (sourceSystem == targetSystem) {
            _verifyWithSystem(sourceSystem, proof, publicInputs);

            ++totalNativeRelays;
            ++totalTranslations;

            emit ProofTranslated(
                sourceSystem,
                targetSystem,
                true,
                keccak256(proof)
            );

            return
                TranslationResult({
                    success: true,
                    nativeCompatible: true,
                    translatedProof: proof,
                    targetSystem: targetSystem
                });
        }

        // Case 2: Same family (PLONK/UltraPlonk/HONK) — natively compatible
        if (
            UniversalChainRegistry.areProofSystemsCompatible(
                sourceSystem,
                targetSystem
            )
        ) {
            _verifyWithSystem(sourceSystem, proof, publicInputs);

            ++totalNativeRelays;
            ++totalTranslations;

            emit ProofTranslated(
                sourceSystem,
                targetSystem,
                true,
                keccak256(proof)
            );

            return
                TranslationResult({
                    success: true,
                    nativeCompatible: true,
                    translatedProof: proof,
                    targetSystem: targetSystem
                });
        }

        // Case 3: Cross-family — not supported
        ++totalUnsupportedRequests;

        emit TranslationUnsupported(sourceSystem, targetSystem);

        revert UnsupportedTranslation(sourceSystem, targetSystem);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /**
     * @notice Register a verifier for a proof system
     * @param system The proof system
     * @param verifier The IProofVerifier implementation address
     */
    function registerVerifier(
        IUniversalChainAdapter.ProofSystem system,
        address verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();

        systemVerifiers[system] = SystemVerifier({
            verifier: verifier,
            active: true,
            registeredAt: block.timestamp
        });

        emit VerifierRegistered(system, verifier);
    }

    /**
     * @notice Deactivate a verifier (emergency use)
     * @param system The proof system to deactivate
     */
    function deactivateVerifier(
        IUniversalChainAdapter.ProofSystem system
    ) external onlyRole(GUARDIAN_ROLE) {
        systemVerifiers[system].active = false;
        emit VerifierDeactivated(system);
    }

    /// @notice Emergency pause
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    /**
     * @dev Verify a proof using the registered verifier for the given proof system
     */
    function _verifyWithSystem(
        IUniversalChainAdapter.ProofSystem system,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) internal view {
        SystemVerifier storage sv = systemVerifiers[system];
        if (sv.verifier == address(0)) revert VerifierNotRegistered(system);
        if (!sv.active) revert VerifierInactive(system);

        bool valid = IProofVerifier(sv.verifier).verify(proof, publicInputs);
        if (!valid) revert ProofVerificationFailed();
    }

    // =========================================================================
    // VIEW
    // =========================================================================

    /// @notice Get the verifier address for a proof system
    function getVerifier(
        IUniversalChainAdapter.ProofSystem system
    ) external view returns (address) {
        return systemVerifiers[system].verifier;
    }

    /// @notice Check if a proof system has an active verifier
    function hasActiveVerifier(
        IUniversalChainAdapter.ProofSystem system
    ) external view returns (bool) {
        return
            systemVerifiers[system].active &&
            systemVerifiers[system].verifier != address(0);
    }
}
