// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "./IProofVerifier.sol";

/**
 * @title IZaseonVerifierRouter
 * @author ZASEON
 * @notice Unified entry point for all ZK proof verification in Zaseon V3.
 * @dev Consumers import only this interface + a `bytes32 circuitId`.
 *      The router is responsible for:
 *        1. Looking up the registered verifier/adapter for `circuitId`.
 *        2. Enforcing per-circuit gas caps.
 *        3. Binding the proof to a `VerificationContext` tag.
 *        4. Validating public-input field bounds.
 *        5. Optionally routing to the multi-prover consensus path.
 */
interface IZaseonVerifierRouter {
    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Single verification request.
    struct Request {
        bytes32 circuitId;
        bytes proof;
        uint256[] publicInputs;
        bytes32 callerCtx;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofVerified(
        bytes32 indexed circuitId,
        address indexed caller,
        bytes32 callerCtx,
        bool consensus
    );

    event BatchVerified(bytes32 indexed firstCircuitId, uint256 count);

    event RouterPaused(address indexed by);
    event RouterUnpaused(address indexed by);
    event CircuitPaused(bytes32 indexed circuitId, address indexed by);
    event CircuitUnpaused(bytes32 indexed circuitId, address indexed by);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error RouterIsPaused();
    error CircuitIsPaused(bytes32 circuitId);
    error CircuitNotRegistered(bytes32 circuitId);
    error CircuitDeprecated(bytes32 circuitId);
    error ContextBindingFailed(bytes32 circuitId);
    error GasCapExceeded(bytes32 circuitId, uint256 used, uint256 cap);
    error VerificationFailed(bytes32 circuitId);
    error InvalidPublicInputCount(
        bytes32 circuitId,
        uint256 got,
        uint256 min,
        uint256 max
    );
    error EmptyBatch();
    error BatchTooLarge(uint256 size, uint256 max);
    error RecursiveProofRequired(bytes32 circuitId);

    /*//////////////////////////////////////////////////////////////
                           VERIFY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a single proof against `circuitId`.
     * @param circuitId    Pinned circuit identifier (registry key).
     * @param proof        Raw proof bytes.
     * @param publicInputs Public inputs as uint256[].
     * @param callerCtx    Opaque caller context (lock id, intent id, etc.).
     * @return ok True iff the proof verified and all router-level checks
     *            passed.
     */
    function verify(
        bytes32 circuitId,
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 callerCtx
    ) external returns (bool ok);

    /**
     * @notice Verify a single proof, additionally requiring the circuit be flagged recursive
     *         in the registry. Used by callers enforcing {PrivacyTier.MAXIMUM} semantics.
     * @dev Reverts with {RecursiveProofRequired} if the circuit is not marked recursive.
     */
    function verifyWithRecursion(
        bytes32 circuitId,
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 callerCtx
    ) external returns (bool ok);

    /**
     * @notice Verify a batch of independent proofs.
     * @dev Same-transaction deduplication is applied via transient
     *      storage (EIP-1153) when supported, else via a memory-set.
     */
    function verifyBatch(
        Request[] calldata requests
    ) external returns (bool allOk);

    /*//////////////////////////////////////////////////////////////
                             VIEW HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice The registry the router dispatches through.
    function registry() external view returns (address);

    /// @notice Whether `circuitId` is registered, active, and not paused.
    function isAvailable(bytes32 circuitId) external view returns (bool);

    /// @notice Resolve the adapter for a circuit (or zero if unavailable).
    function adapterFor(
        bytes32 circuitId
    ) external view returns (IProofVerifier);
}
