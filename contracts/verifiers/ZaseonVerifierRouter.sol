// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {IZaseonVerifierRouter} from "../interfaces/IZaseonVerifierRouter.sol";
import {VerifierRegistryV3} from "./VerifierRegistryV3.sol";
import {VerificationContext} from "../libraries/VerificationContext.sol";
import {CompactProof} from "../libraries/CompactProof.sol";

/**
 * @title ZaseonVerifierRouter
 * @author ZASEON
 * @notice Single synchronous entry point for Zaseon V3 proof verification.
 *
 * Design:
 *   - Consumers call `verify(circuitId, proof, publicInputs, callerCtx)`.
 *   - The router:
 *       1. Resolves the entry from {VerifierRegistryV3}.
 *       2. Checks global pause, circuit pause, activity, input bounds.
 *       3. Validates every public input is a BN254 scalar field element.
 *       4. If `requiresContextBinding`, replaces the last public input
 *          with the domain tag derived from (chainId, registry,
 *          circuitId, vkeyHash, callerCtx) and requires the caller to
 *          have committed to the same tag — i.e. we check that
 *          `publicInputs[last] == contextTag`.
 *       5. Enforces same-transaction deduplication via EIP-1153
 *          transient storage on chains that support it, with a
 *          persistent-map fallback gated by chain-id.
 *       6. Dispatches to the adapter with a per-circuit gas cap.
 *
 *   `consensusMode` on an entry is reserved for a future synchronous
 *   multi-prover integration; V3 ignores it and always single-dispatches.
 */
contract ZaseonVerifierRouter is
    IZaseonVerifierRouter,
    AccessControl,
    ReentrancyGuard
{
    using VerificationContext for uint256[];

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ROUTER_ADMIN_ROLE = keccak256("ROUTER_ADMIN_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                CONFIG
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_BATCH = 64;

    /// @dev BN254 scalar field.
    uint256 private constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the registry address passed to the constructor is zero.
    error RouterRegistryZero();

    /// @notice Thrown when the admin address passed to the constructor is zero.
    error RouterAdminZero();

    /// @dev EIP-1153 storage slot for same-tx dedup (single seed).
    bytes32 private constant _TSTORE_DEDUP_SEED =
        keccak256("zaseon.router.dedup.v1");

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    VerifierRegistryV3 public immutable REGISTRY;

    bool public routerPaused;

    /// @notice Additional circuit-level pause layered on top of registry.
    mapping(bytes32 => bool) public routerCircuitPaused;

    /// @notice True if EIP-1153 (`TSTORE`/`TLOAD`) is expected to be
    ///         available on this chain. If false, the router falls back
    ///         to a persistent mapping for dedup (clean-up on same tx).
    bool public immutable TRANSIENT_STORAGE_AVAILABLE;

    /// @notice Persistent fallback dedup map — cleared within-tx via
    ///         `_dedupFallbackClear` at the end of `verifyBatch`.
    ///         Only used when `TRANSIENT_STORAGE_AVAILABLE == false`.
    mapping(bytes32 => bool) private _dedupFallback;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param registryAddr  The `VerifierRegistryV3` instance.
     * @param admin         Receives `DEFAULT_ADMIN_ROLE` and
     *                      `ROUTER_ADMIN_ROLE`.
     * @param guardian      Receives `GUARDIAN_ROLE` (pause only).
     * @param transientOK   Whether EIP-1153 is available on the target
     *                      chain. Set `false` on zkSync/Scroll until
     *                      they ship Cancun; safe default: see
     *                      deploy script per-chain table.
     */
    constructor(
        address registryAddr,
        address admin,
        address guardian,
        bool transientOK
    ) {
        if (registryAddr == address(0)) revert RouterRegistryZero();
        if (admin == address(0)) revert RouterAdminZero();
        REGISTRY = VerifierRegistryV3(registryAddr);
        TRANSIENT_STORAGE_AVAILABLE = transientOK;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTER_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian == address(0) ? admin : guardian);
    }

    /*//////////////////////////////////////////////////////////////
                            PAUSE CONTROLS
    //////////////////////////////////////////////////////////////*/

    function pauseRouter() external onlyRole(GUARDIAN_ROLE) {
        routerPaused = true;
        emit RouterPaused(msg.sender);
    }

    function unpauseRouter() external onlyRole(ROUTER_ADMIN_ROLE) {
        routerPaused = false;
        emit RouterUnpaused(msg.sender);
    }

    function pauseCircuit(bytes32 circuitId) external onlyRole(GUARDIAN_ROLE) {
        routerCircuitPaused[circuitId] = true;
        emit CircuitPaused(circuitId, msg.sender);
    }

    function unpauseCircuit(
        bytes32 circuitId
    ) external onlyRole(ROUTER_ADMIN_ROLE) {
        routerCircuitPaused[circuitId] = false;
        emit CircuitUnpaused(circuitId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW HELPERS
    //////////////////////////////////////////////////////////////*/

    function registry() external view returns (address) {
        return address(REGISTRY);
    }

    function isAvailable(bytes32 circuitId) external view returns (bool) {
        if (routerPaused || routerCircuitPaused[circuitId]) return false;
        return REGISTRY.isAvailable(circuitId);
    }

    function adapterFor(
        bytes32 circuitId
    ) external view returns (IProofVerifier) {
        return REGISTRY.getAdapter(circuitId);
    }

    /*//////////////////////////////////////////////////////////////
                               VERIFY
    //////////////////////////////////////////////////////////////*/

    function verify(
        bytes32 circuitId,
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 callerCtx
    ) external nonReentrant returns (bool ok) {
        // SECURITY (H-11): Refuse to verify circuits that the registry flags
        // as requiring recursion via this entry point. Callers that need to
        // satisfy a MAXIMUM-tier recursive-proof policy must use
        // {verifyWithRecursion}; the plain {verify} path stays available for
        // non-recursive circuits but cannot be used to downgrade a circuit
        // whose operator declared recursion mandatory.
        if (REGISTRY.isRecursiveCircuit(circuitId)) {
            revert RecursiveProofRequired(circuitId);
        }
        ok = _verifyOne(circuitId, proof, publicInputs, callerCtx);
    }

    /**
     * @notice Verify a proof and require the circuit be flagged as recursive in the registry.
     * @dev Callers enforcing the MAXIMUM privacy tier's `requireRecursiveProof` MUST use this
     *      entry point. Non-recursive circuits are rejected with {RecursiveProofRequired}.
     */
    function verifyWithRecursion(
        bytes32 circuitId,
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 callerCtx
    ) external nonReentrant returns (bool ok) {
        if (!REGISTRY.isRecursiveCircuit(circuitId)) {
            revert RecursiveProofRequired(circuitId);
        }
        ok = _verifyOne(circuitId, proof, publicInputs, callerCtx);
    }

    function verifyBatch(
        Request[] calldata requests
    ) external nonReentrant returns (bool allOk) {
        uint256 n = requests.length;
        if (n == 0) revert EmptyBatch();
        if (n > MAX_BATCH) revert BatchTooLarge(n, MAX_BATCH);

        bytes32[] memory seenKeys;
        if (!TRANSIENT_STORAGE_AVAILABLE) {
            seenKeys = new bytes32[](n);
        }

        allOk = true;
        for (uint256 i = 0; i < n; ) {
            Request calldata r = requests[i];

            bytes32 key = keccak256(
                abi.encodePacked(
                    r.circuitId,
                    keccak256(r.proof),
                    keccak256(abi.encodePacked(r.publicInputs)),
                    r.callerCtx
                )
            );
            bool seen = _dedupCheckAndMark(key);
            if (seen) {
                // Already verified earlier in this tx — treat as success
                // without re-running the adapter. Matches prior V2 semantic.
                unchecked {
                    ++i;
                }
                continue;
            }
            if (!TRANSIENT_STORAGE_AVAILABLE) {
                seenKeys[i] = key;
            }

            bool res = _verifyOne(
                r.circuitId,
                r.proof,
                r.publicInputs,
                r.callerCtx
            );
            if (!res) {
                allOk = false;
                break;
            }
            unchecked {
                ++i;
            }
        }

        // Clean up persistent fallback dedup (transient auto-clears).
        if (!TRANSIENT_STORAGE_AVAILABLE) {
            for (uint256 i = 0; i < n; ) {
                if (seenKeys[i] != bytes32(0)) {
                    delete _dedupFallback[seenKeys[i]];
                }
                unchecked {
                    ++i;
                }
            }
        }

        emit BatchVerified(n == 0 ? bytes32(0) : requests[0].circuitId, n);
    }

    /*//////////////////////////////////////////////////////////////
                             INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _verifyOne(
        bytes32 circuitId,
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 callerCtx
    ) internal returns (bool) {
        if (routerPaused) revert RouterIsPaused();
        if (routerCircuitPaused[circuitId]) {
            revert CircuitIsPaused(circuitId);
        }

        VerifierRegistryV3.Entry memory e = REGISTRY.getEntry(circuitId);
        if (e.registeredAt == 0) revert CircuitNotRegistered(circuitId);
        if (!e.active) revert CircuitDeprecated(circuitId);
        if (e.paused) revert CircuitIsPaused(circuitId);

        uint256 piLen = publicInputs.length;
        if (piLen < e.minPublicInputs || piLen > e.maxPublicInputs) {
            revert InvalidPublicInputCount(
                circuitId,
                piLen,
                e.minPublicInputs,
                e.maxPublicInputs
            );
        }

        // Router-level field bounds — adapters/verifiers may skip this.
        for (uint256 i = 0; i < piLen; ) {
            if (publicInputs[i] >= BN254_R) {
                revert VerificationContext.FieldElementOutOfRange(
                    i,
                    publicInputs[i]
                );
            }
            unchecked {
                ++i;
            }
        }

        // Context binding: last public input MUST equal the tag.
        if (e.requiresContextBinding) {
            if (piLen == 0) revert ContextBindingFailed(circuitId);
            uint256 expected = VerificationContext.contextTag(
                address(REGISTRY),
                circuitId,
                e.vkeyHash,
                callerCtx
            );
            if (publicInputs[piLen - 1] != expected) {
                revert ContextBindingFailed(circuitId);
            }
        }

        // Dispatch with gas cap.
        uint256 forwardGas = e.gasCap == 0 ? gasleft() : e.gasCap;
        uint256 gasStart = gasleft();
        bool ok;
        try
            IProofVerifier(e.adapter).verify{gas: forwardGas}(
                proof,
                publicInputs
            )
        returns (bool r) {
            ok = r;
        } catch {
            ok = false;
        }
        uint256 gasUsed = gasStart - gasleft();
        if (e.gasCap != 0 && gasUsed > e.gasCap) {
            revert GasCapExceeded(circuitId, gasUsed, e.gasCap);
        }
        if (!ok) revert VerificationFailed(circuitId);

        emit ProofVerified(circuitId, msg.sender, callerCtx, e.consensusMode);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          DEDUP (TSTORE / MAP)
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns `true` if `key` was already seen in this tx.
    function _dedupCheckAndMark(bytes32 key) internal returns (bool seen) {
        if (TRANSIENT_STORAGE_AVAILABLE) {
            bytes32 slot = keccak256(abi.encode(_TSTORE_DEDUP_SEED, key));
            assembly {
                seen := tload(slot)
                if iszero(seen) {
                    tstore(slot, 1)
                }
            }
        } else {
            seen = _dedupFallback[key];
            if (!seen) _dedupFallback[key] = true;
        }
    }

    /*//////////////////////////////////////////////////////////////
                       CONVENIENCE: COMPACT PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a compact-packed proof blob (calldata-efficient on L2s).
     * @dev Equivalent to `verify(circuitId, proof, publicInputs, callerCtx)`
     *      but with a single `bytes` calldata argument.
     */
    function verifyCompact(
        bytes calldata blob
    ) external nonReentrant returns (bool) {
        (
            bytes32 circuitId,
            uint256[] memory publicInputs,
            bytes memory proof,
            bytes32 callerCtx
        ) = CompactProof.decode(blob);
        return _verifyOneMem(circuitId, proof, publicInputs, callerCtx);
    }

    function _verifyOneMem(
        bytes32 circuitId,
        bytes memory proof,
        uint256[] memory publicInputs,
        bytes32 callerCtx
    ) internal returns (bool) {
        if (routerPaused) revert RouterIsPaused();
        if (routerCircuitPaused[circuitId]) {
            revert CircuitIsPaused(circuitId);
        }

        VerifierRegistryV3.Entry memory e = REGISTRY.getEntry(circuitId);
        if (e.registeredAt == 0) revert CircuitNotRegistered(circuitId);
        if (!e.active) revert CircuitDeprecated(circuitId);
        if (e.paused) revert CircuitIsPaused(circuitId);

        uint256 piLen = publicInputs.length;
        if (piLen < e.minPublicInputs || piLen > e.maxPublicInputs) {
            revert InvalidPublicInputCount(
                circuitId,
                piLen,
                e.minPublicInputs,
                e.maxPublicInputs
            );
        }

        VerificationContext.assertFieldElements(publicInputs);

        if (e.requiresContextBinding) {
            if (piLen == 0) revert ContextBindingFailed(circuitId);
            uint256 expected = VerificationContext.contextTag(
                address(REGISTRY),
                circuitId,
                e.vkeyHash,
                callerCtx
            );
            if (publicInputs[piLen - 1] != expected) {
                revert ContextBindingFailed(circuitId);
            }
        }

        uint256 forwardGas = e.gasCap == 0 ? gasleft() : e.gasCap;
        uint256 gasStart = gasleft();
        bool ok;
        try
            IProofVerifier(e.adapter).verify{gas: forwardGas}(
                proof,
                publicInputs
            )
        returns (bool r) {
            ok = r;
        } catch {
            ok = false;
        }
        uint256 gasUsed = gasStart - gasleft();
        if (e.gasCap != 0 && gasUsed > e.gasCap) {
            revert GasCapExceeded(circuitId, gasUsed, e.gasCap);
        }
        if (!ok) revert VerificationFailed(circuitId);

        emit ProofVerified(circuitId, msg.sender, callerCtx, e.consensusMode);
        return true;
    }
}
