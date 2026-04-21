// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title VerifierRegistryV3
 * @author ZASEON
 * @notice Registry of verifier/adapter entries keyed by `bytes32 circuitId`.
 * @dev Differences vs V2:
 *        - `bytes32 circuitId` instead of `enum CircuitType` — avoids
 *          redeploys when new circuits are added.
 *        - **Immutable ACIR / vkey hashes per circuit id**: once a
 *          circuit id is registered with a (acirHash, vkeyHash) pair,
 *          those hashes can never change. Rotating a vkey requires
 *          registering a *new* circuit id. This forces an audit trail.
 *        - Per-circuit **gasCap** and public-input bounds enforced at
 *          the router.
 *        - Registration / retirement is gated on the
 *          `REGISTRY_ADMIN_ROLE`, which is expected to be held by
 *          `ZaseonUpgradeTimelock` in production.
 *        - `GUARDIAN_ROLE` can only *pause* circuits, never swap them.
 *        - `requiresContextBinding` flag per circuit: when true, the
 *          router enforces that `publicInputs[last] == contextTag`.
 */
contract VerifierRegistryV3 is AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct Entry {
        address verifier; // raw (Barretenberg / Groth16) verifier
        address adapter; // IProofVerifier-compliant wrapper
        bytes32 acirHash; // ACIR bytecode hash (immutable)
        bytes32 vkeyHash; // vkey hash (immutable)
        uint32 gasCap; // max gas forwarded to adapter (0 = no cap)
        uint16 minPublicInputs;
        uint16 maxPublicInputs;
        bool active; // false = retired, cannot be used
        bool paused; // toggleable by GUARDIAN_ROLE
        bool consensusMode; // route through multi-prover instead
        bool requiresContextBinding; // enforce context tag as last PI
        uint64 registeredAt;
        uint64 deprecatedAt; // 0 if still current
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered circuits.
    mapping(bytes32 => Entry) private _entries;

    /// @notice Reverse lookup: adapter → circuit id.
    mapping(address => bytes32) public adapterToCircuit;

    /// @notice Enumeration of registered circuit ids (insertion order).
    bytes32[] public circuitIds;

    /// @notice Global pause for emergency.
    bool public paused;

    /// @notice Optional: bytes32 proof-type hash ↔ circuit id, for
    ///         backward compatibility with V2's ProofHub interface.
    mapping(bytes32 => bytes32) public proofTypeToCircuit;

    /// @notice True if a circuit has been designated as a recursive / aggregated verifier.
    /// @dev Used by the router to enforce {PrivacyTier.MAXIMUM} tier's `requireRecursiveProof`.
    ///      Admins flip this flag after registering a recursive circuit.
    mapping(bytes32 => bool) public isRecursiveCircuit;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CircuitRegistered(
        bytes32 indexed circuitId,
        address indexed verifier,
        address indexed adapter,
        bytes32 acirHash,
        bytes32 vkeyHash
    );

    event AcirAttested(
        bytes32 indexed circuitId,
        bytes32 acirHash,
        bytes32 vkeyHash,
        address indexed attester
    );

    event CircuitRetired(bytes32 indexed circuitId, address indexed by);
    event CircuitPaused(bytes32 indexed circuitId, address indexed by);
    event CircuitUnpaused(bytes32 indexed circuitId, address indexed by);

    event GasCapUpdated(
        bytes32 indexed circuitId,
        uint32 oldCap,
        uint32 newCap
    );
    event ConsensusModeUpdated(bytes32 indexed circuitId, bool consensusMode);
    event RecursiveFlagUpdated(bytes32 indexed circuitId, bool isRecursive);
    event RegistryPausedEvt(address indexed by);
    event RegistryUnpausedEvt(address indexed by);

    event ProofTypeMapped(bytes32 indexed proofType, bytes32 indexed circuitId);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidAddress();
    error InvalidHash();
    error InvalidInputBounds();
    error CircuitAlreadyExists(bytes32 circuitId);
    error CircuitNotFound(bytes32 circuitId);
    error CircuitInactive(bytes32 circuitId);
    error HashesAreImmutable(bytes32 circuitId);
    error RegistryIsPaused();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param admin  Initial holder of `DEFAULT_ADMIN_ROLE`. In production
     *               this should be the governance multisig.
     * @param timelock Address of `ZaseonUpgradeTimelock` (granted
     *                 `REGISTRY_ADMIN_ROLE`). May be the zero address for
     *                 tests; in that case the deployer is admin.
     * @param guardian Address granted `GUARDIAN_ROLE` (pause-only).
     */
    constructor(address admin, address timelock, address guardian) {
        if (admin == address(0)) revert InvalidAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);

        if (timelock != address(0)) {
            _grantRole(REGISTRY_ADMIN_ROLE, timelock);
        } else {
            _grantRole(REGISTRY_ADMIN_ROLE, admin);
        }
        if (guardian != address(0)) {
            _grantRole(GUARDIAN_ROLE, guardian);
        } else {
            _grantRole(GUARDIAN_ROLE, admin);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new circuit.
     * @dev Reverts if `circuitId` already exists. To rotate a vkey,
     *      allocate a *new* circuit id (e.g.
     *      `keccak256("private_transfer:v2")`).
     */
    function registerCircuit(
        bytes32 circuitId,
        address verifier,
        address adapter,
        bytes32 acirHash,
        bytes32 vkeyHash,
        uint32 gasCap,
        uint16 minPublicInputs,
        uint16 maxPublicInputs,
        bool consensusMode,
        bool requiresContextBinding
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (verifier == address(0) || adapter == address(0)) {
            revert InvalidAddress();
        }
        if (acirHash == bytes32(0) || vkeyHash == bytes32(0)) {
            revert InvalidHash();
        }
        if (minPublicInputs > maxPublicInputs || maxPublicInputs == 0) {
            revert InvalidInputBounds();
        }
        if (_entries[circuitId].registeredAt != 0) {
            revert CircuitAlreadyExists(circuitId);
        }

        _entries[circuitId] = Entry({
            verifier: verifier,
            adapter: adapter,
            acirHash: acirHash,
            vkeyHash: vkeyHash,
            gasCap: gasCap,
            minPublicInputs: minPublicInputs,
            maxPublicInputs: maxPublicInputs,
            active: true,
            paused: false,
            consensusMode: consensusMode,
            requiresContextBinding: requiresContextBinding,
            registeredAt: uint64(block.timestamp),
            deprecatedAt: 0
        });
        adapterToCircuit[adapter] = circuitId;
        circuitIds.push(circuitId);

        emit CircuitRegistered(
            circuitId,
            verifier,
            adapter,
            acirHash,
            vkeyHash
        );
        emit AcirAttested(circuitId, acirHash, vkeyHash, msg.sender);
    }

    /**
     * @notice Retire a circuit (mark inactive). Cannot be undone.
     *         Prevents further verification through the router but
     *         preserves the audit trail.
     */
    function retireCircuit(
        bytes32 circuitId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Entry storage e = _entries[circuitId];
        if (e.registeredAt == 0) revert CircuitNotFound(circuitId);
        e.active = false;
        e.deprecatedAt = uint64(block.timestamp);
        emit CircuitRetired(circuitId, msg.sender);
    }

    /**
     * @notice Guardian pause (reversible).
     */
    function pauseCircuit(bytes32 circuitId) external onlyRole(GUARDIAN_ROLE) {
        Entry storage e = _entries[circuitId];
        if (e.registeredAt == 0) revert CircuitNotFound(circuitId);
        e.paused = true;
        emit CircuitPaused(circuitId, msg.sender);
    }

    function unpauseCircuit(
        bytes32 circuitId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Entry storage e = _entries[circuitId];
        if (e.registeredAt == 0) revert CircuitNotFound(circuitId);
        e.paused = false;
        emit CircuitUnpaused(circuitId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         TUNING (MUTABLE FIELDS)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update gas cap (does not affect cryptographic identity).
     */
    function setGasCap(
        bytes32 circuitId,
        uint32 newCap
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Entry storage e = _entries[circuitId];
        if (e.registeredAt == 0) revert CircuitNotFound(circuitId);
        uint32 old = e.gasCap;
        e.gasCap = newCap;
        emit GasCapUpdated(circuitId, old, newCap);
    }

    /**
     * @notice Toggle consensus mode routing.
     */
    function setConsensusMode(
        bytes32 circuitId,
        bool on
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Entry storage e = _entries[circuitId];
        if (e.registeredAt == 0) revert CircuitNotFound(circuitId);
        e.consensusMode = on;
        emit ConsensusModeUpdated(circuitId, on);
    }

    /**
     * @notice Flag a circuit as recursive / aggregated.
     * @dev Used by {ZaseonVerifierRouter.verifyWithRecursionRequirement} and by
     *      {PrivacyTierRouter} enforcement for the MAXIMUM tier.
     */
    function setRecursive(
        bytes32 circuitId,
        bool recursive
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Entry storage e = _entries[circuitId];
        if (e.registeredAt == 0) revert CircuitNotFound(circuitId);
        isRecursiveCircuit[circuitId] = recursive;
        emit RecursiveFlagUpdated(circuitId, recursive);
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF-TYPE MAPPING
    //////////////////////////////////////////////////////////////*/

    function mapProofType(
        bytes32 proofType,
        bytes32 circuitId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (_entries[circuitId].registeredAt == 0) {
            revert CircuitNotFound(circuitId);
        }
        proofTypeToCircuit[proofType] = circuitId;
        emit ProofTypeMapped(proofType, circuitId);
    }

    /*//////////////////////////////////////////////////////////////
                            GLOBAL PAUSE
    //////////////////////////////////////////////////////////////*/

    function pauseRegistry() external onlyRole(GUARDIAN_ROLE) {
        paused = true;
        emit RegistryPausedEvt(msg.sender);
    }

    function unpauseRegistry() external onlyRole(REGISTRY_ADMIN_ROLE) {
        paused = false;
        emit RegistryUnpausedEvt(msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function getEntry(bytes32 circuitId) external view returns (Entry memory) {
        return _entries[circuitId];
    }

    function isRegistered(bytes32 circuitId) external view returns (bool) {
        return _entries[circuitId].registeredAt != 0;
    }

    function isAvailable(bytes32 circuitId) external view returns (bool) {
        if (paused) return false;
        Entry storage e = _entries[circuitId];
        if (!e.active || e.paused || e.adapter == address(0)) return false;
        // SECURITY: also require the adapter contract still exists on-chain.
        // Defends against silent failure when an adapter is self-destructed or
        // was never deployed at the recorded address. Callers that swallow
        // verifier reverts (e.g. ZaseonVerifierRouter try/catch) would
        // otherwise treat a non-existent adapter as a verification failure
        // without any signal that the registry is misconfigured.
        return e.adapter.code.length > 0;
    }

    function getAdapter(
        bytes32 circuitId
    ) external view returns (IProofVerifier) {
        return IProofVerifier(_entries[circuitId].adapter);
    }

    function circuitCount() external view returns (uint256) {
        return circuitIds.length;
    }
}
