// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title VerifierRegistryV2
 * @author Soul Protocol
 * @notice Centralized registry for all Noir-generated verifiers with versioning and hot-swapping
 * @dev Supports CircuitType enum routing, version history, and emergency rollback
 *
 * Key features:
 *   - Type-safe CircuitType enum for all 20 Noir circuits
 *   - Versioned verifier storage with full history
 *   - Adapter-based architecture (NoirVerifierAdapter pattern)
 *   - Emergency rollback capability for guardians
 *   - Gas-optimized batch verification routing
 *
 * Migration path:
 *   1. Deploy VerifierRegistryV2
 *   2. Register all Noir-generated verifiers with adapters
 *   3. Consumer contracts call registry.verify(circuitType, proof, inputs)
 *   4. Deprecate legacy VerifierRegistry over 2 release cycles
 */
contract VerifierRegistryV2 is AccessControl {
    /*//////////////////////////////////////////////////////////////
                               ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                          CIRCUIT TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Enumeration of all supported Noir circuits
     * @dev Must be kept in sync with noir/Nargo.toml workspace members
     */
    enum CircuitType {
        // Core circuits (11 existing)
        STATE_TRANSFER, // 0
        CROSS_CHAIN_PROOF, // 1
        NULLIFIER, // 2
        MERKLE_PROOF, // 3
        POLICY, // 4
        COMPLIANCE_PROOF, // 5
        CONTAINER, // 6
        CROSS_DOMAIN_NULLIFIER, // 7
        POLICY_BOUND_PROOF, // 8
        PROOF_CARRYING_CONTAINER, // 9
        STATE_COMMITMENT, // 10
        // Phase 1 circuits (P0)
        BALANCE_PROOF, // 11
        PRIVATE_TRANSFER, // 12
        SWAP_PROOF, // 13
        // Phase 2 circuits (P1)
        RING_SIGNATURE, // 14
        PRIVATE_ORDER, // 15
        PEDERSEN_COMMITMENT, // 16
        // Phase 3 circuits (P2)
        AGGREGATOR, // 17
        PQC_VERIFIER, // 18
        INVARIANT_CHECKER // 19
    }

    /// @notice Total number of circuit types
    uint256 public constant CIRCUIT_TYPE_COUNT = 20;

    /*//////////////////////////////////////////////////////////////
                          VERIFIER ENTRY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verifier entry with full metadata
     * @param verifier The raw Noir-generated verifier address
     * @param adapter The adapter contract implementing IProofVerifier
     * @param version Incrementing version number
     * @param registeredAt Block timestamp of registration
     * @param deprecated Whether this verifier is deprecated
     * @param circuitHash ACIR bytecode hash for determinism verification
     */
    struct VerifierEntry {
        address verifier;
        address adapter;
        uint256 version;
        uint256 registeredAt;
        bool deprecated;
        bytes32 circuitHash;
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current verifier for each circuit type
    mapping(CircuitType => VerifierEntry) public verifiers;

    /// @notice Version history for each circuit type
    mapping(CircuitType => VerifierEntry[]) public versionHistory;

    /// @notice Circuit type to human-readable name
    mapping(CircuitType => string) public circuitNames;

    /// @notice Reverse lookup: adapter address to circuit type
    mapping(address => CircuitType) public adapterToCircuit;

    /// @notice Whether a circuit type has been initialized
    mapping(CircuitType => bool) public isInitialized;

    /// @notice Total registered verifiers
    uint256 public totalRegistered;

    /// @notice Registry deployment timestamp
    uint256 public immutable deployedAt;

    /// @notice Pause state for emergency
    bool public paused;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerifierRegistered(
        CircuitType indexed circuitType,
        address indexed verifier,
        address indexed adapter,
        uint256 version,
        bytes32 circuitHash
    );

    event VerifierDeprecated(
        CircuitType indexed circuitType,
        uint256 version,
        string reason
    );

    event VerifierUpgraded(
        CircuitType indexed circuitType,
        address indexed oldAdapter,
        address indexed newAdapter,
        uint256 newVersion
    );

    event EmergencyRollback(
        CircuitType indexed circuitType,
        uint256 fromVersion,
        uint256 toVersion
    );

    event RegistryPaused(address indexed by);
    event RegistryUnpaused(address indexed by);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error VerifierNotRegistered(CircuitType circuitType);
    error VerifierDeprecatedError(CircuitType circuitType);
    error VerifierAlreadyRegistered(CircuitType circuitType);
    error InvalidAddress();
    error NoPreviousVersion(CircuitType circuitType);
    error RegistryPausedError();
    error InvalidCircuitType(uint256 typeId);

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier whenNotPaused() {
        if (paused) revert RegistryPausedError();
        _;
    }

    modifier validCircuitType(CircuitType circuitType) {
        if (uint256(circuitType) >= CIRCUIT_TYPE_COUNT) {
            revert InvalidCircuitType(uint256(circuitType));
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        deployedAt = block.timestamp;

        // Initialize circuit names
        _initializeCircuitNames();
    }

    /*//////////////////////////////////////////////////////////////
                        REGISTRATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new verifier for a circuit type
     * @param circuitType The circuit type enum
     * @param verifier The raw Noir-generated verifier address
     * @param adapter The adapter implementing IProofVerifier
     * @param circuitHash ACIR bytecode hash for verification
     * @return version The assigned version number
     */
    function registerVerifier(
        CircuitType circuitType,
        address verifier,
        address adapter,
        bytes32 circuitHash
    )
        external
        onlyRole(REGISTRY_ADMIN_ROLE)
        validCircuitType(circuitType)
        returns (uint256 version)
    {
        if (verifier == address(0) || adapter == address(0)) {
            revert InvalidAddress();
        }

        VerifierEntry storage current = verifiers[circuitType];

        // Archive old version if exists
        if (current.verifier != address(0)) {
            versionHistory[circuitType].push(current);

            // Clear reverse lookup for old adapter
            delete adapterToCircuit[current.adapter];

            emit VerifierUpgraded(
                circuitType,
                current.adapter,
                adapter,
                current.version + 1
            );
        } else {
            totalRegistered++;
        }

        version = current.version + 1;

        verifiers[circuitType] = VerifierEntry({
            verifier: verifier,
            adapter: adapter,
            version: version,
            registeredAt: block.timestamp,
            deprecated: false,
            circuitHash: circuitHash
        });

        // Set reverse lookup
        adapterToCircuit[adapter] = circuitType;
        isInitialized[circuitType] = true;

        emit VerifierRegistered(
            circuitType,
            verifier,
            adapter,
            version,
            circuitHash
        );
    }

    /**
     * @notice Batch register multiple verifiers
     * @param circuitTypes Array of circuit types
     * @param verifierAddrs Array of verifier addresses
     * @param adapterAddrs Array of adapter addresses
     * @param circuitHashes Array of circuit hashes
     */
    function batchRegisterVerifiers(
        CircuitType[] calldata circuitTypes,
        address[] calldata verifierAddrs,
        address[] calldata adapterAddrs,
        bytes32[] calldata circuitHashes
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(
            circuitTypes.length == verifierAddrs.length &&
                verifierAddrs.length == adapterAddrs.length &&
                adapterAddrs.length == circuitHashes.length,
            "Length mismatch"
        );

        for (uint256 i = 0; i < circuitTypes.length; i++) {
            // Internal call to avoid repeated role checks
            _registerVerifierInternal(
                circuitTypes[i],
                verifierAddrs[i],
                adapterAddrs[i],
                circuitHashes[i]
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                        VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a proof through the registry
     * @param circuitType The circuit type to use
     * @param proof The proof bytes
     * @param publicInputs The public inputs (ABI-encoded)
     * @return valid Whether the proof is valid
     */
    function verify(
        CircuitType circuitType,
        bytes calldata proof,
        bytes calldata publicInputs
    )
        external
        view
        whenNotPaused
        validCircuitType(circuitType)
        returns (bool valid)
    {
        VerifierEntry storage entry = verifiers[circuitType];

        if (entry.adapter == address(0)) {
            revert VerifierNotRegistered(circuitType);
        }
        if (entry.deprecated) {
            revert VerifierDeprecatedError(circuitType);
        }

        return IProofVerifier(entry.adapter).verifyProof(proof, publicInputs);
    }

    /**
     * @notice Batch verify multiple proofs of the same type
     * @param circuitType The circuit type for all proofs
     * @param proofs Array of proof bytes
     * @param publicInputsArray Array of public inputs
     * @return results Array of verification results
     */
    function batchVerify(
        CircuitType circuitType,
        bytes[] calldata proofs,
        bytes[] calldata publicInputsArray
    )
        external
        view
        whenNotPaused
        validCircuitType(circuitType)
        returns (bool[] memory results)
    {
        require(proofs.length == publicInputsArray.length, "Length mismatch");

        VerifierEntry storage entry = verifiers[circuitType];
        if (entry.adapter == address(0)) {
            revert VerifierNotRegistered(circuitType);
        }
        if (entry.deprecated) {
            revert VerifierDeprecatedError(circuitType);
        }

        IProofVerifier adapter = IProofVerifier(entry.adapter);
        results = new bool[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = adapter.verifyProof(proofs[i], publicInputsArray[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the adapter address for a circuit type
     * @param circuitType The circuit type
     * @return adapter The adapter address
     */
    function getAdapter(
        CircuitType circuitType
    ) external view validCircuitType(circuitType) returns (address adapter) {
        VerifierEntry storage entry = verifiers[circuitType];
        if (entry.adapter == address(0)) {
            revert VerifierNotRegistered(circuitType);
        }
        return entry.adapter;
    }

    /**
     * @notice Get full verifier entry for a circuit type
     * @param circuitType The circuit type
     * @return entry The verifier entry struct
     */
    function getVerifierEntry(
        CircuitType circuitType
    )
        external
        view
        validCircuitType(circuitType)
        returns (VerifierEntry memory entry)
    {
        return verifiers[circuitType];
    }

    /**
     * @notice Get version history for a circuit type
     * @param circuitType The circuit type
     * @return history Array of historical verifier entries
     */
    function getVersionHistory(
        CircuitType circuitType
    )
        external
        view
        validCircuitType(circuitType)
        returns (VerifierEntry[] memory history)
    {
        return versionHistory[circuitType];
    }

    /**
     * @notice Get version count for a circuit type
     * @param circuitType The circuit type
     * @return count Number of versions (including current)
     */
    function getVersionCount(
        CircuitType circuitType
    ) external view validCircuitType(circuitType) returns (uint256 count) {
        return
            versionHistory[circuitType].length +
            (isInitialized[circuitType] ? 1 : 0);
    }

    /**
     * @notice Check if a circuit type is registered and active
     * @param circuitType The circuit type
     * @return active True if registered and not deprecated
     */
    function isActive(
        CircuitType circuitType
    ) external view validCircuitType(circuitType) returns (bool active) {
        VerifierEntry storage entry = verifiers[circuitType];
        return entry.adapter != address(0) && !entry.deprecated;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPRECATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deprecate a verifier (soft deprecation)
     * @param circuitType The circuit type to deprecate
     * @param reason Human-readable deprecation reason
     */
    function deprecateVerifier(
        CircuitType circuitType,
        string calldata reason
    ) external onlyRole(REGISTRY_ADMIN_ROLE) validCircuitType(circuitType) {
        VerifierEntry storage entry = verifiers[circuitType];
        if (entry.adapter == address(0)) {
            revert VerifierNotRegistered(circuitType);
        }

        entry.deprecated = true;

        emit VerifierDeprecated(circuitType, entry.version, reason);
    }

    /**
     * @notice Emergency rollback to previous version
     * @param circuitType The circuit type to rollback
     */
    function emergencyRollback(
        CircuitType circuitType
    ) external onlyRole(GUARDIAN_ROLE) validCircuitType(circuitType) {
        VerifierEntry[] storage history = versionHistory[circuitType];
        if (history.length == 0) {
            revert NoPreviousVersion(circuitType);
        }

        VerifierEntry storage current = verifiers[circuitType];
        uint256 fromVersion = current.version;

        // Clear current adapter reverse lookup
        delete adapterToCircuit[current.adapter];

        // Restore previous version
        VerifierEntry memory previous = history[history.length - 1];
        verifiers[circuitType] = previous;
        history.pop();

        // Set new reverse lookup
        adapterToCircuit[previous.adapter] = circuitType;

        emit EmergencyRollback(circuitType, fromVersion, previous.version);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pause the registry (emergency)
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        paused = true;
        emit RegistryPaused(msg.sender);
    }

    /**
     * @notice Unpause the registry
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        paused = false;
        emit RegistryUnpaused(msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerVerifierInternal(
        CircuitType circuitType,
        address verifier,
        address adapter,
        bytes32 circuitHash
    ) internal validCircuitType(circuitType) {
        if (verifier == address(0) || adapter == address(0)) {
            revert InvalidAddress();
        }

        VerifierEntry storage current = verifiers[circuitType];

        if (current.verifier != address(0)) {
            versionHistory[circuitType].push(current);
            delete adapterToCircuit[current.adapter];
        } else {
            totalRegistered++;
        }

        uint256 version = current.version + 1;

        verifiers[circuitType] = VerifierEntry({
            verifier: verifier,
            adapter: adapter,
            version: version,
            registeredAt: block.timestamp,
            deprecated: false,
            circuitHash: circuitHash
        });

        adapterToCircuit[adapter] = circuitType;
        isInitialized[circuitType] = true;

        emit VerifierRegistered(
            circuitType,
            verifier,
            adapter,
            version,
            circuitHash
        );
    }

    function _initializeCircuitNames() internal {
        circuitNames[CircuitType.STATE_TRANSFER] = "state_transfer";
        circuitNames[CircuitType.CROSS_CHAIN_PROOF] = "cross_chain_proof";
        circuitNames[CircuitType.NULLIFIER] = "nullifier";
        circuitNames[CircuitType.MERKLE_PROOF] = "merkle_proof";
        circuitNames[CircuitType.POLICY] = "policy";
        circuitNames[CircuitType.COMPLIANCE_PROOF] = "compliance_proof";
        circuitNames[CircuitType.CONTAINER] = "container";
        circuitNames[
            CircuitType.CROSS_DOMAIN_NULLIFIER
        ] = "cross_domain_nullifier";
        circuitNames[CircuitType.POLICY_BOUND_PROOF] = "policy_bound_proof";
        circuitNames[
            CircuitType.PROOF_CARRYING_CONTAINER
        ] = "proof_carrying_container";
        circuitNames[CircuitType.STATE_COMMITMENT] = "state_commitment";
        circuitNames[CircuitType.BALANCE_PROOF] = "balance_proof";
        circuitNames[CircuitType.PRIVATE_TRANSFER] = "private_transfer";
        circuitNames[CircuitType.SWAP_PROOF] = "swap_proof";
        circuitNames[CircuitType.RING_SIGNATURE] = "ring_signature";
        circuitNames[CircuitType.PRIVATE_ORDER] = "private_order";
        circuitNames[CircuitType.PEDERSEN_COMMITMENT] = "pedersen_commitment";
        circuitNames[CircuitType.AGGREGATOR] = "aggregator";
        circuitNames[CircuitType.PQC_VERIFIER] = "pqc_verifier";
        circuitNames[CircuitType.INVARIANT_CHECKER] = "invariant_checker";
    }
}

/**
 * @title IVerifierRegistryV2
 * @notice Interface for VerifierRegistryV2
 */
interface IVerifierRegistryV2 {
    function verify(
        VerifierRegistryV2.CircuitType circuitType,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);

    function getAdapter(
        VerifierRegistryV2.CircuitType circuitType
    ) external view returns (address);
}
