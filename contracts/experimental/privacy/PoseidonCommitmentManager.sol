// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PoseidonCommitmentManager
 * @author ZASEON
 * @notice Manages the migration from Pedersen to Poseidon commitments.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                          ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Phase 3: Migrates privacy commitments from Pedersen to Poseidon:
 *
 * WHY MIGRATE:
 *   - Pedersen commitments (C = v·H + r·G) rely on discrete log hardness
 *     on elliptic curves → vulnerable to Shor's algorithm
 *   - Poseidon hash commitments are algebraic hashes designed for ZK circuits
 *     → quantum-resistant (only Grover applies, ≥128-bit security)
 *   - Poseidon is ~100x cheaper in ZK circuit constraints vs Pedersen
 *
 * MIGRATION APPROACH:
 *   1. Register Poseidon verifier contracts alongside existing Pedersen
 *   2. Dual-commitment mode: accept both Pedersen and Poseidon during migration
 *   3. Track per-circuit migration status
 *   4. Deprecate Pedersen verifiers after migration period
 *   5. Nullifier-safe: nullifiers are hash-based (already quantum-safe)
 *
 * POSEIDON COMMITMENT:
 *   C = Poseidon(value, blinding_factor, domain_separator)
 *   Binding: Poseidon collision resistance
 *   Hiding: Blinding factor prevents value recovery
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PoseidonCommitmentManager is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MIGRATION_ADMIN_ROLE =
        keccak256("MIGRATION_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator for Poseidon commitments
    bytes32 public constant POSEIDON_DOMAIN =
        keccak256("ZASEON_POSEIDON_COMMITMENT_V1");

    /// @notice Domain separator for Pedersen commitments
    bytes32 public constant PEDERSEN_DOMAIN =
        keccak256("ZASEON_PEDERSEN_COMMITMENT_V1");

    /// @notice Default migration sunset period
    uint256 public constant DEFAULT_SUNSET_PERIOD = 90 days;

    /// @notice Maximum circuits in a single batch migration
    uint256 public constant MAX_BATCH_SIZE = 20;

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Commitment scheme type
    enum CommitmentScheme {
        PEDERSEN, // Classical EC-based (v·H + r·G)
        POSEIDON, // Algebraic hash-based (quantum-resistant)
        HYBRID // Accept both during migration
    }

    /// @notice Circuit migration state
    enum CircuitMigrationState {
        PEDERSEN_ONLY, // Only Pedersen commitments accepted
        DUAL_ACCEPTANCE, // Both Pedersen and Poseidon accepted
        POSEIDON_PRIMARY, // Poseidon primary, Pedersen still accepted
        POSEIDON_ONLY, // Only Poseidon commitments accepted
        COMPLETE // Migration finalized
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit registration for commitment migration
    struct CircuitConfig {
        bytes32 circuitId; // Circuit identifier
        string circuitName; // Human-readable name (e.g., "balance_proof")
        address pedersenVerifier; // Existing Pedersen verifier
        address poseidonVerifier; // New Poseidon verifier
        CircuitMigrationState state; // Current migration state
        uint256 migrationStartedAt; // Migration start timestamp
        uint256 pedersenSunsetAt; // Pedersen deprecation timestamp
        uint256 totalPedersenCommits; // Count of Pedersen commitments verified
        uint256 totalPoseidonCommits; // Count of Poseidon commitments verified
        bool active;
    }

    /// @notice Commitment verification request
    struct CommitmentVerification {
        bytes32 commitment; // The commitment value
        bytes proof; // ZK proof of commitment correctness
        bytes publicInputs; // Public inputs for verification
        CommitmentScheme scheme; // Which scheme was used
    }

    /// @notice Migration statistics for reporting
    struct MigrationReport {
        uint256 totalCircuits;
        uint256 fullyMigrated;
        uint256 inDualMode;
        uint256 notStarted;
        uint256 overallPoseidonRate; // basis points
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit configurations
    mapping(bytes32 => CircuitConfig) public circuits;

    /// @notice List of all circuit IDs
    bytes32[] public circuitIds;

    /// @notice Verified commitment hashes
    mapping(bytes32 => bool) public verifiedCommitments;

    /// @notice Commitment scheme used per commitment hash (for audit)
    mapping(bytes32 => CommitmentScheme) public commitmentSchemes;

    /// @notice Total commitments verified across all circuits
    uint256 public totalCommitmentsVerified;

    /// @notice Total Poseidon commitments verified
    uint256 public totalPoseidonVerified;

    /// @notice Total Pedersen commitments verified
    uint256 public totalPedersenVerified;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event CircuitRegistered(
        bytes32 indexed circuitId,
        string circuitName,
        address pedersenVerifier
    );

    event PoseidonVerifierRegistered(
        bytes32 indexed circuitId,
        address poseidonVerifier,
        uint256 sunsetTimestamp
    );

    event CommitmentVerified(
        bytes32 indexed circuitId,
        bytes32 indexed commitmentHash,
        CommitmentScheme scheme,
        bool valid
    );

    event CircuitMigrationAdvanced(
        bytes32 indexed circuitId,
        CircuitMigrationState oldState,
        CircuitMigrationState newState
    );

    event CircuitMigrationCompleted(
        bytes32 indexed circuitId,
        uint256 totalPoseidonCommits,
        uint256 timestamp
    );

    event BatchMigrationAdvanced(
        uint256 circuitsAdvanced,
        CircuitMigrationState newState
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error CircuitNotFound(bytes32 circuitId);
    error CircuitAlreadyExists(bytes32 circuitId);
    error InvalidMigrationTransition(
        CircuitMigrationState current,
        CircuitMigrationState target
    );
    error CommitmentSchemeNotAccepted(
        bytes32 circuitId,
        CommitmentScheme scheme
    );
    error SunsetNotReached(bytes32 circuitId);
    error VerifierCallFailed();
    error BatchTooLarge(uint256 size);

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(MIGRATION_ADMIN_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                     CIRCUIT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a circuit with its existing Pedersen verifier
     */
    function registerCircuit(
        bytes32 circuitId,
        string calldata circuitName,
        address pedersenVerifier
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        if (circuits[circuitId].active) revert CircuitAlreadyExists(circuitId);
        if (pedersenVerifier == address(0)) revert ZeroAddress();

        circuits[circuitId] = CircuitConfig({
            circuitId: circuitId,
            circuitName: circuitName,
            pedersenVerifier: pedersenVerifier,
            poseidonVerifier: address(0),
            state: CircuitMigrationState.PEDERSEN_ONLY,
            migrationStartedAt: 0,
            pedersenSunsetAt: 0,
            totalPedersenCommits: 0,
            totalPoseidonCommits: 0,
            active: true
        });

        circuitIds.push(circuitId);

        emit CircuitRegistered(circuitId, circuitName, pedersenVerifier);
    }

    /**
     * @notice Register a Poseidon verifier and enter dual-acceptance mode
     */
    function registerPoseidonVerifier(
        bytes32 circuitId,
        address poseidonVerifier,
        uint256 sunsetDuration
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        CircuitConfig storage circuit = circuits[circuitId];
        if (!circuit.active) revert CircuitNotFound(circuitId);
        if (poseidonVerifier == address(0)) revert ZeroAddress();

        circuit.poseidonVerifier = poseidonVerifier;
        circuit.migrationStartedAt = block.timestamp;
        circuit.pedersenSunsetAt =
            block.timestamp +
            (sunsetDuration > 0 ? sunsetDuration : DEFAULT_SUNSET_PERIOD);

        CircuitMigrationState oldState = circuit.state;
        circuit.state = CircuitMigrationState.DUAL_ACCEPTANCE;

        emit PoseidonVerifierRegistered(
            circuitId,
            poseidonVerifier,
            circuit.pedersenSunsetAt
        );

        emit CircuitMigrationAdvanced(
            circuitId,
            oldState,
            CircuitMigrationState.DUAL_ACCEPTANCE
        );
    }

    /*//////////////////////////////////////////////////////////////
                   COMMITMENT VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a commitment using the appropriate scheme
     * @param circuitId The circuit this commitment belongs to
     * @param commitment The commitment hash
     * @param proof ZK proof of commitment validity
     * @param publicInputs Public inputs for the verifier
     * @param scheme Which commitment scheme was used
     * @return valid Whether the commitment verified
     */
    function verifyCommitment(
        bytes32 circuitId,
        bytes32 commitment,
        bytes calldata proof,
        bytes calldata publicInputs,
        CommitmentScheme scheme
    ) external nonReentrant whenNotPaused returns (bool valid) {
        CircuitConfig storage circuit = circuits[circuitId];
        if (!circuit.active) revert CircuitNotFound(circuitId);

        // Check if the scheme is accepted in current state
        if (!_isSchemeAccepted(circuit.state, scheme))
            revert CommitmentSchemeNotAccepted(circuitId, scheme);

        // Route to appropriate verifier
        address verifier;
        if (scheme == CommitmentScheme.PEDERSEN) {
            verifier = circuit.pedersenVerifier;
        } else if (scheme == CommitmentScheme.POSEIDON) {
            verifier = circuit.poseidonVerifier;
        } else {
            // HYBRID: try Poseidon first, then Pedersen
            verifier = circuit.poseidonVerifier != address(0)
                ? circuit.poseidonVerifier
                : circuit.pedersenVerifier;
        }

        if (verifier == address(0)) revert VerifierCallFailed();

        // Call verifier
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, publicInputs)
        );

        if (!success || result.length < 32) {
            emit CommitmentVerified(circuitId, commitment, scheme, false);
            return false;
        }

        valid = abi.decode(result, (bool));

        if (valid) {
            bytes32 commitKey = keccak256(
                abi.encodePacked(POSEIDON_DOMAIN, circuitId, commitment, scheme)
            );
            verifiedCommitments[commitKey] = true;
            commitmentSchemes[commitKey] = scheme;
            totalCommitmentsVerified++;

            if (
                scheme == CommitmentScheme.POSEIDON ||
                scheme == CommitmentScheme.HYBRID
            ) {
                circuit.totalPoseidonCommits++;
                totalPoseidonVerified++;
            } else {
                circuit.totalPedersenCommits++;
                totalPedersenVerified++;
            }
        }

        emit CommitmentVerified(circuitId, commitment, scheme, valid);
    }

    /**
     * @notice Check if a commitment has been verified
     */
    function isCommitmentVerified(
        bytes32 circuitId,
        bytes32 commitment,
        CommitmentScheme scheme
    ) external view returns (bool) {
        bytes32 commitKey = keccak256(
            abi.encodePacked(POSEIDON_DOMAIN, circuitId, commitment, scheme)
        );
        return verifiedCommitments[commitKey];
    }

    /*//////////////////////////////////////////////////////////////
                     MIGRATION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Advance to POSEIDON_PRIMARY state
     */
    function advanceToPoseidonPrimary(
        bytes32 circuitId
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        CircuitConfig storage circuit = circuits[circuitId];
        if (!circuit.active) revert CircuitNotFound(circuitId);

        if (circuit.state != CircuitMigrationState.DUAL_ACCEPTANCE)
            revert InvalidMigrationTransition(
                circuit.state,
                CircuitMigrationState.POSEIDON_PRIMARY
            );

        CircuitMigrationState oldState = circuit.state;
        circuit.state = CircuitMigrationState.POSEIDON_PRIMARY;

        emit CircuitMigrationAdvanced(
            circuitId,
            oldState,
            CircuitMigrationState.POSEIDON_PRIMARY
        );
    }

    /**
     * @notice Advance to POSEIDON_ONLY (deprecate Pedersen)
     */
    function advanceToPoseidonOnly(
        bytes32 circuitId
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        CircuitConfig storage circuit = circuits[circuitId];
        if (!circuit.active) revert CircuitNotFound(circuitId);

        if (circuit.state != CircuitMigrationState.POSEIDON_PRIMARY)
            revert InvalidMigrationTransition(
                circuit.state,
                CircuitMigrationState.POSEIDON_ONLY
            );

        CircuitMigrationState oldState = circuit.state;
        circuit.state = CircuitMigrationState.POSEIDON_ONLY;

        emit CircuitMigrationAdvanced(
            circuitId,
            oldState,
            CircuitMigrationState.POSEIDON_ONLY
        );
    }

    /**
     * @notice Complete migration and finalize
     */
    function completeMigration(
        bytes32 circuitId
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        CircuitConfig storage circuit = circuits[circuitId];
        if (!circuit.active) revert CircuitNotFound(circuitId);

        if (circuit.state != CircuitMigrationState.POSEIDON_ONLY)
            revert InvalidMigrationTransition(
                circuit.state,
                CircuitMigrationState.COMPLETE
            );

        if (block.timestamp < circuit.pedersenSunsetAt)
            revert SunsetNotReached(circuitId);

        CircuitMigrationState oldState = circuit.state;
        circuit.state = CircuitMigrationState.COMPLETE;
        circuit.pedersenVerifier = address(0);

        emit CircuitMigrationAdvanced(
            circuitId,
            oldState,
            CircuitMigrationState.COMPLETE
        );

        emit CircuitMigrationCompleted(
            circuitId,
            circuit.totalPoseidonCommits,
            block.timestamp
        );
    }

    /**
     * @notice Batch advance all eligible circuits to the next state
     */
    function batchAdvance(
        bytes32[] calldata targetCircuitIds,
        CircuitMigrationState targetState
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        if (targetCircuitIds.length > MAX_BATCH_SIZE)
            revert BatchTooLarge(targetCircuitIds.length);

        uint256 advanced = 0;

        for (uint256 i = 0; i < targetCircuitIds.length; ) {
            CircuitConfig storage circuit = circuits[targetCircuitIds[i]];

            if (
                circuit.active && _isValidTransition(circuit.state, targetState)
            ) {
                CircuitMigrationState oldState = circuit.state;
                circuit.state = targetState;

                if (targetState == CircuitMigrationState.COMPLETE) {
                    circuit.pedersenVerifier = address(0);
                }

                emit CircuitMigrationAdvanced(
                    targetCircuitIds[i],
                    oldState,
                    targetState
                );

                advanced++;
            }

            unchecked {
                ++i;
            }
        }

        emit BatchMigrationAdvanced(advanced, targetState);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get migration report across all circuits
     */
    function getMigrationReport()
        external
        view
        returns (MigrationReport memory report)
    {
        report.totalCircuits = circuitIds.length;

        for (uint256 i = 0; i < report.totalCircuits; ) {
            CircuitConfig storage circuit = circuits[circuitIds[i]];

            if (circuit.state == CircuitMigrationState.COMPLETE) {
                report.fullyMigrated++;
            } else if (
                circuit.state == CircuitMigrationState.DUAL_ACCEPTANCE ||
                circuit.state == CircuitMigrationState.POSEIDON_PRIMARY ||
                circuit.state == CircuitMigrationState.POSEIDON_ONLY
            ) {
                report.inDualMode++;
            } else {
                report.notStarted++;
            }

            unchecked {
                ++i;
            }
        }

        report.overallPoseidonRate = totalCommitmentsVerified > 0
            ? (totalPoseidonVerified * 10_000) / totalCommitmentsVerified
            : 0;
    }

    /**
     * @notice Get circuit details
     */
    function getCircuitInfo(
        bytes32 circuitId
    ) external view returns (CircuitConfig memory) {
        return circuits[circuitId];
    }

    /**
     * @notice Get all circuit IDs
     */
    function getAllCircuitIds() external view returns (bytes32[] memory) {
        return circuitIds;
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
     * @dev Check if a commitment scheme is accepted in the current state
     */
    function _isSchemeAccepted(
        CircuitMigrationState state,
        CommitmentScheme scheme
    ) internal pure returns (bool) {
        if (state == CircuitMigrationState.PEDERSEN_ONLY) {
            return scheme == CommitmentScheme.PEDERSEN;
        }

        if (state == CircuitMigrationState.DUAL_ACCEPTANCE) {
            return true; // Accept both
        }

        if (state == CircuitMigrationState.POSEIDON_PRIMARY) {
            return true; // Accept both, prefer Poseidon
        }

        if (
            state == CircuitMigrationState.POSEIDON_ONLY ||
            state == CircuitMigrationState.COMPLETE
        ) {
            return
                scheme == CommitmentScheme.POSEIDON ||
                scheme == CommitmentScheme.HYBRID;
        }

        return false;
    }

    /**
     * @dev Validate a state transition
     */
    function _isValidTransition(
        CircuitMigrationState from,
        CircuitMigrationState to
    ) internal pure returns (bool) {
        if (
            from == CircuitMigrationState.PEDERSEN_ONLY &&
            to == CircuitMigrationState.DUAL_ACCEPTANCE
        ) return true;
        if (
            from == CircuitMigrationState.DUAL_ACCEPTANCE &&
            to == CircuitMigrationState.POSEIDON_PRIMARY
        ) return true;
        if (
            from == CircuitMigrationState.POSEIDON_PRIMARY &&
            to == CircuitMigrationState.POSEIDON_ONLY
        ) return true;
        if (
            from == CircuitMigrationState.POSEIDON_ONLY &&
            to == CircuitMigrationState.COMPLETE
        ) return true;
        return false;
    }
}
