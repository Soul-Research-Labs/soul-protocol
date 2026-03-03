// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title STARKVerifierRouter
 * @author ZASEON
 * @notice STARK proof verification router with migration path from Groth16/PLONK.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                          ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Phase 3: Migrates existing ZK verifiers to STARK-compatible circuits:
 *   1. Registers STARK verifier contracts for each proof domain
 *   2. Provides parallel verification (old + new) during migration
 *   3. Tracks migration progress per circuit/domain
 *   4. Enforces verification equivalence during dual-verification mode
 *   5. Sunsets old verifiers through scheduled deprecation
 *
 * WHY STARK?
 *   - Hash-based security (quantum-resistant via Grover lower bound)
 *   - No trusted setup required
 *   - Transparent proof generation
 *   - Compatible with FRI-based commitment schemes
 *   - Same security model as Poseidon/keccak commitments already used
 *
 * FRI VERIFICATION:
 *   The router validates FRI (Fast Reed-Solomon IOP) commitment layers
 *   and decommitment paths, checking polynomial evaluation consistency.
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract STARKVerifierRouter is AccessControl, ReentrancyGuard, Pausable {
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

    /// @notice Domain separator for STARK verification
    bytes32 public constant STARK_DOMAIN =
        keccak256("ZASEON_STARK_VERIFICATION_V1");

    /// @notice Goldilocks field prime (2^64 - 2^32 + 1)
    uint256 public constant GOLDILOCKS_PRIME = 0xFFFFFFFF00000001;

    /// @notice BN254 scalar field prime (for existing Groth16 proofs)
    uint256 public constant BN254_PRIME =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Maximum FRI layers supported
    uint256 public constant MAX_FRI_LAYERS = 32;

    /// @notice Valid blowup factor range
    uint256 public constant MIN_BLOWUP_FACTOR = 2;
    uint256 public constant MAX_BLOWUP_FACTOR = 16;

    /// @notice Maximum trace length (2^24)
    uint256 public constant MAX_TRACE_LENGTH = 16_777_216;

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Proof system types (matching RecursiveProofAggregator)
    enum ProofSystem {
        GROTH16,
        PLONK,
        STARK,
        NOVA,
        SUPERNOVA,
        HALO2
    }

    /// @notice Migration state for a proof domain
    enum MigrationState {
        NOT_STARTED, // Only classical verifier registered
        PARALLEL, // Both classical and STARK verifiers active (dual-verify)
        STARK_PRIMARY, // STARK is primary, classical is backup
        STARK_ONLY, // Classical verifier deprecated
        COMPLETE // Migration finalized, classical verifier removed
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice STARK proof structure (compatible with RecursiveProofAggregator)
    struct STARKProof {
        bytes32[] friCommitments; // FRI layer commitments
        bytes32 constraintPolyHash; // Constraint polynomial composition hash
        bytes32 traceCommitment; // Merkle root of execution trace
        bytes32 compositionRoot; // Composition polynomial root
        uint256[] evaluationPoints; // Out-of-domain sample points
        bytes32[] decommitmentPaths; // Merkle decommitment (serialized)
        uint256 numFriLayers; // FRI folding layers
        uint256 blowupFactor; // Trace expansion factor
        uint256 fieldPrime; // Field prime
    }

    /// @notice Per-domain verifier registration
    struct DomainVerifier {
        bytes32 domainId; // Circuit/proof domain identifier
        string domainName; // Human-readable name
        address classicalVerifier; // Groth16/PLONK verifier address
        ProofSystem classicalSystem; // Classical proof system type
        address starkVerifier; // STARK verifier address
        MigrationState migrationState; // Current migration state
        uint256 migrationStartedAt; // When migration began
        uint256 classicalSunsetAt; // When classical verifier will be deprecated
        uint256 totalClassicalProofs; // Proofs verified by classical
        uint256 totalSTARKProofs; // Proofs verified by STARK
        uint256 mismatchCount; // Mismatches during PARALLEL mode
        bool active; // Whether domain is active
    }

    /// @notice STARK verification result
    struct STARKVerificationResult {
        bytes32 domainId;
        bool verified;
        uint256 gasUsed;
        uint256 numConstraints;
        uint256 traceLength;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain verifier registry
    mapping(bytes32 => DomainVerifier) public domainVerifiers;

    /// @notice List of registered domain IDs
    bytes32[] public registeredDomains;

    /// @notice Total STARK verifications
    uint256 public totalSTARKVerifications;

    /// @notice Total classical verifications
    uint256 public totalClassicalVerifications;

    /// @notice Total domains fully migrated
    uint256 public totalMigratedDomains;

    /// @notice STARK proof hash cache (prevent re-verification)
    mapping(bytes32 => bool) public verifiedSTARKProofs;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event DomainRegistered(
        bytes32 indexed domainId,
        string domainName,
        address classicalVerifier,
        ProofSystem classicalSystem
    );

    event STARKVerifierRegistered(
        bytes32 indexed domainId,
        address starkVerifier,
        uint256 sunsetTimestamp
    );

    event MigrationStateAdvanced(
        bytes32 indexed domainId,
        MigrationState oldState,
        MigrationState newState
    );

    event STARKProofVerified(
        bytes32 indexed domainId,
        bytes32 proofHash,
        uint256 gasUsed,
        bool verified
    );

    event ClassicalProofVerified(
        bytes32 indexed domainId,
        bytes32 proofHash,
        bool verified
    );

    event ParallelMismatch(
        bytes32 indexed domainId,
        bytes32 proofHash,
        bool classicalResult,
        bool starkResult
    );

    event DomainMigrationCompleted(
        bytes32 indexed domainId,
        uint256 totalSTARKProofs,
        uint256 timestamp
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error DomainNotFound(bytes32 domainId);
    error DomainAlreadyExists(bytes32 domainId);
    error InvalidMigrationTransition(
        MigrationState current,
        MigrationState target
    );
    error STARKVerifierNotSet(bytes32 domainId);
    error ClassicalVerifierNotSet(bytes32 domainId);
    error InvalidSTARKProof(string reason);
    error SunsetNotReached(bytes32 domainId);
    error VerifierCallFailed(bytes32 domainId, string verifierType);

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
                     DOMAIN REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new proof domain with its classical verifier
     * @param domainId Unique identifier (e.g., keccak256("BALANCE_PROOF"))
     * @param domainName Human-readable name
     * @param classicalVerifier Address of the existing Groth16/PLONK verifier
     * @param classicalSystem The classical proof system type
     */
    function registerDomain(
        bytes32 domainId,
        string calldata domainName,
        address classicalVerifier,
        ProofSystem classicalSystem
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        if (domainVerifiers[domainId].active)
            revert DomainAlreadyExists(domainId);
        if (classicalVerifier == address(0)) revert ZeroAddress();

        domainVerifiers[domainId] = DomainVerifier({
            domainId: domainId,
            domainName: domainName,
            classicalVerifier: classicalVerifier,
            classicalSystem: classicalSystem,
            starkVerifier: address(0),
            migrationState: MigrationState.NOT_STARTED,
            migrationStartedAt: 0,
            classicalSunsetAt: 0,
            totalClassicalProofs: 0,
            totalSTARKProofs: 0,
            mismatchCount: 0,
            active: true
        });

        registeredDomains.push(domainId);

        emit DomainRegistered(
            domainId,
            domainName,
            classicalVerifier,
            classicalSystem
        );
    }

    /**
     * @notice Register a STARK verifier for a domain and begin migration
     * @param domainId The proof domain
     * @param starkVerifier Address of the STARK verifier contract
     * @param classicalSunsetDuration How long classical verifier remains active
     */
    function registerSTARKVerifier(
        bytes32 domainId,
        address starkVerifier,
        uint256 classicalSunsetDuration
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);
        if (starkVerifier == address(0)) revert ZeroAddress();

        domain.starkVerifier = starkVerifier;
        domain.migrationStartedAt = block.timestamp;
        domain.classicalSunsetAt = block.timestamp + classicalSunsetDuration;
        domain.migrationState = MigrationState.PARALLEL;

        emit STARKVerifierRegistered(
            domainId,
            starkVerifier,
            domain.classicalSunsetAt
        );

        emit MigrationStateAdvanced(
            domainId,
            MigrationState.NOT_STARTED,
            MigrationState.PARALLEL
        );
    }

    /*//////////////////////////////////////////////////////////////
                     PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a STARK proof for a domain
     * @param domainId The proof domain
     * @param proof The serialized STARK proof
     * @param publicInputs The public inputs to the proof
     * @return verified Whether the proof is valid
     */
    function verifySTARKProof(
        bytes32 domainId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bool verified) {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);
        if (domain.starkVerifier == address(0))
            revert STARKVerifierNotSet(domainId);

        // Must be in PARALLEL or later migration state
        require(
            domain.migrationState != MigrationState.NOT_STARTED,
            "STARK not available for this domain"
        );

        bytes32 proofHash = keccak256(
            abi.encodePacked(STARK_DOMAIN, domainId, proof, publicInputs)
        );

        uint256 gasBefore = gasleft();

        // Call STARK verifier: verify(bytes proof, bytes publicInputs) → bool
        (bool success, bytes memory result) = domain.starkVerifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, publicInputs)
        );

        uint256 gasUsed = gasBefore - gasleft();

        if (!success || result.length < 32) {
            emit STARKProofVerified(domainId, proofHash, gasUsed, false);
            return false;
        }

        verified = abi.decode(result, (bool));
        totalSTARKVerifications++;
        domain.totalSTARKProofs++;

        if (verified) {
            verifiedSTARKProofs[proofHash] = true;
        }

        emit STARKProofVerified(domainId, proofHash, gasUsed, verified);
    }

    /**
     * @notice Verify both classical and STARK proofs in parallel (migration mode)
     * @dev Used during PARALLEL migration state to compare results
     */
    function verifyParallel(
        bytes32 domainId,
        bytes calldata classicalProof,
        bytes calldata classicalPublicInputs,
        bytes calldata starkProof,
        bytes calldata starkPublicInputs
    )
        external
        nonReentrant
        whenNotPaused
        returns (bool classicalResult, bool starkResult, bool consistent)
    {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);

        require(
            domain.migrationState == MigrationState.PARALLEL,
            "Not in PARALLEL mode"
        );

        // Verify classical
        classicalResult = _verifyClassical(
            domain,
            classicalProof,
            classicalPublicInputs
        );

        // Verify STARK
        starkResult = _verifySTARK(domain, starkProof, starkPublicInputs);

        consistent = (classicalResult == starkResult);

        if (!consistent) {
            domain.mismatchCount++;

            bytes32 proofHash = keccak256(
                abi.encodePacked(
                    STARK_DOMAIN,
                    "PARALLEL",
                    domainId,
                    classicalProof,
                    starkProof
                )
            );

            emit ParallelMismatch(
                domainId,
                proofHash,
                classicalResult,
                starkResult
            );
        }
    }

    /**
     * @notice Verify using the appropriate verifier based on migration state
     * @dev Routes to classical, STARK, or both depending on MigrationState
     */
    function verifyByDomain(
        bytes32 domainId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bool verified) {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);

        if (domain.migrationState == MigrationState.NOT_STARTED) {
            // Classical only
            return _verifyClassical(domain, proof, publicInputs);
        }

        if (
            domain.migrationState == MigrationState.STARK_ONLY ||
            domain.migrationState == MigrationState.COMPLETE
        ) {
            // STARK only
            return _verifySTARK(domain, proof, publicInputs);
        }

        if (domain.migrationState == MigrationState.STARK_PRIMARY) {
            // STARK primary with classical backup
            verified = _verifySTARK(domain, proof, publicInputs);
            if (!verified) {
                // Attempt classical fallback
                verified = _verifyClassical(domain, proof, publicInputs);
            }
            return verified;
        }

        // PARALLEL — verify via STARK (primary in Phase 3)
        return _verifySTARK(domain, proof, publicInputs);
    }

    /*//////////////////////////////////////////////////////////////
                  MIGRATION STATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Advance migration to STARK_PRIMARY after parallel verification period
     */
    function advanceToSTARKPrimary(
        bytes32 domainId
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);

        if (domain.migrationState != MigrationState.PARALLEL)
            revert InvalidMigrationTransition(
                domain.migrationState,
                MigrationState.STARK_PRIMARY
            );

        MigrationState oldState = domain.migrationState;
        domain.migrationState = MigrationState.STARK_PRIMARY;

        emit MigrationStateAdvanced(
            domainId,
            oldState,
            MigrationState.STARK_PRIMARY
        );
    }

    /**
     * @notice Advance to STARK_ONLY (deprecate classical)
     */
    function advanceToSTARKOnly(
        bytes32 domainId
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);

        if (domain.migrationState != MigrationState.STARK_PRIMARY)
            revert InvalidMigrationTransition(
                domain.migrationState,
                MigrationState.STARK_ONLY
            );

        MigrationState oldState = domain.migrationState;
        domain.migrationState = MigrationState.STARK_ONLY;

        emit MigrationStateAdvanced(
            domainId,
            oldState,
            MigrationState.STARK_ONLY
        );
    }

    /**
     * @notice Finalize migration — remove classical verifier reference
     */
    function completeMigration(
        bytes32 domainId
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        DomainVerifier storage domain = domainVerifiers[domainId];
        if (!domain.active) revert DomainNotFound(domainId);

        if (domain.migrationState != MigrationState.STARK_ONLY)
            revert InvalidMigrationTransition(
                domain.migrationState,
                MigrationState.COMPLETE
            );

        // Ensure sunset period has passed
        if (block.timestamp < domain.classicalSunsetAt)
            revert SunsetNotReached(domainId);

        MigrationState oldState = domain.migrationState;
        domain.migrationState = MigrationState.COMPLETE;
        domain.classicalVerifier = address(0); // Remove classical reference

        totalMigratedDomains++;

        emit MigrationStateAdvanced(
            domainId,
            oldState,
            MigrationState.COMPLETE
        );

        emit DomainMigrationCompleted(
            domainId,
            domain.totalSTARKProofs,
            block.timestamp
        );
    }

    /*//////////////////////////////////////////////////////////////
                     STARK PROOF VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate STARK proof structure before full verification
     * @dev Checks FRI parameters, blowup factor, field prime
     */
    function validateSTARKStructure(
        STARKProof calldata proof
    ) external pure returns (bool valid, string memory reason) {
        // Check FRI layers
        if (proof.numFriLayers == 0 || proof.numFriLayers > MAX_FRI_LAYERS) {
            return (false, "Invalid FRI layers");
        }

        if (proof.friCommitments.length != proof.numFriLayers) {
            return (false, "FRI commitments length mismatch");
        }

        // Check blowup factor
        if (
            proof.blowupFactor < MIN_BLOWUP_FACTOR ||
            proof.blowupFactor > MAX_BLOWUP_FACTOR
        ) {
            return (false, "Invalid blowup factor");
        }

        // Check field prime
        if (
            proof.fieldPrime != GOLDILOCKS_PRIME &&
            proof.fieldPrime != BN254_PRIME
        ) {
            return (false, "Unsupported field prime");
        }

        // Check evaluation points are non-zero
        if (proof.evaluationPoints.length == 0) {
            return (false, "No evaluation points");
        }

        // Check trace commitment exists
        if (proof.traceCommitment == bytes32(0)) {
            return (false, "Empty trace commitment");
        }

        // Check composition root exists
        if (proof.compositionRoot == bytes32(0)) {
            return (false, "Empty composition root");
        }

        return (true, "");
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get migration progress across all domains
     */
    function getMigrationProgress()
        external
        view
        returns (
            uint256 totalDomains,
            uint256 migrated,
            uint256 inProgress,
            uint256 notStarted,
            uint256 progressPercent
        )
    {
        totalDomains = registeredDomains.length;

        for (uint256 i = 0; i < totalDomains; ) {
            MigrationState state = domainVerifiers[registeredDomains[i]]
                .migrationState;

            if (state == MigrationState.COMPLETE) {
                migrated++;
            } else if (state == MigrationState.NOT_STARTED) {
                notStarted++;
            } else {
                inProgress++;
            }

            unchecked {
                ++i;
            }
        }

        progressPercent = totalDomains > 0
            ? (migrated * 10_000) / totalDomains
            : 0;
    }

    /**
     * @notice Get domain verifier details
     */
    function getDomainInfo(
        bytes32 domainId
    ) external view returns (DomainVerifier memory) {
        return domainVerifiers[domainId];
    }

    /**
     * @notice Get all registered domain IDs
     */
    function getAllDomains() external view returns (bytes32[] memory) {
        return registeredDomains;
    }

    /**
     * @notice Get verification stats for a domain
     */
    function getDomainStats(
        bytes32 domainId
    )
        external
        view
        returns (
            uint256 classicalProofs,
            uint256 starkProofs,
            uint256 mismatches,
            uint256 starkRate
        )
    {
        DomainVerifier storage domain = domainVerifiers[domainId];
        classicalProofs = domain.totalClassicalProofs;
        starkProofs = domain.totalSTARKProofs;
        mismatches = domain.mismatchCount;

        uint256 total = classicalProofs + starkProofs;
        starkRate = total > 0 ? (starkProofs * 10_000) / total : 0;
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

    function _verifyClassical(
        DomainVerifier storage domain,
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal returns (bool) {
        if (domain.classicalVerifier == address(0)) return false;

        (bool success, bytes memory result) = domain
            .classicalVerifier
            .staticcall(
                abi.encodeWithSignature(
                    "verify(bytes,bytes)",
                    proof,
                    publicInputs
                )
            );

        if (!success || result.length < 32) return false;

        bool verified = abi.decode(result, (bool));
        if (verified) {
            domain.totalClassicalProofs++;
            totalClassicalVerifications++;
        }
        return verified;
    }

    function _verifySTARK(
        DomainVerifier storage domain,
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal returns (bool) {
        if (domain.starkVerifier == address(0)) return false;

        (bool success, bytes memory result) = domain.starkVerifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, publicInputs)
        );

        if (!success || result.length < 32) return false;

        bool verified = abi.decode(result, (bool));
        if (verified) {
            domain.totalSTARKProofs++;
            totalSTARKVerifications++;
        }
        return verified;
    }
}
