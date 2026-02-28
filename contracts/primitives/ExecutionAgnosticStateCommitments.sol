// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IProofVerifier.sol";

/// @title ExecutionAgnosticStateCommitments (EASC)
/// @author ZASEON - Zaseon v2
/// @notice State commitments independent of execution environment
/// @dev MVP Implementation - Decouples what happened from how it happened
///
/// Key Properties:
/// - Same commitment is valid across zkVM, TEE backends
/// - Execution backend proves conformance, not ownership
/// - Enables backend switching without re-trusting
/// - Strong mitigation against TEE compromise
///
/// Security Considerations:
/// - Trust scores enable gradual trust adjustment
/// - Multi-attestation prevents single backend compromise
/// - Nullifiers prevent double-consumption
/// - Backend deactivation isolates compromised backends
/**
 * @title ExecutionAgnosticStateCommitments
 * @author ZASEON Team
 * @notice Execution Agnostic State Commitments contract
 */
contract ExecutionAgnosticStateCommitments is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("BACKEND_ADMIN_ROLE")
    bytes32 public constant BACKEND_ADMIN_ROLE =
        0x725cc3989e149a767397970d298615c4843c213a88534e17f727f3ad663e6a6f;
    /// @dev keccak256("COMMITMENT_REGISTRAR_ROLE")
    bytes32 public constant COMMITMENT_REGISTRAR_ROLE =
        0x151a2cff15004c51e0b392e3be007c921d4a445972a9b55ce8e34937e0cb1591;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Execution backend types
    enum BackendType {
        ZkVM, // Zero-knowledge virtual machine (e.g., SP1, RISC Zero)
        TEE, // Trusted Execution Environment (e.g., SGX, TDX)
        Native // Native chain execution (baseline)
    }

    /// @notice Backend registration
    struct ExecutionBackend {
        bytes32 backendId;
        BackendType backendType;
        string name;
        bytes32 attestationKey; // Key for verifying backend attestations
        bytes32 configHash; // Hash of backend configuration
        uint64 registeredAt;
        uint64 lastAttestation;
        bool isActive;
        uint256 trustScore; // 0-10000 (basis points)
    }

    /// @notice Execution-agnostic state commitment
    struct AgnosticCommitment {
        bytes32 commitmentId;
        bytes32 stateHash; // Hash of the state (backend-independent)
        bytes32 transitionHash; // Hash of the state transition
        bytes32 nullifier; // Unique nullifier
        // Backend attestations
        bytes32[] attestedBackends; // Backends that have attested this commitment
        mapping(bytes32 => BackendAttestation) attestations;
        // Metadata
        address creator;
        uint64 createdAt;
        uint32 attestationCount;
        bool isFinalized;
    }

    /// @notice Backend attestation for a commitment
    struct BackendAttestation {
        bytes32 backendId;
        BackendType backendType;
        bytes attestationProof; // Proof from the backend
        bytes32 executionHash; // Hash of execution trace
        uint64 attestedAt;
        bool isValid;
    }

    /// @notice Commitment query result (for external view)
    struct CommitmentView {
        bytes32 commitmentId;
        bytes32 stateHash;
        bytes32 transitionHash;
        bytes32 nullifier;
        bytes32[] attestedBackends;
        address creator;
        uint64 createdAt;
        uint32 attestationCount;
        bool isFinalized;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of backend ID to backend
    mapping(bytes32 => ExecutionBackend) public backends;

    /// @notice Mapping of commitment ID to commitment
    mapping(bytes32 => AgnosticCommitment) internal _commitments;

    /// @notice Mapping of state hash to commitment ID
    mapping(bytes32 => bytes32) public stateHashToCommitment;

    /// @notice Mapping of nullifier to used status
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Backend IDs by type
    mapping(BackendType => bytes32[]) public backendsByType;

    /// @notice Required attestation count for finalization
    uint256 public requiredAttestations = 1;

    /// @notice Minimum trust score for valid attestation
    uint256 public minTrustScore = 5000; // 50%

    /// @notice Maximum trust score
    uint256 public constant MAX_TRUST_SCORE = 10000;

    /// @notice Maximum backends per commitment (prevent DOS)
    uint256 public constant MAX_ATTESTATIONS_PER_COMMITMENT = 10;

    /// @notice Total backends registered
    uint256 public totalBackends;

    /// @notice Total commitments
    uint256 public totalCommitments;

    /// @notice ZK verifier for attestation proofs
    IProofVerifier public attestationVerifier;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BackendRegistered(
        bytes32 indexed backendId,
        BackendType indexed backendType,
        string name
    );

    event BackendUpdated(
        bytes32 indexed backendId,
        uint256 newTrustScore,
        bool isActive
    );

    event CommitmentCreated(
        bytes32 indexed commitmentId,
        bytes32 indexed stateHash,
        bytes32 nullifier,
        address indexed creator
    );

    event CommitmentAttested(
        bytes32 indexed commitmentId,
        bytes32 indexed backendId,
        BackendType backendType
    );

    event CommitmentFinalized(
        bytes32 indexed commitmentId,
        uint32 attestationCount
    );

    event CommitmentConsumed(
        bytes32 indexed commitmentId,
        bytes32 indexed nullifier
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error BackendNotFound(bytes32 backendId);
    error BackendAlreadyExists(bytes32 backendId);
    error BackendInactive(bytes32 backendId);
    error BackendTrustTooLow(bytes32 backendId, uint256 trustScore);
    error CommitmentNotFound(bytes32 commitmentId);
    error CommitmentAlreadyExists(bytes32 commitmentId);
    error CommitmentAlreadyFinalized(bytes32 commitmentId);
    error CommitmentNotFinalized(bytes32 commitmentId);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error AlreadyAttested(bytes32 commitmentId, bytes32 backendId);
    error InvalidAttestationProof();
    error InsufficientAttestations(uint32 have, uint256 need);
    error TooManyAttestations(uint32 count, uint256 max);
    error ZeroStateHash();
    error ZeroNullifier();
    error InvalidTrustScore(uint256 score);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BACKEND_ADMIN_ROLE, msg.sender);
        _grantRole(COMMITMENT_REGISTRAR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          BACKEND MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a new execution backend
    /// @param backendType The type of backend
    /// @param name Human-readable name
    /// @param attestationKey Key for verifying attestations
    /// @param configHash Hash of backend configuration
    /// @return backendId The unique backend identifier
        /**
     * @notice Registers backend
     * @param backendType The backend type
     * @param name The name
     * @param attestationKey The attestation key
     * @param configHash The configHash hash value
     * @return backendId The backend id
     */
function registerBackend(
        BackendType backendType,
        string calldata name,
        bytes32 attestationKey,
        bytes32 configHash
    ) external onlyRole(BACKEND_ADMIN_ROLE) returns (bytes32 backendId) {
        backendId = keccak256(
            abi.encode(backendType, name, attestationKey, block.timestamp)
        );

        if (backends[backendId].registeredAt != 0) {
            revert BackendAlreadyExists(backendId);
        }

        backends[backendId] = ExecutionBackend({
            backendId: backendId,
            backendType: backendType,
            name: name,
            attestationKey: attestationKey,
            configHash: configHash,
            registeredAt: uint64(block.timestamp),
            lastAttestation: 0,
            isActive: true,
            trustScore: MAX_TRUST_SCORE // Start with full trust
        });

        backendsByType[backendType].push(backendId);

        unchecked {
            ++totalBackends;
        }

        emit BackendRegistered(backendId, backendType, name);
    }

    /// @notice Update backend trust score
    /// @param backendId The backend to update
    /// @param trustScore New trust score (0-10000)
        /**
     * @notice Updates backend trust
     * @param backendId The backendId identifier
     * @param trustScore The trust score
     */
function updateBackendTrust(
        bytes32 backendId,
        uint256 trustScore
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        ExecutionBackend storage backend = backends[backendId];
        if (backend.registeredAt == 0) {
            revert BackendNotFound(backendId);
        }

        // Clamp to max
        uint256 clampedScore = trustScore > MAX_TRUST_SCORE
            ? MAX_TRUST_SCORE
            : trustScore;
        backend.trustScore = clampedScore;

        emit BackendUpdated(backendId, clampedScore, backend.isActive);
    }

    /// @notice Deactivate a backend
    /// @param backendId The backend to deactivate
        /**
     * @notice Deactivate backend
     * @param backendId The backendId identifier
     */
function deactivateBackend(
        bytes32 backendId
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        if (backends[backendId].registeredAt == 0) {
            revert BackendNotFound(backendId);
        }

        backends[backendId].isActive = false;
        emit BackendUpdated(backendId, backends[backendId].trustScore, false);
    }

    /*//////////////////////////////////////////////////////////////
                       COMMITMENT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a new execution-agnostic commitment
    /// @param stateHash Hash of the state
    /// @param transitionHash Hash of the state transition
    /// @param nullifier Unique nullifier
    /// @return commitmentId The unique commitment identifier
        /**
     * @notice Creates commitment
     * @param stateHash The state hash
     * @param transitionHash The transitionHash hash value
     * @param nullifier The nullifier hash
     * @return commitmentId The commitment id
     */
function createCommitment(
        bytes32 stateHash,
        bytes32 transitionHash,
        bytes32 nullifier
    )
        external
        whenNotPaused
        onlyRole(COMMITMENT_REGISTRAR_ROLE)
        returns (bytes32 commitmentId)
    {
        if (stateHash == bytes32(0)) revert ZeroStateHash();
        if (nullifier == bytes32(0)) revert ZeroNullifier();

        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        commitmentId = keccak256(
            abi.encode(stateHash, transitionHash, nullifier)
        );

        if (_commitments[commitmentId].createdAt != 0) {
            revert CommitmentAlreadyExists(commitmentId);
        }

        AgnosticCommitment storage commitment = _commitments[commitmentId];
        commitment.commitmentId = commitmentId;
        commitment.stateHash = stateHash;
        commitment.transitionHash = transitionHash;
        commitment.nullifier = nullifier;
        commitment.creator = msg.sender;
        commitment.createdAt = uint64(block.timestamp);
        commitment.attestationCount = 0;
        commitment.isFinalized = false;

        stateHashToCommitment[stateHash] = commitmentId;

        unchecked {
            ++totalCommitments;
        }

        emit CommitmentCreated(commitmentId, stateHash, nullifier, msg.sender);
    }

    /// @notice Add a backend attestation to a commitment
    /// @param commitmentId The commitment to attest
    /// @param backendId The attesting backend
    /// @param attestationProof Proof from the backend
    /// @param executionHash Hash of execution trace
        /**
     * @notice Attest commitment
     * @param commitmentId The commitmentId identifier
     * @param backendId The backendId identifier
     * @param attestationProof The attestation proof
     * @param executionHash The executionHash hash value
     */
function attestCommitment(
        bytes32 commitmentId,
        bytes32 backendId,
        bytes calldata attestationProof,
        bytes32 executionHash
    ) external whenNotPaused {
        AgnosticCommitment storage commitment = _commitments[commitmentId];

        if (commitment.createdAt == 0) {
            revert CommitmentNotFound(commitmentId);
        }

        if (commitment.isFinalized) {
            revert CommitmentAlreadyFinalized(commitmentId);
        }

        ExecutionBackend storage backend = backends[backendId];

        if (backend.registeredAt == 0) {
            revert BackendNotFound(backendId);
        }

        if (!backend.isActive) {
            revert BackendInactive(backendId);
        }

        if (backend.trustScore < minTrustScore) {
            revert BackendTrustTooLow(backendId, backend.trustScore);
        }

        // Check not already attested by this backend
        if (commitment.attestations[backendId].attestedAt != 0) {
            revert AlreadyAttested(commitmentId, backendId);
        }

        // Check attestation limit
        if (commitment.attestationCount >= MAX_ATTESTATIONS_PER_COMMITMENT) {
            revert TooManyAttestations(
                commitment.attestationCount,
                MAX_ATTESTATIONS_PER_COMMITMENT
            );
        }

        // Verify attestation proof via real SNARK verifier (Phase 3)
        require(
            address(attestationVerifier) != address(0),
            "Attestation verifier not configured"
        );
        {
            uint256[] memory inputs = new uint256[](4);
            inputs[0] = uint256(commitmentId);
            inputs[1] = uint256(backendId);
            inputs[2] = uint256(executionHash);
            inputs[3] = uint256(commitment.stateHash);

            bool proofValid = attestationVerifier.verify(
                attestationProof,
                inputs
            );
            if (!proofValid) {
                revert InvalidAttestationProof();
            }
        }

        // Record attestation
        commitment.attestations[backendId] = BackendAttestation({
            backendId: backendId,
            backendType: backend.backendType,
            attestationProof: attestationProof,
            executionHash: executionHash,
            attestedAt: uint64(block.timestamp),
            isValid: true
        });

        commitment.attestedBackends.push(backendId);

        unchecked {
            ++commitment.attestationCount;
        }

        // Update backend last attestation
        backend.lastAttestation = uint64(block.timestamp);

        emit CommitmentAttested(commitmentId, backendId, backend.backendType);

        // Auto-finalize if threshold met
        if (commitment.attestationCount >= requiredAttestations) {
            commitment.isFinalized = true;
            emit CommitmentFinalized(commitmentId, commitment.attestationCount);
        }
    }

    /// @notice Consume a finalized commitment
    /// @param commitmentId The commitment to consume
        /**
     * @notice Consume commitment
     * @param commitmentId The commitmentId identifier
     */
function consumeCommitment(
        bytes32 commitmentId
    ) external whenNotPaused onlyRole(COMMITMENT_REGISTRAR_ROLE) {
        AgnosticCommitment storage commitment = _commitments[commitmentId];

        if (commitment.createdAt == 0) {
            revert CommitmentNotFound(commitmentId);
        }

        if (!commitment.isFinalized) {
            revert CommitmentNotFinalized(commitmentId);
        }

        if (usedNullifiers[commitment.nullifier]) {
            revert NullifierAlreadyUsed(commitment.nullifier);
        }

        usedNullifiers[commitment.nullifier] = true;

        emit CommitmentConsumed(commitmentId, commitment.nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get commitment details
        /**
     * @notice Returns the commitment
     * @param commitmentId The commitmentId identifier
     * @return view_ The view_
     */
function getCommitment(
        bytes32 commitmentId
    ) external view returns (CommitmentView memory view_) {
        AgnosticCommitment storage commitment = _commitments[commitmentId];

        view_.commitmentId = commitment.commitmentId;
        view_.stateHash = commitment.stateHash;
        view_.transitionHash = commitment.transitionHash;
        view_.nullifier = commitment.nullifier;
        view_.attestedBackends = commitment.attestedBackends;
        view_.creator = commitment.creator;
        view_.createdAt = commitment.createdAt;
        view_.attestationCount = commitment.attestationCount;
        view_.isFinalized = commitment.isFinalized;
    }

    /// @notice Get attestation for a commitment by backend
        /**
     * @notice Returns the attestation
     * @param commitmentId The commitmentId identifier
     * @param backendId The backendId identifier
     * @return backendType The backend type
     * @return attestationProof The attestation proof
     * @return executionHash The execution hash
     * @return attestedAt The attested at
     * @return isValid The is valid
     */
function getAttestation(
        bytes32 commitmentId,
        bytes32 backendId
    )
        external
        view
        returns (
            BackendType backendType,
            bytes memory attestationProof,
            bytes32 executionHash,
            uint64 attestedAt,
            bool isValid
        )
    {
        BackendAttestation storage att = _commitments[commitmentId]
            .attestations[backendId];
        return (
            att.backendType,
            att.attestationProof,
            att.executionHash,
            att.attestedAt,
            att.isValid
        );
    }

    /// @notice Get backend details
        /**
     * @notice Returns the backend
     * @param backendId The backendId identifier
     * @return The result value
     */
function getBackend(
        bytes32 backendId
    ) external view returns (ExecutionBackend memory) {
        return backends[backendId];
    }

    /// @notice Get backends by type
        /**
     * @notice Returns the backends by type
     * @param backendType The backend type
     * @return The result value
     */
function getBackendsByType(
        BackendType backendType
    ) external view returns (bytes32[] memory) {
        return backendsByType[backendType];
    }

    /// @notice Get all active backend IDs
        /**
     * @notice Returns the active backends
     * @return The result value
     */
function getActiveBackends() external view returns (bytes32[] memory) {
        // First pass: count active backends
        uint256 activeCount = 0;
        uint256 typeCount = uint256(BackendType.Native) + 1;

        for (uint256 i = 0; i < typeCount; ) {
            bytes32[] storage typeBackends = backendsByType[BackendType(i)];
            uint256 len = typeBackends.length;
            for (uint256 j = 0; j < len; ) {
                if (backends[typeBackends[j]].isActive) {
                    unchecked {
                        ++activeCount;
                    }
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Second pass: collect active backend IDs
        bytes32[] memory result = new bytes32[](activeCount);
        uint256 index = 0;

        for (uint256 i = 0; i < typeCount; ) {
            bytes32[] storage typeBackends = backendsByType[BackendType(i)];
            uint256 len = typeBackends.length;
            for (uint256 j = 0; j < len; ) {
                bytes32 bid = typeBackends[j];
                if (backends[bid].isActive) {
                    result[index] = bid;
                    unchecked {
                        ++index;
                    }
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        return result;
    }

    /// @notice Check if commitment is valid and finalized
        /**
     * @notice Checks if commitment valid
     * @param commitmentId The commitmentId identifier
     * @return The result value
     */
function isCommitmentValid(
        bytes32 commitmentId
    ) external view returns (bool) {
        AgnosticCommitment storage commitment = _commitments[commitmentId];
        return commitment.isFinalized && !usedNullifiers[commitment.nullifier];
    }

    /// @notice Batch check commitment validity
    /// @param commitmentIds Array of commitment IDs to check
    /// @return validities Array of validity results
        /**
     * @notice Batchs check commitments
     * @param commitmentIds The commitmentIds identifier
     * @return validities The validities
     */
function batchCheckCommitments(
        bytes32[] calldata commitmentIds
    ) external view returns (bool[] memory validities) {
        uint256 len = commitmentIds.length;
        validities = new bool[](len);
        for (uint256 i = 0; i < len; ) {
            validities[i] = this.isCommitmentValid(commitmentIds[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Get commitment stats
    /// @return total Total commitments
    /// @return finalized Total finalized commitments (approximate)
    /// @return backends_ Total registered backends
        /**
     * @notice Returns the stats
     * @return total The total
     * @return finalized The finalized
     * @return backends_ The backends_
     */
function getStats()
        external
        view
        returns (uint256 total, uint256 finalized, uint256 backends_)
    {
        total = totalCommitments;
        finalized = totalCommitments; // All created commitments tracked
        backends_ = totalBackends;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set required attestation count
        /**
     * @notice Sets the required attestations
     * @param count The count value
     */
function setRequiredAttestations(
        uint256 count
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        requiredAttestations = count;
    }

    /// @notice Set minimum trust score
        /**
     * @notice Sets the min trust score
     * @param score The score value
     */
function setMinTrustScore(
        uint256 score
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        minTrustScore = score;
    }

    /// @notice Set the ZK verifier for attestation proofs
    /// @dev Phase 3: Required for real SNARK verification of attestations
    /// @param _verifier Address of the IProofVerifier-compatible contract
        /**
     * @notice Sets the attestation verifier
     * @param _verifier The _verifier
     */
function setAttestationVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_verifier != address(0), "Zero verifier address");
        attestationVerifier = IProofVerifier(_verifier);
        emit AttestationVerifierUpdated(_verifier);
    }

    event AttestationVerifierUpdated(address indexed newVerifier);

    /// @notice Pause contract
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause contract
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
