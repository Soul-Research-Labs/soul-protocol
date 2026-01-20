// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title ExecutionBackendAbstraction
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Pluggable Execution Backends with Uniform ExecutionReceipt Output
 * @dev Abstracts ZK/TEE/MPC backends into a uniform interface with deterministic receipts
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    DESIGN PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Soul abstracts heterogeneous execution backends into a uniform interface:
 *
 * ╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║ Backend Type                    │ Soul Implementation                                              ║
 * ╠════════════════════════════════════════════════════════════════════════════════════════════════════╣
 * ║ Zero-Knowledge Circuits         │ Cryptographic execution correctness (SNARK/STARK)                ║
 * ║ Trusted Execution Environments  │ Hardware-attested confidential compute (SGX/TDX)                 ║
 * ║ Multi-Party Computation         │ Threshold-secured distributed execution                          ║
 * ║ Hybrid                          │ Combined guarantees from multiple backends                       ║
 * ╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
 *
 * All backends produce uniform ExecutionReceipt { state_old, state_new, policy, proof }
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                           EXECUTION BACKEND ABSTRACTION (EBA)
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * EBA provides:
 * 1. Uniform interface for all execution backends
 * 2. Standard ExecutionReceipt format
 * 3. Backend capability negotiation
 * 4. Proof/attestation verification routing
 *
 * Backends produce ExecutionReceipt with:
 * - state_commitment_old: Pre-execution state
 * - state_commitment_new: Post-execution state
 * - policy_hash: Policy enforced during execution
 * - proof_or_attestation: Backend-specific proof
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                               BACKEND SELECTION FLOW
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 *                    ┌─────────────────────────────────────┐
 *                    │        Execution Request            │
 *                    │  (message, policy, requirements)    │
 *                    └──────────────────┬──────────────────┘
 *                                       │
 *                                       ▼
 *                    ┌─────────────────────────────────────┐
 *                    │      Backend Selector               │
 *                    │  - Check capabilities               │
 *                    │  - Check policy requirements        │
 *                    │  - Select optimal backend           │
 *                    └──────────────────┬──────────────────┘
 *                                       │
 *           ┌───────────────────────────┼───────────────────────────┐
 *           │                           │                           │
 *           ▼                           ▼                           ▼
 *    ┌─────────────┐            ┌─────────────┐            ┌─────────────┐
 *    │  ZK Backend │            │ TEE Backend │            │ MPC Backend │
 *    │  - Circuits │            │ - Enclaves  │            │ - Nodes     │
 *    │  - Provers  │            │ - Remote    │            │ - Threshold │
 *    └──────┬──────┘            └──────┬──────┘            └──────┬──────┘
 *           │                           │                           │
 *           └───────────────────────────┼───────────────────────────┘
 *                                       │
 *                                       ▼
 *                    ┌─────────────────────────────────────┐
 *                    │       Uniform ExecutionReceipt      │
 *                    │  { state_old, state_new, proof }    │
 *                    └─────────────────────────────────────┘
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract ExecutionBackendAbstraction is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant BACKEND_ADMIN_ROLE =
        keccak256("BACKEND_ADMIN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error BackendNotRegistered(bytes32 backendId);
    error BackendNotActive(bytes32 backendId);
    error BackendAlreadyRegistered(bytes32 backendId);
    error InsufficientCapabilities(bytes32 backendId, bytes32 required);
    error ExecutionFailed(bytes32 executionId, string reason);
    error InvalidReceipt(bytes32 receiptId);
    error VerificationFailed(bytes32 receiptId);
    error PolicyMismatch(bytes32 expected, bytes32 actual);
    error NoSuitableBackend(bytes32 capabilityHash);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Backend types (mirroring ExecutionIndirectionLayer)
    enum BackendType {
        ZK, // Zero-Knowledge proofs
        TEE, // Trusted Execution Environment
        MPC, // Multi-Party Computation
        HYBRID // Combined approaches
    }

    /// @notice Backend capability flags
    struct BackendCapabilities {
        bool supportsConfidentialCompute;
        bool supportsStateTransitions;
        bool supportsCrossChain;
        bool supportsComposability;
        bool supportsRecursiveProofs;
        bool supportsAttestations;
        uint256 maxInputSize;
        uint256 maxOutputSize;
        uint256 estimatedLatency; // milliseconds
    }

    /**
     * @notice Backend Registration with capabilities
     * @dev Full backend metadata for selection and routing
     */
    struct Backend {
        bytes32 backendId;
        BackendType backendType;
        string name;
        bytes32 capabilityHash;
        BackendCapabilities capabilities;
        address verifierContract; // Proof/attestation verifier
        address executorContract; // Execution endpoint
        uint256 stake; // Economic security (optional)
        bool isActive;
        uint64 registeredAt;
        uint64 lastUsedAt;
        uint256 totalExecutions;
        uint256 successfulExecutions;
    }

    /**
     * @notice Uniform Execution Receipt
     * @dev Standard output format for ALL backends (ZK, TEE, MPC)
     *
     * This is the key abstraction: regardless of backend type,
     * the output is always the same structure.
     */
    struct ExecutionReceipt {
        bytes32 receiptId;
        bytes32 executionId;
        bytes32 backendId;
        // State transitions
        bytes32 stateCommitmentOld;
        bytes32 stateCommitmentNew;
        // Policy binding
        bytes32 policyHash;
        bytes32 policyProof;
        // Proof or attestation (type depends on backend)
        ProofType proofType;
        bytes proofOrAttestation;
        // Execution metadata
        bytes32 inputHash;
        bytes32 outputHash;
        // Timestamps
        uint64 executedAt;
        uint64 expiresAt;
        // Verification status
        bool verified;
        address verifiedBy;
    }

    /// @notice Proof types for different backends
    enum ProofType {
        ZK_SNARK, // Zero-knowledge SNARK proof
        ZK_STARK, // Zero-knowledge STARK proof
        TEE_ATTESTATION, // TEE remote attestation
        MPC_SIGNATURE, // MPC threshold signature
        HYBRID_PROOF // Combined proof types
    }

    /**
     * @notice Execution Request
     * @dev Request format submitted to EBA
     */
    struct ExecutionRequest {
        bytes32 requestId;
        bytes32 messageId; // Link to SoulControlPlane message
        bytes32 preferredBackend; // Optional: preferred backend
        bytes32 requiredCapabilities; // Hash of required capabilities
        bytes encryptedInput;
        bytes32 policyHash;
        bytes32 stateCommitmentOld;
        uint64 deadline;
    }

    /**
     * @notice Backend Selection Criteria
     * @dev Used by selector to find optimal backend
     */
    struct SelectionCriteria {
        BackendType preferredType;
        bool requireConfidential;
        bool requireCrossChain;
        bool requireRecursive;
        uint256 maxLatency;
        bytes32 minCapabilities;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Backend registry
    mapping(bytes32 => Backend) public backends;

    /// @notice Execution receipts
    mapping(bytes32 => ExecutionReceipt) public receipts;

    /// @notice Pending requests
    mapping(bytes32 => ExecutionRequest) public pendingRequests;

    /// @notice Backend list by type
    mapping(BackendType => bytes32[]) public backendsByType;

    /// @notice Capability to backends mapping
    mapping(bytes32 => bytes32[]) public backendsByCapability;

    /// @notice All backend IDs
    bytes32[] public allBackendIds;

    /// @notice Counters
    uint256 public totalBackends;
    uint256 public totalExecutions;
    uint256 public totalVerifications;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BackendRegistered(
        bytes32 indexed backendId,
        BackendType indexed backendType,
        string name
    );

    event BackendDeactivated(bytes32 indexed backendId);

    event ExecutionRequested(
        bytes32 indexed requestId,
        bytes32 indexed backendId,
        bytes32 messageId
    );

    event ExecutionCompleted(
        bytes32 indexed executionId,
        bytes32 indexed backendId,
        bytes32 receiptId
    );

    event ReceiptVerified(bytes32 indexed receiptId, bool success);

    event BackendSelected(
        bytes32 indexed requestId,
        bytes32 indexed selectedBackend,
        BackendType backendType
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BACKEND_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        BACKEND REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new execution backend
     * @param backendType Type of backend (ZK, TEE, MPC, HYBRID)
     * @param name Human-readable name
     * @param capabilities Backend capabilities
     * @param verifierContract Proof/attestation verifier address
     * @param executorContract Execution endpoint address
     * @return backendId The generated backend ID
     */
    function registerBackend(
        BackendType backendType,
        string calldata name,
        BackendCapabilities calldata capabilities,
        address verifierContract,
        address executorContract
    ) external onlyRole(BACKEND_ADMIN_ROLE) returns (bytes32 backendId) {
        // Generate backend ID
        backendId = keccak256(
            abi.encodePacked(
                backendType,
                name,
                verifierContract,
                executorContract,
                block.timestamp
            )
        );

        if (backends[backendId].isActive) {
            revert BackendAlreadyRegistered(backendId);
        }

        // Generate capability hash
        bytes32 capabilityHash = _hashCapabilities(capabilities);

        // Store backend
        backends[backendId] = Backend({
            backendId: backendId,
            backendType: backendType,
            name: name,
            capabilityHash: capabilityHash,
            capabilities: capabilities,
            verifierContract: verifierContract,
            executorContract: executorContract,
            stake: 0,
            isActive: true,
            registeredAt: uint64(block.timestamp),
            lastUsedAt: 0,
            totalExecutions: 0,
            successfulExecutions: 0
        });

        // Add to indices
        allBackendIds.push(backendId);
        backendsByType[backendType].push(backendId);
        backendsByCapability[capabilityHash].push(backendId);

        unchecked {
            ++totalBackends;
        }

        emit BackendRegistered(backendId, backendType, name);
        return backendId;
    }

    /**
     * @notice Register pre-defined ZK backend
     * @param name Backend name
     * @param verifierContract Verifier address
     * @param executorContract Executor address
     * @return backendId The backend ID
     */
    function registerZKBackend(
        string calldata name,
        address verifierContract,
        address executorContract
    ) external onlyRole(BACKEND_ADMIN_ROLE) returns (bytes32 backendId) {
        BackendCapabilities memory caps = BackendCapabilities({
            supportsConfidentialCompute: true,
            supportsStateTransitions: true,
            supportsCrossChain: true,
            supportsComposability: true,
            supportsRecursiveProofs: true,
            supportsAttestations: false,
            maxInputSize: 1024 * 1024, // 1MB
            maxOutputSize: 512 * 1024, // 512KB
            estimatedLatency: 30000 // 30 seconds
        });

        return
            this.registerBackend(
                BackendType.ZK,
                name,
                caps,
                verifierContract,
                executorContract
            );
    }

    /**
     * @notice Register pre-defined TEE backend
     * @param name Backend name
     * @param attestationVerifier Attestation verifier address
     * @param enclaveEndpoint Enclave endpoint address
     * @return backendId The backend ID
     */
    function registerTEEBackend(
        string calldata name,
        address attestationVerifier,
        address enclaveEndpoint
    ) external onlyRole(BACKEND_ADMIN_ROLE) returns (bytes32 backendId) {
        BackendCapabilities memory caps = BackendCapabilities({
            supportsConfidentialCompute: true,
            supportsStateTransitions: true,
            supportsCrossChain: true,
            supportsComposability: true,
            supportsRecursiveProofs: false,
            supportsAttestations: true,
            maxInputSize: 10 * 1024 * 1024, // 10MB
            maxOutputSize: 5 * 1024 * 1024, // 5MB
            estimatedLatency: 1000 // 1 second
        });

        return
            this.registerBackend(
                BackendType.TEE,
                name,
                caps,
                attestationVerifier,
                enclaveEndpoint
            );
    }

    /**
     * @notice Register pre-defined MPC backend
     * @param name Backend name
     * @param signatureVerifier Signature verifier address
     * @param coordinatorEndpoint MPC coordinator address
     * @return backendId The backend ID
     */
    function registerMPCBackend(
        string calldata name,
        address signatureVerifier,
        address coordinatorEndpoint
    ) external onlyRole(BACKEND_ADMIN_ROLE) returns (bytes32 backendId) {
        BackendCapabilities memory caps = BackendCapabilities({
            supportsConfidentialCompute: true,
            supportsStateTransitions: true,
            supportsCrossChain: true,
            supportsComposability: false,
            supportsRecursiveProofs: false,
            supportsAttestations: true,
            maxInputSize: 100 * 1024 * 1024, // 100MB
            maxOutputSize: 50 * 1024 * 1024, // 50MB
            estimatedLatency: 5000 // 5 seconds
        });

        return
            this.registerBackend(
                BackendType.MPC,
                name,
                caps,
                signatureVerifier,
                coordinatorEndpoint
            );
    }

    /*//////////////////////////////////////////////////////////////
                        BACKEND SELECTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Select optimal backend based on criteria
     * @param criteria Selection criteria
     * @return selectedBackend The selected backend ID
     */
    function selectBackend(
        SelectionCriteria calldata criteria
    ) external view returns (bytes32 selectedBackend) {
        bytes32[] storage candidates = backendsByType[criteria.preferredType];

        // If no candidates for preferred type, search all
        if (candidates.length == 0) {
            candidates = allBackendIds;
        }

        uint256 bestScore = 0;
        bytes32 bestBackend = bytes32(0);

        for (uint256 i = 0; i < candidates.length; i++) {
            Backend storage backend = backends[candidates[i]];

            if (!backend.isActive) continue;

            // Check required capabilities
            if (
                criteria.requireConfidential &&
                !backend.capabilities.supportsConfidentialCompute
            ) continue;
            if (
                criteria.requireCrossChain &&
                !backend.capabilities.supportsCrossChain
            ) continue;
            if (
                criteria.requireRecursive &&
                !backend.capabilities.supportsRecursiveProofs
            ) continue;
            if (
                criteria.maxLatency > 0 &&
                backend.capabilities.estimatedLatency > criteria.maxLatency
            ) continue;

            // Score based on success rate and latency
            uint256 score = _scoreBackend(backend);

            if (score > bestScore) {
                bestScore = score;
                bestBackend = candidates[i];
            }
        }

        if (bestBackend == bytes32(0)) {
            revert NoSuitableBackend(criteria.minCapabilities);
        }

        return bestBackend;
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit execution request
     * @param request Execution request details
     * @return requestId The request identifier
     */
    function submitRequest(
        ExecutionRequest calldata request
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        returns (bytes32 requestId)
    {
        requestId = request.requestId;

        bytes32 backendId = request.preferredBackend;

        // Validate backend
        if (!backends[backendId].isActive) {
            revert BackendNotActive(backendId);
        }

        // Store request
        pendingRequests[requestId] = request;

        emit ExecutionRequested(requestId, backendId, request.messageId);
        return requestId;
    }

    /**
     * @notice Submit execution receipt from backend
     * @param executionId Execution identifier
     * @param backendId Backend that executed
     * @param stateCommitmentNew New state commitment
     * @param policyProof Proof of policy enforcement
     * @param proofType Type of proof/attestation
     * @param proofOrAttestation The proof or attestation bytes
     * @return receiptId The receipt identifier
     */
    function submitReceipt(
        bytes32 executionId,
        bytes32 backendId,
        bytes32 stateCommitmentNew,
        bytes32 policyProof,
        ProofType proofType,
        bytes calldata proofOrAttestation
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        returns (bytes32 receiptId)
    {
        Backend storage backend = backends[backendId];

        if (!backend.isActive) {
            revert BackendNotActive(backendId);
        }

        ExecutionRequest storage request = pendingRequests[executionId];

        // Generate receipt ID
        receiptId = keccak256(
            abi.encodePacked(
                executionId,
                backendId,
                stateCommitmentNew,
                block.timestamp
            )
        );

        // Create receipt
        receipts[receiptId] = ExecutionReceipt({
            receiptId: receiptId,
            executionId: executionId,
            backendId: backendId,
            stateCommitmentOld: request.stateCommitmentOld,
            stateCommitmentNew: stateCommitmentNew,
            policyHash: request.policyHash,
            policyProof: policyProof,
            proofType: proofType,
            proofOrAttestation: proofOrAttestation,
            inputHash: keccak256(request.encryptedInput),
            outputHash: stateCommitmentNew, // For now, output = new state
            executedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 24 hours),
            verified: false,
            verifiedBy: address(0)
        });

        // Update backend stats
        backend.lastUsedAt = uint64(block.timestamp);
        unchecked {
            backend.totalExecutions++;
            ++totalExecutions;
        }

        emit ExecutionCompleted(executionId, backendId, receiptId);
        return receiptId;
    }

    /*//////////////////////////////////////////////////////////////
                        VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify execution receipt
     * @param receiptId Receipt to verify
     * @return verified True if verification passed
     */
    function verifyReceipt(
        bytes32 receiptId
    ) external onlyRole(VERIFIER_ROLE) nonReentrant returns (bool verified) {
        ExecutionReceipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert InvalidReceipt(receiptId);
        }

        Backend storage backend = backends[receipt.backendId];

        // Route verification to appropriate verifier
        verified = _verifyProofOrAttestation(
            backend.verifierContract,
            receipt.proofType,
            receipt.proofOrAttestation,
            receipt.stateCommitmentOld,
            receipt.stateCommitmentNew,
            receipt.policyHash
        );

        if (!verified) {
            revert VerificationFailed(receiptId);
        }

        // Mark as verified
        receipt.verified = true;
        receipt.verifiedBy = msg.sender;

        // Update backend success stats
        unchecked {
            backend.successfulExecutions++;
            ++totalVerifications;
        }

        emit ReceiptVerified(receiptId, true);
        return true;
    }

    /**
     * @notice Batch verify multiple receipts
     * @param receiptIds Array of receipt IDs
     * @return results Verification results
     */
    function batchVerifyReceipts(
        bytes32[] calldata receiptIds
    )
        external
        onlyRole(VERIFIER_ROLE)
        nonReentrant
        returns (bool[] memory results)
    {
        results = new bool[](receiptIds.length);

        for (uint256 i = 0; i < receiptIds.length; i++) {
            try this.verifyReceipt(receiptIds[i]) returns (bool result) {
                results[i] = result;
            } catch {
                results[i] = false;
            }
        }

        return results;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _hashCapabilities(
        BackendCapabilities memory caps
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(caps));
    }

    function _scoreBackend(
        Backend storage backend
    ) internal view returns (uint256) {
        // Score based on:
        // - Success rate (higher is better)
        // - Latency (lower is better)
        // - Recent usage (active backends preferred)

        uint256 score = 1000; // Base score

        // Success rate bonus (up to 500 points)
        if (backend.totalExecutions > 0) {
            score +=
                (backend.successfulExecutions * 500) /
                backend.totalExecutions;
        }

        // Latency penalty
        if (backend.capabilities.estimatedLatency > 0) {
            uint256 latencyPenalty = backend.capabilities.estimatedLatency /
                100; // 1 point per 100ms
            if (latencyPenalty < score) {
                score -= latencyPenalty;
            }
        }

        // Active usage bonus (used in last 24 hours)
        if (
            backend.lastUsedAt > 0 &&
            block.timestamp - backend.lastUsedAt < 24 hours
        ) {
            score += 100;
        }

        return score;
    }

    function _verifyProofOrAttestation(
        address verifierContract,
        ProofType proofType,
        bytes storage proofOrAttestation,
        bytes32 stateOld,
        bytes32 stateNew,
        bytes32 policyHash
    ) internal view returns (bool) {
        // In production: call verifier contract based on proof type
        // For MVP: basic validation

        if (verifierContract == address(0)) {
            // No verifier = trusted execution
            return proofOrAttestation.length > 0;
        }

        // Validate proof data exists
        if (proofOrAttestation.length == 0) {
            return false;
        }

        // Validate state transitions are valid
        if (stateOld == bytes32(0) || stateNew == bytes32(0)) {
            return false;
        }

        // Validate policy hash
        if (policyHash == bytes32(0)) {
            return false;
        }

        // In production: route to specific verifier based on proofType
        // For MVP: return true if all checks pass
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get backend details
    function getBackend(
        bytes32 backendId
    ) external view returns (Backend memory) {
        return backends[backendId];
    }

    /// @notice Get receipt details
    function getReceipt(
        bytes32 receiptId
    ) external view returns (ExecutionReceipt memory) {
        return receipts[receiptId];
    }

    /// @notice Get backends by type
    function getBackendsByType(
        BackendType backendType
    ) external view returns (bytes32[] memory) {
        return backendsByType[backendType];
    }

    /// @notice Get all active backends
    function getActiveBackends()
        external
        view
        returns (bytes32[] memory activeIds)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < allBackendIds.length; i++) {
            if (backends[allBackendIds[i]].isActive) {
                count++;
            }
        }

        activeIds = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < allBackendIds.length; i++) {
            if (backends[allBackendIds[i]].isActive) {
                activeIds[index++] = allBackendIds[i];
            }
        }
        return activeIds;
    }

    /// @notice Get backend capabilities
    function getCapabilities(
        bytes32 backendId
    ) external view returns (BackendCapabilities memory) {
        return backends[backendId].capabilities;
    }

    /// @notice Check if backend is active
    function isBackendActive(bytes32 backendId) external view returns (bool) {
        return backends[backendId].isActive;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function deactivateBackend(
        bytes32 backendId
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        backends[backendId].isActive = false;
        emit BackendDeactivated(backendId);
    }

    function activateBackend(
        bytes32 backendId
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        if (backends[backendId].registeredAt == 0) {
            revert BackendNotRegistered(backendId);
        }
        backends[backendId].isActive = true;
    }

    function updateBackendStake(
        bytes32 backendId,
        uint256 stake
    ) external onlyRole(BACKEND_ADMIN_ROLE) {
        backends[backendId].stake = stake;
    }
}
