// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IExecutionMicroservice
 * @author Soul Protocol
 * @notice Standard interface for all execution backends (ZK, TEE, MPC)
 * @dev Celestia's execution-agnosticism, generalized for privacy
 *
 * DESIGN PHILOSOPHY:
 * Soul never assumes a single execution model. All backends are microservices
 * that produce a STANDARD ExecutionReceipt. This enables:
 * - Backend swapping without protocol changes
 * - Hybrid execution (ZK + TEE fallback)
 * - Backend-specific optimizations
 * - Unified verification
 *
 * EXECUTION MICROSERVICE ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                         EXECUTION SERVICE LAYER                            │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    IExecutionMicroservice                           │   │
 * │  │                    (Standard Interface)                             │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │         │                    │                    │                        │
 * │         ▼                    ▼                    ▼                        │
 * │  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
 * │  │ ZK Backend  │     │ TEE Backend │     │ MPC Backend │                   │
 * │  │             │     │             │     │             │                   │
 * │  │ - SNARK     │     │ - SGX       │     │ - Shamir    │                   │
 * │  │ - STARK     │     │ - TrustZone │     │ - Threshold │                   │
 * │  │ - Plonk     │     │ - Nitro     │     │ - FROST     │                   │
 * │  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                   │
 * │         │                   │                   │                          │
 * │         └───────────────────┼───────────────────┘                          │
 * │                             ▼                                              │
 * │                   ┌─────────────────┐                                      │
 * │                   │ ExecutionReceipt │                                     │
 * │                   │ (Standard Output)│                                     │
 * │                   └─────────────────┘                                      │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */

/**
 * @notice Backend type enumeration
 */
enum BackendType {
    Unknown,
    ZK_SNARK, // Zero-knowledge SNARK (Groth16, etc.)
    ZK_STARK, // Zero-knowledge STARK (transparent setup)
    ZK_PLONK, // PLONK-based systems
    ZK_HALO2, // Halo2-based systems
    TEE_SGX, // Intel SGX
    TEE_TRUSTZONE, // ARM TrustZone
    TEE_NITRO, // AWS Nitro Enclaves
    TEE_SEV, // AMD SEV
    MPC_SHAMIR, // Shamir secret sharing
    MPC_THRESHOLD, // Threshold cryptography
    MPC_FROST, // FROST signatures
    HYBRID // Combination of backends
}

/**
 * @notice Backend capability flags
 */
struct BackendCapabilities {
    bool supportsPrivateInputs; // Can process encrypted inputs
    bool supportsPrivateOutputs; // Can produce encrypted outputs
    bool supportsStateProofs; // Can prove state transitions
    bool supportsBatching; // Can batch multiple executions
    bool supportsRecursion; // Can verify other proofs
    bool supportsComposition; // Can compose with other backends
    uint256 maxInputSize; // Maximum input size in bytes
    uint256 maxOutputSize; // Maximum output size in bytes
    uint256 avgProofTime; // Average proof generation time (ms)
    uint256 avgVerifyTime; // Average verification time (ms)
}

/**
 * @notice Standard execution request format
 */
struct ExecutionRequest {
    bytes32 requestId; // Unique request identifier
    bytes32 programId; // Program/circuit identifier
    bytes32 inputCommitment; // Commitment to inputs
    bytes32 policyHash; // Execution policy
    bytes32 domainSeparator; // Cross-domain isolation
    address requester; // Request originator
    uint64 deadline; // Execution deadline
    uint256 maxGas; // Maximum gas/compute units
    bytes encryptedInputs; // Encrypted input data
    bytes auxData; // Backend-specific auxiliary data
}

/**
 * @notice Standard execution receipt format (ALL backends produce this)
 */
struct ExecutionReceipt {
    // Identity
    bytes32 receiptId; // Unique receipt ID
    bytes32 requestId; // Link to request
    bytes32 executionId; // Execution instance ID
    // State transition
    bytes32 stateCommitmentOld; // State before execution
    bytes32 stateCommitmentNew; // State after execution
    bytes32 stateTransitionHash; // Hash of (old, new, inputs)
    // Policy binding
    bytes32 policyHash; // Applied policy
    bytes32 constraintRoot; // Root of constraint set
    // Proof/attestation
    BackendType backendType; // Which backend produced this
    bytes32 proofHash; // Hash of proof/attestation
    bytes proof; // Actual proof data
    // Outputs
    bytes32 outputCommitment; // Commitment to outputs
    bytes encryptedOutputs; // Encrypted output data
    // Metadata
    address executor; // Who executed
    uint64 executedAt; // Execution timestamp
    uint64 expiresAt; // Receipt validity
    bool verified; // Verification status
    // Nullifier
    bytes32 nullifier; // Replay protection
}

/**
 * @notice Verification result
 */
struct VerificationResult {
    bool valid;
    bytes32 receiptId;
    string reason; // Empty if valid
    uint64 verifiedAt;
    address verifier;
}

/**
 * @title IExecutionMicroservice
 * @notice Standard interface all execution backends must implement
 */
interface IExecutionMicroservice {
    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ExecutionRequested(
        bytes32 indexed requestId,
        bytes32 indexed programId,
        address requester
    );

    event ExecutionCompleted(
        bytes32 indexed requestId,
        bytes32 indexed receiptId,
        BackendType backendType,
        bool success
    );

    event ExecutionFailed(bytes32 indexed requestId, string reason);

    event ReceiptVerified(bytes32 indexed receiptId, bool valid);

    /*//////////////////////////////////////////////////////////////
                          CORE EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit execution request
     * @param request The execution request
     * @return requestId The request identifier
     */
    function submitRequest(
        ExecutionRequest calldata request
    ) external returns (bytes32 requestId);

    /**
     * @notice Execute and produce receipt
     * @param requestId The request to execute
     * @return receipt The execution receipt
     */
    function execute(
        bytes32 requestId
    ) external returns (ExecutionReceipt memory receipt);

    /**
     * @notice Submit pre-computed receipt (for off-chain execution)
     * @param receipt The execution receipt
     * @return verified Whether receipt is valid
     */
    function submitReceipt(
        ExecutionReceipt calldata receipt
    ) external returns (bool verified);

    /*//////////////////////////////////////////////////////////////
                           VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify an execution receipt
     * @param receipt The receipt to verify
     * @return result The verification result
     */
    function verifyReceipt(
        ExecutionReceipt calldata receipt
    ) external returns (VerificationResult memory result);

    /**
     * @notice Batch verify multiple receipts
     * @param receipts Array of receipts to verify
     * @return results Array of verification results
     */
    function batchVerify(
        ExecutionReceipt[] calldata receipts
    ) external returns (VerificationResult[] memory results);

    /**
     * @notice Verify proof only (without full receipt)
     * @param proofHash The proof hash
     * @param proof The proof data
     * @param publicInputs Public inputs to the proof
     * @return valid Whether proof is valid
     */
    function verifyProof(
        bytes32 proofHash,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external returns (bool valid);

    /*//////////////////////////////////////////////////////////////
                            CAPABILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get backend type
     * @return backendType The type of this backend
     */
    function getBackendType() external view returns (BackendType backendType);

    /**
     * @notice Get backend capabilities
     * @return capabilities The capability flags
     */
    function getCapabilities()
        external
        view
        returns (BackendCapabilities memory capabilities);

    /**
     * @notice Check if program is supported
     * @param programId The program to check
     * @return supported Whether program can be executed
     */
    function supportsProgram(
        bytes32 programId
    ) external view returns (bool supported);

    /**
     * @notice Estimate execution cost
     * @param request The execution request
     * @return gasEstimate Estimated gas/compute units
     * @return timeEstimate Estimated execution time (ms)
     */
    function estimateExecution(
        ExecutionRequest calldata request
    ) external view returns (uint256 gasEstimate, uint256 timeEstimate);

    /*//////////////////////////////////////////////////////////////
                              STATUS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get request status
     * @param requestId The request to check
     * @return pending Whether request is pending
     * @return executed Whether request was executed
     * @return receiptId The receipt ID if executed
     */
    function getRequestStatus(
        bytes32 requestId
    ) external view returns (bool pending, bool executed, bytes32 receiptId);

    /**
     * @notice Get receipt by ID
     * @param receiptId The receipt ID
     * @return receipt The execution receipt
     */
    function getReceipt(
        bytes32 receiptId
    ) external view returns (ExecutionReceipt memory receipt);

    /**
     * @notice Check if backend is healthy
     * @return healthy Whether backend is operational
     * @return message Status message
     */
    function healthCheck()
        external
        view
        returns (bool healthy, string memory message);
}

/**
 * @title IZKBackend
 * @notice Extended interface for ZK-specific backends
 */
interface IZKBackend is IExecutionMicroservice {
    /**
     * @notice Get verification key for program
     * @param programId The program ID
     * @return vkHash Hash of verification key
     */
    function getVerificationKey(
        bytes32 programId
    ) external view returns (bytes32 vkHash);

    /**
     * @notice Register new program/circuit
     * @param programId Program identifier
     * @param vkHash Verification key hash
     * @param circuitMetadata Circuit metadata
     */
    function registerProgram(
        bytes32 programId,
        bytes32 vkHash,
        bytes calldata circuitMetadata
    ) external;

    /**
     * @notice Aggregate multiple proofs into one
     * @param proofs Array of proofs to aggregate
     * @return aggregatedProof The aggregated proof
     */
    function aggregateProofs(
        bytes[] calldata proofs
    ) external returns (bytes memory aggregatedProof);

    /**
     * @notice Recursively verify proof of proofs
     * @param outerProof The outer proof
     * @param innerProofHashes Hashes of inner proofs
     * @return valid Whether recursive verification passed
     */
    function verifyRecursive(
        bytes calldata outerProof,
        bytes32[] calldata innerProofHashes
    ) external returns (bool valid);
}

/**
 * @title ITEEBackend
 * @notice Extended interface for TEE-specific backends
 */
interface ITEEBackend is IExecutionMicroservice {
    /**
     * @notice Enclave information
     */
    struct EnclaveInfo {
        bytes32 enclaveId;
        bytes32 mrEnclave; // Measurement of enclave
        bytes32 mrSigner; // Measurement of signer
        uint64 attestationTime;
        bool active;
    }

    /**
     * @notice Get enclave attestation
     * @return attestation The remote attestation
     */
    function getAttestation() external view returns (bytes memory attestation);

    /**
     * @notice Verify remote attestation
     * @param attestation The attestation to verify
     * @return valid Whether attestation is valid
     * @return info Enclave information
     */
    function verifyAttestation(
        bytes calldata attestation
    ) external returns (bool valid, EnclaveInfo memory info);

    /**
     * @notice Get active enclave info
     * @return info The enclave information
     */
    function getEnclaveInfo() external view returns (EnclaveInfo memory info);

    /**
     * @notice Rotate enclave (key rotation)
     * @param newAttestation Attestation of new enclave
     * @return enclaveId New enclave ID
     */
    function rotateEnclave(
        bytes calldata newAttestation
    ) external returns (bytes32 enclaveId);
}

/**
 * @title IMPCBackend
 * @notice Extended interface for MPC-specific backends
 */
interface IMPCBackend is IExecutionMicroservice {
    /**
     * @notice MPC party information
     */
    struct PartyInfo {
        bytes32 partyId;
        address operator;
        bytes publicKey;
        uint256 stake;
        bool active;
    }

    /**
     * @notice Get threshold parameters
     * @return threshold Minimum parties required
     * @return total Total parties
     */
    function getThreshold()
        external
        view
        returns (uint8 threshold, uint8 total);

    /**
     * @notice Get all parties
     * @return parties Array of party info
     */
    function getParties() external view returns (PartyInfo[] memory parties);

    /**
     * @notice Register MPC party
     * @param partyId Party identifier
     * @param publicKey Party's public key
     */
    function registerParty(
        bytes32 partyId,
        bytes calldata publicKey
    ) external payable;

    /**
     * @notice Submit party's share of result
     * @param requestId The execution request
     * @param share The party's share
     * @param signature Signature on share
     */
    function submitShare(
        bytes32 requestId,
        bytes calldata share,
        bytes calldata signature
    ) external;

    /**
     * @notice Combine shares to produce result
     * @param requestId The execution request
     * @return combined Whether combination succeeded
     * @return result The combined result
     */
    function combineShares(
        bytes32 requestId
    ) external returns (bool combined, bytes memory result);
}

/**
 * @title IExecutionRouter
 * @notice Routes execution to appropriate backend
 */
interface IExecutionRouter {
    /**
     * @notice Route request to best backend
     * @param request The execution request
     * @param preferredBackend Preferred backend type (can be Unknown for auto)
     * @return receipt The execution receipt
     */
    function route(
        ExecutionRequest calldata request,
        BackendType preferredBackend
    ) external returns (ExecutionReceipt memory receipt);

    /**
     * @notice Get available backends
     * @return backends Array of registered backend addresses
     * @return types Array of backend types
     */
    function getBackends()
        external
        view
        returns (address[] memory backends, BackendType[] memory types);

    /**
     * @notice Register new backend
     * @param backend Backend contract address
     * @param backendType Type of backend
     */
    function registerBackend(address backend, BackendType backendType) external;

    /**
     * @notice Select optimal backend for request
     * @param request The execution request
     * @return backend Selected backend address
     * @return backendType Backend type
     */
    function selectBackend(
        ExecutionRequest calldata request
    ) external view returns (address backend, BackendType backendType);
}
