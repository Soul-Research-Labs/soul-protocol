// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title StatelessKernelVerifier
 * @author Soul Protocol
 * @notice JAM-inspired: Stateless verification - the kernel only verifies, never executes
 * @dev Core JAM insight: "The future blockchain kernel is not a VM — it is a verifier."
 *
 * JAM'S STATELESS VERIFICATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Traditional VM:                                                            │
 * │   - Loads state                                                            │
 * │   - Executes transaction                                                   │
 * │   - Updates state                                                          │
 * │   - Stores new state                                                       │
 * │                                                                            │
 * │ JAM Verifier:                                                              │
 * │   - Receives proof                                                         │
 * │   - Verifies proof (O(1) state access)                                     │
 * │   - Accepts/rejects                                                        │
 * │   - Accumulates if accepted                                                │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S EXTENSION (Stateless + Privacy):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ The kernel:                                                                │
 * │ - Never sees actual state (only commitments)                               │
 * │ - Never sees actual computation (only proofs)                              │
 * │ - Never stores sensitive data (only nullifiers)                            │
 * │ - Is truly stateless for privacy-preserving verification                   │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * KEY PRINCIPLE: The kernel has NO state machine. Only a proof verifier.
 */
contract StatelessKernelVerifier is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant SUBMITTER_ROLE = keccak256("SUBMITTER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verifying key for a proof system
     * @dev The kernel stores ONLY verifying keys, not execution logic
     */
    struct VerifyingKey {
        bytes32 keyId;
        bytes32 keyHash;
        // Key type
        ProofSystem proofSystem;
        // Key data (commitment only, not full key)
        bytes32 alphaCommitment;
        bytes32 betaCommitment;
        bytes32 gammaCommitment;
        bytes32 deltaCommitment;
        bytes32 icCommitment; // IC points commitment
        // Associated circuit
        bytes32 circuitHash;
        uint256 publicInputCount;
        // Status
        bool active;
        uint64 registeredAt;
    }

    enum ProofSystem {
        Unknown,
        GROTH16,
        PLONK,
        STARK,
        BULLETPROOFS,
        HALO2,
        NOVA,
        CUSTOM
    }

    /**
     * @notice Verification request - stateless input
     * @dev Everything needed to verify without state access
     */
    struct VerificationRequest {
        bytes32 requestId;
        // Proof data
        bytes32 proofHash;
        bytes32 verifyingKeyId;
        bytes32[] publicInputs;
        // State references (commitments, not actual state)
        bytes32 inputStateCommitment;
        bytes32 outputStateCommitment;
        bytes32 nullifier; // For replay protection
        // Policy binding
        bytes32 policyHash;
        bytes32 policyProof;
        // Request metadata
        address requester;
        RequestStatus status;
        uint64 submittedAt;
        uint64 verifiedAt;
    }

    enum RequestStatus {
        Pending,
        Verified,
        Rejected,
        Expired
    }

    /**
     * @notice Verification result - the ONLY output
     */
    struct VerificationResult {
        bytes32 requestId;
        bool valid;
        // What was verified (all stateless)
        bool proofValid;
        bool nullifierUnused;
        bool policyValid;
        bool inputsValid;
        // Output (for accumulation)
        bytes32 outputStateCommitment;
        bytes32 nullifier;
        // Verification metadata
        uint64 verifiedAt;
        uint256 gasUsed;
    }

    /**
     * @notice Batch verification request
     * @dev Verify multiple proofs in single call (more efficient)
     */
    struct BatchVerificationRequest {
        bytes32 batchId;
        bytes32[] requestIds;
        uint256 count;
        // Batch metadata
        bytes32 aggregateInputHash;
        bytes32 aggregateOutputHash;
        // Status
        bool verified;
        uint256 validCount;
        uint256 invalidCount;
        uint64 submittedAt;
        uint64 verifiedAt;
    }

    /**
     * @notice Stateless proof - everything in one package
     */
    struct StatelessProof {
        // Proof itself
        bytes32 proofHash;
        bytes proof; // Actual proof bytes
        // Verification context
        bytes32 verifyingKeyId;
        bytes32[] publicInputs;
        // State commitments (NOT actual state)
        bytes32 beforeStateCommitment;
        bytes32 afterStateCommitment;
        // Witness commitments (for ZK)
        bytes32 witnessCommitment;
        // Replay protection
        bytes32 nullifier;
        // Policy
        bytes32 policyHash;
    }

    /*//////////////////////////////////////////////////////////////
                           MINIMAL STORAGE
    //////////////////////////////////////////////////////////////*/

    // The kernel stores MINIMAL state - only what's needed for verification

    /// @notice Verifying keys: keyId => key
    mapping(bytes32 => VerifyingKey) public verifyingKeys;

    /// @notice Used nullifiers (the ONLY "state" we track for proofs)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Verification requests: requestId => request
    mapping(bytes32 => VerificationRequest) public requests;

    /// @notice Verification results: requestId => result
    mapping(bytes32 => VerificationResult) public results;

    /// @notice Batch requests: batchId => batch
    mapping(bytes32 => BatchVerificationRequest) public batches;

    /// @notice Request expiry time
    uint256 public requestExpiry;

    /// @notice Counters (for metrics only)
    uint256 public totalKeys;
    uint256 public totalRequests;
    uint256 public totalVerified;
    uint256 public totalRejected;
    uint256 public totalBatches;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerifyingKeyRegistered(
        bytes32 indexed keyId,
        ProofSystem proofSystem,
        bytes32 circuitHash
    );

    event VerificationRequested(
        bytes32 indexed requestId,
        bytes32 indexed verifyingKeyId,
        bytes32 nullifier
    );

    event VerificationCompleted(
        bytes32 indexed requestId,
        bool valid,
        bytes32 outputStateCommitment
    );

    event BatchVerificationCompleted(
        bytes32 indexed batchId,
        uint256 validCount,
        uint256 invalidCount
    );

    event NullifierUsed(bytes32 indexed nullifier, bytes32 indexed requestId);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        _grantRole(SUBMITTER_ROLE, msg.sender);

        requestExpiry = 1 hours;
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFYING KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a verifying key
     * @dev The kernel only stores key commitments, not full keys
     */
    function registerVerifyingKey(
        ProofSystem proofSystem,
        bytes32 alphaCommitment,
        bytes32 betaCommitment,
        bytes32 gammaCommitment,
        bytes32 deltaCommitment,
        bytes32 icCommitment,
        bytes32 circuitHash,
        uint256 publicInputCount
    ) external onlyRole(VERIFIER_ADMIN_ROLE) returns (bytes32 keyId) {
        require(
            proofSystem != ProofSystem.Unknown,
            "SKV: unknown proof system"
        );
        require(circuitHash != bytes32(0), "SKV: no circuit hash");
        require(publicInputCount > 0, "SKV: no public inputs");

        keyId = keccak256(
            abi.encodePacked(
                proofSystem,
                alphaCommitment,
                betaCommitment,
                circuitHash
            )
        );

        require(verifyingKeys[keyId].keyId == bytes32(0), "SKV: key exists");

        verifyingKeys[keyId] = VerifyingKey({
            keyId: keyId,
            keyHash: keccak256(
                abi.encodePacked(
                    alphaCommitment,
                    betaCommitment,
                    gammaCommitment,
                    deltaCommitment,
                    icCommitment
                )
            ),
            proofSystem: proofSystem,
            alphaCommitment: alphaCommitment,
            betaCommitment: betaCommitment,
            gammaCommitment: gammaCommitment,
            deltaCommitment: deltaCommitment,
            icCommitment: icCommitment,
            circuitHash: circuitHash,
            publicInputCount: publicInputCount,
            active: true,
            registeredAt: uint64(block.timestamp)
        });

        totalKeys++;

        emit VerifyingKeyRegistered(keyId, proofSystem, circuitHash);
    }

    /*//////////////////////////////////////////////////////////////
                      STATELESS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit verification request
     * @dev Request contains EVERYTHING needed - no state lookups required
     */
    function submitVerificationRequest(
        bytes32 proofHash,
        bytes32 verifyingKeyId,
        bytes32[] calldata publicInputs,
        bytes32 inputStateCommitment,
        bytes32 outputStateCommitment,
        bytes32 nullifier,
        bytes32 policyHash,
        bytes32 policyProof
    ) external whenNotPaused nonReentrant returns (bytes32 requestId) {
        VerifyingKey storage vk = verifyingKeys[verifyingKeyId];
        require(vk.active, "SKV: key not active");
        require(
            publicInputs.length == vk.publicInputCount,
            "SKV: wrong input count"
        );
        require(nullifier != bytes32(0), "SKV: no nullifier");
        require(!usedNullifiers[nullifier], "SKV: nullifier used");

        requestId = keccak256(
            abi.encodePacked(
                proofHash,
                verifyingKeyId,
                nullifier,
                block.timestamp,
                totalRequests
            )
        );

        requests[requestId] = VerificationRequest({
            requestId: requestId,
            proofHash: proofHash,
            verifyingKeyId: verifyingKeyId,
            publicInputs: publicInputs,
            inputStateCommitment: inputStateCommitment,
            outputStateCommitment: outputStateCommitment,
            nullifier: nullifier,
            policyHash: policyHash,
            policyProof: policyProof,
            requester: msg.sender,
            status: RequestStatus.Pending,
            submittedAt: uint64(block.timestamp),
            verifiedAt: 0
        });

        totalRequests++;

        emit VerificationRequested(requestId, verifyingKeyId, nullifier);
    }

    /**
     * @notice Verify a request
     * @dev This is the CORE stateless verification function
     */
    function verify(
        bytes32 requestId,
        bool proofValid,
        bool policyValid
    ) external onlyRole(SUBMITTER_ROLE) whenNotPaused nonReentrant {
        VerificationRequest storage request = requests[requestId];
        require(request.requestId != bytes32(0), "SKV: request not found");
        require(request.status == RequestStatus.Pending, "SKV: not pending");

        // Check expiry
        if (block.timestamp > request.submittedAt + requestExpiry) {
            request.status = RequestStatus.Expired;
            return;
        }

        // Check nullifier hasn't been used since submission
        bool nullifierUnused = !usedNullifiers[request.nullifier];

        // Validate public inputs format
        bool inputsValid = request.publicInputs.length > 0;

        // Determine overall validity
        bool valid = proofValid &&
            nullifierUnused &&
            policyValid &&
            inputsValid;

        // Record result
        uint256 gasStart = gasleft();

        results[requestId] = VerificationResult({
            requestId: requestId,
            valid: valid,
            proofValid: proofValid,
            nullifierUnused: nullifierUnused,
            policyValid: policyValid,
            inputsValid: inputsValid,
            outputStateCommitment: valid
                ? request.outputStateCommitment
                : bytes32(0),
            nullifier: request.nullifier,
            verifiedAt: uint64(block.timestamp),
            gasUsed: gasStart - gasleft()
        });

        // Update request status
        request.status = valid
            ? RequestStatus.Verified
            : RequestStatus.Rejected;
        request.verifiedAt = uint64(block.timestamp);

        // Mark nullifier as used if valid
        if (valid) {
            usedNullifiers[request.nullifier] = true;
            totalVerified++;
            emit NullifierUsed(request.nullifier, requestId);
        } else {
            totalRejected++;
        }

        emit VerificationCompleted(
            requestId,
            valid,
            request.outputStateCommitment
        );
    }

    /**
     * @notice Direct stateless verification (single call)
     * @dev Combines submit + verify for efficiency
     */
    function verifyDirect(
        StatelessProof calldata proof,
        bool proofValid,
        bool policyValid
    )
        external
        onlyRole(SUBMITTER_ROLE)
        whenNotPaused
        nonReentrant
        returns (bool valid, bytes32 requestId)
    {
        VerifyingKey storage vk = verifyingKeys[proof.verifyingKeyId];
        require(vk.active, "SKV: key not active");
        require(!usedNullifiers[proof.nullifier], "SKV: nullifier used");

        // Generate request ID
        requestId = keccak256(
            abi.encodePacked(
                proof.proofHash,
                proof.verifyingKeyId,
                proof.nullifier,
                block.timestamp
            )
        );

        // Determine validity
        bool nullifierUnused = !usedNullifiers[proof.nullifier];
        bool inputsValid = proof.publicInputs.length == vk.publicInputCount;
        valid = proofValid && nullifierUnused && policyValid && inputsValid;

        // Record result
        results[requestId] = VerificationResult({
            requestId: requestId,
            valid: valid,
            proofValid: proofValid,
            nullifierUnused: nullifierUnused,
            policyValid: policyValid,
            inputsValid: inputsValid,
            outputStateCommitment: valid
                ? proof.afterStateCommitment
                : bytes32(0),
            nullifier: proof.nullifier,
            verifiedAt: uint64(block.timestamp),
            gasUsed: 0
        });

        // Mark nullifier
        if (valid) {
            usedNullifiers[proof.nullifier] = true;
            totalVerified++;
            emit NullifierUsed(proof.nullifier, requestId);
        } else {
            totalRejected++;
        }

        totalRequests++;

        emit VerificationCompleted(
            requestId,
            valid,
            proof.afterStateCommitment
        );
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit batch verification
     * @param requestIds Requests to verify in batch
     */
    function submitBatchVerification(
        bytes32[] calldata requestIds
    ) external onlyRole(SUBMITTER_ROLE) returns (bytes32 batchId) {
        require(requestIds.length > 0, "SKV: empty batch");
        require(requestIds.length <= 64, "SKV: batch too large");

        // Compute aggregate hashes
        bytes32 aggregateInput = bytes32(0);
        bytes32 aggregateOutput = bytes32(0);

        for (uint256 i = 0; i < requestIds.length; i++) {
            VerificationRequest storage req = requests[requestIds[i]];
            require(
                req.status == RequestStatus.Pending,
                "SKV: request not pending"
            );
            aggregateInput = keccak256(
                abi.encodePacked(aggregateInput, req.inputStateCommitment)
            );
            aggregateOutput = keccak256(
                abi.encodePacked(aggregateOutput, req.outputStateCommitment)
            );
        }

        batchId = keccak256(
            abi.encodePacked(requestIds, block.timestamp, totalBatches)
        );

        batches[batchId] = BatchVerificationRequest({
            batchId: batchId,
            requestIds: requestIds,
            count: requestIds.length,
            aggregateInputHash: aggregateInput,
            aggregateOutputHash: aggregateOutput,
            verified: false,
            validCount: 0,
            invalidCount: 0,
            submittedAt: uint64(block.timestamp),
            verifiedAt: 0
        });

        totalBatches++;

        return batchId;
    }

    /**
     * @notice Verify a batch
     * @param batchId Batch to verify
     * @param validFlags Array of validity flags for each request
     */
    function verifyBatch(
        bytes32 batchId,
        bool[] calldata validFlags
    ) external onlyRole(SUBMITTER_ROLE) whenNotPaused {
        BatchVerificationRequest storage batch = batches[batchId];
        require(!batch.verified, "SKV: already verified");
        require(validFlags.length == batch.count, "SKV: flag count mismatch");

        uint256 validCount = 0;
        uint256 invalidCount = 0;

        for (uint256 i = 0; i < batch.count; i++) {
            VerificationRequest storage req = requests[batch.requestIds[i]];

            if (validFlags[i] && !usedNullifiers[req.nullifier]) {
                req.status = RequestStatus.Verified;
                usedNullifiers[req.nullifier] = true;
                validCount++;
                totalVerified++;
                emit NullifierUsed(req.nullifier, batch.requestIds[i]);
            } else {
                req.status = RequestStatus.Rejected;
                invalidCount++;
                totalRejected++;
            }

            req.verifiedAt = uint64(block.timestamp);
        }

        batch.verified = true;
        batch.validCount = validCount;
        batch.invalidCount = invalidCount;
        batch.verifiedAt = uint64(block.timestamp);

        emit BatchVerificationCompleted(batchId, validCount, invalidCount);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getVerifyingKey(
        bytes32 keyId
    ) external view returns (VerifyingKey memory) {
        return verifyingKeys[keyId];
    }

    function getRequest(
        bytes32 requestId
    ) external view returns (VerificationRequest memory) {
        return requests[requestId];
    }

    function getResult(
        bytes32 requestId
    ) external view returns (VerificationResult memory) {
        return results[requestId];
    }

    function getBatch(
        bytes32 batchId
    ) external view returns (BatchVerificationRequest memory) {
        return batches[batchId];
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    function getMetrics()
        external
        view
        returns (
            uint256 _totalKeys,
            uint256 _totalRequests,
            uint256 _totalVerified,
            uint256 _totalRejected,
            uint256 _totalBatches
        )
    {
        return (
            totalKeys,
            totalRequests,
            totalVerified,
            totalRejected,
            totalBatches
        );
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function deactivateKey(
        bytes32 keyId
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        verifyingKeys[keyId].active = false;
    }

    function setRequestExpiry(
        uint256 _expiry
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        requestExpiry = _expiry;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
