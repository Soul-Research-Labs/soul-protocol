// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AccumulatedProofState
 * @author Soul Protocol
 * @notice JAM-inspired: State is updated ONLY by accumulating verified proofs
 * @dev Core JAM insight: No direct execution updates state. Only verified proofs can.
 *
 * JAM'S ACCUMULATE PRIMITIVE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Traditional Model:                                                         │
 * │   State(n+1) = Execute(State(n), Transaction)                              │
 * │                                                                            │
 * │ JAM Model:                                                                 │
 * │   State(n+1) = Accumulate(State(n), VerifiedProof)                         │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S EXTENSION (Accumulate + Privacy):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Confidential Accumulation:                                                 │
 * │   - Proof verifies correctness WITHOUT revealing execution                 │
 * │   - State commitment updates hide actual state                             │
 * │   - Policy proofs verify compliance without data exposure                  │
 * │   - Accumulation itself is privacy-preserving                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * KEY PRINCIPLE: "The kernel never executes. It only accumulates verified proofs."
 */
contract AccumulatedProofState is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ACCUMULATOR_ROLE = keccak256("ACCUMULATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant STATE_ADMIN_ROLE = keccak256("STATE_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Proof types that can be accumulated
     */
    enum ProofType {
        Unknown,
        ZK_STATE_TRANSITION, // Proof of state change
        ZK_COMPUTATION, // Proof of computation result
        ZK_POLICY_COMPLIANCE, // Proof of policy adherence
        ZK_MEMBERSHIP, // Proof of set membership
        ZK_RANGE, // Proof of value in range
        TEE_ATTESTATION, // TEE execution attestation
        MPC_THRESHOLD, // MPC threshold signature
        CROSS_CHAIN, // Cross-chain state proof
        AGGREGATED // Aggregated multiple proofs
    }

    /**
     * @notice Verified proof ready for accumulation
     */
    struct VerifiedProof {
        bytes32 proofId;
        ProofType proofType;
        // State references
        bytes32 previousStateRoot; // State before
        bytes32 newStateRoot; // State after
        bytes32 stateTransitionHash; // Transition descriptor
        // Proof data
        bytes32 proofHash;
        bytes32 publicInputsHash;
        bytes32 verifyingKeyHash;
        // Policy binding
        bytes32 policyHash;
        bytes32 policyProof;
        // Verification
        bool verified;
        address verifier;
        uint64 verifiedAt;
        // Accumulation
        bool accumulated;
        uint256 accumulationEpoch;
        uint64 accumulatedAt;
    }

    /**
     * @notice State epoch - accumulation happens per epoch
     */
    struct StateEpoch {
        uint256 epochNumber;
        bytes32 startStateRoot;
        bytes32 endStateRoot;
        // Proofs accumulated
        uint256 proofsAccumulated;
        bytes32[] proofIds;
        // Epoch proof
        bytes32 epochProofHash; // Proof of all accumulations
        // Status
        EpochStatus status;
        uint64 startedAt;
        uint64 finalizedAt;
    }

    enum EpochStatus {
        Active, // Accepting proofs
        Accumulating, // Processing proofs
        Finalized, // Epoch complete
        Archived // Historical
    }

    /**
     * @notice State commitment - the core state primitive
     * @dev State is ONLY updated via proof accumulation
     */
    struct StateCommitment {
        bytes32 stateRoot; // Merkle root of state
        bytes32 nullifierRoot; // Root of spent nullifiers
        bytes32 noteCommitmentRoot; // Root of note commitments
        bytes32 policyStateRoot; // Root of policy state
        uint256 epoch;
        uint256 proofCount; // Total proofs accumulated
        uint64 updatedAt;
    }

    /**
     * @notice Accumulation batch - multiple proofs accumulated together
     */
    struct AccumulationBatch {
        bytes32 batchId;
        uint256 epoch;
        // Proofs in batch
        bytes32[] proofIds;
        uint256 proofCount;
        // State transition
        bytes32 inputStateRoot;
        bytes32 outputStateRoot;
        bytes32 batchTransitionHash;
        // Proof of batch validity
        bytes32 batchProofHash;
        bytes batchProof;
        // Status
        BatchStatus status;
        uint64 createdAt;
        uint64 accumulatedAt;
    }

    enum BatchStatus {
        Pending,
        Verified,
        Accumulated,
        Failed
    }

    /**
     * @notice Accumulation proof - proves correct accumulation
     */
    struct AccumulationProof {
        bytes32 proofId;
        bytes32 batchId;
        // Transition
        bytes32 beforeStateRoot;
        bytes32 afterStateRoot;
        // Validity
        bytes32 validityProofHash;
        bool valid;
        // Rollback info
        bool canRollback;
        bytes32 rollbackProof;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current state commitment
    StateCommitment public currentState;

    /// @notice State history: epoch => state
    mapping(uint256 => StateCommitment) public stateHistory;

    /// @notice Verified proofs: proofId => proof
    mapping(bytes32 => VerifiedProof) public verifiedProofs;

    /// @notice Epochs: epochNumber => epoch
    mapping(uint256 => StateEpoch) public epochs;

    /// @notice Batches: batchId => batch
    mapping(bytes32 => AccumulationBatch) public batches;

    /// @notice Accumulation proofs: proofId => accumulationProof
    mapping(bytes32 => AccumulationProof) public accumulationProofs;

    /// @notice Proof queue for current epoch
    bytes32[] public proofQueue;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Counters
    uint256 public currentEpoch;
    uint256 public totalProofs;
    uint256 public totalBatches;
    uint256 public totalAccumulated;

    /// @notice Configuration
    uint256 public epochDuration;
    uint256 public maxProofsPerBatch;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofSubmitted(
        bytes32 indexed proofId,
        ProofType proofType,
        bytes32 previousStateRoot,
        bytes32 newStateRoot
    );

    event ProofVerified(bytes32 indexed proofId, bool valid, address verifier);

    event ProofAccumulated(
        bytes32 indexed proofId,
        uint256 epoch,
        bytes32 newStateRoot
    );

    event BatchCreated(bytes32 indexed batchId, uint256 proofCount);

    event BatchAccumulated(
        bytes32 indexed batchId,
        bytes32 inputState,
        bytes32 outputState
    );

    event EpochFinalized(
        uint256 indexed epoch,
        bytes32 stateRoot,
        uint256 proofsAccumulated
    );

    event StateUpdated(bytes32 stateRoot, uint256 epoch, uint256 totalProofs);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(bytes32 genesisStateRoot) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ACCUMULATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(STATE_ADMIN_ROLE, msg.sender);

        // Initialize genesis state
        currentState = StateCommitment({
            stateRoot: genesisStateRoot,
            nullifierRoot: bytes32(0),
            noteCommitmentRoot: bytes32(0),
            policyStateRoot: bytes32(0),
            epoch: 0,
            proofCount: 0,
            updatedAt: uint64(block.timestamp)
        });

        // Initialize epoch 0
        epochs[0] = StateEpoch({
            epochNumber: 0,
            startStateRoot: genesisStateRoot,
            endStateRoot: genesisStateRoot,
            proofsAccumulated: 0,
            proofIds: new bytes32[](0),
            epochProofHash: bytes32(0),
            status: EpochStatus.Active,
            startedAt: uint64(block.timestamp),
            finalizedAt: 0
        });

        stateHistory[0] = currentState;

        // Default configuration
        epochDuration = 100; // 100 blocks per epoch
        maxProofsPerBatch = 64;
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a proof for verification
     * @dev Proof must reference current state root
     * @param proofType Type of proof
     * @param previousStateRoot State root this proof builds on
     * @param newStateRoot State root after this proof
     * @param stateTransitionHash Hash describing the transition
     * @param proofHash Hash of the actual proof
     * @param publicInputsHash Hash of public inputs
     * @param verifyingKeyHash Hash of verifying key
     * @param policyHash Policy this proof is bound to
     * @param policyProof Proof of policy compliance
     * @return proofId The proof identifier
     */
    function submitProof(
        ProofType proofType,
        bytes32 previousStateRoot,
        bytes32 newStateRoot,
        bytes32 stateTransitionHash,
        bytes32 proofHash,
        bytes32 publicInputsHash,
        bytes32 verifyingKeyHash,
        bytes32 policyHash,
        bytes32 policyProof
    ) external whenNotPaused nonReentrant returns (bytes32 proofId) {
        require(proofType != ProofType.Unknown, "APS: unknown proof type");
        require(proofHash != bytes32(0), "APS: no proof");
        require(newStateRoot != bytes32(0), "APS: no new state");

        // Generate proof ID
        proofId = keccak256(
            abi.encodePacked(
                proofType,
                previousStateRoot,
                newStateRoot,
                proofHash,
                block.timestamp,
                totalProofs
            )
        );

        // Create nullifier for this proof
        bytes32 nullifier = keccak256(
            abi.encodePacked(proofId, previousStateRoot, newStateRoot)
        );
        require(!nullifiers[nullifier], "APS: duplicate proof");
        nullifiers[nullifier] = true;

        verifiedProofs[proofId] = VerifiedProof({
            proofId: proofId,
            proofType: proofType,
            previousStateRoot: previousStateRoot,
            newStateRoot: newStateRoot,
            stateTransitionHash: stateTransitionHash,
            proofHash: proofHash,
            publicInputsHash: publicInputsHash,
            verifyingKeyHash: verifyingKeyHash,
            policyHash: policyHash,
            policyProof: policyProof,
            verified: false,
            verifier: address(0),
            verifiedAt: 0,
            accumulated: false,
            accumulationEpoch: 0,
            accumulatedAt: 0
        });

        totalProofs++;

        emit ProofSubmitted(
            proofId,
            proofType,
            previousStateRoot,
            newStateRoot
        );
    }

    /**
     * @notice Verify a submitted proof
     * @param proofId Proof to verify
     * @param valid Whether proof is valid
     */
    function verifyProof(
        bytes32 proofId,
        bool valid
    ) external onlyRole(VERIFIER_ROLE) {
        VerifiedProof storage proof = verifiedProofs[proofId];
        require(proof.proofId != bytes32(0), "APS: proof not found");
        require(!proof.verified, "APS: already verified");

        proof.verified = valid;
        proof.verifier = msg.sender;
        proof.verifiedAt = uint64(block.timestamp);

        if (valid) {
            // Add to queue for accumulation
            proofQueue.push(proofId);
        }

        emit ProofVerified(proofId, valid, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         ACCUMULATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Accumulate a single verified proof into state
     * @dev This is the core JAM primitive: state changes ONLY via proof accumulation
     * @param proofId Verified proof to accumulate
     */
    function accumulateProof(
        bytes32 proofId
    ) external onlyRole(ACCUMULATOR_ROLE) whenNotPaused nonReentrant {
        VerifiedProof storage proof = verifiedProofs[proofId];
        require(proof.verified, "APS: not verified");
        require(!proof.accumulated, "APS: already accumulated");

        // Verify proof builds on current state
        require(
            proof.previousStateRoot == currentState.stateRoot,
            "APS: state mismatch"
        );

        // Accumulate: update state commitment
        currentState.stateRoot = proof.newStateRoot;
        currentState.proofCount++;
        currentState.updatedAt = uint64(block.timestamp);

        // Mark proof as accumulated
        proof.accumulated = true;
        proof.accumulationEpoch = currentEpoch;
        proof.accumulatedAt = uint64(block.timestamp);

        // Update epoch
        epochs[currentEpoch].proofsAccumulated++;
        epochs[currentEpoch].endStateRoot = proof.newStateRoot;

        totalAccumulated++;

        emit ProofAccumulated(proofId, currentEpoch, proof.newStateRoot);
        emit StateUpdated(
            proof.newStateRoot,
            currentEpoch,
            currentState.proofCount
        );
    }

    /**
     * @notice Create a batch of proofs for accumulation
     * @param proofIds Proofs to batch
     * @return batchId The batch identifier
     */
    function createBatch(
        bytes32[] calldata proofIds
    ) external onlyRole(ACCUMULATOR_ROLE) returns (bytes32 batchId) {
        require(proofIds.length > 0, "APS: empty batch");
        require(proofIds.length <= maxProofsPerBatch, "APS: batch too large");

        // Verify all proofs are valid and chain correctly
        bytes32 expectedState = currentState.stateRoot;
        for (uint256 i = 0; i < proofIds.length; i++) {
            VerifiedProof storage proof = verifiedProofs[proofIds[i]];
            require(proof.verified, "APS: proof not verified");
            require(!proof.accumulated, "APS: already accumulated");
            require(
                proof.previousStateRoot == expectedState,
                "APS: chain broken"
            );
            expectedState = proof.newStateRoot;
        }

        // Using abi.encode for array to prevent hash collisions
        batchId = keccak256(
            abi.encode(proofIds, block.timestamp, totalBatches)
        );

        batches[batchId] = AccumulationBatch({
            batchId: batchId,
            epoch: currentEpoch,
            proofIds: proofIds,
            proofCount: proofIds.length,
            inputStateRoot: currentState.stateRoot,
            outputStateRoot: expectedState,
            batchTransitionHash: keccak256(abi.encode(proofIds)),
            batchProofHash: bytes32(0),
            batchProof: "",
            status: BatchStatus.Pending,
            createdAt: uint64(block.timestamp),
            accumulatedAt: 0
        });

        totalBatches++;

        emit BatchCreated(batchId, proofIds.length);
    }

    /**
     * @notice Accumulate a verified batch
     * @param batchId Batch to accumulate
     * @param batchProof Proof of batch validity
     */
    function accumulateBatch(
        bytes32 batchId,
        bytes calldata batchProof
    ) external onlyRole(ACCUMULATOR_ROLE) whenNotPaused nonReentrant {
        AccumulationBatch storage batch = batches[batchId];
        require(batch.status == BatchStatus.Pending, "APS: not pending");
        require(
            batch.inputStateRoot == currentState.stateRoot,
            "APS: state mismatch"
        );

        // Store batch proof
        batch.batchProofHash = keccak256(batchProof);
        batch.batchProof = batchProof;
        batch.status = BatchStatus.Accumulated;
        batch.accumulatedAt = uint64(block.timestamp);

        // Accumulate all proofs in batch
        for (uint256 i = 0; i < batch.proofIds.length; i++) {
            VerifiedProof storage proof = verifiedProofs[batch.proofIds[i]];
            proof.accumulated = true;
            proof.accumulationEpoch = currentEpoch;
            proof.accumulatedAt = uint64(block.timestamp);
        }

        // Update state
        currentState.stateRoot = batch.outputStateRoot;
        currentState.proofCount += batch.proofCount;
        currentState.updatedAt = uint64(block.timestamp);

        // Update epoch
        epochs[currentEpoch].proofsAccumulated += batch.proofCount;
        epochs[currentEpoch].endStateRoot = batch.outputStateRoot;

        totalAccumulated += batch.proofCount;

        emit BatchAccumulated(
            batchId,
            batch.inputStateRoot,
            batch.outputStateRoot
        );
        emit StateUpdated(
            batch.outputStateRoot,
            currentEpoch,
            currentState.proofCount
        );
    }

    /*//////////////////////////////////////////////////////////////
                          EPOCH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Finalize current epoch and start new one
     * @param epochProof Proof of all accumulations in epoch
     */
    function finalizeEpoch(
        bytes calldata epochProof
    ) external onlyRole(STATE_ADMIN_ROLE) {
        StateEpoch storage epoch = epochs[currentEpoch];
        require(epoch.status == EpochStatus.Active, "APS: epoch not active");

        // Finalize current epoch
        epoch.endStateRoot = currentState.stateRoot;
        epoch.epochProofHash = keccak256(epochProof);
        epoch.status = EpochStatus.Finalized;
        epoch.finalizedAt = uint64(block.timestamp);

        // Save state history
        stateHistory[currentEpoch] = currentState;

        emit EpochFinalized(
            currentEpoch,
            currentState.stateRoot,
            epoch.proofsAccumulated
        );

        // Start new epoch
        currentEpoch++;
        currentState.epoch = currentEpoch;

        epochs[currentEpoch] = StateEpoch({
            epochNumber: currentEpoch,
            startStateRoot: currentState.stateRoot,
            endStateRoot: currentState.stateRoot,
            proofsAccumulated: 0,
            proofIds: new bytes32[](0),
            epochProofHash: bytes32(0),
            status: EpochStatus.Active,
            startedAt: uint64(block.timestamp),
            finalizedAt: 0
        });

        // Clear proof queue
        delete proofQueue;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current state
     */
    function getCurrentState() external view returns (StateCommitment memory) {
        return currentState;
    }

    /**
     * @notice Get historical state
     */
    function getStateAtEpoch(
        uint256 epoch
    ) external view returns (StateCommitment memory) {
        return stateHistory[epoch];
    }

    /**
     * @notice Get proof details
     */
    function getProof(
        bytes32 proofId
    ) external view returns (VerifiedProof memory) {
        return verifiedProofs[proofId];
    }

    /**
     * @notice Get batch details
     */
    function getBatch(
        bytes32 batchId
    ) external view returns (AccumulationBatch memory) {
        return batches[batchId];
    }

    /**
     * @notice Get epoch details
     */
    function getEpoch(uint256 epoch) external view returns (StateEpoch memory) {
        return epochs[epoch];
    }

    /**
     * @notice Get pending proof queue
     */
    function getPendingProofs() external view returns (bytes32[] memory) {
        return proofQueue;
    }

    /**
     * @notice Get metrics
     */
    function getMetrics()
        external
        view
        returns (
            uint256 _currentEpoch,
            uint256 _totalProofs,
            uint256 _totalAccumulated,
            uint256 _totalBatches,
            bytes32 _currentStateRoot
        )
    {
        return (
            currentEpoch,
            totalProofs,
            totalAccumulated,
            totalBatches,
            currentState.stateRoot
        );
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setEpochDuration(
        uint256 _duration
    ) external onlyRole(STATE_ADMIN_ROLE) {
        epochDuration = _duration;
    }

    function setMaxProofsPerBatch(
        uint256 _max
    ) external onlyRole(STATE_ADMIN_ROLE) {
        maxProofsPerBatch = _max;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
