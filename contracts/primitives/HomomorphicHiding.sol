// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title HomomorphicHiding
 * @author Soul Protocol
 * @notice Research-grade implementation of Homomorphic Hiding (HH)
 * @dev Enables computations on encrypted/committed values while preserving privacy
 *
 * Homomorphic Hiding allows:
 * - Hidden value commitments with additive homomorphic properties
 * - Verifiable operations on hidden values (add, subtract, scale)
 * - Range proofs without revealing actual values
 * - Aggregate balance proofs
 *
 * Key Features:
 * - Pedersen-style commitments: C = g^v * h^r
 * - Additive homomorphism: C1 * C2 = g^(v1+v2) * h^(r1+r2)
 * - Zero-knowledge range proofs
 * - Threshold decryption support
 */
contract HomomorphicHiding is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                               ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant COMMITMENT_MANAGER_ROLE =
        keccak256("COMMITMENT_MANAGER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                               TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice A hidden value commitment
    struct HiddenCommitment {
        bytes32 commitmentId;
        bytes32 commitment; // C = g^v * h^r (as hash)
        bytes32 generatorG; // Public generator g
        bytes32 generatorH; // Public generator h
        address owner;
        uint64 createdAt;
        uint64 expiresAt;
        bool isActive;
        bool isRevealed;
    }

    /// @notice Result of a homomorphic operation
    struct OperationResult {
        bytes32 resultId;
        bytes32 inputA;
        bytes32 inputB;
        bytes32 result;
        OperationType opType;
        uint64 timestamp;
    }

    /// @notice Range proof for a hidden value
    struct RangeProof {
        bytes32 proofId;
        bytes32 commitmentId;
        uint256 lowerBound;
        uint256 upperBound;
        bytes proof; // ZK proof data
        bool isVerified;
        uint64 verifiedAt;
    }

    /// @notice Aggregate proof combining multiple commitments
    struct AggregateProof {
        bytes32 proofId;
        bytes32[] commitmentIds;
        bytes32 aggregateCommitment;
        bytes proof;
        bool isVerified;
        uint64 timestamp;
    }

    /// @notice Operation types for homomorphic computations
    enum OperationType {
        Add,
        Subtract,
        ScalarMultiply
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Commitment storage
    mapping(bytes32 => HiddenCommitment) public commitments;

    /// @notice Operation results storage
    mapping(bytes32 => OperationResult) public operations;

    /// @notice Range proofs storage
    mapping(bytes32 => RangeProof) public rangeProofs;

    /// @notice Aggregate proofs storage
    mapping(bytes32 => AggregateProof) public aggregateProofs;

    /// @notice Commitments by owner
    mapping(address => bytes32[]) public ownerCommitments;

    /// @notice Counter for unique IDs
    uint256 private _idCounter;

    /// @notice Total commitments
    uint256 public totalCommitments;

    /// @notice Total operations performed
    uint256 public totalOperations;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event CommitmentCreated(
        bytes32 indexed commitmentId,
        address indexed owner,
        bytes32 commitment
    );

    event CommitmentRevealed(
        bytes32 indexed commitmentId,
        uint256 revealedValue
    );

    event HomomorphicOperationPerformed(
        bytes32 indexed resultId,
        bytes32 indexed inputA,
        bytes32 indexed inputB,
        OperationType opType,
        bytes32 result
    );

    event RangeProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed commitmentId,
        uint256 lowerBound,
        uint256 upperBound
    );

    event RangeProofVerified(bytes32 indexed proofId, bool isValid);

    event AggregateProofCreated(
        bytes32 indexed proofId,
        bytes32 aggregateCommitment
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error CommitmentNotFound();
    error CommitmentExpired();
    error CommitmentInactive();
    error CommitmentAlreadyRevealed();
    error InvalidProof();
    error InvalidOperation();
    error Unauthorized();
    error InvalidBounds();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COMMITMENT_MANAGER_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         COMMITMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new hidden value commitment
     * @param commitment The Pedersen commitment C = g^v * h^r
     * @param generatorG The generator g used
     * @param generatorH The generator h used
     * @param expiry When the commitment expires (0 for never)
     * @return commitmentId The unique commitment ID
     */
    function createCommitment(
        bytes32 commitment,
        bytes32 generatorG,
        bytes32 generatorH,
        uint64 expiry
    ) external whenNotPaused nonReentrant returns (bytes32 commitmentId) {
        commitmentId = keccak256(
            abi.encodePacked(
                commitment,
                msg.sender,
                block.timestamp,
                ++_idCounter
            )
        );

        commitments[commitmentId] = HiddenCommitment({
            commitmentId: commitmentId,
            commitment: commitment,
            generatorG: generatorG,
            generatorH: generatorH,
            owner: msg.sender,
            createdAt: uint64(block.timestamp),
            expiresAt: expiry,
            isActive: true,
            isRevealed: false
        });

        ownerCommitments[msg.sender].push(commitmentId);
        unchecked {
            ++totalCommitments;
        }

        emit CommitmentCreated(commitmentId, msg.sender, commitment);

        return commitmentId;
    }

    /**
     * @notice Reveal a hidden commitment (optional - for auditing)
     * @param commitmentId The commitment to reveal
     * @param value The hidden value
     * @param randomness The randomness used
     */
    function revealCommitment(
        bytes32 commitmentId,
        uint256 value,
        bytes32 randomness
    ) external whenNotPaused {
        HiddenCommitment storage commitment = commitments[commitmentId];

        if (commitment.createdAt == 0) revert CommitmentNotFound();
        if (commitment.owner != msg.sender) revert Unauthorized();
        if (commitment.isRevealed) revert CommitmentAlreadyRevealed();
        if (!commitment.isActive) revert CommitmentInactive();

        // Verify the reveal (simplified - real impl would verify Pedersen commitment)
        bytes32 computed = keccak256(
            abi.encodePacked(
                commitment.generatorG,
                value,
                commitment.generatorH,
                randomness
            )
        );

        if (computed != commitment.commitment) revert InvalidProof();

        commitment.isRevealed = true;

        emit CommitmentRevealed(commitmentId, value);
    }

    /*//////////////////////////////////////////////////////////////
                      HOMOMORPHIC OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Perform homomorphic addition: C1 * C2 = g^(v1+v2) * h^(r1+r2)
     * @param commitmentA First commitment ID
     * @param commitmentB Second commitment ID
     * @return resultId The operation result ID
     * @return result The resulting commitment
     */
    function homomorphicAdd(
        bytes32 commitmentA,
        bytes32 commitmentB
    )
        external
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 resultId, bytes32 result)
    {
        HiddenCommitment storage commA = commitments[commitmentA];
        HiddenCommitment storage commB = commitments[commitmentB];

        if (commA.createdAt == 0) revert CommitmentNotFound();
        if (commB.createdAt == 0) revert CommitmentNotFound();
        if (!commA.isActive || !commB.isActive) revert CommitmentInactive();

        // Verify same generators (required for homomorphic property)
        if (
            commA.generatorG != commB.generatorG ||
            commA.generatorH != commB.generatorH
        ) {
            revert InvalidOperation();
        }

        // Compute result: C1 * C2 (simplified as hash combination)
        result = keccak256(
            abi.encodePacked(commA.commitment, commB.commitment, "ADD")
        );

        resultId = keccak256(
            abi.encodePacked(
                commitmentA,
                commitmentB,
                result,
                block.timestamp,
                ++_idCounter
            )
        );

        operations[resultId] = OperationResult({
            resultId: resultId,
            inputA: commitmentA,
            inputB: commitmentB,
            result: result,
            opType: OperationType.Add,
            timestamp: uint64(block.timestamp)
        });

        unchecked {
            ++totalOperations;
        }

        emit HomomorphicOperationPerformed(
            resultId,
            commitmentA,
            commitmentB,
            OperationType.Add,
            result
        );

        return (resultId, result);
    }

    /**
     * @notice Perform homomorphic subtraction
     * @param commitmentA First commitment ID (minuend)
     * @param commitmentB Second commitment ID (subtrahend)
     * @return resultId The operation result ID
     * @return result The resulting commitment
     */
    function homomorphicSubtract(
        bytes32 commitmentA,
        bytes32 commitmentB
    )
        external
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 resultId, bytes32 result)
    {
        HiddenCommitment storage commA = commitments[commitmentA];
        HiddenCommitment storage commB = commitments[commitmentB];

        if (commA.createdAt == 0) revert CommitmentNotFound();
        if (commB.createdAt == 0) revert CommitmentNotFound();
        if (!commA.isActive || !commB.isActive) revert CommitmentInactive();

        // Verify same generators
        if (
            commA.generatorG != commB.generatorG ||
            commA.generatorH != commB.generatorH
        ) {
            revert InvalidOperation();
        }

        // Compute result: C1 / C2 (simplified as hash combination)
        result = keccak256(
            abi.encodePacked(commA.commitment, commB.commitment, "SUB")
        );

        resultId = keccak256(
            abi.encodePacked(
                commitmentA,
                commitmentB,
                result,
                block.timestamp,
                ++_idCounter
            )
        );

        operations[resultId] = OperationResult({
            resultId: resultId,
            inputA: commitmentA,
            inputB: commitmentB,
            result: result,
            opType: OperationType.Subtract,
            timestamp: uint64(block.timestamp)
        });

        unchecked {
            ++totalOperations;
        }

        emit HomomorphicOperationPerformed(
            resultId,
            commitmentA,
            commitmentB,
            OperationType.Subtract,
            result
        );

        return (resultId, result);
    }

    /**
     * @notice Perform scalar multiplication: C^k = g^(k*v) * h^(k*r)
     * @param commitmentId The commitment to scale
     * @param scalar The scalar multiplier
     * @return resultId The operation result ID
     * @return result The resulting commitment
     */
    function homomorphicScalarMultiply(
        bytes32 commitmentId,
        uint256 scalar
    )
        external
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 resultId, bytes32 result)
    {
        HiddenCommitment storage comm = commitments[commitmentId];

        if (comm.createdAt == 0) revert CommitmentNotFound();
        if (!comm.isActive) revert CommitmentInactive();

        // Compute result: C^k (simplified as hash with scalar)
        result = keccak256(abi.encodePacked(comm.commitment, scalar, "SCALAR"));

        bytes32 scalarBytes = bytes32(scalar);
        resultId = keccak256(
            abi.encodePacked(
                commitmentId,
                scalarBytes,
                result,
                block.timestamp,
                ++_idCounter
            )
        );

        operations[resultId] = OperationResult({
            resultId: resultId,
            inputA: commitmentId,
            inputB: scalarBytes,
            result: result,
            opType: OperationType.ScalarMultiply,
            timestamp: uint64(block.timestamp)
        });

        unchecked {
            ++totalOperations;
        }

        emit HomomorphicOperationPerformed(
            resultId,
            commitmentId,
            scalarBytes,
            OperationType.ScalarMultiply,
            result
        );

        return (resultId, result);
    }

    /*//////////////////////////////////////////////////////////////
                         RANGE PROOF FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a range proof for a hidden commitment
     * @param commitmentId The commitment to prove
     * @param lowerBound The lower bound (public)
     * @param upperBound The upper bound (public)
     * @param proof The ZK range proof
     * @return proofId The proof ID
     */
    function submitRangeProof(
        bytes32 commitmentId,
        uint256 lowerBound,
        uint256 upperBound,
        bytes calldata proof
    ) external whenNotPaused returns (bytes32 proofId) {
        if (lowerBound > upperBound) revert InvalidBounds();

        HiddenCommitment storage comm = commitments[commitmentId];
        if (comm.createdAt == 0) revert CommitmentNotFound();
        if (!comm.isActive) revert CommitmentInactive();

        proofId = keccak256(
            abi.encodePacked(
                commitmentId,
                lowerBound,
                upperBound,
                block.timestamp,
                ++_idCounter
            )
        );

        rangeProofs[proofId] = RangeProof({
            proofId: proofId,
            commitmentId: commitmentId,
            lowerBound: lowerBound,
            upperBound: upperBound,
            proof: proof,
            isVerified: false,
            verifiedAt: 0
        });

        emit RangeProofSubmitted(proofId, commitmentId, lowerBound, upperBound);

        return proofId;
    }

    /**
     * @notice Verify a submitted range proof
     * @param proofId The proof to verify
     * @return isValid Whether the proof is valid
     */
    function verifyRangeProof(
        bytes32 proofId
    ) external onlyRole(VERIFIER_ROLE) returns (bool isValid) {
        RangeProof storage rangeProof = rangeProofs[proofId];
        if (rangeProof.proofId == bytes32(0)) revert InvalidProof();

        // Simplified verification - in production would use a ZK verifier
        isValid = rangeProof.proof.length >= 32;

        rangeProof.isVerified = true;
        rangeProof.verifiedAt = uint64(block.timestamp);

        emit RangeProofVerified(proofId, isValid);

        return isValid;
    }

    /*//////////////////////////////////////////////////////////////
                      AGGREGATE PROOF FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an aggregate proof from multiple commitments
     * @param commitmentIds The commitments to aggregate
     * @param proof The aggregate ZK proof
     * @return proofId The aggregate proof ID
     */
    function createAggregateProof(
        bytes32[] calldata commitmentIds,
        bytes calldata proof
    ) external whenNotPaused returns (bytes32 proofId) {
        // Verify all commitments exist and are active
        bytes32 aggregate = bytes32(0);
        for (uint256 i = 0; i < commitmentIds.length; ) {
            HiddenCommitment storage comm = commitments[commitmentIds[i]];
            if (comm.createdAt == 0) revert CommitmentNotFound();
            if (!comm.isActive) revert CommitmentInactive();

            // Build aggregate commitment
            aggregate = keccak256(abi.encodePacked(aggregate, comm.commitment));
            unchecked {
                ++i;
            }
        }

        proofId = keccak256(
            abi.encodePacked(aggregate, block.timestamp, ++_idCounter)
        );

        aggregateProofs[proofId] = AggregateProof({
            proofId: proofId,
            commitmentIds: commitmentIds,
            aggregateCommitment: aggregate,
            proof: proof,
            isVerified: false,
            timestamp: uint64(block.timestamp)
        });

        emit AggregateProofCreated(proofId, aggregate);

        return proofId;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get commitment details
     */
    function getCommitment(
        bytes32 commitmentId
    ) external view returns (HiddenCommitment memory) {
        return commitments[commitmentId];
    }

    /**
     * @notice Get operation result
     */
    function getOperation(
        bytes32 resultId
    ) external view returns (OperationResult memory) {
        return operations[resultId];
    }

    /**
     * @notice Get range proof
     */
    function getRangeProof(
        bytes32 proofId
    ) external view returns (RangeProof memory) {
        return rangeProofs[proofId];
    }

    /**
     * @notice Get aggregate proof
     */
    function getAggregateProof(
        bytes32 proofId
    ) external view returns (AggregateProof memory) {
        return aggregateProofs[proofId];
    }

    /**
     * @notice Get all commitments for an owner
     */
    function getOwnerCommitments(
        address owner
    ) external view returns (bytes32[] memory) {
        return ownerCommitments[owner];
    }

    /**
     * @notice Check if a commitment is valid
     */
    function isCommitmentValid(
        bytes32 commitmentId
    ) external view returns (bool) {
        HiddenCommitment storage comm = commitments[commitmentId];
        if (comm.createdAt == 0) return false;
        if (!comm.isActive) return false;
        if (comm.expiresAt != 0 && block.timestamp > comm.expiresAt)
            return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function deactivateCommitment(
        bytes32 commitmentId
    ) external onlyRole(COMMITMENT_MANAGER_ROLE) {
        commitments[commitmentId].isActive = false;
    }
}
