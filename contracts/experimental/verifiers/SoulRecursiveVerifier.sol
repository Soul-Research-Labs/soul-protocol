// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {ExperimentalFeatureGated} from "../ExperimentalFeatureGated.sol";
import {ExperimentalFeatureRegistry} from "../../security/ExperimentalFeatureRegistry.sol";

/**
 * @title SoulRecursiveVerifier
 * @notice Verifies aggregated recursive proofs for Soul protocol
 * @dev Supports both single proofs (backward compatible) and aggregated proofs
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 */
contract SoulRecursiveVerifier is
    Ownable,
    ReentrancyGuard,
    Pausable,
    ExperimentalFeatureGated
{
    // ============================================
    // Types
    // ============================================

    struct AggregatedProofData {
        uint256 proofCount;
        bytes32 initialStateHash;
        bytes32 finalStateHash;
        bytes32 accumulatedInstanceHash;
        bytes32 nullifierBatchRoot;
        uint256 batchVolume;
    }

    struct VerificationResult {
        bool valid;
        bytes32 batchId;
        uint256 timestamp;
        uint256 gasUsed;
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice Verifier contract for aggregated proofs
    address public aggregatedVerifier;

    /// @notice Verifier contract for single proofs (backward compatibility)
    address public singleVerifier;

    /// @notice Mapping of verified batch IDs
    mapping(bytes32 => bool) public verifiedBatches;

    /// @notice Mapping of transfer IDs to their batch
    mapping(bytes32 => bytes32) public transferToBatch;

    /// @notice Mapping of nullifiers to prevent double-spend
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Batch verification results
    mapping(bytes32 => VerificationResult) public batchResults;

    /// @notice Total proofs verified
    uint256 public totalProofsVerified;

    /// @notice Total batches verified
    uint256 public totalBatchesVerified;

    /// @notice Minimum batch size for aggregation
    uint256 public minBatchSize = 5;

    /// @notice Maximum batch size
    uint256 public maxBatchSize = 100;

    // ============================================
    // Errors
    // ============================================

    error BatchTooSmall();
    error BatchTooLarge();
    error TransferCountMismatch();
    error NullifierCountMismatch();
    error NullifierAlreadyUsed();
    error BatchAlreadyVerified();
    error InvalidAggregatedProof();
    error InvalidProof();
    error InvalidAddress();
    error MinMustBePositive();
    error MaxMustBeLessThanMin();
    error MaxTooLarge();

    // ============================================
    // Events
    // ============================================

    event BatchVerified(
        bytes32 indexed batchId,
        uint256 proofCount,
        bytes32 initialState,
        bytes32 finalState,
        uint256 gasUsed
    );

    event SingleProofVerified(
        bytes32 indexed proofId,
        bytes32 nullifier,
        bytes32 commitment
    );

    event NullifierUsed(bytes32 indexed nullifier, bytes32 indexed batchId);

    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier,
        bool isAggregated
    );

    // ============================================
    // Constructor
    // ============================================

    constructor(
        address _aggregatedVerifier,
        address _singleVerifier,
        address _featureRegistry
    ) Ownable(msg.sender) {
        aggregatedVerifier = _aggregatedVerifier;
        singleVerifier = _singleVerifier;

        // Wire to ExperimentalFeatureRegistry
        _setFeatureRegistry(
            _featureRegistry,
            ExperimentalFeatureRegistry(_featureRegistry).RECURSIVE_VERIFIER()
        );
    }

    // ============================================
    // External Functions
    // ============================================

    /**
     * @notice Verify an aggregated proof batch
     * @param proof The aggregated proof bytes
     * @param proofData The structured proof data
     * @param transferIds Array of transfer IDs in the batch
     * @param nullifiers Array of nullifiers in the batch
     * @return batchId The unique identifier for this verified batch
     */
    function verifyAggregatedProof(
        bytes calldata proof,
        AggregatedProofData calldata proofData,
        bytes32[] calldata transferIds,
        bytes32[] calldata nullifiers
    ) external nonReentrant whenNotPaused returns (bytes32 batchId) {
        uint256 gasStart = gasleft();

        // Validate inputs
        if (proofData.proofCount < minBatchSize) revert BatchTooSmall();
        if (proofData.proofCount > maxBatchSize) revert BatchTooLarge();
        if (transferIds.length != proofData.proofCount)
            revert TransferCountMismatch();
        if (nullifiers.length != proofData.proofCount)
            revert NullifierCountMismatch();

        // Check nullifiers haven't been used
        for (uint256 i = 0; i < nullifiers.length; ) {
            if (usedNullifiers[nullifiers[i]]) revert NullifierAlreadyUsed();
            unchecked {
                ++i;
            }
        }

        // Compute batch ID
        batchId = keccak256(
            abi.encode(
                proofData.initialStateHash,
                proofData.finalStateHash,
                proofData.nullifierBatchRoot,
                block.number
            )
        );

        if (verifiedBatches[batchId]) revert BatchAlreadyVerified();

        // Verify the proof
        bytes32 proofHash = keccak256(abi.encode(proofData));
        bool valid = _verifyAggregatedProof(proof, proofHash, proofData);
        if (!valid) revert InvalidAggregatedProof();

        // Mark batch as verified
        verifiedBatches[batchId] = true;

        // Record nullifiers
        for (uint256 i = 0; i < nullifiers.length; ) {
            usedNullifiers[nullifiers[i]] = true;
            emit NullifierUsed(nullifiers[i], batchId);
            unchecked {
                ++i;
            }
        }

        // Map transfers to batch
        for (uint256 i = 0; i < transferIds.length; ) {
            transferToBatch[transferIds[i]] = batchId;
            unchecked {
                ++i;
            }
        }

        // Record result
        uint256 gasUsed = gasStart - gasleft();
        batchResults[batchId] = VerificationResult({
            valid: true,
            batchId: batchId,
            timestamp: block.timestamp,
            gasUsed: gasUsed
        });

        // Update counters
        totalProofsVerified += proofData.proofCount;
        totalBatchesVerified++;

        emit BatchVerified(
            batchId,
            proofData.proofCount,
            proofData.initialStateHash,
            proofData.finalStateHash,
            gasUsed
        );

        return batchId;
    }

    /**
     * @notice Verify a single proof (backward compatibility)
     * @param proof The proof bytes
     * @param nullifier The nullifier being spent
     * @param commitment The new commitment
     * @param publicInputs Additional public inputs
     * @return proofId The unique identifier for this proof
     */
    function verifySingleProof(
        bytes calldata proof,
        bytes32 nullifier,
        bytes32 commitment,
        bytes32[] calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bytes32 proofId) {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();

        proofId = keccak256(abi.encode(nullifier, commitment, block.number));

        // Verify proof
        bool valid = _verifySingleProof(
            proof,
            nullifier,
            commitment,
            publicInputs
        );
        if (!valid) revert InvalidProof();

        // Mark nullifier as used
        usedNullifiers[nullifier] = true;

        // Update counters
        totalProofsVerified++;

        emit SingleProofVerified(proofId, nullifier, commitment);
        emit NullifierUsed(nullifier, proofId);

        return proofId;
    }

    /**
     * @notice Check if a transfer has been verified
     * @param transferId The transfer ID to check
     * @return verified Whether the transfer is in a verified batch
     * @return batchId The batch containing this transfer (if verified)
     */
    function isTransferVerified(
        bytes32 transferId
    ) external view returns (bool verified, bytes32 batchId) {
        batchId = transferToBatch[transferId];
        verified = verifiedBatches[batchId];
    }

    /**
     * @notice Check if a nullifier has been used
     * @param nullifier The nullifier to check
     * @return used Whether the nullifier has been spent
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /**
     * @notice Get batch verification result
     * @param batchId The batch ID
     * @return result The verification result
     */
    function getBatchResult(
        bytes32 batchId
    ) external view returns (VerificationResult memory) {
        return batchResults[batchId];
    }

    /**
     * @notice Get gas savings from aggregation
     * @param proofCount Number of proofs in batch
     * @param batchGasUsed Actual gas used for batch verification
     * @return savings Estimated gas saved vs individual verification
     * @return savingsPercent Percentage of gas saved
     */
    function calculateGasSavings(
        uint256 proofCount,
        uint256 batchGasUsed
    ) external pure returns (uint256 savings, uint256 savingsPercent) {
        // Estimated gas per single proof verification
        uint256 singleProofGas = 250000;
        uint256 expectedIndividualGas = proofCount * singleProofGas;

        if (batchGasUsed < expectedIndividualGas) {
            savings = expectedIndividualGas - batchGasUsed;
            savingsPercent = (savings * 100) / expectedIndividualGas;
        }
    }

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Update the aggregated verifier contract
     * @param newVerifier Address of new verifier
     */
    function setAggregatedVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidAddress();

        address old = aggregatedVerifier;
        aggregatedVerifier = newVerifier;
        emit VerifierUpdated(old, newVerifier, true);
    }

    /**
     * @notice Update the single verifier contract
     * @param newVerifier Address of new verifier
     */
    function setSingleVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidAddress();

        address old = singleVerifier;
        singleVerifier = newVerifier;
        emit VerifierUpdated(old, newVerifier, false);
    }

    /**
     * @notice Update batch size limits
     * @param _minBatchSize Minimum batch size
     * @param _maxBatchSize Maximum batch size
     */
    function setBatchLimits(
        uint256 _minBatchSize,
        uint256 _maxBatchSize
    ) external onlyOwner {
        if (_minBatchSize == 0) revert MinMustBePositive();
        if (_maxBatchSize < _minBatchSize) revert MaxMustBeLessThanMin();
        if (_maxBatchSize > 1000) revert MaxTooLarge();

        minBatchSize = _minBatchSize;
        maxBatchSize = _maxBatchSize;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Internal aggregated proof verification
     */
    function _verifyAggregatedProof(
        bytes calldata proof,
        bytes32 proofHash,
        AggregatedProofData calldata proofData
    ) internal view returns (bool) {
        if (aggregatedVerifier == address(0)) {
            return false;
        }

        // Encode public inputs
        bytes memory publicInputs = abi.encode(
            proofHash,
            proofData.initialStateHash,
            proofData.finalStateHash,
            proofData.nullifierBatchRoot,
            proofData.batchVolume,
            proofData.proofCount
        );

        // Call verifier
        (bool success, bytes memory result) = aggregatedVerifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, publicInputs)
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    /**
     * @notice Internal single proof verification
     */
    function _verifySingleProof(
        bytes calldata proof,
        bytes32 nullifier,
        bytes32 commitment,
        bytes32[] calldata publicInputs
    ) internal view returns (bool) {
        if (singleVerifier == address(0)) {
            return false;
        }

        // Encode all public inputs
        bytes memory encodedInputs = abi.encode(
            nullifier,
            commitment,
            publicInputs
        );

        // Call verifier
        (bool success, bytes memory result) = singleVerifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, encodedInputs)
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }
}
