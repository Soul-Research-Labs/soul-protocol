// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IGroth16VerifierBN254.sol";

/**
 * @title BatchVerifier
 * @notice Optimized batch verification for multiple proofs
 * @dev Uses aggregated verification when possible for gas savings
 */
contract BatchVerifier {
    // The underlying single-proof verifier
    IGroth16VerifierBN254 public immutable verifier;

    // Maximum proofs per batch
    uint256 public constant MAX_BATCH_SIZE = 32;

    // Batch verification result
    struct BatchResult {
        bool allValid;
        uint256 validCount;
        uint256 invalidCount;
        bool[] results;
    }

    // Events
    event BatchVerified(
        uint256 indexed batchId,
        uint256 totalProofs,
        uint256 validCount,
        uint256 gasUsed
    );

    constructor(address _verifier) {
        verifier = IGroth16VerifierBN254(_verifier);
    }

    /**
     * @notice Verify a batch of proofs
     * @param proofs Array of proof data
     * @param publicInputsArray Array of public inputs for each proof
     * @return result Batch verification result
     */
    function verifyBatch(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputsArray
    ) external returns (BatchResult memory result) {
        uint256 startGas = gasleft();

        require(proofs.length == publicInputsArray.length, "Length mismatch");
        require(proofs.length <= MAX_BATCH_SIZE, "Batch too large");
        require(proofs.length > 0, "Empty batch");

        result.results = new bool[](proofs.length);
        result.validCount = 0;
        result.invalidCount = 0;
        result.allValid = true;

        for (uint256 i = 0; i < proofs.length; i++) {
            bool valid = _verifySingle(proofs[i], publicInputsArray[i]);
            result.results[i] = valid;

            if (valid) {
                result.validCount++;
            } else {
                result.invalidCount++;
                result.allValid = false;
            }
        }

        uint256 gasUsed = startGas - gasleft();

        emit BatchVerified(
            uint256(keccak256(abi.encode(proofs))),
            proofs.length,
            result.validCount,
            gasUsed
        );

        return result;
    }

    /**
     * @notice Verify batch with early exit on first failure
     * @param proofs Array of proof data
     * @param publicInputsArray Array of public inputs
     * @return allValid True only if all proofs are valid
     * @return failedIndex Index of first failed proof (or proofs.length if all valid)
     */
    function verifyBatchStrict(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputsArray
    ) external view returns (bool allValid, uint256 failedIndex) {
        require(proofs.length == publicInputsArray.length, "Length mismatch");
        require(proofs.length <= MAX_BATCH_SIZE, "Batch too large");

        for (uint256 i = 0; i < proofs.length; i++) {
            if (!_verifySingle(proofs[i], publicInputsArray[i])) {
                return (false, i);
            }
        }

        return (true, proofs.length);
    }

    /**
     * @notice Estimate gas for batch verification
     * @param batchSize Number of proofs
     * @return estimatedGas Estimated gas consumption
     */
    function estimateBatchGas(
        uint256 batchSize
    ) external pure returns (uint256 estimatedGas) {
        // Base cost + per-proof verification cost
        // These are estimates based on typical Groth16 verification
        uint256 baseCost = 50000;
        uint256 perProofCost = 250000;

        return baseCost + (perProofCost * batchSize);
    }

    /**
     * @notice Get optimal batch size based on gas limit
     * @param gasLimit Available gas
     * @return optimalSize Recommended batch size
     */
    function getOptimalBatchSize(
        uint256 gasLimit
    ) external pure returns (uint256 optimalSize) {
        uint256 baseCost = 50000;
        uint256 perProofCost = 250000;
        uint256 safetyMargin = 50000;

        if (gasLimit <= baseCost + safetyMargin) {
            return 0;
        }

        uint256 availableGas = gasLimit - baseCost - safetyMargin;
        uint256 size = availableGas / perProofCost;

        return size > MAX_BATCH_SIZE ? MAX_BATCH_SIZE : size;
    }

    /**
     * @dev Verify a single proof
     */
    function _verifySingle(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        // Decode proof into Groth16 format
        if (proof.length < 256) {
            return false;
        }

        // Parse proof components
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;

        // Extract a (first 64 bytes)
        a[0] = abi.decode(proof[0:32], (uint256));
        a[1] = abi.decode(proof[32:64], (uint256));

        // Extract b (next 128 bytes)
        b[0][0] = abi.decode(proof[64:96], (uint256));
        b[0][1] = abi.decode(proof[96:128], (uint256));
        b[1][0] = abi.decode(proof[128:160], (uint256));
        b[1][1] = abi.decode(proof[160:192], (uint256));

        // Extract c (next 64 bytes)
        c[0] = abi.decode(proof[192:224], (uint256));
        c[1] = abi.decode(proof[224:256], (uint256));

        // Call the verifier
        try verifier.verifyProof(a, b, c, publicInputs) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }
}
