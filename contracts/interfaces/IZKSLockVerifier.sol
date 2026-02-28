// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZKSLockVerifier - Standard Interface for Noir ZK Verifiers
 * @author Zaseon v2 - ZASEON
 * @dev Defines the standard interface for Noir-generated verifier contracts
 *
 * NOIR INTEGRATION:
 * - Noir compiles circuits to Solidity verifiers
 * - This interface ensures compatibility across different backends
 * - Supports multiple proof systems (Groth16, Plonk, UltraPlonk, etc.)
 *
 * PROOF FORMATS BY BACKEND:
 * - Groth16: 3 x G1 points (A, B, C) - ~256 bytes
 * - UltraPlonk: Multiple field elements - ~2-4 KB
 * - Halo2: Custom serialization format
 *
 * CURVE SUPPORT:
 * - BN254 (alt_bn128): Default for Ethereum compatibility
 * - BLS12-381: For cross-chain with other ecosystems
 * - BLS12-377: For recursive proof composition
 */
interface IZKSLockVerifier {
    /**
     * @notice Verifies a zero-knowledge proof
     * @dev Implementation varies by Noir backend (Groth16, Plonk, etc.)
     *
     * @param proof The serialized ZK proof bytes
     * @param publicInputs Array of public inputs to the circuit (Field elements as bytes32)
     * @return isValid True if proof is valid, false otherwise
     *
     * PUBLIC INPUTS ORDER FOR ZK-SLOCKS:
     * [0] = old_state_commitment
     * [1] = new_state_commitment
     * [2] = transition_predicate_hash
     * [3] = policy_hash
     * [4] = domain_separator
     * [5] = nullifier
     */
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool isValid);

    /**
     * @notice Returns the verification key hash
     * @dev Used to identify the specific circuit/parameters
     * @return Hash of the verification key
     */
    function verificationKeyHash() external view returns (bytes32);

    /**
     * @notice Returns the curve type used
     * @dev Curve identifiers:
     *   0 = BN254 (alt_bn128)
     *   1 = BLS12-381
     *   2 = BLS12-377
     *   3 = Grumpkin (for recursive proofs)
     * @return Curve type identifier
     */
    function curveType() external view returns (uint8);

    /**
     * @notice Returns the proof system type
     * @dev Proof system identifiers:
     *   0 = Groth16
     *   1 = UltraPlonk
     *   2 = Halo2
     *   3 = Nova (folding)
     * @return Proof system identifier
     */
    function proofSystem() external view returns (uint8);

    /**
     * @notice Returns the number of public inputs expected
     * @return Number of public inputs
     */
    function numPublicInputs() external view returns (uint256);
}

/**
 * @title IZKSLockVerifierBatch - Batch verification interface
 * @dev Extended interface for efficient batch verification
 */
interface IZKSLockVerifierBatch is IZKSLockVerifier {
    /**
     * @notice Verifies multiple proofs in batch
     * @dev Uses aggregation techniques for gas efficiency
     *
     * @param proofs Array of serialized proofs
     * @param publicInputs Array of public input arrays
     * @return isValid True if all proofs are valid
     */
    function verifyBatch(
        bytes[] calldata proofs,
        bytes32[][] calldata publicInputs
    ) external view returns (bool isValid);

    /**
     * @notice Returns the maximum batch size supported
     * @return Maximum number of proofs per batch
     */
    function maxBatchSize() external view returns (uint256);
}

/**
 * @title IZKSLockVerifierRecursive - Recursive proof verification
 * @dev Interface for verifiers that support proof recursion
 */
interface IZKSLockVerifierRecursive is IZKSLockVerifier {
    /**
     * @notice Verifies a recursive proof wrapping multiple inner proofs
     * @dev The recursive proof attests to the validity of multiple inner proofs
     *
     * @param outerProof The recursive wrapper proof
     * @param innerProofHashes Hashes of the inner proofs being verified
     * @param publicInputs Combined public inputs
     * @return isValid True if recursive proof is valid
     */
    function verifyRecursive(
        bytes calldata outerProof,
        bytes32[] calldata innerProofHashes,
        bytes32[] calldata publicInputs
    ) external view returns (bool isValid);

    /**
     * @notice Returns the inner verifier for recursive verification
     * @return Address of inner verifier contract
     */
    function innerVerifier() external view returns (address);
}
