// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IProofVerifier
 * @author Soul Protocol
 * @notice Standard interface for ZK proof verifiers
 * @dev All PIL v2 proof verifiers must implement this interface
 */
interface IProofVerifier {
    /**
     * @notice Verify a zero-knowledge proof
     * @param proof The proof bytes (format depends on implementation)
     * @param publicInputs The public inputs for verification
     * @return success True if the proof is valid
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool success);

    /**
     * @notice Verify a proof with a single public input (common case)
     * @param proof The proof bytes
     * @param publicInput Single public input
     * @return success True if the proof is valid
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success);

    /**
     * @notice Get the expected number of public inputs
     * @return count Number of public inputs expected
     */
    function getPublicInputCount() external view returns (uint256 count);

    /**
     * @notice Check if the verifier is properly initialized
     * @return ready True if verifier is ready to verify proofs
     */
    function isReady() external view returns (bool ready);
}

/**
 * @title IVerifierRegistry
 * @notice Registry for managing multiple proof verifiers
 */
interface IVerifierRegistry {
    /**
     * @notice Get the verifier for a specific proof type
     * @param proofType The type of proof (e.g., "validity", "policy", "nullifier")
     * @return verifier The verifier address
     */
    function getVerifier(
        bytes32 proofType
    ) external view returns (IProofVerifier verifier);

    /**
     * @notice Check if a verifier is registered for a proof type
     * @param proofType The type of proof
     * @return registered True if a verifier is registered
     */
    function hasVerifier(
        bytes32 proofType
    ) external view returns (bool registered);
}
