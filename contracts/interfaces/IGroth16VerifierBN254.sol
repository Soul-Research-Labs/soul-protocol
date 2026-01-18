// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IGroth16VerifierBN254
 * @notice Interface for Groth16 proof verification on BN254 curve
 */
interface IGroth16VerifierBN254 {
    /**
     * @notice Verify a Groth16 proof
     * @param a First element of the proof (G1 point)
     * @param b Second element of the proof (G2 point)
     * @param c Third element of the proof (G1 point)
     * @param input Public inputs to the circuit
     * @return bool True if the proof is valid
     */
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external view returns (bool);
}
