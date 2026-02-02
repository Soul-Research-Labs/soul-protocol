// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../Groth16VerifierBN254.sol";

/**
 * @title AggregatorAdapter
 * @notice Adapter for aggregated proof verification
 */
contract AggregatorAdapter {
    Groth16VerifierBN254 public immutable verifier;
    
    constructor(address _verifier) {
        verifier = Groth16VerifierBN254(_verifier);
    }
    
    /// @notice Standard interface for proof verification
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool) {
        return verifier.verifyProof(proof, publicInputs);
    }
    
    function verifyBatch(
        bytes calldata aggregatedProof,
        bytes32[] calldata publicInputs
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](publicInputs.length);
        for (uint256 i = 0; i < publicInputs.length; i++) {
            inputs[i] = uint256(publicInputs[i]);
        }
        
        return verifier.verify(aggregatedProof, inputs);
    }
}
