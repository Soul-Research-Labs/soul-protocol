// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../Groth16VerifierBN254.sol";

/**
 * @title NullifierAdapter
 * @notice Adapter for nullifier proof verification
 */
contract NullifierAdapter {
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
    
    function verify(
        bytes calldata proof,
        bytes32 nullifier,
        bytes32 commitment
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(nullifier);
        inputs[1] = uint256(commitment);
        
        return verifier.verify(proof, inputs);
    }
}
