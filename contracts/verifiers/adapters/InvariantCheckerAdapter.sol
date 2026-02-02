// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../Groth16VerifierBN254.sol";

/**
 * @title InvariantCheckerAdapter
 * @notice Adapter for invariant checker proof verification
 */
contract InvariantCheckerAdapter {
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
    
    /// @notice Verify soul binding proof
    function verifySoulBinding(
        bytes calldata proof,
        bytes32 soulBinding
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = uint256(soulBinding);
        return verifier.verify(proof, inputs);
    }
    
    function verify(
        bytes calldata proof,
        bytes32 preStateRoot,
        bytes32 postStateRoot,
        bytes32 invariantHash
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = uint256(preStateRoot);
        inputs[1] = uint256(postStateRoot);
        inputs[2] = uint256(invariantHash);
        
        return verifier.verify(proof, inputs);
    }
}
