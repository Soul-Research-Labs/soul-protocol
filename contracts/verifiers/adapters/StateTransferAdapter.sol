// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../Groth16VerifierBN254.sol";

/**
 * @title StateTransferAdapter
 * @notice Adapter for state transfer proof verification
 */
contract StateTransferAdapter {
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
        bytes32 oldStateRoot,
        bytes32 newStateRoot,
        bytes32 transferHash
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = uint256(oldStateRoot);
        inputs[1] = uint256(newStateRoot);
        inputs[2] = uint256(transferHash);
        
        return verifier.verify(proof, inputs);
    }
}
