// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../Groth16VerifierBN254.sol";

/**
 * @title PedersenCommitmentAdapter
 * @notice Adapter for Pedersen commitment proof verification
 */
contract PedersenCommitmentAdapter {
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
    
    /// @notice Verify commitment ownership
    function verifyCommitment(
        bytes calldata proof,
        bytes32 commitment,
        bytes32 ownerPubkey
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(commitment);
        inputs[1] = uint256(ownerPubkey);
        return verifier.verify(proof, inputs);
    }
    
    function verify(
        bytes calldata proof,
        bytes32 commitment,
        uint256 value,
        bytes32 blinding
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = uint256(commitment);
        inputs[1] = value;
        inputs[2] = uint256(blinding);
        
        return verifier.verify(proof, inputs);
    }
}
