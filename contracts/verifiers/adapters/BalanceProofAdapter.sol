// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../Groth16VerifierBN254.sol";

/**
 * @title BalanceProofAdapter
 * @notice Adapter for balance proof verification
 */
contract BalanceProofAdapter {
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
        uint256 balance,
        uint256 minRequired,
        bytes32 commitment
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = balance;
        inputs[1] = minRequired;
        inputs[2] = uint256(commitment);
        
        return verifier.verify(proof, inputs);
    }
}
