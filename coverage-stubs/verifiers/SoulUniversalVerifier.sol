// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

// STUB for coverage only
contract SoulUniversalVerifier is Ownable {
    enum ProofSystem { Groth16, Plonk, Noir, SP1, Plonky3, Jolt, Binius, Recursive }

    struct UniversalProof {
        ProofSystem system;
        bytes32 vkeyOrCircuitHash;
        bytes32 publicInputsHash;
        bytes proof;
    }

    struct VerifierConfig {
        address verifier;
        bool active;
        uint256 gasLimit;
        uint256 totalVerified;
    }

    mapping(ProofSystem => VerifierConfig) public verifiers;
    mapping(bytes32 => bool) public verifiedProofs;
    uint256 public totalVerified;
    uint256 public defaultGasLimit = 500000;

    constructor() Ownable(msg.sender) {}

    function registerVerifier(ProofSystem, address, uint256) external {}
    function deactivateVerifier(ProofSystem) external {}
    function updateGasLimit(ProofSystem, uint256) external {}
    function verify(UniversalProof calldata, bytes calldata) external returns (bool, uint256) { return (true, 0); }
    function batchVerify(UniversalProof[] calldata, bytes[] calldata) external returns (bool[] memory) { return new bool[](0); }
    function isVerified(bytes32) external view returns (bool) { return true; }
    function getVerifier(ProofSystem) external view returns (VerifierConfig memory) { return verifiers[ProofSystem.Groth16]; }
    function getStats() external view returns (ProofSystem[] memory, uint256[] memory, bool[] memory) { 
        return (new ProofSystem[](0), new uint256[](0), new bool[](0)); 
    }
}
