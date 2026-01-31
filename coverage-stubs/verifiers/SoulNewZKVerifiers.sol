// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
contract SoulNewZKVerifiers {
    function verifyProof(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) { return true; }
    function verifyBatch(bytes[] calldata proofs, bytes32[][] calldata publicInputs) external pure returns (bool) { return true; }
    function verifyRecursive(bytes calldata proof, bytes32[] calldata publicInputs, bytes32 vkey) external pure returns (bool) { return true; }
}
