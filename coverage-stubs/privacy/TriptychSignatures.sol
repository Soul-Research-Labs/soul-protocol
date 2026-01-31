// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
contract TriptychSignatures {
    struct TriptychProof { bytes32 L; bytes32 R; bytes32 K; bytes32[] f; bytes32[] za; bytes32[] zb; }
    
    function verify(bytes32 message, bytes32[] calldata ring, bytes32 keyImage, bytes calldata proof) external pure returns (bool) { return true; }
    function verifyBatch(bytes32[] calldata messages, bytes32[][] calldata rings, bytes32[] calldata keyImages, bytes[] calldata proofs) external pure returns (bool[] memory r) { return new bool[](messages.length); }
    function link(bytes32 keyImage1, bytes32 keyImage2) external pure returns (bool) { return true; }
}
