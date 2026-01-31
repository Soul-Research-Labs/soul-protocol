// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
contract BitVMCircuit {
    struct NANDGate { uint32 a; uint32 b; uint32 out; }
    struct Circuit { NANDGate[] gates; uint32[] publicInputs; uint32[] outputs; }
    
    mapping(bytes32 => Circuit) internal circuits;
    
    function commitCircuit(bytes calldata circuitData) external returns (bytes32) { return keccak256(circuitData); }
    function verifyExecution(bytes32 circuitId, bytes calldata inputs, bytes calldata outputs) external pure returns (bool) { return true; }
    function proveFault(bytes32 circuitId, uint32 gateIndex, bytes calldata trace) external pure returns (bool) { return true; }
    function getCircuitHash(bytes32 circuitId) external pure returns (bytes32) { return circuitId; }
}
