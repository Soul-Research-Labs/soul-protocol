// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract StarknetProofVerifier is AccessControl {
    struct FRIConfig { uint256 domainSize; uint256 blowupFactor; uint256 numQueries; uint256 foldingFactor; uint256 lastLayerDegBound; uint256 numLayers; }
    struct Proof { bytes32 proofId; bytes32 programHash; uint8 proofType; bytes32 traceCommitment; bytes32 constraintCommitment; bytes32 compositionCommitment; bytes32[] friCommitments; uint256[] publicInputs; bool verified; uint256 submittedAt; }

    mapping(bytes32 => FRIConfig) public programConfigs;
    mapping(bytes32 => Proof) public proofs;
    uint256 public totalProofs;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerProgram(bytes32, FRIConfig calldata) external {}
    function submitProof(bytes32, uint8, bytes32, bytes32, bytes32, bytes32[] calldata, uint256[] calldata) external returns (bytes32) { return bytes32(0); }
    function getStats() external view returns (uint256[] memory) { return new uint256[](0); }
}
