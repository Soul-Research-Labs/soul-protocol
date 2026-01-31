// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract L2ProofRouter is AccessControl {
    enum ProofType {
        GROTH16, PLONK, STARK, BULLETPROOF, NOVA_IVC, RECURSIVE, STATE_PROOF, NULLIFIER_PROOF
    }

    struct Proof {
        bytes32 proofId;
        ProofType proofType;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes proofData;
        bytes publicInputs;
        address submitter;
        uint256 timestamp;
        uint256 gasEstimate;
        bool verified;
        bytes32 nullifierBinding;
    }

    mapping(bytes32 => Proof) public proofs;

    constructor(address, address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function routeProof(uint256, bytes32, bytes calldata) external {}
    function submitProof(ProofType, uint256, bytes calldata, bytes calldata, bytes32) external returns (bytes32) { return bytes32(0); }
    function getProof(bytes32 proofId) external view returns (Proof memory) { return proofs[proofId]; }
    function getActiveBatch(uint256) external view returns (bytes32) { return bytes32(0); }
    function getCacheSize() external view returns (uint256) { return 0; }
}
