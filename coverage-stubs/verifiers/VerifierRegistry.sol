// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

interface IProofVerifier {
    function verify(bytes calldata, uint256[] calldata) external view returns (bool);
    function verifySingle(bytes calldata, uint256) external view returns (bool);
    function getPublicInputCount() external view returns (uint256);
    function isReady() external view returns (bool);
}

// STUB for coverage only
contract VerifierRegistry is AccessControl {
    bytes32 public constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant VALIDITY_PROOF = keccak256("VALIDITY_PROOF");
    bytes32 public constant POLICY_PROOF = keccak256("POLICY_PROOF");
    bytes32 public constant NULLIFIER_PROOF = keccak256("NULLIFIER_PROOF");
    bytes32 public constant STATE_TRANSITION_PROOF = keccak256("STATE_TRANSITION_PROOF");
    bytes32 public constant CROSS_DOMAIN_PROOF = keccak256("CROSS_DOMAIN_PROOF");
    bytes32 public constant RANGE_PROOF = keccak256("RANGE_PROOF");
    bytes32 public constant MEMBERSHIP_PROOF = keccak256("MEMBERSHIP_PROOF");

    mapping(bytes32 => address) public verifiers;
    bytes32[] public registeredTypes;
    mapping(bytes32 => bool) public isTypeRegistered;
    uint256 public totalVerifiers;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerVerifier(bytes32 proofType, address verifier) external {}
    function updateVerifier(bytes32 proofType, address newVerifier) external {}
    function removeVerifier(bytes32 proofType) external {}
    function getVerifier(bytes32 proofType) external view returns (address) { return verifiers[proofType]; }
    function hasVerifier(bytes32 proofType) external view returns (bool) { return isTypeRegistered[proofType]; }
    function getAllProofTypes() external view returns (bytes32[] memory) { return registeredTypes; }
    function verifyProof(bytes32 proofType, bytes calldata, uint256[] calldata) external view returns (bool) { return true; }
    function verifySingleInput(bytes32 proofType, bytes calldata, uint256) external view returns (bool) { return true; }
}
