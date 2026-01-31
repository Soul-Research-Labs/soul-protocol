// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract VerifierHub is AccessControl, Pausable {
    bytes32 public constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");

    enum CircuitType {
        StateCommitment,
        StateTransfer,
        MerkleProof,
        CrossChainProof,
        ComplianceProof
    }

    struct VerifierInfo {
        address verifier;
        uint256 version;
        uint256 deployedAt;
        bool active;
        uint256 totalVerifications;
        uint256 totalFailures;
    }

    mapping(CircuitType => VerifierInfo) public verifiers;
    mapping(CircuitType => mapping(uint256 => address)) public historicalVerifiers;
    mapping(bytes32 => bool) public verifiedProofs;
    bool public replayProtectionEnabled;

    event VerifierRegistered(CircuitType indexed circuitType, address indexed verifier, uint256 version);
    event VerifierDeactivated(CircuitType indexed circuitType, address indexed verifier);
    event ProofVerified(CircuitType indexed circuitType, bytes32 indexed proofHash, bool success);
    event ReplayProtectionToggled(bool enabled);

    error VerifierNotRegistered(CircuitType circuitType);
    error VerifierInactive(CircuitType circuitType);
    error ZeroAddress();
    error ProofAlreadyUsed(bytes32 proofHash);
    error VerificationFailed();

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerVerifier(CircuitType, address) external {}
    function deactivateVerifier(CircuitType) external {}
    function setReplayProtection(bool) external {}
    function pause() external {}
    function unpause() external {}
    function verifyProof(CircuitType, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function verifyStateCommitment(uint256[8] calldata, uint256, uint256) external returns (bool) { return true; }
    function verifyStateTransfer(uint256[8] calldata, uint256, uint256, uint256, uint256, uint256) external returns (bool) { return true; }
    function getVerifierInfo(CircuitType) external view returns (VerifierInfo memory) { return verifiers[CircuitType.StateCommitment]; }
    function isVerifierActive(CircuitType) external view returns (bool) { return true; }
    function getHistoricalVerifier(CircuitType, uint256) external view returns (address) { return address(0); }
    function isProofUsed(bytes32) external view returns (bool) { return false; }
}
