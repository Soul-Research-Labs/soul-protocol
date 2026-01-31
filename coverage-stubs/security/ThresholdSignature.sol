// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract ThresholdSignature is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant COORDINATOR_ROLE = keccak256("COORDINATOR_ROLE");
    bytes32 public constant KEY_MANAGER_ROLE = keccak256("KEY_MANAGER_ROLE");

    enum SignatureType { ECDSA_THRESHOLD, BLS_THRESHOLD, SCHNORR_THRESHOLD, FROST }
    enum KeyGenStatus { NOT_STARTED, ROUND_1, ROUND_2, ROUND_3, COMPLETED, FAILED }
    enum SigningStatus { PENDING, ROUND_1, ROUND_2, COMPLETED, FAILED, EXPIRED }

    struct SignerInfo {
        address signer;
        bytes publicKey;
        uint256 index;
        bool active;
        uint256 participations;
        uint256 successfulSigs;
        uint256 failedSigs;
        uint256 lastActive;
    }

    struct VerificationResult {
        bool valid;
        bytes32 messageHash;
        bytes32 groupId;
        uint256 signerCount;
        uint256 verifiedAt;
    }

    mapping(address => SignerInfo) public signerInfo;
    mapping(bytes32 => VerificationResult) public verificationResults;
    bytes32[] public groupIds;
    bytes32[] public sessionIds;
    address[] public registeredSigners;
    mapping(bytes32 => mapping(uint256 => bool)) public usedNonces;
    uint256 public totalGroups;
    uint256 public totalSignatures;
    uint256 public totalVerifications;

    error GroupNotFound();
    error SessionNotFound();
    error InvalidThreshold();
    error TooManySigners();
    error NotASigner();
    error AlreadySigned();
    error SessionExpired();
    error DKGNotCompleted();
    error DKGAlreadyCompleted();
    error InvalidRound();
    error InsufficientSignatures();
    error InvalidSignature();
    error SignerAlreadyRegistered();
    error GroupNotActive();
    error InvalidPublicKey();
    error ZeroAddress();

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function createGroup(SignatureType, uint256, address[] calldata) external returns (bytes32) { return bytes32(0); }
    function startDKG(bytes32) external {}
    function submitDKGCommitment(bytes32, bytes calldata) external {}
    function submitEncryptedShare(bytes32, address, bytes calldata) external {}
    function completeDKG(bytes32, bytes calldata, bytes[] calldata) external {}
    function createSigningSession(bytes32, bytes32) external returns (bytes32) { return bytes32(0); }
    function submitPartialSignature(bytes32, bytes calldata) external {}
    function aggregateSignatures(bytes32) external returns (bytes memory) { return ""; }
    function verifyAggregatedSignature(bytes32) external returns (bool) { return true; }
    
    function getGroup(bytes32) external view returns (SignatureType, uint256, uint256, bytes memory, KeyGenStatus, bool) {
        return (SignatureType.ECDSA_THRESHOLD, 0, 0, "", KeyGenStatus.NOT_STARTED, false);
    }
    function getGroupSigners(bytes32) external view returns (address[] memory) { return new address[](0); }
    function getSession(bytes32) external view returns (bytes32, bytes32, SigningStatus, uint256, bytes memory, bool) {
        return (bytes32(0), bytes32(0), SigningStatus.PENDING, 0, "", false);
    }
    function hasSignerSubmitted(bytes32, address) external view returns (bool) { return false; }
    function getActiveGroups() external view returns (bytes32[] memory) { return new bytes32[](0); }
    
    function deactivateGroup(bytes32) external {}
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
}
