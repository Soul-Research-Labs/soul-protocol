// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// STUB for coverage only
contract SoulThresholdSignature is AccessControl, ReentrancyGuard {
    bytes32 public constant SIGNER_ROLE = 0xe2f4eaae4a9751e85a3e4a7b9587827a877f29914755229b07a7b2da98285f70;
    bytes32 public constant COORDINATOR_ROLE = 0x2e8b98eef02e8df3bd27d1270ded3bea3d14db99c5234c7b14001a7fff957bcc;

    struct SignerInfo { address signer; bytes32 publicKeyShare; uint256 index; uint256 joinedAt; uint256 signatureCount; bool active; }
    struct SigningSession { bytes32 messageHash; bytes32 sessionId; uint256 startedAt; uint256 expiresAt; address[] participants; mapping(address => bytes32) commitments; mapping(address => bytes) partialSignatures; uint256 commitmentCount; uint256 signatureCount; bool completed; bytes aggregatedSignature; }
    struct ThresholdConfig { uint256 threshold; uint256 totalSigners; uint256 sessionTimeout; bytes32 groupPublicKey; }

    ThresholdConfig public config;
    mapping(address => SignerInfo) public signers;
    address[] public signerList;
    mapping(bytes32 => bool) public executedMessages;
    uint256 public sessionNonce;
    mapping(bytes32 => bytes32) public messageToSession;

    event SignerAdded(address indexed signer, uint256 index, bytes32 publicKeyShare);
    event SessionStarted(bytes32 indexed sessionId, bytes32 messageHash, address[] participants);
    event MessageExecuted(bytes32 indexed messageHash, bytes32 indexed sessionId);

    error InvalidThreshold();

    constructor(uint256 _t, uint256 _st) {
        config.threshold = _t;
        config.sessionTimeout = _st;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function addSigner(address s, bytes32 p) external {
        signers[s] = SignerInfo(s, p, signerList.length, block.timestamp, 0, true);
        signerList.push(s);
        config.totalSigners++;
    }
    function removeSigner(address) external {}
    function updateThreshold(uint256) external {}
    function setGroupPublicKey(bytes32) external {}
    function startSession(bytes32 m, address[] calldata p) external returns (bytes32 id) {
        id = keccak256(abi.encode(m, block.timestamp));
        messageToSession[m] = id;
        return id;
    }
    function submitCommitment(bytes32, bytes32) external {}
    function submitPartialSignature(bytes32, bytes calldata) external {}
    function getSessionStatus(bytes32) external view returns (bytes32, uint256, uint256, bool, bool) { return (bytes32(0), 0, 0, false, false); }
    function getAggregatedSignature(bytes32) external pure returns (bytes memory) { return new bytes(0); }
    function verifyThresholdSignature(bytes32, bytes calldata) external pure returns (bool) { return true; }
    function executeWithSignature(address, bytes calldata, bytes32, bytes calldata) external returns (bytes memory) { return new bytes(0); }
    function getActiveSigners() external view returns (address[] memory) { return signerList; }
    function getSignerInfo(address s) external view returns (SignerInfo memory) { return signers[s]; }
    function getConfig() external view returns (uint256, uint256, uint256) { return (config.threshold, config.totalSigners, config.sessionTimeout); }
}
