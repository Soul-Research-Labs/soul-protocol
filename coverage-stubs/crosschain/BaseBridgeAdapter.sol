// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract BaseBridgeAdapter is AccessControl {
    struct AttestationSync {
        bytes32 attestationId;
        address subject;
        bytes32 schemaId;
        bytes data;
        uint256 timestamp;
        bool synced;
    }

    mapping(bytes32 => AttestationSync) public attestations;
    mapping(bytes32 => uint256) public confirmedStateRoots;
    mapping(bytes32 => bool) public isProofRelayed;
    
    uint256 public messageNonce;
    uint64 public cctpNonce;
    uint256 public totalBridged;
    uint256 public totalUSDC;

    error ProofAlreadyRelayed();
    error InsufficientGasLimit();
    error InvalidAmount();
    error InvalidChainId();
    error CCTPNotConfigured();

    constructor(address, address, address, address, bool) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    receive() external payable {}

    function setL2Target(address) external {}
    function setMessenger(address, bool) external {}
    function configureCCTP(address, address) external {}
    
    function receiveProofFromL1(bytes32 hash, bytes calldata, bytes calldata, uint256) external {
        if (isProofRelayed[hash]) revert ProofAlreadyRelayed();
        isProofRelayed[hash] = true;
    }
    
    function sendProofToL2(bytes32, bytes calldata, bytes calldata, uint256 gasLimit) external payable {
        if (paused) revert("Paused");
        if (gasLimit < 100000) revert InsufficientGasLimit();
        messageNonce++;
        totalBridged += msg.value;
    }

    function initiateUSDCTransfer(address, uint256 amount, uint32) external {
        if (amount == 0) revert InvalidAmount();
        cctpNonce++;
        totalUSDC += amount;
    }

    function getStats() external view returns (uint256, uint256, uint256, uint256, uint256) {
        return (0, 0, totalBridged, totalUSDC, 0);
    }
    
    function bridgeAsset(uint256, address, uint256) external payable {}
    function getAttestation(bytes32 attestationId) external view returns (AttestationSync memory) { return attestations[attestationId]; }
    
    function syncAttestation(bytes32 id, address subj, bytes32 schema, bytes calldata data) external {
        attestations[id] = AttestationSync(id, subj, schema, data, block.timestamp, true);
    }

    function initiateWithdrawal(bytes32) external payable {}
    
    function emergencyWithdraw(address to, uint256 amount) external {
        (bool s,) = to.call{value: amount}("");
        require(s);
    }

    function receiveStateFromL1(bytes32 root, uint256 blockNum) external {
        confirmedStateRoots[root] = blockNum;
    }
    
    bool public paused;
    function pause() external { paused = true; }
    function unpause() external { paused = false; }
}
