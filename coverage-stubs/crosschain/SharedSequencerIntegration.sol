// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract SharedSequencerIntegration is ReentrancyGuard, AccessControl, Pausable {
    error InvalidSequencer();
    error SequencerNotActive();
    error InvalidCommitment();
    error CommitmentExpired();
    error InvalidProof();
    error TransactionAlreadyIncluded();
    error InvalidChainSet();
    error QuorumNotReached();
    error InclusionFailed();
    error InvalidSignature();
    error TransactionNotFound();

    enum SequencerType { ESPRESSO, ASTRIA, RADIUS, CUSTOM }
    enum BundleStatus { PENDING, COMMITTED, FINALIZED, FAILED }

    struct AtomicTransaction {
        bytes32 transactionHash;
        uint256 targetChainId;
        address target;
        bytes data;
        uint256 value;
        uint256 gasLimit;
        bytes32 nullifierBinding;
    }

    struct InclusionProof {
        bytes32 transactionHash;
        uint256 chainId;
        bytes32[] merkleProof;
        uint256 leafIndex;
        bytes32 blockHash;
        uint64 blockNumber;
    }

    struct EspressoCommitment { uint64 blockHeight; bytes32 blockCommitment; bytes32 namespaceRoot; bytes signature; }
    struct AstriaCommitment { uint64 sequenceHeight; bytes32 actionRoot; bytes32 rollupDataRoot; bytes signature; }
    struct RadiusCommitment { uint64 encryptedSlot; bytes32 pvdeCommitment; bytes32 decryptionKey; bytes signature; }

    constructor(address _admin, address _pilHub) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    function registerSequencer(address, SequencerType, uint256[] calldata, uint256, address[] calldata) external {}
    function deactivateSequencer(address) external {}
    function submitAtomicBundle(AtomicTransaction[] calldata, address) external returns (bytes32) { return bytes32(0); }
    function commitBundleEspresso(bytes32, EspressoCommitment calldata) external {}
    function commitBundleAstria(bytes32, AstriaCommitment calldata) external {}
    function commitBundleRadius(bytes32, RadiusCommitment calldata) external {}
    function finalizeBundle(bytes32, InclusionProof[] calldata) external {}
    function requestOrderedMessage(uint256, bytes32, address) external returns (uint256) { return 0; }
    
    function getSequencerCount() external view returns (uint256) { return 0; }
    function getActiveSequencers() external view returns (address[] memory) { return new address[](0); }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }
}
