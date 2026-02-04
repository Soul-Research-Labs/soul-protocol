// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulStateExpiry
/// @notice Interface for EIP-7736 compatible state expiry management
interface ISoulStateExpiry {
    struct ExpiringState {
        bytes32 stateHash;
        uint64 createdAt;
        uint64 lastAccessed;
        uint64 expiryEpoch;
        bool isActive;
        bool isResurrected;
    }

    struct ResurrectionProof {
        bytes32 stateHash;
        bytes32 archiveRoot;
        bytes32[] merkleProof;
        bytes32 leafValue;
        uint256 archiveEpoch;
    }

    struct ExpiringCommitment {
        bytes32 commitment;
        bytes32 nullifierHash;
        uint64 createdEpoch;
        uint64 expiryEpoch;
        bool isSpent;
        bool isExpired;
    }

    struct KeepAlive {
        address stealthAddress;
        bytes32 viewingKeyHash;
        uint64 lastKeepAlive;
        uint64 nextRequired;
    }

    event StateCreated(
        bytes32 indexed stateKey,
        bytes32 stateHash,
        uint64 expiryEpoch
    );

    event StateResurrected(
        bytes32 indexed stateKey,
        bytes32 archiveRoot,
        uint256 newExpiryEpoch
    );

    event CommitmentCreated(bytes32 indexed commitment, uint64 expiryEpoch);

    event KeepAliveSubmitted(
        address indexed stealthAddress,
        uint64 nextRequired
    );

    function createState(
        bytes32 stateKey,
        bytes32 stateHash
    ) external returns (uint64 expiryEpoch);

    function accessState(bytes32 stateKey) external returns (bytes32 stateHash);

    function resurrectState(
        bytes32 stateKey,
        ResurrectionProof calldata proof
    ) external payable;

    function createExpiringCommitment(
        bytes32 commitment,
        bytes32 nullifierHash
    ) external returns (uint64 expiryEpoch);

    function spendCommitment(bytes32 commitment, bytes32 nullifier) external;

    function resurrectCommitment(
        bytes32 commitment,
        ResurrectionProof calldata proof
    ) external payable;

    function submitKeepAlive(
        address stealthAddress,
        bytes32 viewingKeyHash
    ) external;

    function isStealthAddressActive(
        address stealthAddress
    ) external view returns (bool isActive);

    function getCurrentEpoch() external view returns (uint256);

    function isHistoricalDataAvailable(
        uint256 blockNumber
    ) external view returns (bool available);

    function getArchiveLocation(
        uint256 blockNumber
    ) external pure returns (string memory archiveURI);
}
