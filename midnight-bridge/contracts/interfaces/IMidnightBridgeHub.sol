// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMidnightBridgeHub
 * @notice Interface for the Midnight Bridge Hub contract
 */
interface IMidnightBridgeHub {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct Lock {
        bytes32 lockId;
        address token;
        uint256 amount;
        bytes32 commitment;
        bytes32 midnightRecipient;
        address ethSender;
        uint64 createdAt;
        uint64 unlockDeadline;
        LockStatus status;
    }

    struct Claim {
        bytes32 claimId;
        bytes32 nullifier;
        address token;
        uint256 amount;
        address ethRecipient;
        uint64 claimedAt;
    }

    struct MidnightProofBundle {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 merkleRoot;
        bytes proof;
        uint64 midnightBlock;
        bytes32 stateRoot;
    }

    struct MidnightState {
        bytes32 depositRoot;
        bytes32 nullifierRoot;
        uint64 blockNumber;
        uint64 timestamp;
        bytes32 stateHash;
    }

    enum LockStatus {
        None,
        Pending,
        Confirmed,
        Claimed,
        Refunded
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event LockCreated(
        bytes32 indexed lockId,
        address indexed sender,
        address indexed token,
        uint256 amount,
        bytes32 commitment,
        bytes32 midnightRecipient
    );

    event LockConfirmed(bytes32 indexed lockId, bytes32 midnightTxHash);

    event ClaimProcessed(
        bytes32 indexed claimId,
        bytes32 indexed nullifier,
        address indexed recipient,
        address token,
        uint256 amount
    );

    event LockRefunded(
        bytes32 indexed lockId,
        address indexed sender,
        uint256 amount
    );

    event MidnightStateUpdated(
        bytes32 depositRoot,
        bytes32 nullifierRoot,
        uint64 blockNumber,
        bytes32 stateHash
    );

    event RelayerRegistered(address indexed relayer, uint256 bond);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        bytes32 reason
    );
    event AssetWhitelisted(address indexed asset, bool status);

    // =========================================================================
    // FUNCTIONS
    // =========================================================================

    // Lock Functions
    function lockETHForMidnight(
        bytes32 commitment,
        bytes32 midnightRecipient
    ) external payable returns (bytes32 lockId);

    function lockTokenForMidnight(
        address token,
        uint256 amount,
        bytes32 commitment,
        bytes32 midnightRecipient
    ) external returns (bytes32 lockId);

    // Claim Functions
    function claimFromMidnight(
        MidnightProofBundle calldata proof,
        address token,
        uint256 amount,
        address recipient
    ) external;

    // Refund Functions
    function refundLock(bytes32 lockId) external;

    // View Functions
    function getLock(bytes32 lockId) external view returns (Lock memory);

    function getClaim(bytes32 claimId) external view returns (Claim memory);

    function isNullifierUsed(bytes32 nullifier) external view returns (bool);

    function getMidnightState()
        external
        view
        returns (
            bytes32 depositRoot,
            bytes32 nullifierRoot,
            uint64 blockNumber,
            uint64 timestamp,
            bytes32 stateHash
        );

    function getTVL(address token) external view returns (uint256);

    function whitelistedAssets(address token) external view returns (bool);

    function isActiveRelayer(address relayer) external view returns (bool);

    // Admin Functions
    function updateMidnightState(
        bytes32 depositRoot,
        bytes32 nullifierRoot,
        uint64 blockNumber,
        bytes32 stateHash
    ) external;

    function whitelistAsset(address asset, bool status) external;

    function registerRelayer() external payable;

    function pause() external;

    function unpause() external;
}
