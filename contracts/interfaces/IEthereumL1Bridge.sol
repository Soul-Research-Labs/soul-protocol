// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IEthereumL1Bridge
 * @notice Interface for Ethereum L1 Bridge
 */
interface IEthereumL1Bridge {
    /// @notice Rollup types
    enum RollupType {
        OPTIMISTIC,
        ZK_ROLLUP,
        VALIDIUM
    }

    /// @notice Commitment status
    enum CommitmentStatus {
        PENDING,
        CHALLENGED,
        FINALIZED,
        REJECTED
    }

    /// @notice L2 chain configuration
    struct L2Config {
        uint256 chainId;
        string name;
        RollupType rollupType;
        address canonicalBridge;
        address messenger;
        address stateCommitmentChain;
        uint256 challengePeriod;
        uint256 confirmationBlocks;
        bool enabled;
        uint256 gasLimit;
        uint256 lastSyncedBlock;
    }

    /// @notice State commitment
    struct StateCommitment {
        bytes32 commitmentId;
        uint256 sourceChainId;
        bytes32 stateRoot;
        bytes32 proofRoot;
        uint256 blockNumber;
        uint256 timestamp;
        CommitmentStatus status;
        uint256 challengeDeadline;
        address submitter;
    }

    /// @notice Deposit record
    struct Deposit {
        bytes32 depositId;
        address depositor;
        uint256 targetChainId;
        address token;
        uint256 amount;
        bytes32 commitment;
        uint256 timestamp;
        bool claimed;
    }

    /// @notice Withdrawal record
    struct Withdrawal {
        bytes32 withdrawalId;
        address recipient;
        uint256 sourceChainId;
        address token;
        uint256 amount;
        bytes32 nullifier;
        bytes32[] proof;
        uint256 timestamp;
        bool finalized;
        bool claimed;
    }

    // Events
    event L2ChainConfigured(
        uint256 indexed chainId,
        string name,
        RollupType rollupType,
        address canonicalBridge
    );

    event StateCommitmentSubmitted(
        bytes32 indexed commitmentId,
        uint256 indexed sourceChainId,
        bytes32 stateRoot,
        address submitter
    );

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed depositor,
        uint256 indexed targetChainId,
        address token,
        uint256 amount,
        bytes32 commitment
    );

    event WithdrawalFinalized(
        bytes32 indexed withdrawalId,
        address recipient,
        uint256 amount
    );

    // Functions
    function submitStateCommitment(
        uint256 sourceChainId,
        bytes32 stateRoot,
        bytes32 proofRoot,
        uint256 blockNumber
    ) external payable;

    function challengeCommitment(bytes32 commitmentId, bytes32 reason) external;

    function finalizeCommitment(bytes32 commitmentId) external;

    function depositETH(
        uint256 targetChainId,
        bytes32 commitment
    ) external payable;

    function initiateWithdrawal(
        uint256 sourceChainId,
        uint256 amount,
        bytes32 nullifier,
        bytes32[] calldata proof
    ) external;

    function finalizeWithdrawal(bytes32 withdrawalId) external;

    function claimWithdrawal(bytes32 withdrawalId) external;

    function relayProof(
        uint256 sourceChainId,
        bytes32 proofHash,
        bytes32 stateRoot,
        bytes calldata proofData
    ) external;

    function getSupportedChainIds() external view returns (uint256[] memory);

    function getL2Config(
        uint256 chainId
    ) external view returns (L2Config memory);

    function isChainSupported(uint256 chainId) external view returns (bool);

    function getLatestStateRoot(
        uint256 chainId
    ) external view returns (bytes32);

    function isNullifierUsed(bytes32 nullifier) external view returns (bool);
}
