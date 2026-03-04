// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IBaseBridgeAdapter
 * @author ZASEON
 * @notice Interface for the Base bridge adapter
 * @dev Enables cross-chain interoperability between ZASEON and Base (Coinbase L2)
 *
 * BASE CONCEPTS:
 * - Wei: Standard EVM 18-decimal precision (ETH native)
 * - OP Stack: Base runs on Optimism's OP Stack (Bedrock)
 * - Fault Proofs: Shared with Optimism Superchain dispute game
 * - Sequencer: Coinbase-operated sequencer (decentralizing via Superchain)
 * - L1 derivation: Blocks derived from L1 data availability
 * - SuperchainERC20: Cross-chain token messaging within Superchain
 * - Chain ID: 8453 (Base Mainnet)
 * - Finality: ~7 days (fault proof window), instant for L2 soft confirmation
 * - Block time: ~2 seconds
 */
interface IBaseBridgeAdapter {
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }
    enum WithdrawalStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        REFUNDED,
        FAILED
    }
    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }
    enum BaseBridgeOpType {
        ETH_TRANSFER,
        ERC20_TRANSFER,
        L1_MESSAGE,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address baseBridgeContract;
        address wrappedBase;
        address l1OutputOracle;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct BaseDeposit {
        bytes32 depositId;
        bytes32 l2TxHash;
        address l2Sender;
        address evmRecipient;
        uint256 amountWei;
        uint256 netAmountWei;
        uint256 fee;
        DepositStatus status;
        uint256 l2BlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct BaseWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address l2Recipient;
        uint256 amountWei;
        bytes32 l2TxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct BaseEscrow {
        bytes32 escrowId;
        address evmParty;
        address l2Party;
        uint256 amountWei;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct L2OutputProposal {
        uint256 l2BlockNumber;
        bytes32 outputRoot;
        bytes32 stateRoot;
        bytes32 withdrawalStorageRoot;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct OutputRootProof {
        bytes32 version;
        bytes32 stateRoot;
        bytes32 messagePasserStorageRoot;
        bytes32 latestBlockhash;
    }

    error ZeroAddress();
    error AmountBelowMinimum(uint256 amount, uint256 minimum);
    error AmountAboveMaximum(uint256 amount, uint256 maximum);
    error DepositNotFound(bytes32 depositId);
    error DepositAlreadyCompleted(bytes32 depositId);
    error DepositNotVerified(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalNotPending(bytes32 withdrawalId);
    error RefundTooEarly(uint256 current, uint256 earliest);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error EscrowTimelockNotMet();
    error InvalidPreimage(bytes32 expected, bytes32 actual);
    error InvalidTimelockRange();
    error InvalidAmount();
    error L2TxAlreadyUsed(bytes32 txHash);
    error L2BlockNotVerified(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address baseBridgeContract,
        address wrappedBase,
        address l1OutputOracle
    );
    event L2OutputVerified(
        uint256 l2BlockNumber,
        bytes32 outputRoot,
        bytes32 stateRoot
    );
    event BaseDepositInitiated(
        bytes32 indexed depositId,
        bytes32 l2TxHash,
        address l2Sender,
        address indexed evmRecipient,
        uint256 amountWei
    );
    event BaseDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountWei
    );
    event BaseWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address l2Recipient,
        uint256 amountWei
    );
    event BaseWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 l2TxHash
    );
    event BaseWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountWei
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address l2Party,
        uint256 amountWei,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );
    event FeesWithdrawn(address indexed treasury, uint256 amount);

    function configure(
        address baseBridgeContract,
        address wrappedBase,
        address l1OutputOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitL2Output(
        uint256 l2BlockNumber,
        bytes32 outputRoot,
        bytes32 stateRoot,
        bytes32 withdrawalStorageRoot,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateBaseDeposit(
        bytes32 l2TxHash,
        address l2Sender,
        address evmRecipient,
        uint256 amountWei,
        uint256 l2BlockNumber,
        OutputRootProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeBaseDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address l2Recipient,
        uint256 amountWei
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 l2TxHash,
        OutputRootProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address l2Party,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    function cancelEscrow(bytes32 escrowId) external;

    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    function getDeposit(
        bytes32 depositId
    ) external view returns (BaseDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BaseWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (BaseEscrow memory);

    function getL2Output(
        uint256 l2BlockNumber
    ) external view returns (L2OutputProposal memory);

    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory);

    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory);

    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory);
}
