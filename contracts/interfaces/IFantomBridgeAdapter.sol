// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IFantomBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Fantom/Sonic bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Fantom/Sonic
 *
 * FANTOM/SONIC CONCEPTS:
 * - Wei: Standard EVM 18-decimal precision (FTM native)
 * - Lachesis: Asynchronous BFT DAG consensus (original Fantom)
 * - Sonic: Next-gen Fantom with 10k TPS, sub-second finality
 * - SonicVM: Optimized EVM execution engine
 * - FeeM: Fee monetization for dApp developers
 * - Sonic Gateway: Official Fantom→Sonic bridge
 * - Chain ID: 250 (Opera), 146 (Sonic)
 * - Finality: ~1 second (aBFT)
 * - Block time: ~1 second
 */
interface IFantomBridgeAdapter {
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
    enum FantomBridgeOpType {
        FTM_TRANSFER,
        ERC20_TRANSFER,
        SONIC_GATEWAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address fantomBridgeContract;
        address wrappedFTM;
        address lachesisVerifier;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct FTMDeposit {
        bytes32 depositId;
        bytes32 ftmTxHash;
        address ftmSender;
        address evmRecipient;
        uint256 amountWei;
        uint256 netAmountWei;
        uint256 fee;
        DepositStatus status;
        uint256 ftmBlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct FTMWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address ftmRecipient;
        uint256 amountWei;
        bytes32 ftmTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct FTMEscrow {
        bytes32 escrowId;
        address evmParty;
        address ftmParty;
        uint256 amountWei;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct LachesisEvent {
        uint256 eventId;
        uint256 epoch;
        bytes32 eventHash;
        bytes32 parentHash;
        bytes32 stateRoot;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct DAGStateProof {
        bytes32[] merkleProof;
        bytes32 stateRoot;
        bytes value;
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
    error FTMTxAlreadyUsed(bytes32 txHash);
    error FTMBlockNotVerified(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address fantomBridgeContract,
        address wrappedFTM,
        address lachesisVerifier
    );
    event LachesisEventVerified(
        uint256 eventId,
        uint256 epoch,
        bytes32 eventHash
    );
    event FTMDepositInitiated(
        bytes32 indexed depositId,
        bytes32 ftmTxHash,
        address ftmSender,
        address indexed evmRecipient,
        uint256 amountWei
    );
    event FTMDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountWei
    );
    event FTMWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address ftmRecipient,
        uint256 amountWei
    );
    event FTMWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 ftmTxHash
    );
    event FTMWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountWei
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address ftmParty,
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
        address fantomBridgeContract,
        address wrappedFTM,
        address lachesisVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitLachesisEvent(
        uint256 eventId,
        uint256 epoch,
        bytes32 eventHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateFTMDeposit(
        bytes32 ftmTxHash,
        address ftmSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 ftmBlockNumber,
        DAGStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeFTMDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address ftmRecipient,
        uint256 amountWei
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 ftmTxHash,
        DAGStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address ftmParty,
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
    ) external view returns (FTMDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (FTMWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (FTMEscrow memory);

    function getLachesisEvent(
        uint256 eventId
    ) external view returns (LachesisEvent memory);

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
