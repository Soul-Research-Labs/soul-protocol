// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title INEARBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the NEAR Protocol bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and NEAR
 *
 * NEAR CONCEPTS:
 * - Yocto: Smallest unit of NEAR (1 NEAR = 1e24 yoctoNEAR, 24 decimals)
 * - Nightshade: Dynamic sharding protocol
 * - Doomslug: Block production consensus (~1.3s blocks)
 * - Finality: 2 block finality (~2.6s for Doomslug finality)
 * - Account Model: Human-readable named accounts (alice.near)
 * - Receipts: Async cross-shard communication
 * - Chain ID: mainnet
 */
interface INEARBridgeAdapter {
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
    enum NEARBridgeOpType {
        NEAR_TRANSFER,
        NEP141_TRANSFER,
        RECEIPT_RELAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address nearBridgeContract;
        address wrappedNEAR;
        address nearLightClient;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct NEARDeposit {
        bytes32 depositId;
        bytes32 nearTxHash;
        bytes32 nearSender;
        address evmRecipient;
        uint256 amountYocto;
        uint256 netAmountYocto;
        uint256 fee;
        DepositStatus status;
        uint256 nearBlockHeight;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct NEARWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 nearRecipient;
        uint256 amountYocto;
        bytes32 nearTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct NEAREscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 nearParty;
        uint256 amountYocto;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct NEARBlockHeader {
        uint256 blockHeight;
        bytes32 blockHash;
        bytes32 prevBlockHash;
        bytes32 epochId;
        bytes32 outcomeRoot;
        bytes32 chunkMask;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct NEARStateProof {
        bytes32[] proofPath;
        bytes32 outcomeHash;
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
    error NEARTxAlreadyUsed(bytes32 txHash);
    error NEARBlockNotVerified(uint256 blockHeight);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address nearBridgeContract,
        address wrappedNEAR,
        address nearLightClient
    );
    event NEARBlockVerified(
        uint256 blockHeight,
        bytes32 blockHash,
        bytes32 epochId
    );
    event NEARDepositInitiated(
        bytes32 indexed depositId,
        bytes32 nearTxHash,
        bytes32 nearSender,
        address indexed evmRecipient,
        uint256 amountYocto
    );
    event NEARDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountYocto
    );
    event NEARWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 nearRecipient,
        uint256 amountYocto
    );
    event NEARWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 nearTxHash
    );
    event NEARWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountYocto
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 nearParty,
        uint256 amountYocto,
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
        address nearBridgeContract,
        address wrappedNEAR,
        address nearLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitNEARBlock(
        uint256 blockHeight,
        bytes32 blockHash,
        bytes32 prevBlockHash,
        bytes32 epochId,
        bytes32 outcomeRoot,
        bytes32 chunkMask,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateNEARDeposit(
        bytes32 nearTxHash,
        bytes32 nearSender,
        address evmRecipient,
        uint256 amountYocto,
        uint256 nearBlockHeight,
        NEARStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeNEARDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 nearRecipient,
        uint256 amountYocto
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 nearTxHash,
        NEARStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 nearParty,
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
    ) external view returns (NEARDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (NEARWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (NEAREscrow memory);

    function getNEARBlock(
        uint256 blockHeight
    ) external view returns (NEARBlockHeader memory);

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
