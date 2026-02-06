// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPlasmaBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Plasma bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Plasma child chains
 *
 * PLASMA INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │       Plasma Chain        │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ PlasmaBridge        │◄─┼────────►│  │  Root Chain Contract│  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (L1 Commitment)    │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Exit Game          │  │
 *   │  │  (ZK Commitments)   │  │         │  │  (Fraud Proof)      │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock PLASMA on child chain → Mint wPLASMA on Soul Protocol
 * 2. Burn & Release: Burn wPLASMA on Soul → Release PLASMA on Plasma chain
 * 3. Operator Commitment: Block roots committed to L1 for verification
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Plasma operator submits block roots to L1 root chain contract
 * - Fraud proofs enable trustless exits during challenge period
 * - Merkle inclusion proofs verify transactions against committed roots
 * - UTXO-based exit priority from Plasma Cash model
 * - 7-day challenge period for exit finalization
 *
 * PLASMA CONCEPTS:
 * - satoplasma: Smallest unit of PLASMA (1 PLASMA = 1e8 satoplasma, 8 decimals)
 * - Operator: Single trusted block producer for child chain
 * - Root Chain Contract: L1 smart contract storing block commitments
 * - Block Commitment: Merkle root of child chain block committed to L1
 * - Exit Game: Protocol for withdrawing funds back to L1
 * - Challenge Period: 7-day window to submit fraud proofs
 * - UTXO Position: Unique identifier for transaction outputs
 * - Fraud Proof: Evidence of invalid state transition
 * - Chain ID: plasma-mainnet-1 → numeric 515 for EVM mapping
 * - Finality: 12 L1 commitment confirmations for cross-chain safety
 * - Child chain blocks: ~1 second block time
 */
interface IPlasmaBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a PLASMA deposit (Plasma → Soul)
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a PLASMA withdrawal (Soul → Plasma)
    enum WithdrawalStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        REFUNDED,
        FAILED
    }

    /// @notice Status of a token swap escrow
    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }

    /// @notice Types of Plasma transactions
    enum PlasmaTxType {
        DEPOSIT,      // Deposit from L1 into Plasma chain
        TRANSFER,     // Transfer within Plasma child chain
        EXIT,         // Exit from Plasma to L1
        CROSS_CHAIN   // Cross-chain via Soul bridge
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration for Plasma integration
    struct BridgeConfig {
        address plasmaBridgeContract;
        address wrappedPLASMA;
        address operatorOracle;
        uint256 minOperatorConfirmations;
        uint256 requiredL1Confirmations;
        bool active;
    }

    /// @notice A PLASMA deposit from Plasma chain into Soul Protocol
    struct PLASMADeposit {
        bytes32 depositId;
        bytes32 plasmaTxHash;
        address plasmaSender;
        address evmRecipient;
        uint256 amountSatoplasma;
        uint256 netAmountSatoplasma;
        uint256 fee;
        DepositStatus status;
        uint256 blockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice A PLASMA withdrawal from Soul Protocol back to Plasma chain
    struct PLASMAWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address plasmaRecipient;
        uint256 amountSatoplasma;
        bytes32 plasmaTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice HTLC escrow for atomic operations
    struct PLASMAEscrow {
        bytes32 escrowId;
        address evmParty;
        address plasmaParty;
        uint256 amountSatoplasma;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice Plasma child chain block commitment to L1
    struct PlasmaBlockCommitment {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 transactionsRoot;
        bytes32 stateRoot;
        address operatorAddress;
        bytes32 commitmentTxHash;
        uint256 blockTime;
        bool committed;
    }

    /// @notice Operator confirmation for block commitments
    struct OperatorConfirmation {
        address operator;
        bytes signature;
    }

    /// @notice Merkle inclusion proof for Plasma UTXO transactions
    struct PlasmaInclusionProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event PLASMADepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed plasmaTxHash,
        address plasmaSender,
        address indexed evmRecipient,
        uint256 amountSatoplasma
    );

    event PLASMADepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountSatoplasma
    );

    event PLASMAWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address plasmaRecipient,
        uint256 amountSatoplasma
    );

    event PLASMAWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 plasmaTxHash
    );

    event PLASMAWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountSatoplasma
    );

    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address plasmaParty,
        uint256 amountSatoplasma,
        bytes32 hashlock
    );

    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);

    event BlockCommitmentSubmitted(
        uint256 indexed blockNumber,
        bytes32 blockHash,
        bytes32 commitmentTxHash
    );

    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );

    event BridgeConfigured(
        address indexed plasmaBridgeContract,
        address wrappedPLASMA,
        address operatorOracle
    );

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error AmountTooSmall(uint256 amount);
    error AmountTooLarge(uint256 amount);
    error PlasmaTxAlreadyUsed(bytes32 txHash);
    error DepositNotFound(bytes32 depositId);
    error DepositNotPending(bytes32 depositId);
    error DepositAlreadyCompleted(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalNotPending(bytes32 withdrawalId);
    error WithdrawalAlreadyCompleted(bytes32 withdrawalId);
    error WithdrawalRefundTooEarly(bytes32 withdrawalId, uint256 refundableAt);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error EscrowTimelockTooShort(uint256 duration);
    error EscrowTimelockTooLong(uint256 duration);
    error EscrowNotYetFinishable(bytes32 escrowId, uint256 finishAfter);
    error EscrowNotYetCancellable(bytes32 escrowId, uint256 cancelAfter);
    error InvalidPreimage(bytes32 expected, bytes32 actual);
    error BlockNotCommitted(uint256 blockNumber);
    error InvalidBlockProof(uint256 blockNumber);
    error InsufficientOperatorConfirmations(uint256 provided, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error BridgeNotActive();

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configure the Plasma bridge parameters
    function configure(
        address plasmaBridgeContract,
        address wrappedPLASMA,
        address operatorOracle,
        uint256 minOperatorConfirmations,
        uint256 requiredL1Confirmations
    ) external;

    /// @notice Initiate a PLASMA deposit from Plasma chain
    function initiatePLASMADeposit(
        bytes32 plasmaTxHash,
        address plasmaSender,
        address evmRecipient,
        uint256 amountSatoplasma,
        uint256 blockNumber,
        PlasmaInclusionProof calldata txProof,
        OperatorConfirmation[] calldata confirmations
    ) external returns (bytes32 depositId);

    /// @notice Complete a verified PLASMA deposit
    function completePLASMADeposit(bytes32 depositId) external;

    /// @notice Initiate a withdrawal back to Plasma chain
    function initiateWithdrawal(
        address plasmaRecipient,
        uint256 amountSatoplasma
    ) external returns (bytes32 withdrawalId);

    /// @notice Complete withdrawal with Plasma-side confirmation
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 plasmaTxHash,
        PlasmaInclusionProof calldata txProof,
        OperatorConfirmation[] calldata confirmations
    ) external;

    /// @notice Refund a withdrawal after the refund delay
    function refundWithdrawal(bytes32 withdrawalId) external;

    /// @notice Create an HTLC escrow for atomic swap
    function createEscrow(
        address plasmaParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    /// @notice Finish an escrow by revealing the preimage
    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    /// @notice Cancel an expired escrow
    function cancelEscrow(bytes32 escrowId) external;

    /// @notice Submit a Plasma block commitment for verification
    function submitBlockCommitment(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        address operatorAddress,
        bytes32 commitmentTxHash,
        uint256 blockTime,
        OperatorConfirmation[] calldata confirmations
    ) external;

    /// @notice Register a private deposit with ZK proof
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    /// @notice Get deposit details
    function getDeposit(bytes32 depositId) external view returns (PLASMADeposit memory);

    /// @notice Get withdrawal details
    function getWithdrawal(bytes32 withdrawalId) external view returns (PLASMAWithdrawal memory);

    /// @notice Get escrow details
    function getEscrow(bytes32 escrowId) external view returns (PLASMAEscrow memory);

    /// @notice Get bridge statistics
    function getBridgeStats() external view returns (
        uint256 totalDeposited,
        uint256 totalWithdrawn,
        uint256 totalEscrows,
        uint256 totalEscrowsFinished,
        uint256 totalEscrowsCancelled,
        uint256 accumulatedFees,
        uint256 latestBlockNumber
    );
}
