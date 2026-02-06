// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ICantonBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Canton Network bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Canton Network
 *
 * CANTON INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │     Canton Network        │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ CantonBridge        │◄─┼────────►│  │  Global Synchronizer│  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Canton Protocol)  │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Sub-Transaction    │  │
 *   │  │  (ZK Commitments)   │  │         │  │  Privacy (Daml)     │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock CANTON on Canton → Mint wCANTON on Soul Protocol
 * 2. Burn & Release: Burn wCANTON on Soul → Release CANTON on Canton
 * 3. Mediator Attestation: Cross-chain verification via Canton mediator signatures
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Canton uses the Canton Protocol with Global Synchronizer
 * - Mediator nodes coordinate transaction confirmation
 * - Sequencer nodes order transactions within domains
 * - Sub-transaction privacy: only involved parties see data
 * - Merkle-based commitment proofs for state verification
 * - Domain topology determines trust boundaries
 *
 * CANTON CONCEPTS:
 * - microcanton: Smallest unit of CANTON (1 CANTON = 1e6 microcanton, 6 decimals)
 * - Sequencing Round: ~2 second ordering intervals
 * - Canton Protocol: Privacy-preserving synchronization protocol
 * - Daml: Digital Asset Modeling Language for smart contracts
 * - Global Synchronizer: Cross-domain transaction coordination
 * - Participant Node: Node running Daml applications
 * - Mediator Node: Confirms transaction results
 * - Sequencer Node: Orders messages within a domain
 * - Chain ID: canton-global-1 → numeric 510 for EVM mapping
 * - Finality: 5 sequencing rounds (~10s) for cross-chain safety
 * - Party IDs: party::domain format (Daml party identifiers)
 */
interface ICantonBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a CANTON deposit (Canton → Soul)
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a CANTON withdrawal (Soul → Canton)
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

    /// @notice Canton transaction types relevant to the bridge
    enum CantonTxType {
        TRANSFER,
        DAML_EXERCISE,
        DOMAIN_TRANSFER,
        CROSS_CHAIN
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct BridgeConfig {
        address cantonBridgeContract;
        address wrappedCANTON;
        address mediatorOracle;
        uint256 minMediatorSignatures;
        uint256 requiredRoundConfirmations;
        bool active;
    }

    struct CANTONDeposit {
        bytes32 depositId;
        bytes32 cantonTxHash;
        address cantonSender;
        address evmRecipient;
        uint256 amountMicrocanton;
        uint256 netAmountMicrocanton;
        uint256 fee;
        DepositStatus status;
        uint256 roundNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct CANTONWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address cantonRecipient;
        uint256 amountMicrocanton;
        bytes32 cantonTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct CANTONEscrow {
        bytes32 escrowId;
        address evmParty;
        address cantonParty;
        uint256 amountMicrocanton;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct SynchronizerRoundHeader {
        uint256 roundNumber;
        bytes32 roundHash;
        bytes32 parentHash;
        bytes32 transactionsRoot;
        bytes32 stateRoot;
        bytes32 mediatorSetHash;
        bytes32 domainTopologyHash;
        uint256 roundTime;
        bool finalized;
    }

    struct MediatorAttestation {
        address mediator;
        bytes signature;
    }

    struct CantonMerkleProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed cantonBridgeContract,
        address wrappedCANTON,
        address mediatorOracle
    );
    event CANTONDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed cantonTxHash,
        address cantonSender,
        address indexed evmRecipient,
        uint256 amountMicrocanton
    );
    event CANTONDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountMicrocanton
    );
    event CANTONWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address cantonRecipient,
        uint256 amountMicrocanton
    );
    event CANTONWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 cantonTxHash
    );
    event CANTONWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountMicrocanton
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address cantonParty,
        uint256 amountMicrocanton,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event RoundHeaderSubmitted(uint256 indexed roundNumber, bytes32 roundHash);
    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidAmount();
    error AmountTooSmall(uint256 amount);
    error AmountTooLarge(uint256 amount);
    error BridgeNotConfigured();
    error CantonTxAlreadyUsed(bytes32 cantonTxHash);
    error DepositNotFound(bytes32 depositId);
    error InvalidDepositStatus(bytes32 depositId, DepositStatus status);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error InvalidWithdrawalStatus(
        bytes32 withdrawalId,
        WithdrawalStatus status
    );
    error WithdrawalTimelockNotExpired(bytes32 withdrawalId);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error InvalidHashlock();
    error InvalidPreimage(bytes32 expected, bytes32 actual);
    error TimelockTooShort(uint256 duration, uint256 minimum);
    error TimelockTooLong(uint256 duration, uint256 maximum);
    error FinishAfterNotReached(bytes32 escrowId, uint256 finishAfter);
    error CancelAfterNotReached(bytes32 escrowId, uint256 cancelAfter);
    error RoundNotFinalized(uint256 roundNumber);
    error InvalidRoundProof();
    error InsufficientMediatorSignatures(uint256 provided, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function configure(
        address cantonBridgeContract,
        address wrappedCANTON,
        address mediatorOracle,
        uint256 minMediatorSignatures,
        uint256 requiredRoundConfirmations
    ) external;

    function initiateCANTONDeposit(
        bytes32 cantonTxHash,
        address cantonSender,
        address evmRecipient,
        uint256 amountMicrocanton,
        uint256 roundNumber,
        CantonMerkleProof calldata txProof,
        MediatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeCANTONDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address cantonRecipient,
        uint256 amountMicrocanton
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cantonTxHash,
        CantonMerkleProof calldata txProof,
        MediatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address cantonParty,
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

    function submitRoundHeader(
        uint256 roundNumber,
        bytes32 roundHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        bytes32 mediatorSetHash,
        bytes32 domainTopologyHash,
        uint256 roundTime,
        MediatorAttestation[] calldata attestations
    ) external;

    function getDeposit(
        bytes32 depositId
    ) external view returns (CANTONDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (CANTONWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (CANTONEscrow memory);

    function getRoundHeader(
        uint256 roundNumber
    ) external view returns (SynchronizerRoundHeader memory);
}
