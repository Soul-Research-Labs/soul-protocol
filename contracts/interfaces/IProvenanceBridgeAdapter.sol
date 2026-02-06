// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IProvenanceBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Provenance Blockchain bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Provenance Blockchain
 *
 * PROVENANCE INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │   Provenance Blockchain   │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ ProvenanceBridge    │◄─┼────────►│  │  IBC Bridge Module  │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Cosmos SDK side)  │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Tendermint BFT     │  │
 *   │  │  (ZK Commitments)   │  │         │  │  + Marker Module    │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock HASH on Provenance → Mint wHASH on Soul Protocol
 * 2. Burn & Release: Burn wHASH on Soul → Release HASH on Provenance
 * 3. Validator Attestation: Cross-chain verification via Tendermint validator signatures
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Provenance uses Tendermint BFT consensus (Cosmos SDK)
 * - ~100 active validators in the validator set
 * - 2/3+1 supermajority required for block finality
 * - State proofs via IAVL+ Merkle tree inclusion
 * - IBC (Inter-Blockchain Communication) for cross-chain messaging
 * - Ed25519/Secp256k1 validator signatures
 *
 * PROVENANCE CONCEPTS:
 * - nhash: Smallest unit of HASH (1 HASH = 1e9 nhash, 9 decimals)
 * - Block: ~6 second block time
 * - Tendermint BFT: Byzantine fault tolerant consensus
 * - Marker Module: Native asset management (tokenization)
 * - Scope Module: Data management & provenance tracking
 * - Chain ID: pio-mainnet-1 → numeric 505 for EVM mapping
 * - Finality: ~10 blocks (~60 seconds) for practical finality
 * - Bech32 addresses: pb1... prefix
 */
interface IProvenanceBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a HASH deposit (Provenance → Soul)
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a HASH withdrawal (Soul → Provenance)
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

    /// @notice Provenance transaction types relevant to the bridge
    enum ProvenanceTxType {
        TRANSFER,
        MARKER_TRANSFER,
        IBC_TRANSFER,
        CROSS_CHAIN
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct BridgeConfig {
        address provenanceBridgeContract;
        address wrappedHASH;
        address validatorOracle;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct HASHDeposit {
        bytes32 depositId;
        bytes32 provTxHash;
        address provSender;
        address evmRecipient;
        uint256 amountNhash;
        uint256 netAmountNhash;
        uint256 fee;
        DepositStatus status;
        uint256 blockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct HASHWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address provRecipient;
        uint256 amountNhash;
        bytes32 provTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct HASHEscrow {
        bytes32 escrowId;
        address evmParty;
        address provParty;
        uint256 amountNhash;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct TendermintBlockHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 transactionsRoot;
        bytes32 stateRoot;
        bytes32 validatorsHash;
        uint256 blockTime;
        bool finalized;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct ProvenanceMerkleProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed provenanceBridgeContract,
        address wrappedHASH,
        address validatorOracle
    );
    event HASHDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed provTxHash,
        address provSender,
        address indexed evmRecipient,
        uint256 amountNhash
    );
    event HASHDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountNhash
    );
    event HASHWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address provRecipient,
        uint256 amountNhash
    );
    event HASHWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 provTxHash
    );
    event HASHWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountNhash
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address provParty,
        uint256 amountNhash,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event BlockHeaderSubmitted(uint256 indexed blockNumber, bytes32 blockHash);
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
    error BridgeNotConfigured();
    error InvalidAmount();
    error AmountTooSmall(uint256 amountNhash);
    error AmountTooLarge(uint256 amountNhash);
    error DepositNotFound(bytes32 depositId);
    error InvalidDepositStatus(bytes32 depositId, DepositStatus current);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error InvalidWithdrawalStatus(
        bytes32 withdrawalId,
        WithdrawalStatus current
    );
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error FinishAfterNotReached(bytes32 escrowId, uint256 finishAfter);
    error CancelAfterNotReached(bytes32 escrowId, uint256 cancelAfter);
    error InvalidHashlock();
    error InvalidPreimage(bytes32 expected, bytes32 got);
    error InvalidBlockProof();
    error BlockNotFinalized(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error ProvTxAlreadyUsed(bytes32 txHash);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error InsufficientFee(uint256 provided, uint256 required);
    error TimelockTooShort(uint256 provided, uint256 minimum);
    error TimelockTooLong(uint256 provided, uint256 maximum);
    error WithdrawalTimelockNotExpired(bytes32 withdrawalId);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function configure(
        address provenanceBridgeContract,
        address wrappedHASH,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function initiateHASHDeposit(
        bytes32 provTxHash,
        address provSender,
        address evmRecipient,
        uint256 amountNhash,
        uint256 blockNumber,
        ProvenanceMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeHASHDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address provRecipient,
        uint256 amountNhash
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 provTxHash,
        ProvenanceMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address provParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    function cancelEscrow(bytes32 escrowId) external;

    function getDeposit(
        bytes32 depositId
    ) external view returns (HASHDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (HASHWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (HASHEscrow memory);

    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (TendermintBlockHeader memory);

    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory);
}
