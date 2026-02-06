// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IXRPLBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the XRP Ledger bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and the XRP Ledger
 *
 * XRP LEDGER INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │       XRP Ledger          │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ XRPLBridgeAdapter   │◄─┼────────►│  │  Multisig / Escrow  │  │
 *   │  │ (EVM side)          │  │         │  │  (XRPL side)        │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Payment Channels   │  │
 *   │  │  (ZK Commitments)   │  │         │  │  + Escrow           │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock XRP on XRPL → Mint wXRP on EVM
 * 2. Burn & Release: Burn wXRP on EVM → Release XRP on XRPL
 * 3. Escrow: XRPL native escrow for time-locked + crypto-conditioned swaps
 * 4. Payment Channels: Off-chain XRP payments settled on-chain
 *
 * PROOF VERIFICATION:
 * - XRPL uses UNL (Unique Node List) validator consensus
 * - State proofs via SHAMap (Shamir's Secret Sharing Hash Map) inclusion
 * - Transaction proofs via validated ledger headers + Merkle inclusion
 */
interface IXRPLBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of an XRP deposit (XRPL → EVM)
    enum DepositStatus {
        PENDING,        // Awaiting proof submission
        VERIFIED,       // Proof verified, awaiting minting
        COMPLETED,      // wXRP minted to recipient
        FAILED          // Verification failed
    }

    /// @notice Status of an XRP withdrawal (EVM → XRPL)
    enum WithdrawalStatus {
        PENDING,        // wXRP burned, awaiting XRPL release
        PROCESSING,     // Multisig signing in progress
        COMPLETED,      // XRP released on XRPL
        REFUNDED,       // Refunded on EVM side
        FAILED          // Release failed
    }

    /// @notice Status of an escrow
    enum EscrowStatus {
        ACTIVE,         // Escrow created, awaiting finish/cancel
        FINISHED,       // Escrow successfully finished
        CANCELLED       // Escrow cancelled (after cancel-after time)
    }

    /// @notice XRPL transaction types relevant to the bridge
    enum XRPLTxType {
        PAYMENT,
        ESCROW_CREATE,
        ESCROW_FINISH,
        ESCROW_CANCEL,
        TRUST_SET,
        OFFER_CREATE
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    struct BridgeConfig {
        bytes20 xrplMultisigAccount;   // XRPL multisig bridge account (r-address decoded)
        address wrappedXRP;             // ERC-20 wrapped XRP token
        address validatorOracle;        // Oracle contract for XRPL validator signatures
        uint256 minSignatures;          // Min validator signatures for proof
        uint256 requiredLedgerConfirmations; // Ledger confirmations before proof acceptance
        bool active;
    }

    /// @notice XRP deposit record (XRPL → EVM)
    struct XRPDeposit {
        bytes32 depositId;
        bytes32 xrplTxHash;             // XRPL transaction hash
        bytes20 xrplSender;             // XRPL sender account
        address evmRecipient;           // EVM recipient
        uint256 amountDrops;            // Amount in drops (1 XRP = 1,000,000 drops)
        uint256 netAmountDrops;         // After bridge fee
        uint256 fee;                    // Bridge fee in drops
        bytes32 destinationTag;         // XRPL destination tag for routing
        DepositStatus status;
        uint256 ledgerIndex;            // XRPL ledger index of the tx
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice XRP withdrawal record (EVM → XRPL)
    struct XRPWithdrawal {
        bytes32 withdrawalId;
        address evmSender;              // EVM sender
        bytes20 xrplRecipient;          // XRPL recipient account
        uint256 amountDrops;            // Amount in drops
        bytes32 xrplTxHash;             // XRPL release tx hash (set on completion)
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice XRPL escrow (for atomic swaps)
    struct XRPLEscrow {
        bytes32 escrowId;
        address evmParty;               // EVM-side party
        bytes20 xrplParty;              // XRPL-side party
        uint256 amountDrops;            // Amount in drops
        bytes32 condition;              // Crypto-condition (PREIMAGE-SHA-256)
        bytes32 fulfillment;            // Fulfillment (set on finish)
        uint256 finishAfter;            // Earliest finish time (UNIX)
        uint256 cancelAfter;            // Earliest cancel time (UNIX)
        bytes32 xrplEscrowTxHash;       // XRPL EscrowCreate tx hash
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice XRPL ledger header (for proof verification)
    struct LedgerHeader {
        uint256 ledgerIndex;
        bytes32 ledgerHash;
        bytes32 parentHash;
        bytes32 transactionHash;        // Root of tx SHAMap tree
        bytes32 accountStateHash;       // Root of account state SHAMap tree
        uint256 closeTime;              // Close time in Ripple epoch
        bool validated;
    }

    /// @notice XRPL validator attestation
    struct ValidatorAttestation {
        bytes32 validatorPubKey;         // Ed25519 public key of validator
        bytes signature;                 // Ed25519 signature over ledger hash
    }

    /// @notice XRPL SHAMap inclusion proof
    struct SHAMapProof {
        bytes32 leafHash;                // Transaction hash (leaf in SHAMap)
        bytes32[] innerNodes;            // SHAMap inner node hashes
        uint8[] nodeTypes;               // 0 = inner, 1 = leaf, 2 = empty branch
        bytes32[] branchKeys;            // Branch key bytes at each level
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        bytes20 indexed xrplMultisig,
        address wrappedXRP,
        address validatorOracle
    );

    event XRPDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed xrplTxHash,
        bytes20 xrplSender,
        address indexed evmRecipient,
        uint256 amountDrops
    );

    event XRPDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountDrops
    );

    event XRPWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes20 xrplRecipient,
        uint256 amountDrops
    );

    event XRPWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 xrplTxHash
    );

    event XRPWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountDrops
    );

    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes20 xrplParty,
        uint256 amountDrops,
        bytes32 condition
    );

    event EscrowFinished(
        bytes32 indexed escrowId,
        bytes32 fulfillment
    );

    event EscrowCancelled(bytes32 indexed escrowId);

    event LedgerHeaderSubmitted(
        uint256 indexed ledgerIndex,
        bytes32 ledgerHash
    );

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
    error AmountTooSmall(uint256 amountDrops);
    error AmountTooLarge(uint256 amountDrops);
    error DepositNotFound(bytes32 depositId);
    error InvalidDepositStatus(bytes32 depositId, DepositStatus current);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error InvalidWithdrawalStatus(bytes32 withdrawalId, WithdrawalStatus current);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error FinishAfterNotReached(bytes32 escrowId, uint256 finishAfter);
    error CancelAfterNotReached(bytes32 escrowId, uint256 cancelAfter);
    error InvalidCondition();
    error InvalidFulfillment(bytes32 expected, bytes32 got);
    error InvalidLedgerProof();
    error LedgerNotValidated(uint256 ledgerIndex);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error XRPLTxAlreadyUsed(bytes32 txHash);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error InsufficientFee(uint256 provided, uint256 required);
    error TimelockTooShort(uint256 provided, uint256 minimum);
    error TimelockTooLong(uint256 provided, uint256 maximum);
    error WithdrawalTimelockNotExpired(bytes32 withdrawalId);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configure the bridge
    function configure(
        bytes20 xrplMultisigAccount,
        address wrappedXRP,
        address validatorOracle,
        uint256 minSignatures,
        uint256 requiredLedgerConfirmations
    ) external;

    /// @notice Initiate an XRP deposit (XRPL → EVM)
    /// @dev Called by relayer with XRPL transaction proof
    function initiateXRPDeposit(
        bytes32 xrplTxHash,
        bytes20 xrplSender,
        address evmRecipient,
        uint256 amountDrops,
        bytes32 destinationTag,
        uint256 ledgerIndex,
        SHAMapProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    /// @notice Complete an XRP deposit after verification
    function completeXRPDeposit(bytes32 depositId) external;

    /// @notice Initiate an XRP withdrawal (EVM → XRPL)
    /// @dev Burns wXRP and queues XRPL release
    function initiateWithdrawal(
        bytes20 xrplRecipient,
        uint256 amountDrops
    ) external returns (bytes32 withdrawalId);

    /// @notice Complete a withdrawal after XRPL release
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 xrplTxHash,
        SHAMapProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    /// @notice Refund a stale withdrawal
    function refundWithdrawal(bytes32 withdrawalId) external;

    /// @notice Create an escrow for atomic swaps
    function createEscrow(
        bytes20 xrplParty,
        bytes32 condition,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    /// @notice Finish an escrow by providing the fulfillment
    function finishEscrow(
        bytes32 escrowId,
        bytes32 fulfillment
    ) external;

    /// @notice Cancel an expired escrow
    function cancelEscrow(bytes32 escrowId) external;

    /// @notice Register a private deposit with ZK commitment
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    /// @notice Submit a validated XRPL ledger header
    function submitLedgerHeader(
        uint256 ledgerIndex,
        bytes32 ledgerHash,
        bytes32 parentHash,
        bytes32 transactionHash,
        bytes32 accountStateHash,
        uint256 closeTime,
        ValidatorAttestation[] calldata attestations
    ) external;

    // View functions
    function getDeposit(bytes32 depositId) external view returns (XRPDeposit memory);
    function getWithdrawal(bytes32 withdrawalId) external view returns (XRPWithdrawal memory);
    function getEscrow(bytes32 escrowId) external view returns (XRPLEscrow memory);
    function getLedgerHeader(uint256 ledgerIndex) external view returns (LedgerHeader memory);
}
