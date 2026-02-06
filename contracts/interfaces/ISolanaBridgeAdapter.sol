// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISolanaBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Solana bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Solana
 *
 * SOLANA INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │         Solana            │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ SolanaBridgeAdapter │◄─┼────────►│  │  Wormhole / Bridge  │  │
 *   │  │ (EVM side)          │  │         │  │  Program (Solana)   │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Token Program      │  │
 *   │  │  (ZK Commitments)   │  │         │  │  + SPL Tokens       │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock SOL on Solana → Mint wSOL on EVM
 * 2. Burn & Release: Burn wSOL on EVM → Release SOL on Solana
 * 3. SPL Token Bridge: Bridge SPL tokens to/from ERC-20 equivalents
 * 4. Wormhole VAA: Cross-chain message verification via Guardian attestations
 *
 * PROOF VERIFICATION:
 * - Solana uses Tower BFT consensus (PoH-augmented PBFT)
 * - State proofs via Merkle inclusion in slot block headers
 * - Transaction proofs via Wormhole VAA (Verified Action Approval) Guardian signatures
 * - Ed25519 signature verification for validator attestations
 *
 * SOLANA CONCEPTS:
 * - Lamports: Smallest unit of SOL (1 SOL = 1,000,000,000 lamports)
 * - Slot: Solana's block equivalent (~400ms)
 * - Epoch: ~2 days, validator set changes at epoch boundaries
 * - Program: Solana's equivalent of smart contracts
 * - PDA: Program Derived Address (deterministic account addresses)
 * - VAA: Verified Action Approval (Wormhole cross-chain message format)
 */
interface ISolanaBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a SOL deposit (Solana → EVM)
    enum DepositStatus {
        PENDING,    // Awaiting proof submission
        VERIFIED,   // Proof verified, awaiting minting
        COMPLETED,  // wSOL minted to recipient
        FAILED      // Verification failed
    }

    /// @notice Status of a SOL withdrawal (EVM → Solana)
    enum WithdrawalStatus {
        PENDING,     // wSOL burned, awaiting Solana release
        PROCESSING,  // Guardian signing in progress
        COMPLETED,   // SOL released on Solana
        REFUNDED,    // Refunded on EVM side
        FAILED       // Release failed
    }

    /// @notice Status of a token swap escrow
    enum EscrowStatus {
        ACTIVE,     // Escrow created, awaiting finish/cancel
        FINISHED,   // Escrow successfully finished
        CANCELLED   // Escrow cancelled after timeout
    }

    /// @notice Solana transaction types relevant to the bridge
    enum SolanaTxType {
        TRANSFER,          // Native SOL transfer
        SPL_TRANSFER,      // SPL token transfer
        WORMHOLE_TRANSFER, // Wormhole-mediated transfer
        PROGRAM_CALL       // Arbitrary program invocation
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    struct BridgeConfig {
        bytes32 solanaBridgeProgram;  // Solana bridge program address (32 bytes)
        address wrappedSOL;           // ERC-20 wrapped SOL token
        address guardianOracle;       // Oracle for Wormhole Guardian signatures
        uint256 minGuardianSignatures; // Min Guardian signatures required
        uint256 requiredSlotConfirmations; // Slot confirmations before acceptance
        bool active;
    }

    /// @notice SOL deposit record (Solana → EVM)
    struct SOLDeposit {
        bytes32 depositId;
        bytes32 solanaTxSignature;  // Solana transaction signature (64 bytes compressed to 32)
        bytes32 solanaSender;       // Solana sender pubkey
        address evmRecipient;       // EVM recipient address
        uint256 amountLamports;     // Amount in lamports (1 SOL = 1e9 lamports)
        uint256 netAmountLamports;  // After bridge fee
        uint256 fee;                // Bridge fee in lamports
        DepositStatus status;
        uint256 slot;               // Solana slot number
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice SOL withdrawal record (EVM → Solana)
    struct SOLWithdrawal {
        bytes32 withdrawalId;
        address evmSender;          // EVM sender
        bytes32 solanaRecipient;    // Solana recipient pubkey
        uint256 amountLamports;     // Amount in lamports
        bytes32 solanaTxSignature;  // Solana release tx signature (set on completion)
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Token swap escrow (for atomic cross-chain swaps)
    struct SolanaEscrow {
        bytes32 escrowId;
        address evmParty;           // EVM-side party
        bytes32 solanaParty;        // Solana-side party pubkey
        uint256 amountLamports;     // Amount in lamports
        bytes32 hashlock;           // SHA-256 hashlock for HTLC
        bytes32 preimage;           // Preimage (set on finish)
        uint256 finishAfter;        // Earliest finish time (UNIX)
        uint256 cancelAfter;        // Earliest cancel time (UNIX)
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice Solana slot header (for proof verification)
    struct SlotHeader {
        uint256 slot;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 transactionsRoot;   // Merkle root of transactions in the slot
        bytes32 accountsRoot;       // Root of accounts state
        uint256 blockTime;          // Block time in UNIX seconds
        bool finalized;
    }

    /// @notice Wormhole Guardian attestation
    struct GuardianAttestation {
        bytes32 guardianPubKey;     // Guardian's public key
        bytes signature;            // ECDSA/Ed25519 signature over VAA hash
    }

    /// @notice Solana Merkle inclusion proof
    struct SolanaMerkleProof {
        bytes32 leafHash;           // Transaction signature hash
        bytes32[] proof;            // Merkle proof nodes
        uint256 index;              // Leaf index in the tree
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the bridge is configured
    event BridgeConfigured(
        bytes32 indexed solanaBridgeProgram,
        address wrappedSOL,
        address guardianOracle
    );

    /// @notice Emitted when a SOL deposit is initiated
    event SOLDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed solanaTxSignature,
        bytes32 solanaSender,
        address indexed evmRecipient,
        uint256 amountLamports
    );

    /// @notice Emitted when a SOL deposit is completed (wSOL minted)
    event SOLDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountLamports
    );

    /// @notice Emitted when a SOL withdrawal is initiated (wSOL burned)
    event SOLWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 solanaRecipient,
        uint256 amountLamports
    );

    /// @notice Emitted when a SOL withdrawal is completed on Solana
    event SOLWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 solanaTxSignature
    );

    /// @notice Emitted when a SOL withdrawal is refunded on EVM
    event SOLWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountLamports
    );

    /// @notice Emitted when a cross-chain escrow is created
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 solanaParty,
        uint256 amountLamports,
        bytes32 hashlock
    );

    /// @notice Emitted when an escrow is finished with valid preimage
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);

    /// @notice Emitted when an escrow is cancelled after timeout
    event EscrowCancelled(bytes32 indexed escrowId);

    /// @notice Emitted when a Solana slot header is submitted
    event SlotHeaderSubmitted(
        uint256 indexed slot,
        bytes32 blockHash
    );

    /// @notice Emitted when a private deposit is registered with ZK proof
    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a zero address is provided
    error ZeroAddress();
    /// @notice Thrown when the bridge is not configured
    error BridgeNotConfigured();
    /// @notice Thrown when an invalid amount is provided
    error InvalidAmount();
    /// @notice Thrown when deposit amount is below minimum
    error AmountTooSmall(uint256 amountLamports);
    /// @notice Thrown when deposit amount exceeds maximum
    error AmountTooLarge(uint256 amountLamports);
    /// @notice Thrown when a deposit ID is not found
    error DepositNotFound(bytes32 depositId);
    /// @notice Thrown when a deposit is in an unexpected status
    error InvalidDepositStatus(bytes32 depositId, DepositStatus current);
    /// @notice Thrown when a withdrawal ID is not found
    error WithdrawalNotFound(bytes32 withdrawalId);
    /// @notice Thrown when a withdrawal is in an unexpected status
    error InvalidWithdrawalStatus(bytes32 withdrawalId, WithdrawalStatus current);
    /// @notice Thrown when an escrow ID is not found
    error EscrowNotFound(bytes32 escrowId);
    /// @notice Thrown when an escrow is not in ACTIVE status
    error EscrowNotActive(bytes32 escrowId);
    /// @notice Thrown when finish time has not been reached
    error FinishAfterNotReached(bytes32 escrowId, uint256 finishAfter);
    /// @notice Thrown when cancel time has not been reached
    error CancelAfterNotReached(bytes32 escrowId, uint256 cancelAfter);
    /// @notice Thrown when an invalid hashlock is provided
    error InvalidHashlock();
    /// @notice Thrown when a preimage does not match the hashlock
    error InvalidPreimage(bytes32 expected, bytes32 got);
    /// @notice Thrown when a Merkle proof is invalid
    error InvalidSlotProof();
    /// @notice Thrown when a slot is not finalized
    error SlotNotFinalized(uint256 slot);
    /// @notice Thrown when Guardian signatures are insufficient
    error InsufficientGuardianSignatures(uint256 got, uint256 required);
    /// @notice Thrown when a Solana tx signature has already been used
    error SolanaTxAlreadyUsed(bytes32 txSignature);
    /// @notice Thrown when a nullifier has already been consumed
    error NullifierAlreadyUsed(bytes32 nullifier);
    /// @notice Thrown when a ZK proof is invalid
    error InvalidProof();
    /// @notice Thrown when an insufficient fee is provided
    error InsufficientFee(uint256 provided, uint256 required);
    /// @notice Thrown when an escrow timelock duration is too short
    error TimelockTooShort(uint256 provided, uint256 minimum);
    /// @notice Thrown when an escrow timelock duration is too long
    error TimelockTooLong(uint256 provided, uint256 maximum);
    /// @notice Thrown when a withdrawal refund delay has not expired
    error WithdrawalTimelockNotExpired(bytes32 withdrawalId);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configure the bridge parameters
    function configure(
        bytes32 solanaBridgeProgram,
        address wrappedSOL,
        address guardianOracle,
        uint256 minGuardianSignatures,
        uint256 requiredSlotConfirmations
    ) external;

    /// @notice Initiate a SOL deposit (Solana → EVM)
    /// @dev Called by relayer with Solana transaction proof
    function initiateSOLDeposit(
        bytes32 solanaTxSignature,
        bytes32 solanaSender,
        address evmRecipient,
        uint256 amountLamports,
        uint256 slot,
        SolanaMerkleProof calldata txProof,
        GuardianAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    /// @notice Complete a SOL deposit after verification
    function completeSOLDeposit(bytes32 depositId) external;

    /// @notice Initiate a SOL withdrawal (EVM → Solana)
    /// @dev Burns wSOL and queues Solana release
    function initiateWithdrawal(
        bytes32 solanaRecipient,
        uint256 amountLamports
    ) external returns (bytes32 withdrawalId);

    /// @notice Complete a withdrawal after Solana release
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 solanaTxSignature,
        SolanaMerkleProof calldata txProof,
        GuardianAttestation[] calldata attestations
    ) external;

    /// @notice Refund a pending withdrawal after grace period
    function refundWithdrawal(bytes32 withdrawalId) external;

    /// @notice Create a cross-chain escrow (HTLC) for atomic swaps
    function createEscrow(
        bytes32 solanaParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    /// @notice Finish an escrow by providing the valid preimage
    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    /// @notice Cancel an escrow after the cancel-after time
    function cancelEscrow(bytes32 escrowId) external;

    /// @notice Register a private deposit with ZK proof
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    /// @notice Submit a finalized Solana slot header
    function submitSlotHeader(
        uint256 slot,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 accountsRoot,
        uint256 blockTime,
        GuardianAttestation[] calldata attestations
    ) external;

    /// @notice Get deposit details
    function getDeposit(bytes32 depositId) external view returns (SOLDeposit memory);

    /// @notice Get withdrawal details
    function getWithdrawal(bytes32 withdrawalId) external view returns (SOLWithdrawal memory);

    /// @notice Get escrow details
    function getEscrow(bytes32 escrowId) external view returns (SolanaEscrow memory);

    /// @notice Get slot header details
    function getSlotHeader(uint256 slot) external view returns (SlotHeader memory);
}
