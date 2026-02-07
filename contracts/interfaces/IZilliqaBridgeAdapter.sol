// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IZilliqaBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Zilliqa bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and the Zilliqa Network
 *
 * ZILLIQA INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │      Zilliqa Network      │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ ZilliqaBridge        │◄─┼────────►│  │  Scilla Contracts   │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Typed Functional) │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  pBFT + PoW         │  │
 *   │  │  (ZK Commitments)   │  │         │  │  Hybrid Consensus   │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock ZIL on Zilliqa → Mint wZIL on Soul Protocol
 * 2. Burn & Release: Burn wZIL on Soul → Release ZIL on Zilliqa
 * 3. DS Committee Attestation: DS nodes attest to finalized blocks
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Zilliqa uses pBFT consensus within DS committee (2/3+1 majority)
 * - PoW used for Sybil resistance in shard joins (Ethash/Sha3)
 * - DS blocks finalize every ~30 seconds; TX blocks every ~1-2 minutes
 * - Sharding: network, transaction, and computational sharding
 * - Microblocks from each shard aggregated into TX blocks by DS committee
 *
 * ZILLIQA CONCEPTS:
 * - Qa: Smallest unit of ZIL (1 ZIL = 1e12 Qa, 12 decimals)
 * - Scilla: Safe-by-design smart contract language
 * - DS Committee: Directory Service committee managing consensus
 * - DS Block: Directory Service block (~30s, epoch marker)
 * - TX Block: Transaction block containing microblocks from shards
 * - Microblock: Shard-level block with transactions
 * - Chain ID: zilliqa-mainnet → 1
 * - Finality: 30 TX block confirmations for cross-chain safety
 * - Block time: ~30s DS blocks, ~1-2min TX blocks
 */
interface IZilliqaBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a deposit from Zilliqa → Soul
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a withdrawal from Soul → Zilliqa
    enum WithdrawalStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        REFUNDED,
        FAILED
    }

    /// @notice Status of an HTLC escrow
    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }

    /// @notice Operation types for the Zilliqa bridge
    enum ZilliqaBridgeOpType {
        ZIL_TRANSFER,       // Standard ZIL transfer
        ZRC2_TRANSFER,      // ZRC-2 fungible token transfer
        DS_COMMITTEE_UPDATE, // DS committee rotation
        EMERGENCY_OP        // Emergency governance action
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    /// @param zilliqaBridgeContract Address of the Zilliqa-side Scilla bridge contract
    /// @param wrappedZIL ERC-20 wrapper for ZIL
    /// @param dsCommitteeOracle Oracle for DS committee verification
    /// @param minDSSignatures Minimum DS committee signatures required
    /// @param requiredTxBlockConfirmations TX block confirmations needed
    /// @param active Whether the bridge is accepting transfers
    struct BridgeConfig {
        address zilliqaBridgeContract;
        address wrappedZIL;
        address dsCommitteeOracle;
        uint256 minDSSignatures;
        uint256 requiredTxBlockConfirmations;
        bool active;
    }

    /// @notice Deposit record (Zilliqa → Soul)
    /// @param depositId Unique deposit identifier
    /// @param zilliqaTxHash Zilliqa transaction hash (32 bytes)
    /// @param zilliqaSender Zilliqa bech32 address encoded as bytes32
    /// @param evmRecipient EVM recipient address
    /// @param amountQa Amount in Qa (1e12 per ZIL)
    /// @param netAmountQa Amount after fee deduction
    /// @param fee Bridge fee deducted
    /// @param status Current deposit status
    /// @param txBlockNumber Zilliqa TX block number for this deposit
    /// @param initiatedAt Block timestamp when initiated
    /// @param completedAt Block timestamp when completed
    struct ZILDeposit {
        bytes32 depositId;
        bytes32 zilliqaTxHash;
        bytes32 zilliqaSender;
        address evmRecipient;
        uint256 amountQa;
        uint256 netAmountQa;
        uint256 fee;
        DepositStatus status;
        uint256 txBlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Withdrawal record (Soul → Zilliqa)
    /// @param withdrawalId Unique withdrawal identifier
    /// @param evmSender EVM sender address
    /// @param zilliqaRecipient Zilliqa bech32 address encoded as bytes32
    /// @param amountQa Amount in Qa
    /// @param zilliqaTxHash Confirmed Zilliqa transaction hash
    /// @param status Current withdrawal status
    /// @param initiatedAt Block timestamp when initiated
    /// @param completedAt Block timestamp when completed
    struct ZILWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 zilliqaRecipient;
        uint256 amountQa;
        bytes32 zilliqaTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice HTLC Escrow record for atomic swaps
    /// @param escrowId Unique escrow identifier
    /// @param evmParty EVM-side participant
    /// @param zilliqaParty Zilliqa-side participant (bech32 as bytes32)
    /// @param amountQa Amount locked in Qa
    /// @param hashlock SHA-256 hashlock
    /// @param preimage Revealed preimage (zero until finished)
    /// @param finishAfter Earliest time the escrow can be finished
    /// @param cancelAfter Earliest time the escrow can be cancelled
    /// @param status Current escrow status
    /// @param createdAt Block timestamp when created
    struct ZILEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 zilliqaParty;
        uint256 amountQa;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice Zilliqa DS Block header for cross-chain verification
    /// @param dsBlockNumber DS block number (monotonically increasing)
    /// @param blockHash Hash of the DS block
    /// @param stateRootHash Root hash of the global state trie
    /// @param txBlockStart First TX block in this DS epoch
    /// @param txBlockEnd Last TX block in this DS epoch
    /// @param dsCommitteeHash Hash of the DS committee for this epoch
    /// @param shardCount Number of shards in this DS epoch
    /// @param timestamp Block timestamp
    /// @param verified Whether this header has been verified
    struct ZilliqaDSBlock {
        uint256 dsBlockNumber;
        bytes32 blockHash;
        bytes32 stateRootHash;
        uint256 txBlockStart;
        uint256 txBlockEnd;
        bytes32 dsCommitteeHash;
        uint256 shardCount;
        uint256 timestamp;
        bool verified;
    }

    /// @notice DS committee member attestation
    /// @param member DS committee member address (EVM-mapped)
    /// @param signature Member's signature over block data
    struct DSCommitteeAttestation {
        address member;
        bytes signature;
    }

    /// @notice Zilliqa state proof (Patricia-Merkle trie)
    /// @param leafHash Hash of the leaf node
    /// @param proof Array of sibling hashes
    /// @param index Position in the trie
    struct ZilliqaStateProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed zilliqaBridgeContract,
        address wrappedZIL,
        address dsCommitteeOracle
    );

    event ZILDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed zilliqaTxHash,
        bytes32 zilliqaSender,
        address indexed evmRecipient,
        uint256 amountQa
    );

    event ZILDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountQa
    );

    event ZILWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 zilliqaRecipient,
        uint256 amountQa
    );

    event ZILWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 zilliqaTxHash
    );

    event ZILWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountQa
    );

    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 zilliqaParty,
        uint256 amountQa,
        bytes32 hashlock
    );

    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);

    event EscrowCancelled(bytes32 indexed escrowId);

    event DSBlockVerified(
        uint256 indexed dsBlockNumber,
        bytes32 blockHash,
        uint256 shardCount
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
    error BridgeAlreadyConfigured();
    error InvalidAmount();
    error AmountBelowMinimum(uint256 amount, uint256 minimum);
    error AmountAboveMaximum(uint256 amount, uint256 maximum);
    error ZilliqaTxAlreadyUsed(bytes32 txHash);
    error DepositNotFound(bytes32 depositId);
    error DepositAlreadyCompleted(bytes32 depositId);
    error DepositNotVerified(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalAlreadyCompleted(bytes32 withdrawalId);
    error WithdrawalNotPending(bytes32 withdrawalId);
    error RefundTooEarly(uint256 currentTime, uint256 refundAfter);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error EscrowTimelockNotMet();
    error InvalidPreimage(bytes32 expected, bytes32 actual);
    error InvalidTimelockRange();
    error TxBlockNotConfirmed(uint256 txBlock);
    error InvalidStateProof();
    error InsufficientDSSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function configure(
        address zilliqaBridgeContract,
        address wrappedZIL,
        address dsCommitteeOracle,
        uint256 minDSSignatures,
        uint256 requiredTxBlockConfirmations
    ) external;

    function setTreasury(address treasury) external;

    function initiateZILDeposit(
        bytes32 zilliqaTxHash,
        bytes32 zilliqaSender,
        address evmRecipient,
        uint256 amountQa,
        uint256 txBlockNumber,
        ZilliqaStateProof calldata txProof,
        DSCommitteeAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeZILDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 zilliqaRecipient,
        uint256 amountQa
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 zilliqaTxHash,
        ZilliqaStateProof calldata txProof,
        DSCommitteeAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 zilliqaParty,
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

    function submitDSBlock(
        uint256 dsBlockNumber,
        bytes32 blockHash,
        bytes32 stateRootHash,
        uint256 txBlockStart,
        uint256 txBlockEnd,
        bytes32 dsCommitteeHash,
        uint256 shardCount,
        uint256 timestamp,
        DSCommitteeAttestation[] calldata attestations
    ) external;

    function getDeposit(
        bytes32 depositId
    ) external view returns (ZILDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ZILWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (ZILEscrow memory);

    function getDSBlock(
        uint256 dsBlockNumber
    ) external view returns (ZilliqaDSBlock memory);

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
