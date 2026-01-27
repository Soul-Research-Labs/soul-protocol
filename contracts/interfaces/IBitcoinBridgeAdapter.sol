// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IBitcoinBridgeAdapter
 * @notice Interface for Bitcoin bridge adapter
 */
interface IBitcoinBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum DepositStatus {
        PENDING,
        COMPLETED,
        FAILED
    }

    enum WithdrawalStatus {
        PENDING,
        COMPLETED,
        REFUNDED,
        FAILED
    }

    enum HTLCStatus {
        ACTIVE,
        REDEEMED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BTC to ETH deposit
    struct BTCDeposit {
        bytes32 depositId;
        bytes32 btcTxId;
        bytes scriptPubKey;
        uint256 satoshis;
        uint256 netAmount;
        uint256 fee;
        address ethRecipient;
        bytes32 proofHash;
        DepositStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice ETH to BTC withdrawal
    struct BTCWithdrawal {
        bytes32 withdrawalId;
        address ethSender;
        bytes20 btcRecipientPubKeyHash;
        uint256 satoshis;
        uint256 netAmount;
        uint256 fee;
        bytes32 hashlock;
        uint256 timelock;
        bytes32 preimage;
        bytes32 btcTxId;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Hash Time-Locked Contract
    struct HTLC {
        bytes32 htlcId;
        address sender;
        address recipient;
        uint256 amount;
        bytes32 hashlock;
        uint256 timelock;
        bytes32 preimage;
        HTLCStatus status;
        uint256 createdAt;
        uint256 completedAt;
    }

    /// @notice Bitcoin block header
    struct BTCBlockHeader {
        bytes32 blockHash;
        bytes32 prevBlockHash;
        bytes32 merkleRoot;
        uint256 timestamp;
        uint256 height;
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(address indexed spvVerifier, address indexed wrappedBTC);
    event TreasuryUpdated(address indexed treasury);

    // Deposit events
    event BTCDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed btcTxId,
        uint256 satoshis,
        address indexed recipient
    );
    event BTCDepositCompleted(
        bytes32 indexed depositId,
        address indexed recipient,
        uint256 amount
    );

    // Withdrawal events
    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed sender,
        bytes20 btcRecipient,
        uint256 satoshis,
        bytes32 hashlock
    );
    event WithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 indexed btcTxId,
        bytes32 preimage
    );
    event WithdrawalRefunded(bytes32 indexed withdrawalId, address indexed sender);

    // HTLC events
    event HTLCCreated(
        bytes32 indexed htlcId,
        address indexed sender,
        address indexed recipient,
        uint256 amount,
        bytes32 hashlock,
        uint256 timelock
    );
    event HTLCRedeemed(bytes32 indexed htlcId, bytes32 preimage, address indexed recipient);
    event HTLCRefunded(bytes32 indexed htlcId, address indexed sender);

    // Privacy events
    event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 indexed nullifier);

    // Block header events
    event BlockHeaderSubmitted(bytes32 indexed blockHash, uint256 height);

    // Fee events
    event FeesWithdrawn(address indexed treasury, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error BridgeNotConfigured();
    error InvalidAmount();
    error AmountTooSmall(uint256 amount);
    error AmountTooLarge(uint256 amount);
    error DepositTooSmall(uint256 satoshis);
    error DepositTooLarge(uint256 satoshis);

    error BTCTxAlreadyUsed(bytes32 btcTxId);
    error InvalidSPVProof(bytes32 btcTxId);
    error DepositNotFound(bytes32 depositId);
    error InvalidDepositStatus(bytes32 depositId, DepositStatus status);

    error WithdrawalNotFound(bytes32 withdrawalId);
    error InvalidWithdrawalStatus(bytes32 withdrawalId, WithdrawalStatus status);
    error InvalidPreimage(bytes32 id);

    error HTLCNotFound(bytes32 htlcId);
    error HTLCNotActive(bytes32 htlcId);

    error InvalidHashlock();
    error TimelockTooShort(uint256 timelock);
    error TimelockTooLong(uint256 timelock);
    error TimelockNotExpired(bytes32 id, uint256 timelock);

    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof(bytes32 depositId);
    error InvalidBlockHeader();

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function initiateBTCDeposit(
        bytes32 btcTxId,
        bytes calldata btcTxRaw,
        bytes32[] calldata merkleProof,
        bytes calldata blockHeader,
        address ethRecipient
    ) external returns (bytes32 depositId);

    function completeBTCDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes20 btcRecipientPubKeyHash,
        uint256 satoshis,
        bytes32 hashlock,
        uint256 timelock
    ) external payable returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 btcTxId,
        bytes32 preimage
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createHTLC(
        bytes32 hashlock,
        uint256 timelock,
        address recipient
    ) external payable returns (bytes32 htlcId);

    function redeemHTLC(bytes32 htlcId, bytes32 preimage) external;

    function refundHTLC(bytes32 htlcId) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(bytes32 depositId) external view returns (BTCDeposit memory);
    function getHTLC(bytes32 htlcId) external view returns (HTLC memory);
    function getWithdrawal(bytes32 withdrawalId) external view returns (BTCWithdrawal memory);
}
