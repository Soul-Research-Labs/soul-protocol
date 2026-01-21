// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title zkSyncBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for zkSync Era integration
 * @dev Enables native bridging with zkSync Era (ZK rollup on Ethereum)
 *
 * ZKSYNC ERA INTEGRATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    PIL <-> zkSync Era Bridge                            │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   zkSync Era      │                 │
 * │  │  (L1 Ethereum)    │           │   (L2 ZK Rollup)  │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ Bridge      │  │           │  │ Bridge      │  │                 │
 * │  │  │ Contract    │  │◄─────────►│  │ Contract    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Proof       │  │           │  │ ZK Circuits │  │                 │
 * │  │  │ Verifier    │  │◄──────────│  │ (Boojum)    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Native L1 <-> L2 Messaging                       │ │
 * │  │  - L1 -> L2: Priority Operations (Deposit)                         │ │
 * │  │  - L2 -> L1: L2 Log Proofs (Withdrawal)                            │ │
 * │  │  - ZK Proof Verification (PLONK/Boojum)                            │ │
 * │  │  - Batch Commitment & Verification                                 │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ZKSYNC CONCEPTS:
 * - ZK Rollup: All transactions proved with zero-knowledge proofs
 * - Boojum: zkSync Era's ZK proving system
 * - Priority Queue: L1 -> L2 messages queue
 * - L2 Logs: Emitted on L2, provable on L1
 * - Account Abstraction: Native AA support
 */
contract zkSyncBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice zkSync Era chain ID
    uint256 public constant ZKSYNC_CHAIN_ID = 324;

    /// @notice L2 gas per pubdata byte
    uint256 public constant L2_GAS_PER_PUBDATA = 800;

    /// @notice Default L2 gas limit
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 2000000;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        PROVED,
        EXECUTED,
        FAILED
    }

    enum ProofType {
        DEPOSIT,
        WITHDRAWAL,
        MESSAGE
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice L1 -> L2 Deposit
    struct L1ToL2Deposit {
        bytes32 depositId; // Deposit identifier
        address sender; // L1 sender
        address l2Receiver; // L2 receiver
        address l1Token; // L1 token address
        address l2Token; // L2 token address
        uint256 amount; // Deposit amount
        uint256 l2GasLimit; // L2 execution gas limit
        uint256 l2GasPerPubdata; // Gas per pubdata byte
        bytes32 l2TxHash; // L2 transaction hash
        TransferStatus status; // Deposit status
        uint256 priorityOpId; // Priority operation ID
        uint256 initiatedAt; // Initiation timestamp
    }

    /// @notice L2 -> L1 Withdrawal
    struct L2ToL1Withdrawal {
        bytes32 withdrawalId; // Withdrawal identifier
        address l2Sender; // L2 sender
        address l1Receiver; // L1 receiver
        address l2Token; // L2 token address
        address l1Token; // L1 token address
        uint256 amount; // Withdrawal amount
        uint256 l2BatchNumber; // L2 batch containing withdrawal
        uint256 l2MessageIndex; // Message index in batch
        uint16 l2TxNumberInBatch; // Transaction number in batch
        bytes32 l2TxHash; // L2 transaction hash
        TransferStatus status; // Withdrawal status
        uint256 initiatedAt; // Initiation timestamp
        uint256 finalizedAt; // Finalization timestamp
    }

    /// @notice L2 Log for withdrawal proof
    struct L2Log {
        uint8 l2ShardId; // L2 shard ID
        bool isService; // Is service log
        uint16 txNumberInBatch; // Transaction number
        address sender; // Log sender
        bytes32 key; // Log key
        bytes32 value; // Log value
    }

    /// @notice Batch information
    struct BatchInfo {
        uint256 batchNumber; // Batch number
        bytes32 batchHash; // Batch hash
        bytes32 stateRoot; // State root after batch
        uint64 timestamp; // Batch timestamp
        bytes32 commitment; // Batch commitment
        bool verified; // Is batch verified (proof accepted)
        bool executed; // Is batch executed on L1
    }

    /// @notice Token mapping
    struct TokenMapping {
        address l1Token; // L1 token address
        address l2Token; // L2 token address
        string symbol; // Token symbol
        uint8 decimals; // Token decimals
        uint256 totalDeposited; // Total deposited
        uint256 totalWithdrawn; // Total withdrawn
        bool active; // Is mapping active
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum deposit amount
    uint256 public minDepositAmount;

    /// @notice Maximum deposit amount
    uint256 public maxDepositAmount;

    /// @notice zkSync Era Diamond Proxy address
    address public zkSyncDiamond;

    /// @notice Priority operation counter
    uint256 public priorityOpCounter;

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Treasury address
    address public treasury;

    /// @notice Latest verified batch number
    uint256 public latestVerifiedBatch;

    /// @notice Latest executed batch number
    uint256 public latestExecutedBatch;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits by ID
    mapping(bytes32 => L1ToL2Deposit) public deposits;

    /// @notice User's deposits
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => L2ToL1Withdrawal) public withdrawals;

    /// @notice User's withdrawals
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Batches by number
    mapping(uint256 => BatchInfo) public batches;

    /// @notice Token mappings
    mapping(address => TokenMapping) public tokenMappings;
    address[] public registeredTokens;

    /// @notice Processed L2 logs
    mapping(bytes32 => bool) public processedL2Logs;

    /// @notice Priority operations
    mapping(uint256 => bytes32) public priorityOperations;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalValueDeposited;
    uint256 public totalValueWithdrawn;
    uint256 public totalBatchesVerified;
    uint256 public totalFeesCollected;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        address l2Receiver,
        uint256 amount,
        uint256 priorityOpId
    );

    event DepositExecuted(bytes32 indexed depositId, bytes32 l2TxHash);

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address l2Sender,
        address indexed l1Receiver,
        uint256 amount
    );

    event WithdrawalFinalized(bytes32 indexed withdrawalId);

    event BatchVerified(uint256 indexed batchNumber, bytes32 stateRoot);
    event BatchExecuted(uint256 indexed batchNumber);

    event TokenMapped(address indexed l1Token, address indexed l2Token);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidAmount();
    error AmountTooLow();
    error AmountTooHigh();
    error TokenNotMapped();
    error DepositNotFound();
    error WithdrawalNotFound();
    error BatchNotVerified();
    error BatchNotExecuted();
    error InvalidProof();
    error AlreadyProcessed();
    error InsufficientFee();
    error InvalidL2GasLimit();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _zkSyncDiamond) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        zkSyncDiamond = _zkSyncDiamond;
        bridgeFee = 10; // 0.1%
        minDepositAmount = 1e15;
        maxDepositAmount = 1e24;
    }

    /*//////////////////////////////////////////////////////////////
                    L1 -> L2 DEPOSITS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a deposit to zkSync Era
     */
    function deposit(
        address l2Receiver,
        address l1Token,
        uint256 amount,
        uint256 l2GasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 depositId) {
        TokenMapping storage mapping_ = tokenMappings[l1Token];
        if (!mapping_.active) revert TokenNotMapped();

        if (amount < minDepositAmount) revert AmountTooLow();
        if (amount > maxDepositAmount) revert AmountTooHigh();
        if (l2GasLimit == 0) l2GasLimit = DEFAULT_L2_GAS_LIMIT;

        // Calculate fee
        uint256 fee = (amount * bridgeFee) / 10000;
        if (msg.value < fee) revert InsufficientFee();

        uint256 priorityOpId = priorityOpCounter++;

        depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                l2Receiver,
                l1Token,
                amount,
                priorityOpId,
                block.timestamp
            )
        );

        deposits[depositId] = L1ToL2Deposit({
            depositId: depositId,
            sender: msg.sender,
            l2Receiver: l2Receiver,
            l1Token: l1Token,
            l2Token: mapping_.l2Token,
            amount: amount,
            l2GasLimit: l2GasLimit,
            l2GasPerPubdata: L2_GAS_PER_PUBDATA,
            l2TxHash: bytes32(0),
            status: TransferStatus.PENDING,
            priorityOpId: priorityOpId,
            initiatedAt: block.timestamp
        });

        userDeposits[msg.sender].push(depositId);
        priorityOperations[priorityOpId] = depositId;

        mapping_.totalDeposited += amount;
        totalDeposits++;
        totalValueDeposited += amount;
        totalFeesCollected += fee;

        emit DepositInitiated(
            depositId,
            msg.sender,
            l2Receiver,
            amount,
            priorityOpId
        );
    }

    /**
     * @notice Confirm deposit execution on L2
     */
    function confirmDeposit(
        bytes32 depositId,
        bytes32 l2TxHash
    ) external onlyRole(PROVER_ROLE) {
        L1ToL2Deposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound();

        dep.status = TransferStatus.EXECUTED;
        dep.l2TxHash = l2TxHash;

        emit DepositExecuted(depositId, l2TxHash);
    }

    /*//////////////////////////////////////////////////////////////
                    L2 -> L1 WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a withdrawal from L2
     */
    function registerWithdrawal(
        address l2Sender,
        address l1Receiver,
        address l2Token,
        uint256 amount,
        uint256 l2BatchNumber,
        uint256 l2MessageIndex,
        uint16 l2TxNumberInBatch,
        bytes32 l2TxHash
    ) external onlyRole(PROVER_ROLE) returns (bytes32 withdrawalId) {
        address l1Token;

        // Find L1 token from L2 token
        for (uint256 i = 0; i < registeredTokens.length; i++) {
            if (tokenMappings[registeredTokens[i]].l2Token == l2Token) {
                l1Token = tokenMappings[registeredTokens[i]].l1Token;
                break;
            }
        }
        if (l1Token == address(0)) revert TokenNotMapped();

        withdrawalId = keccak256(
            abi.encodePacked(
                l2Sender,
                l1Receiver,
                l2Token,
                amount,
                l2BatchNumber,
                l2MessageIndex
            )
        );

        withdrawals[withdrawalId] = L2ToL1Withdrawal({
            withdrawalId: withdrawalId,
            l2Sender: l2Sender,
            l1Receiver: l1Receiver,
            l2Token: l2Token,
            l1Token: l1Token,
            amount: amount,
            l2BatchNumber: l2BatchNumber,
            l2MessageIndex: l2MessageIndex,
            l2TxNumberInBatch: l2TxNumberInBatch,
            l2TxHash: l2TxHash,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            finalizedAt: 0
        });

        userWithdrawals[l1Receiver].push(withdrawalId);

        emit WithdrawalInitiated(withdrawalId, l2Sender, l1Receiver, amount);
    }

    /**
     * @notice Finalize a withdrawal with proof
     */
    function finalizeWithdrawal(
        bytes32 withdrawalId,
        uint256 l2BatchNumber,
        uint256 l2MessageIndex,
        uint16 l2TxNumberInBatch,
        bytes calldata message,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        L2ToL1Withdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.initiatedAt == 0) revert WithdrawalNotFound();
        if (withdrawal.status != TransferStatus.PENDING)
            revert AlreadyProcessed();

        // Verify batch is executed
        BatchInfo storage batch = batches[l2BatchNumber];
        if (!batch.executed) revert BatchNotExecuted();

        // Verify Merkle proof
        bytes32 messageHash = keccak256(message);
        if (!_verifyMerkleProof(messageHash, merkleProof, batch.stateRoot)) {
            revert InvalidProof();
        }

        withdrawal.status = TransferStatus.EXECUTED;
        withdrawal.finalizedAt = block.timestamp;

        TokenMapping storage mapping_ = tokenMappings[withdrawal.l1Token];
        mapping_.totalWithdrawn += withdrawal.amount;

        totalWithdrawals++;
        totalValueWithdrawn += withdrawal.amount;

        emit WithdrawalFinalized(withdrawalId);
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit batch information
     */
    function submitBatch(
        uint256 batchNumber,
        bytes32 batchHash,
        bytes32 stateRoot,
        uint64 timestamp,
        bytes32 commitment
    ) external onlyRole(PROVER_ROLE) {
        batches[batchNumber] = BatchInfo({
            batchNumber: batchNumber,
            batchHash: batchHash,
            stateRoot: stateRoot,
            timestamp: timestamp,
            commitment: commitment,
            verified: false,
            executed: false
        });
    }

    /**
     * @notice Verify batch (proof accepted)
     */
    function verifyBatch(uint256 batchNumber) external onlyRole(PROVER_ROLE) {
        BatchInfo storage batch = batches[batchNumber];
        batch.verified = true;

        if (batchNumber > latestVerifiedBatch) {
            latestVerifiedBatch = batchNumber;
        }

        totalBatchesVerified++;
        emit BatchVerified(batchNumber, batch.stateRoot);
    }

    /**
     * @notice Execute batch on L1
     */
    function executeBatch(uint256 batchNumber) external onlyRole(PROVER_ROLE) {
        BatchInfo storage batch = batches[batchNumber];
        if (!batch.verified) revert BatchNotVerified();

        batch.executed = true;

        if (batchNumber > latestExecutedBatch) {
            latestExecutedBatch = batchNumber;
        }

        emit BatchExecuted(batchNumber);
    }

    /*//////////////////////////////////////////////////////////////
                    TOKEN MAPPING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Map L1 token to L2 token
     */
    function mapToken(
        address l1Token,
        address l2Token,
        string calldata symbol,
        uint8 decimals
    ) external onlyRole(OPERATOR_ROLE) {
        tokenMappings[l1Token] = TokenMapping({
            l1Token: l1Token,
            l2Token: l2Token,
            symbol: symbol,
            decimals: decimals,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });

        registeredTokens.push(l1Token);

        emit TokenMapped(l1Token, l2Token);
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function setBridgeFee(uint256 newFee) external onlyRole(OPERATOR_ROLE) {
        require(newFee <= 100, "Fee too high");
        bridgeFee = newFee;
    }

    function setDepositLimits(
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minDepositAmount = minAmount;
        maxDepositAmount = maxAmount;
    }

    function setZkSyncDiamond(
        address diamond
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        zkSyncDiamond = diamond;
    }

    function setTreasury(
        address newTreasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        treasury = newTreasury;
    }

    /*//////////////////////////////////////////////////////////////
                           PAUSABLE
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                           STATISTICS
    //////////////////////////////////////////////////////////////*/

    function getBridgeStats()
        external
        view
        returns (
            uint256 depositCount,
            uint256 withdrawalCount,
            uint256 valueDeposited,
            uint256 valueWithdrawn,
            uint256 batchesVerified,
            uint256 fees
        )
    {
        return (
            totalDeposits,
            totalWithdrawals,
            totalValueDeposited,
            totalValueWithdrawn,
            totalBatchesVerified,
            totalFeesCollected
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (uint256(computedHash) < uint256(proof[i])) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof[i], computedHash)
                );
            }
        }

        return computedHash == root;
    }

    receive() external payable {}
}
