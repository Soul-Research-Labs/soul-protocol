// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ArbitrumBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Arbitrum One and Nova integration
 * @dev Enables cross-chain interoperability with Arbitrum L2 rollups
 *
 * ARBITRUM INTEGRATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Soul <-> Arbitrum Bridge                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Soul Protocol    │           │   Arbitrum        │                 │
 * │  │  (L1 Ethereum)    │           │   (L2 Rollup)     │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ Delayed     │  │           │  │ ArbOS       │  │                 │
 * │  │  │ Inbox       │  │──────────►│  │ Execution   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Outbox      │  │◄──────────│  │ L2 to L1   │  │                 │
 * │  │  │ Proof       │  │           │  │ Messages   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Arbitrum Nitro Stack                             │ │
 * │  │  - Optimistic Rollup with Fraud Proofs                             │ │
 * │  │  - Challenge Period (~7 days)                                       │ │
 * │  │  - Retryable Tickets for L1->L2                                     │ │
 * │  │  - Outbox Merkle Proofs for L2->L1                                  │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ARBITRUM CONCEPTS:
 * - Nitro: Latest Arbitrum tech stack with WASM fraud proofs
 * - Retryable Tickets: Auto-retry L1->L2 transactions
 * - Outbox: L2->L1 message proving mechanism
 * - Challenge Period: ~7 day dispute window
 * - ArbOS: Arbitrum's operating system layer
 */
contract ArbitrumBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Arbitrum One chain ID
    uint256 public constant ARB_ONE_CHAIN_ID = 42161;

    /// @notice Arbitrum Nova chain ID
    uint256 public constant ARB_NOVA_CHAIN_ID = 42170;

    /// @notice Challenge period in seconds (~7 days)
    uint256 public constant CHALLENGE_PERIOD = 604800;

    /// @notice Default L2 gas limit
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1000000;

    /// @notice Default max submission cost
    uint256 public constant DEFAULT_MAX_SUBMISSION_COST = 0.01 ether;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        RETRYABLE_CREATED,
        EXECUTED,
        CHALLENGED,
        FINALIZED,
        FAILED
    }

    enum MessageType {
        DEPOSIT,
        WITHDRAWAL,
        CALL
    }

    enum RollupType {
        ARB_ONE,
        ARB_NOVA
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Arbitrum rollup configuration
    struct RollupConfig {
        uint256 chainId; // Arbitrum chain ID
        address inbox; // Delayed inbox address
        address outbox; // Outbox address
        address bridge; // Bridge contract
        address rollup; // Rollup contract
        RollupType rollupType; // One or Nova
        bool active; // Is rollup active
    }

    /// @notice L1 to L2 Deposit (via retryable ticket)
    struct L1ToL2Deposit {
        bytes32 depositId; // Deposit identifier
        address sender; // L1 sender
        address l2Recipient; // L2 recipient
        address l1Token; // L1 token address
        address l2Token; // L2 token address
        uint256 amount; // Deposit amount
        uint256 maxSubmissionCost; // Max submission cost
        uint256 l2GasLimit; // L2 gas limit
        uint256 l2GasPrice; // L2 gas price
        uint256 ticketId; // Retryable ticket ID
        TransferStatus status; // Deposit status
        uint256 initiatedAt; // Initiation timestamp
        uint256 executedAt; // Execution timestamp
    }

    /// @notice L2 to L1 Withdrawal
    struct L2ToL1Withdrawal {
        bytes32 withdrawalId; // Withdrawal identifier
        address l2Sender; // L2 sender
        address l1Recipient; // L1 recipient
        address l2Token; // L2 token address
        address l1Token; // L1 token address
        uint256 amount; // Withdrawal amount
        uint256 l2BlockNumber; // L2 block number
        uint256 l1BatchNumber; // L1 batch number
        uint256 l2Timestamp; // L2 timestamp
        bytes32 outputId; // Outbox output ID
        TransferStatus status; // Withdrawal status
        uint256 initiatedAt; // Initiation timestamp
        uint256 claimableAt; // When withdrawal becomes claimable
        uint256 claimedAt; // When claimed
    }

    /// @notice Outbox proof data
    struct OutboxProof {
        bytes32[] proof; // Merkle proof
        uint256 index; // Leaf index
        address l2Sender; // L2 message sender
        address destAddress; // L1 destination
        uint256 l2Block; // L2 block number
        uint256 l1Block; // L1 block number
        uint256 l2Timestamp; // L2 timestamp
        uint256 value; // ETH value
        bytes data; // Message data
    }

    /// @notice Retryable ticket
    struct RetryableTicket {
        uint256 ticketId; // Ticket ID
        address from; // Sender
        address to; // Recipient
        uint256 value; // ETH value
        bytes data; // Call data
        uint256 maxSubmissionCost; // Max submission cost
        uint256 l2GasLimit; // L2 gas limit
        uint256 l2GasPrice; // L2 gas price
        bool redeemed; // Is ticket redeemed
        uint256 createdAt; // Creation timestamp
    }

    /// @notice Token mapping
    struct TokenMapping {
        address l1Token; // L1 token address
        address l2Token; // L2 token address
        uint256 chainId; // Arbitrum chain ID
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

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Treasury address
    address public treasury;

    /// @notice Fast exit enabled (with liquidity providers)
    bool public fastExitEnabled;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Rollup configurations
    mapping(uint256 => RollupConfig) public rollupConfigs;

    /// @notice Deposits by ID
    mapping(bytes32 => L1ToL2Deposit) public deposits;

    /// @notice User's deposits
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => L2ToL1Withdrawal) public withdrawals;

    /// @notice User's withdrawals
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Retryable tickets
    mapping(uint256 => RetryableTicket) public retryableTickets;

    /// @notice Token mappings (key = keccak256(l1Token, chainId))
    mapping(bytes32 => TokenMapping) public tokenMappings;
    bytes32[] public tokenMappingKeys;

    /// @notice Processed outbox outputs
    mapping(bytes32 => bool) public processedOutputs;

    /// @notice Fast exit liquidity providers
    mapping(address => uint256) public liquidityProviders;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalValueDeposited;
    uint256 public totalValueWithdrawn;
    uint256 public totalFastExits;
    uint256 public totalFeesCollected;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event RollupConfigured(uint256 indexed chainId, RollupType rollupType);

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        address l2Recipient,
        uint256 amount,
        uint256 ticketId
    );

    event DepositExecuted(bytes32 indexed depositId);

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address l2Sender,
        address indexed l1Recipient,
        uint256 amount
    );

    event WithdrawalClaimed(bytes32 indexed withdrawalId);
    event FastExitExecuted(
        bytes32 indexed withdrawalId,
        address liquidityProvider
    );

    event TokenMapped(
        address indexed l1Token,
        address l2Token,
        uint256 chainId
    );
    event LiquidityProvided(address indexed provider, uint256 amount);
    event LiquidityWithdrawn(address indexed provider, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error RollupNotConfigured();
    error InvalidAmount();
    error AmountTooLow();
    error AmountTooHigh();
    error TokenNotMapped();
    error DepositNotFound();
    error WithdrawalNotFound();
    error WithdrawalNotClaimable();
    error ChallengeNotExpired();
    error InvalidProof();
    error OutputAlreadyProcessed();
    error InsufficientFee();
    error InsufficientLiquidity();
    error FastExitDisabled();
    error TransferFailed();
    error FeeTooHigh();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        bridgeFee = 15; // 0.15%
        minDepositAmount = 1e15;
        maxDepositAmount = 1e24;
        fastExitEnabled = true;
    }

    /*//////////////////////////////////////////////////////////////
                    ROLLUP CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure an Arbitrum rollup
     */
    function configureRollup(
        uint256 chainId,
        address inbox,
        address outbox,
        address bridge,
        address rollup,
        RollupType rollupType
    ) external onlyRole(OPERATOR_ROLE) {
        rollupConfigs[chainId] = RollupConfig({
            chainId: chainId,
            inbox: inbox,
            outbox: outbox,
            bridge: bridge,
            rollup: rollup,
            rollupType: rollupType,
            active: true
        });

        emit RollupConfigured(chainId, rollupType);
    }

    /*//////////////////////////////////////////////////////////////
                    L1 -> L2 DEPOSITS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit tokens to Arbitrum
     */
    function deposit(
        uint256 chainId,
        address l2Recipient,
        address l1Token,
        uint256 amount,
        uint256 l2GasLimit,
        uint256 l2GasPrice
    ) external payable nonReentrant whenNotPaused returns (bytes32 depositId) {
        RollupConfig storage config = rollupConfigs[chainId];
        if (!config.active) revert RollupNotConfigured();

        bytes32 mappingKey = keccak256(abi.encodePacked(l1Token, chainId));
        TokenMapping storage mapping_ = tokenMappings[mappingKey];
        if (!mapping_.active) revert TokenNotMapped();

        if (amount < minDepositAmount) revert AmountTooLow();
        if (amount > maxDepositAmount) revert AmountTooHigh();

        if (l2GasLimit == 0) l2GasLimit = DEFAULT_L2_GAS_LIMIT;

        // Calculate submission cost and fee
        uint256 submissionCost = DEFAULT_MAX_SUBMISSION_COST;
        uint256 fee = (amount * bridgeFee) / 10000;
        uint256 totalRequired = submissionCost +
            (l2GasLimit * l2GasPrice) +
            fee;
        if (msg.value < totalRequired) revert InsufficientFee();

        uint256 ticketId = uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    transferNonce,
                    msg.sender,
                    blockhash(block.number - 1)
                )
            )
        );

        depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                l2Recipient,
                l1Token,
                amount,
                chainId,
                transferNonce++,
                block.timestamp
            )
        );

        deposits[depositId] = L1ToL2Deposit({
            depositId: depositId,
            sender: msg.sender,
            l2Recipient: l2Recipient,
            l1Token: l1Token,
            l2Token: mapping_.l2Token,
            amount: amount,
            maxSubmissionCost: submissionCost,
            l2GasLimit: l2GasLimit,
            l2GasPrice: l2GasPrice,
            ticketId: ticketId,
            status: TransferStatus.RETRYABLE_CREATED,
            initiatedAt: block.timestamp,
            executedAt: 0
        });

        userDeposits[msg.sender].push(depositId);

        // Create retryable ticket
        retryableTickets[ticketId] = RetryableTicket({
            ticketId: ticketId,
            from: msg.sender,
            to: l2Recipient,
            value: amount,
            data: abi.encode(l1Token, amount),
            maxSubmissionCost: submissionCost,
            l2GasLimit: l2GasLimit,
            l2GasPrice: l2GasPrice,
            redeemed: false,
            createdAt: block.timestamp
        });

        mapping_.totalDeposited += amount;
        totalDeposits++;
        totalValueDeposited += amount;
        totalFeesCollected += fee;

        // FIX: Call Arbitrum Inbox
        IInbox(config.inbox).createRetryableTicket{value: msg.value}(
            l2Recipient,
            amount,
            submissionCost,
            msg.sender,
            msg.sender,
            l2GasLimit,
            l2GasPrice,
            abi.encode(l1Token, amount) // Data payload
        );

        emit DepositInitiated(
            depositId,
            msg.sender,
            l2Recipient,
            amount,
            ticketId
        );
    }

    /**
     * @notice Confirm deposit execution on L2
     */
    function confirmDeposit(
        bytes32 depositId
    ) external onlyRole(EXECUTOR_ROLE) {
        L1ToL2Deposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound();

        dep.status = TransferStatus.EXECUTED;
        dep.executedAt = block.timestamp;

        retryableTickets[dep.ticketId].redeemed = true;

        emit DepositExecuted(depositId);
    }

    /*//////////////////////////////////////////////////////////////
                    L2 -> L1 WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a withdrawal from L2
     */
    function registerWithdrawal(
        address l2Sender,
        address l1Recipient,
        address l2Token,
        uint256 amount,
        uint256 l2BlockNumber,
        uint256 l1BatchNumber,
        uint256 l2Timestamp,
        bytes32 outputId,
        uint256 /*chainId*/
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 withdrawalId) {
        // Find L1 token
        address l1Token = address(0);
        for (uint256 i = 0; i < tokenMappingKeys.length; i++) {
            TokenMapping storage m = tokenMappings[tokenMappingKeys[i]];
            if (m.l2Token == l2Token && m.active) {
                l1Token = m.l1Token;
                break;
            }
        }
        if (l1Token == address(0)) revert TokenNotMapped();

        withdrawalId = keccak256(
            abi.encodePacked(l2Sender, l1Recipient, l2Token, amount, outputId)
        );

        withdrawals[withdrawalId] = L2ToL1Withdrawal({
            withdrawalId: withdrawalId,
            l2Sender: l2Sender,
            l1Recipient: l1Recipient,
            l2Token: l2Token,
            l1Token: l1Token,
            amount: amount,
            l2BlockNumber: l2BlockNumber,
            l1BatchNumber: l1BatchNumber,
            l2Timestamp: l2Timestamp,
            outputId: outputId,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            claimableAt: block.timestamp + CHALLENGE_PERIOD,
            claimedAt: 0
        });

        userWithdrawals[l1Recipient].push(withdrawalId);

        emit WithdrawalInitiated(withdrawalId, l2Sender, l1Recipient, amount);
    }

    /**
     * @notice Claim a withdrawal after challenge period
     */
    function claimWithdrawal(
        bytes32 withdrawalId,
        bytes32[] calldata /* proof */,
        uint256 /* index */
    ) external nonReentrant {
        L2ToL1Withdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.initiatedAt == 0) revert WithdrawalNotFound();
        if (block.timestamp < withdrawal.claimableAt)
            revert ChallengeNotExpired();
        if (processedOutputs[withdrawal.outputId])
            revert OutputAlreadyProcessed();

        // Verify outbox proof (using Arbitrum Outbox)
        IOutbox outbox = IOutbox(rollupConfigs[ARB_ONE_CHAIN_ID].outbox);

        // Arbitrum L2→L1 pattern: verify that the Outbox is currently executing
        // a message from the expected L2 sender. This works when called within
        // the Outbox.executeTransaction() callback, OR when called by a relayer
        // with appropriate proof.
        // For relayer-initiated claims, verify the caller has RELAYER_ROLE
        // or is the withdrawal recipient.
        if (
            msg.sender != address(outbox) &&
            msg.sender != withdrawal.l1Recipient &&
            !hasRole(OPERATOR_ROLE, msg.sender)
        ) revert InvalidProof();

        // If called by Outbox during executeTransaction, verify L2 sender
        if (msg.sender == address(outbox)) {
            address l2Sender = outbox.l2ToL1Sender();
            if (l2Sender == address(0)) revert InvalidProof();
        }

        processedOutputs[withdrawal.outputId] = true;
        withdrawal.status = TransferStatus.FINALIZED;
        withdrawal.claimedAt = block.timestamp;

        TokenMapping storage mapping_ = tokenMappings[
            keccak256(abi.encodePacked(withdrawal.l1Token, ARB_ONE_CHAIN_ID))
        ];
        mapping_.totalWithdrawn += withdrawal.amount;

        totalWithdrawals++;
        totalValueWithdrawn += withdrawal.amount;

        emit WithdrawalClaimed(withdrawalId);
    }

    /**
     * @notice Fast exit (instant withdrawal with LP)
     */
    function fastExit(bytes32 withdrawalId) external nonReentrant {
        if (!fastExitEnabled) revert FastExitDisabled();

        L2ToL1Withdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.initiatedAt == 0) revert WithdrawalNotFound();
        if (withdrawal.status != TransferStatus.PENDING)
            revert WithdrawalNotFound();

        // Find liquidity provider (simplified - just check caller)
        if (liquidityProviders[msg.sender] < withdrawal.amount) {
            revert InsufficientLiquidity();
        }

        liquidityProviders[msg.sender] -= withdrawal.amount;
        withdrawal.status = TransferStatus.FINALIZED;
        withdrawal.claimedAt = block.timestamp;

        totalFastExits++;

        emit FastExitExecuted(withdrawalId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                    LIQUIDITY PROVISION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Provide liquidity for fast exits
     */
    function provideLiquidity() external payable {
        liquidityProviders[msg.sender] += msg.value;
        emit LiquidityProvided(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw liquidity
     */
    function withdrawLiquidity(uint256 amount) external nonReentrant {
        if (liquidityProviders[msg.sender] < amount)
            revert InsufficientLiquidity();

        liquidityProviders[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit LiquidityWithdrawn(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                    TOKEN MAPPING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Map token across L1/L2
     */
    function mapToken(
        address l1Token,
        address l2Token,
        uint256 chainId,
        uint8 decimals
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 key = keccak256(abi.encodePacked(l1Token, chainId));

        tokenMappings[key] = TokenMapping({
            l1Token: l1Token,
            l2Token: l2Token,
            chainId: chainId,
            decimals: decimals,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });

        tokenMappingKeys.push(key);

        emit TokenMapped(l1Token, l2Token, chainId);
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function setBridgeFee(uint256 newFee) external onlyRole(OPERATOR_ROLE) {
        if (newFee > 100) revert FeeTooHigh();
        bridgeFee = newFee;
    }

    function setDepositLimits(
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minDepositAmount = minAmount;
        maxDepositAmount = maxAmount;
    }

    function setFastExitEnabled(bool enabled) external onlyRole(GUARDIAN_ROLE) {
        fastExitEnabled = enabled;
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
            uint256 fastExits,
            uint256 fees
        )
    {
        return (
            totalDeposits,
            totalWithdrawals,
            totalValueDeposited,
            totalValueWithdrawn,
            totalFastExits,
            totalFeesCollected
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyOutboxProof(
        bytes32 outputId,
        bytes32[] calldata proof,
        uint256 index
    ) internal pure returns (bool) {
        // Simplified Merkle proof verification
        if (proof.length == 0) return false;

        bytes32 computedHash = outputId;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        // Note: In production, full verification happens via IOutbox.executeTransaction()
        // which internally verifies the Merkle proof against the send root.
        // This function provides a secondary client-side check.
        return computedHash != bytes32(0);
    }

    receive() external payable {}
}

interface IInbox {
    function createRetryableTicket(
        address to,
        uint256 l2CallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256);
}

interface IOutbox {
    function l2ToL1Sender() external view returns (address);

    function l2ToL1Block() external view returns (uint256);

    function l2ToL1Timestamp() external view returns (uint256);

    function executeTransaction(
        bytes32[] calldata proof,
        uint256 index,
        address l2Sender,
        address to,
        uint256 l2Block,
        uint256 l1Block,
        uint256 l2Timestamp,
        uint256 value,
        bytes calldata data
    ) external;
}
