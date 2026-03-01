// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ICrossChainLiquidityVault
 * @author ZASEON
 * @notice Interface for the cross-chain liquidity vault that backs private proof relays with real token value
 *
 * @dev This is the critical missing piece in the ZASEON architecture. The protocol can relay ZK proofs
 *      across chains, but without a liquidity vault there is no mechanism to transfer actual token value.
 *
 *      ARCHITECTURE:
 *      ┌─────────────────────────────────────────────────────────────────────────────────┐
 *      │                        Cross-Chain Token Flow                                    │
 *      │                                                                                  │
 *      │  Chain A (Source)                          Chain B (Destination)                  │
 *      │  ┌──────────────────────┐                  ┌──────────────────────┐              │
 *      │  │ CrossChainPrivacyHub │  ZK proof relay  │ CrossChainPrivacyHub │              │
 *      │  │   escrows tokens     │ ═══════════════> │   verifies proof     │              │
 *      │  └──────────┬───────────┘                  └──────────┬───────────┘              │
 *      │             │ lockLiquidity()                          │ releaseLiquidity()       │
 *      │  ┌──────────▼───────────┐                  ┌──────────▼───────────┐              │
 *      │  │ LiquidityVault (A)   │                  │ LiquidityVault (B)   │              │
 *      │  │   locks amount       │                  │   releases to recip  │              │
 *      │  │   ↕ LP deposits      │                  │   ↕ LP deposits      │              │
 *      │  └──────────────────────┘                  └──────────────────────┘              │
 *      │                                                                                  │
 *      │  Settlement: Periodic rebalancing between vaults via canonical bridges           │
 *      └─────────────────────────────────────────────────────────────────────────────────┘
 *
 *      FLOW:
 *      1. User calls initiatePrivateTransfer on Chain A → tokens escrowed in PrivacyHub
 *      2. PrivacyHub calls lockLiquidity() on Vault A → vault records locked amount
 *      3. ZK proof relayed to Chain B
 *      4. Relayer calls completeRelay() on Chain B PrivacyHub → PrivacyHub calls releaseLiquidity() on Vault B
 *      5. Vault B releases tokens to recipient from LP pool
 *      6. Periodic settlement: Net flows rebalanced between vaults via canonical bridges
 */
interface ICrossChainLiquidityVault {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Liquidity provider position
    struct LPPosition {
        uint256 ethDeposited;
        uint256 ethAvailable; // After pending locks
        mapping(address => uint256) tokenDeposited;
        mapping(address => uint256) tokenAvailable;
        uint256 depositTimestamp;
        uint256 totalFeesEarned;
        bool active;
    }

    /// @notice Locked liquidity for a pending cross-chain transfer
    struct LiquidityLock {
        bytes32 requestId;
        address token; // address(0) for ETH
        uint256 amount;
        uint256 sourceChainId;
        uint256 destChainId;
        uint64 lockTimestamp;
        uint64 expiry;
        bool released;
        bool refunded;
    }

    /// @notice Settlement batch for rebalancing between vaults
    struct SettlementBatch {
        bytes32 batchId;
        uint256 remoteChainId;
        address token; // address(0) for ETH
        uint256 netAmount; // Net flow direction
        bool isOutflow; // true = this chain owes remote chain
        uint64 timestamp;
        bool executed;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event LiquidityDeposited(
        address indexed provider,
        address indexed token,
        uint256 amount
    );

    event LiquidityWithdrawn(
        address indexed provider,
        address indexed token,
        uint256 amount
    );

    event LiquidityLocked(
        bytes32 indexed requestId,
        address indexed token,
        uint256 amount,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event LiquidityReleased(
        bytes32 indexed requestId,
        address indexed recipient,
        address indexed token,
        uint256 amount
    );

    event LiquidityLockRefunded(
        bytes32 indexed requestId,
        address indexed token,
        uint256 amount
    );

    event SettlementProposed(
        bytes32 indexed batchId,
        uint256 remoteChainId,
        address token,
        uint256 netAmount,
        bool isOutflow
    );

    event SettlementExecuted(
        bytes32 indexed batchId,
        uint256 remoteChainId,
        uint256 amount
    );

    event ChainRegistered(uint256 indexed chainId, address remoteVault);

    event FeesDistributed(address indexed token, uint256 totalFees);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InsufficientLiquidity(
        address token,
        uint256 requested,
        uint256 available
    );
    error LockNotFound(bytes32 requestId);
    error LockAlreadyReleased(bytes32 requestId);
    error LockAlreadyExists(bytes32 requestId);
    error LockAlreadyRefunded(bytes32 requestId);
    error LockNotExpired(bytes32 requestId);
    error InvalidAmount();
    error ZeroAddress();
    error ChainNotRegistered(uint256 chainId);
    error UnauthorizedCaller();
    error WithdrawalCooldownActive(uint256 availableAt);
    error SettlementAlreadyExecuted(bytes32 batchId);
    error InsufficientLPBalance(uint256 requested, uint256 available);

    // =========================================================================
    // LP FUNCTIONS
    // =========================================================================

    /// @notice Deposit ETH liquidity into the vault
    /// @dev LP earns proportional share of relay fees
    function depositETH() external payable;

    /// @notice Deposit ERC20 tokens into the vault
    /// @param token ERC20 token address
    /// @param amount Amount to deposit
    function depositToken(address token, uint256 amount) external;

    /// @notice Withdraw ETH liquidity from the vault
    /// @param amount Amount to withdraw
    /// @dev Subject to cooldown period to prevent flash-loan manipulation
    function withdrawETH(uint256 amount) external;

    /// @notice Withdraw ERC20 tokens from the vault
    /// @param token ERC20 token address
    /// @param amount Amount to withdraw
    function withdrawToken(address token, uint256 amount) external;

    // =========================================================================
    // LIQUIDITY MANAGEMENT (called by CrossChainPrivacyHub)
    // =========================================================================

    /// @notice Lock liquidity on the source chain for a pending cross-chain transfer
    /// @param requestId Unique identifier for the relay request
    /// @param token Token address (address(0) for ETH)
    /// @param amount Amount to lock
    /// @param destChainId Destination chain ID
    /// @return success Whether liquidity was successfully locked
    function lockLiquidity(
        bytes32 requestId,
        address token,
        uint256 amount,
        uint256 destChainId
    ) external returns (bool success);

    /// @notice Release locked liquidity on the destination chain to the recipient
    /// @param requestId Matching request ID from the source chain lock
    /// @param token Token address (address(0) for ETH)
    /// @param recipient Recipient address
    /// @param amount Amount to release
    /// @param sourceChainId Source chain ID (for settlement tracking)
    function releaseLiquidity(
        bytes32 requestId,
        address token,
        address recipient,
        uint256 amount,
        uint256 sourceChainId
    ) external;

    /// @notice Refund a lock that has expired without completion
    /// @param requestId The request ID for the expired lock
    function refundExpiredLock(bytes32 requestId) external;

    // =========================================================================
    // SETTLEMENT
    // =========================================================================

    /// @notice Propose a settlement batch for cross-chain rebalancing
    /// @param remoteChainId The remote chain to settle with
    /// @param token Token address (address(0) for ETH)
    /// @return batchId Settlement batch identifier
    function proposeSettlement(
        uint256 remoteChainId,
        address token
    ) external returns (bytes32 batchId);

    /// @notice Execute a settlement batch (send tokens to canonical bridge)
    /// @param batchId The settlement batch to execute
    function executeSettlement(bytes32 batchId) external payable;

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get available liquidity for a token
    /// @param token Token address (address(0) for ETH)
    /// @return available Unlocked liquidity available for releases
    function getAvailableLiquidity(
        address token
    ) external view returns (uint256 available);

    /// @notice Get total locked liquidity for a token
    /// @param token Token address (address(0) for ETH)
    /// @return locked Total amount currently locked in pending transfers
    function getLockedLiquidity(
        address token
    ) external view returns (uint256 locked);

    /// @notice Get the net settlement owed to/from a remote chain
    /// @param remoteChainId Remote chain ID
    /// @param token Token address (address(0) for ETH)
    /// @return netAmount Net amount
    /// @return isOutflow True if this chain owes the remote chain
    function getNetSettlement(
        uint256 remoteChainId,
        address token
    ) external view returns (uint256 netAmount, bool isOutflow);

    /// @notice Get lock details for a request
    /// @param requestId The request ID
    /// @return token The token address
    /// @return amount The locked amount
    /// @return sourceChainId The source chain ID
    /// @return destChainId The destination chain ID
    /// @return lockTimestamp When the lock was created
    /// @return expiry When the lock expires
    /// @return released Whether the lock has been released
    /// @return refunded Whether the lock has been refunded
    function getLock(
        bytes32 requestId
    )
        external
        view
        returns (
            address token,
            uint256 amount,
            uint256 sourceChainId,
            uint256 destChainId,
            uint64 lockTimestamp,
            uint64 expiry,
            bool released,
            bool refunded
        );

    /// @notice Check if the vault has sufficient liquidity for a release
    /// @param token Token address (address(0) for ETH)
    /// @param amount Amount needed
    /// @return sufficient True if enough unlocked liquidity exists
    function hasSufficientLiquidity(
        address token,
        uint256 amount
    ) external view returns (bool sufficient);
}
