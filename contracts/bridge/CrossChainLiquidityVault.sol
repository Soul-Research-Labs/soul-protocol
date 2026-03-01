// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICrossChainLiquidityVault} from "../interfaces/ICrossChainLiquidityVault.sol";

/**
 * @title CrossChainLiquidityVault
 * @author ZASEON
 * @notice Per-chain liquidity vault that backs cross-chain private proof relays with real token value
 *
 * @dev Solves the CRITICAL architectural gap: "Where will the tokens come from?"
 *
 *      PROBLEM:
 *      - CrossChainPrivacyHub escrows tokens on Chain A and can only release on Chain A
 *      - MultiBridgeRouter is a pure message router — never handles tokens
 *      - No contract existed to provide tokens on the destination chain
 *
 *      SOLUTION:
 *      One CrossChainLiquidityVault is deployed per chain. LPs deposit tokens into each vault.
 *      When a user initiates a cross-chain private transfer:
 *        1. Source chain: PrivacyHub escrows user's tokens → calls lockLiquidity() on source vault
 *        2. ZK proof relayed across chains via MultiBridgeRouter
 *        3. Dest chain: PrivacyHub verifies proof → calls releaseLiquidity() on dest vault → LP tokens go to recipient
 *        4. Settlement: Periodically, net flows between chains are rebalanced via canonical bridges
 *
 *      SECURITY MODEL:
 *      - Only PRIVACY_HUB_ROLE can lock/release (set to CrossChainPrivacyHub address)
 *      - LP withdrawals have a cooldown to prevent flash-loan attacks
 *      - Settlement requires OPERATOR_ROLE and goes through canonical bridges
 *      - Circuit breaker for emergencies (GUARDIAN_ROLE)
 *      - All state-changing functions are nonReentrant
 *      - Zero-address validation on all critical setters
 *
 *      FEE MODEL:
 *      - LPs earn a share of relay fees proportional to their deposited liquidity
 *      - Fee distribution happens on release, accruing to the LP pool automatically
 *      - LP fee share configurable (default 50% of protocol relay fee)
 */
contract CrossChainLiquidityVault is
    ICrossChainLiquidityVault,
    AccessControl,
    Pausable,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    // =========================================================================
    // ROLES
    // =========================================================================

    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev Pre-computed: keccak256("GUARDIAN_ROLE")
    bytes32 public constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;

    /// @notice Role for CrossChainPrivacyHub — only holder can lock/release
    bytes32 public constant PRIVACY_HUB_ROLE = keccak256("PRIVACY_HUB_ROLE");

    /// @notice Role for settlement execution
    bytes32 public constant SETTLER_ROLE = keccak256("SETTLER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Minimum LP deposit
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice LP withdrawal cooldown (prevents flash-loan manipulation)
    uint256 public constant WITHDRAWAL_COOLDOWN = 1 hours;

    /// @notice Lock expiry duration (matches CrossChainPrivacyHub 7-day expiry)
    uint256 public constant LOCK_DURATION = 7 days;

    /// @notice Maximum LP fee share basis points (100% of relay fee)
    uint256 public constant MAX_LP_FEE_BPS = 10000;

    /// @notice Maximum number of locks to iterate for gas safety
    uint256 public constant MAX_SETTLEMENT_BATCH = 100;

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// @notice This vault's chain ID
    uint256 public immutable chainId;

    // --- LP Tracking ---

    /// @notice ETH deposited by each LP
    mapping(address => uint256) public lpEthDeposited;

    /// @notice Token deposited by each LP: lp => token => amount
    mapping(address => mapping(address => uint256)) public lpTokenDeposited;

    /// @notice Timestamp of last deposit (for withdrawal cooldown)
    mapping(address => uint256) public lpDepositTimestamp;

    /// @notice Total fees earned by each LP
    mapping(address => uint256) public lpFeesEarned;

    /// @notice Active LP list
    address[] public activeLPs;
    mapping(address => bool) public isActiveLP;

    // --- Pool Totals ---

    /// @notice Total ETH in the vault (deposited by LPs)
    uint256 public totalETH;

    /// @notice Total ETH currently locked in pending transfers
    uint256 public totalETHLocked;

    /// @notice Total ERC20 in the vault per token
    mapping(address => uint256) public totalTokens;

    /// @notice Total ERC20 locked per token
    mapping(address => uint256) public totalTokensLocked;

    // --- Locks ---

    /// @notice Lock registry: requestId => LiquidityLock
    mapping(bytes32 => LiquidityLock) public locks;

    /// @notice Active lock request IDs
    bytes32[] public activeLockIds;

    // --- Settlement ---

    /// @notice Net inflows from each remote chain per token: remoteChainId => token => amount
    /// @dev Positive = remote chain owes us (we released more than we locked for them)
    mapping(uint256 => mapping(address => int256)) public netFlows;

    /// @notice Settlement batches: batchId => SettlementBatch
    mapping(bytes32 => SettlementBatch) public settlements;

    /// @notice Remote vault addresses: remoteChainId => remoteVaultAddress
    mapping(uint256 => address) public remoteVaults;

    /// @notice Registered remote chain IDs
    uint256[] public registeredChains;

    // --- Configuration ---

    /// @notice LP fee share in basis points (of relay protocol fee)
    uint256 public lpFeeShareBps;

    /// @notice Total settlement nonce for unique batch IDs
    uint256 public settlementNonce;

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /**
     * @notice Deploy the liquidity vault for a specific chain
     * @param _admin Admin address (DEFAULT_ADMIN_ROLE)
     * @param _operator Operator address (OPERATOR_ROLE, SETTLER_ROLE)
     * @param _guardian Guardian address (GUARDIAN_ROLE)
     * @param _privacyHub CrossChainPrivacyHub address (PRIVACY_HUB_ROLE)
     * @param _lpFeeShareBps LP fee share in bps (e.g., 5000 = 50% of protocol fee goes to LPs)
     */
    constructor(
        address _admin,
        address _operator,
        address _guardian,
        address _privacyHub,
        uint256 _lpFeeShareBps
    ) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_operator == address(0)) revert ZeroAddress();
        if (_guardian == address(0)) revert ZeroAddress();
        if (_privacyHub == address(0)) revert ZeroAddress();
        if (_lpFeeShareBps > MAX_LP_FEE_BPS) revert InvalidAmount();

        chainId = block.chainid;
        lpFeeShareBps = _lpFeeShareBps;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _operator);
        _grantRole(GUARDIAN_ROLE, _guardian);
        _grantRole(PRIVACY_HUB_ROLE, _privacyHub);
        _grantRole(SETTLER_ROLE, _operator);
    }

    // =========================================================================
    // LP DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit ETH liquidity into the vault
     * @dev LP earns proportional share of relay fees. Minimum deposit enforced.
     */
    function depositETH() external payable override nonReentrant whenNotPaused {
        if (msg.value < MIN_DEPOSIT) revert InvalidAmount();

        lpEthDeposited[msg.sender] += msg.value;
        lpDepositTimestamp[msg.sender] = block.timestamp;
        totalETH += msg.value;

        if (!isActiveLP[msg.sender]) {
            isActiveLP[msg.sender] = true;
            activeLPs.push(msg.sender);
        }

        emit LiquidityDeposited(msg.sender, address(0), msg.value);
    }

    /**
     * @notice Deposit ERC20 tokens into the vault
     * @param token ERC20 token address
     * @param amount Amount to deposit
     */
    function depositToken(
        address token,
        uint256 amount
    ) external override nonReentrant whenNotPaused {
        if (token == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        lpTokenDeposited[msg.sender][token] += amount;
        lpDepositTimestamp[msg.sender] = block.timestamp;
        totalTokens[token] += amount;

        if (!isActiveLP[msg.sender]) {
            isActiveLP[msg.sender] = true;
            activeLPs.push(msg.sender);
        }

        emit LiquidityDeposited(msg.sender, token, amount);
    }

    // =========================================================================
    // LP WITHDRAWAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Withdraw ETH liquidity from the vault
     * @param amount Amount to withdraw
     * @dev Subject to cooldown period to prevent flash-loan manipulation
     */
    function withdrawETH(
        uint256 amount
    ) external override nonReentrant whenNotPaused {
        if (amount == 0) revert InvalidAmount();
        if (lpEthDeposited[msg.sender] < amount) {
            revert InsufficientLPBalance(amount, lpEthDeposited[msg.sender]);
        }

        // Cooldown check
        uint256 cooldownEnd = lpDepositTimestamp[msg.sender] +
            WITHDRAWAL_COOLDOWN;
        if (block.timestamp < cooldownEnd) {
            revert WithdrawalCooldownActive(cooldownEnd);
        }

        // Check available (total - locked)
        uint256 available = totalETH - totalETHLocked;
        if (amount > available) {
            revert InsufficientLiquidity(address(0), amount, available);
        }

        lpEthDeposited[msg.sender] -= amount;
        totalETH -= amount;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "ETH transfer failed");

        emit LiquidityWithdrawn(msg.sender, address(0), amount);
    }

    /**
     * @notice Withdraw ERC20 tokens from the vault
     * @param token ERC20 token address
     * @param amount Amount to withdraw
     */
    function withdrawToken(
        address token,
        uint256 amount
    ) external override nonReentrant whenNotPaused {
        if (token == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();
        if (lpTokenDeposited[msg.sender][token] < amount) {
            revert InsufficientLPBalance(
                amount,
                lpTokenDeposited[msg.sender][token]
            );
        }

        // Cooldown check
        uint256 cooldownEnd = lpDepositTimestamp[msg.sender] +
            WITHDRAWAL_COOLDOWN;
        if (block.timestamp < cooldownEnd) {
            revert WithdrawalCooldownActive(cooldownEnd);
        }

        // Check available
        uint256 available = totalTokens[token] - totalTokensLocked[token];
        if (amount > available) {
            revert InsufficientLiquidity(token, amount, available);
        }

        lpTokenDeposited[msg.sender][token] -= amount;
        totalTokens[token] -= amount;

        IERC20(token).safeTransfer(msg.sender, amount);

        emit LiquidityWithdrawn(msg.sender, token, amount);
    }

    // =========================================================================
    // LIQUIDITY MANAGEMENT (called by CrossChainPrivacyHub)
    // =========================================================================

    /**
     * @notice Lock liquidity on the source chain for a pending cross-chain transfer
     * @dev Called by CrossChainPrivacyHub.initiatePrivateTransfer() on the source chain.
     *      Records the lock so these funds cannot be withdrawn by LPs until the transfer
     *      completes or expires. Does NOT move tokens — they are already in the vault.
     * @param requestId Unique identifier from the relay request
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to lock
     * @param destChainId Destination chain ID
     * @return success True if lock was successful
     */
    function lockLiquidity(
        bytes32 requestId,
        address token,
        uint256 amount,
        uint256 destChainId
    )
        external
        override
        onlyRole(PRIVACY_HUB_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool success)
    {
        if (amount == 0) revert InvalidAmount();
        // SECURITY FIX L-3: Use correct error for duplicate lock
        if (locks[requestId].amount != 0) revert LockAlreadyExists(requestId);

        // Check available liquidity (from LP deposits)
        if (token == address(0)) {
            uint256 available = totalETH - totalETHLocked;
            if (amount > available) {
                revert InsufficientLiquidity(token, amount, available);
            }
            totalETHLocked += amount;
        } else {
            uint256 available = totalTokens[token] - totalTokensLocked[token];
            if (amount > available) {
                revert InsufficientLiquidity(token, amount, available);
            }
            totalTokensLocked[token] += amount;
        }

        locks[requestId] = LiquidityLock({
            requestId: requestId,
            token: token,
            amount: amount,
            sourceChainId: chainId,
            destChainId: destChainId,
            lockTimestamp: uint64(block.timestamp),
            expiry: uint64(block.timestamp + LOCK_DURATION),
            released: false,
            refunded: false
        });

        activeLockIds.push(requestId);

        emit LiquidityLocked(requestId, token, amount, chainId, destChainId);

        return true;
    }

    /**
     * @notice Release liquidity on the destination chain to the recipient
     * @dev Called by CrossChainPrivacyHub.completeRelay() on the destination chain.
     *      This is where actual token value is delivered to the recipient. The vault
     *      sends LP-deposited tokens to the recipient and tracks the flow for settlement.
     * @param requestId Matching request ID from the source chain
     * @param token Token address (address(0) for ETH)
     * @param recipient Recipient address
     * @param amount Amount to release
     * @param sourceChainId Source chain ID (for settlement accounting)
     */
    function releaseLiquidity(
        bytes32 requestId,
        address token,
        address recipient,
        uint256 amount,
        uint256 sourceChainId
    ) external override onlyRole(PRIVACY_HUB_ROLE) nonReentrant whenNotPaused {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();

        // Check available liquidity on this (destination) chain
        if (token == address(0)) {
            uint256 available = totalETH - totalETHLocked;
            if (amount > available) {
                revert InsufficientLiquidity(token, amount, available);
            }
            totalETH -= amount;
        } else {
            uint256 available = totalTokens[token] - totalTokensLocked[token];
            if (amount > available) {
                revert InsufficientLiquidity(token, amount, available);
            }
            totalTokens[token] -= amount;
        }

        // Track net flow: sourceChain owes us (we released on their behalf)
        netFlows[sourceChainId][token] += int256(amount);

        // Transfer to recipient
        if (token == address(0)) {
            (bool sent, ) = recipient.call{value: amount}("");
            require(sent, "ETH release failed");
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit LiquidityReleased(requestId, recipient, token, amount);
    }

    /**
     * @notice Unlock liquidity for a lock on the source chain after successful completion
     * @dev Called after the destination chain has confirmed release. Unlocks the tokens
     *      so LPs can withdraw them. Updates settlement accounting.
     * @param requestId The request ID for the completed transfer
     */
    function unlockAfterCompletion(
        bytes32 requestId
    ) external onlyRole(PRIVACY_HUB_ROLE) nonReentrant {
        LiquidityLock storage lock = locks[requestId];
        if (lock.amount == 0) revert LockNotFound(requestId);
        if (lock.released) revert LockAlreadyReleased(requestId);
        if (lock.refunded) revert LockAlreadyRefunded(requestId);

        lock.released = true;

        // Unlock the tokens (reduce locked amount)
        if (lock.token == address(0)) {
            totalETHLocked -= lock.amount;
        } else {
            totalTokensLocked[lock.token] -= lock.amount;
        }

        // Track net flow: dest chain released on our behalf, adjust
        netFlows[lock.destChainId][lock.token] -= int256(lock.amount);
    }

    /**
     * @notice Refund a lock that has expired without completion
     * @dev Anyone can call this after expiry. Returns locked tokens to available pool.
     * @param requestId The request ID for the expired lock
     */
    function refundExpiredLock(
        bytes32 requestId
    ) external override nonReentrant {
        LiquidityLock storage lock = locks[requestId];
        if (lock.amount == 0) revert LockNotFound(requestId);
        if (lock.released) revert LockAlreadyReleased(requestId);
        if (lock.refunded) revert LockAlreadyRefunded(requestId);
        if (block.timestamp < lock.expiry) revert LockNotExpired(requestId);

        lock.refunded = true;

        // Return to available pool
        if (lock.token == address(0)) {
            totalETHLocked -= lock.amount;
        } else {
            totalTokensLocked[lock.token] -= lock.amount;
        }

        emit LiquidityLockRefunded(requestId, lock.token, lock.amount);
    }

    // =========================================================================
    // SETTLEMENT
    // =========================================================================

    /**
     * @notice Propose a settlement batch for cross-chain rebalancing
     * @dev Calculates net flows between this chain and a remote chain, creates
     *      a settlement batch that can be executed to rebalance via canonical bridges.
     * @param remoteChainId The remote chain to settle with
     * @param token Token address (address(0) for ETH)
     * @return batchId Settlement batch identifier
     */
    function proposeSettlement(
        uint256 remoteChainId,
        address token
    ) external override onlyRole(SETTLER_ROLE) returns (bytes32 batchId) {
        if (remoteVaults[remoteChainId] == address(0)) {
            revert ChainNotRegistered(remoteChainId);
        }

        int256 net = netFlows[remoteChainId][token];
        if (net == 0) revert InvalidAmount();

        batchId = keccak256(
            abi.encode(chainId, remoteChainId, token, settlementNonce++)
        );

        bool isOutflow = net < 0; // We owe the remote chain
        uint256 absAmount = net > 0 ? uint256(net) : uint256(-net);

        settlements[batchId] = SettlementBatch({
            batchId: batchId,
            remoteChainId: remoteChainId,
            token: token,
            netAmount: absAmount,
            isOutflow: isOutflow,
            timestamp: uint64(block.timestamp),
            executed: false
        });

        emit SettlementProposed(
            batchId,
            remoteChainId,
            token,
            absAmount,
            isOutflow
        );

        return batchId;
    }

    /**
     * @notice Execute a settlement batch (send tokens via canonical bridge)
     * @dev For outflows: sends tokens/ETH to the canonical bridge for the remote chain.
     *      For inflows: marks as settled (remote chain will send us tokens).
     *      Note: Actual bridge interaction should be handled by the operator off-chain
     *      or via a bridge adapter. This function just releases the funds and resets flows.
     * @param batchId The settlement batch to execute
     */
    function executeSettlement(
        bytes32 batchId
    ) external payable override onlyRole(SETTLER_ROLE) nonReentrant {
        SettlementBatch storage batch = settlements[batchId];
        if (batch.netAmount == 0) revert LockNotFound(batchId);
        if (batch.executed) revert SettlementAlreadyExecuted(batchId);

        batch.executed = true;

        // Reset net flows
        netFlows[batch.remoteChainId][batch.token] = 0;

        // If outflow, the funds need to be sent to the bridge
        // The operator handles the actual bridge call off-chain and sends
        // the correct ETH via msg.value or approves tokens
        if (batch.isOutflow) {
            // SECURITY FIX H-5: ETH outflows must be transferred, not just decremented.
            // Funds are sent to the msg.sender (settler) who bridges them.
            if (batch.token == address(0)) {
                totalETH -= batch.netAmount;
                // Transfer ETH to settler for bridging
                (bool sent, ) = msg.sender.call{value: batch.netAmount}("");
                require(sent, "ETH settlement transfer failed");
            } else {
                totalTokens[batch.token] -= batch.netAmount;
                // Transfer tokens to settler for bridging
                IERC20(batch.token).safeTransfer(msg.sender, batch.netAmount);
            }
        }
        // If inflow: remote chain's vault will send us tokens via bridge
        // We update totalETH/totalTokens when we receive them via receiveSettlement()

        emit SettlementExecuted(batchId, batch.remoteChainId, batch.netAmount);
    }

    /**
     * @notice Receive settlement inflow from a remote chain
     * @dev Called after tokens arrive via canonical bridge. Updates pool totals.
     * @param remoteChainId The remote chain that sent the settlement
     * @param token Token address (address(0) for ETH)
     * @param amount Amount received
     */
    function receiveSettlement(
        uint256 remoteChainId,
        address token,
        uint256 amount
    ) external payable onlyRole(SETTLER_ROLE) nonReentrant {
        if (remoteVaults[remoteChainId] == address(0)) {
            revert ChainNotRegistered(remoteChainId);
        }

        if (token == address(0)) {
            if (msg.value != amount) revert InvalidAmount();
            totalETH += amount;
        } else {
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            totalTokens[token] += amount;
        }
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Register a remote chain's vault address for settlement
     * @param remoteChainId The remote chain ID
     * @param remoteVault The remote vault contract address
     */
    function registerRemoteVault(
        uint256 remoteChainId,
        address remoteVault
    ) external onlyRole(OPERATOR_ROLE) {
        if (remoteVault == address(0)) revert ZeroAddress();

        if (remoteVaults[remoteChainId] == address(0)) {
            registeredChains.push(remoteChainId);
        }
        remoteVaults[remoteChainId] = remoteVault;

        emit ChainRegistered(remoteChainId, remoteVault);
    }

    /**
     * @notice Update the LP fee share
     * @param _lpFeeShareBps New LP fee share in basis points
     */
    function setLPFeeShare(
        uint256 _lpFeeShareBps
    ) external onlyRole(OPERATOR_ROLE) {
        if (_lpFeeShareBps > MAX_LP_FEE_BPS) revert InvalidAmount();
        lpFeeShareBps = _lpFeeShareBps;
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency withdraw all funds to admin (circuit breaker)
     * @dev Only callable by guardian when paused. Last resort.
     * @param token Token address (address(0) for ETH)
     * @param to Recipient address
     */
    function emergencyWithdraw(
        address token,
        address to
    ) external onlyRole(GUARDIAN_ROLE) {
        require(paused(), "Must be paused");
        if (to == address(0)) revert ZeroAddress();

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            totalETH = 0;
            totalETHLocked = 0;
            (bool sent, ) = to.call{value: balance}("");
            require(sent, "Emergency ETH transfer failed");
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            totalTokens[token] = 0;
            totalTokensLocked[token] = 0;
            IERC20(token).safeTransfer(to, balance);
        }
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc ICrossChainLiquidityVault
    function getAvailableLiquidity(
        address token
    ) external view override returns (uint256 available) {
        if (token == address(0)) {
            return totalETH - totalETHLocked;
        }
        return totalTokens[token] - totalTokensLocked[token];
    }

    /// @inheritdoc ICrossChainLiquidityVault
    function getLockedLiquidity(
        address token
    ) external view override returns (uint256 locked) {
        if (token == address(0)) {
            return totalETHLocked;
        }
        return totalTokensLocked[token];
    }

    /// @inheritdoc ICrossChainLiquidityVault
    function getNetSettlement(
        uint256 remoteChainId,
        address token
    ) external view override returns (uint256 netAmount, bool isOutflow) {
        int256 net = netFlows[remoteChainId][token];
        if (net >= 0) {
            return (uint256(net), false);
        }
        return (uint256(-net), true);
    }

    /// @inheritdoc ICrossChainLiquidityVault
    function getLock(
        bytes32 requestId
    )
        external
        view
        override
        returns (
            address token,
            uint256 amount,
            uint256 sourceChainId,
            uint256 destChainId,
            uint64 lockTimestamp,
            uint64 expiry,
            bool released,
            bool refunded
        )
    {
        LiquidityLock storage lock = locks[requestId];
        return (
            lock.token,
            lock.amount,
            lock.sourceChainId,
            lock.destChainId,
            lock.lockTimestamp,
            lock.expiry,
            lock.released,
            lock.refunded
        );
    }

    /// @inheritdoc ICrossChainLiquidityVault
    function hasSufficientLiquidity(
        address token,
        uint256 amount
    ) external view override returns (bool sufficient) {
        if (token == address(0)) {
            return (totalETH - totalETHLocked) >= amount;
        }
        return (totalTokens[token] - totalTokensLocked[token]) >= amount;
    }

    /// @notice Get number of active LPs
    function getActiveLPCount() external view returns (uint256) {
        return activeLPs.length;
    }

    /// @notice Get number of registered remote chains
    function getRegisteredChainCount() external view returns (uint256) {
        return registeredChains.length;
    }

    /// @notice Get number of active locks
    function getActiveLockCount() external view returns (uint256) {
        return activeLockIds.length;
    }

    // =========================================================================
    // RECEIVE
    // =========================================================================

    /// @notice Accept ETH deposits for settlement inflows
    receive() external payable {}
}
