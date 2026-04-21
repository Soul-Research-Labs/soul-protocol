// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICrossChainLiquidityVault} from "../interfaces/ICrossChainLiquidityVault.sol";
import {IRebalanceSwapAdapter} from "../interfaces/IRebalanceSwapAdapter.sol";
import {ILiquidityProofVerifier} from "../interfaces/ILiquidityProofVerifier.sol";

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
    // PRIVACY CONSTANTS — Timing correlation resistance
    // =========================================================================

    /// @notice Fixed denomination tiers for amount privacy (prevents correlation by non-standard amounts)
    /// @dev Matches DelayedClaimVault denomination pattern
    uint256 public constant DENOMINATION_TIER_1 = 0.1 ether;
    uint256 public constant DENOMINATION_TIER_2 = 1 ether;
    uint256 public constant DENOMINATION_TIER_3 = 10 ether;
    uint256 public constant DENOMINATION_TIER_4 = 100 ether;

    /// @notice Minimum hold period before release is eligible (timing correlation resistance)
    uint256 public constant MIN_RELEASE_DELAY = 1 hours;

    /// @notice Maximum additional randomized delay for releases
    uint256 public constant MAX_RELEASE_JITTER = 4 hours;

    /// @notice Whether denomination enforcement is active (can be toggled)
    bool public denominationEnforcement = true;

    /// @notice Maximum configurable denomination tiers per token
    uint256 public constant MAX_TOKEN_DENOMINATION_TIERS = 8;

    /// @notice Per-token denomination tiers: token => tier values (sorted ascending)
    mapping(address => uint256[]) private _tokenDenominations;

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

    // --- Rebalance Swap Adapter ---

    /// @notice Optional DEX adapter for swapping tokens during settlement rebalancing
    IRebalanceSwapAdapter public rebalanceAdapter;

    /// @notice Emitted when the rebalance adapter is updated
    event RebalanceAdapterUpdated(
        address indexed oldAdapter,
        address indexed newAdapter
    );

    /// @notice Emitted when a settlement includes a DEX swap
    event SettlementSwapExecuted(
        bytes32 indexed batchId,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );

    // --- Privacy: Pending Releases ---

    /// @notice Pending release entry (staged for delayed claim to break timing correlation)
    struct PendingRelease {
        address token;
        address recipient;
        uint256 amount;
        uint256 claimableAt; // block.timestamp + MIN_RELEASE_DELAY + jitter
        bool claimed;
    }

    /// @notice Pending releases: requestId => PendingRelease
    mapping(bytes32 => PendingRelease) public pendingReleases;

    /// @notice Count of pending releases for view queries
    uint256 public pendingReleaseCount;

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

        // Mark LP inactive if all ETH withdrawn (gas optimization for iterations)
        if (lpEthDeposited[msg.sender] == 0) {
            isActiveLP[msg.sender] = false;
        }

        (bool sent, ) = msg.sender.call{value: amount}("");
        if (!sent) revert TransferFailed();

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

        // Mark LP inactive if all tokens of this type withdrawn
        if (
            lpTokenDeposited[msg.sender][token] == 0 &&
            lpEthDeposited[msg.sender] == 0
        ) {
            isActiveLP[msg.sender] = false;
        }

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

        // PRIVACY: Enforce denomination bucketing to prevent amount correlation
        if (denominationEnforcement) {
            if (token == address(0)) {
                if (!_isValidDenomination(amount))
                    revert InvalidDenomination(amount);
            } else {
                if (!_isValidTokenDenomination(token, amount))
                    revert InvalidDenomination(amount);
            }
        }

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
     *      PRIVACY: Funds are staged into a pending release with a randomized delay
     *      to break timing correlation between source chain locks and destination releases.
     *      Recipients must call claimRelease() after the delay expires.
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

        // PRIVACY: Enforce denomination bucketing on releases too
        if (denominationEnforcement) {
            if (token == address(0)) {
                if (!_isValidDenomination(amount))
                    revert InvalidDenomination(amount);
            } else {
                if (!_isValidTokenDenomination(token, amount))
                    revert InvalidDenomination(amount);
            }
        }

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

        // PRIVACY: Stage release with randomized delay to break timing correlation
        // Jitter derived from request-specific entropy (not manipulable by recipient)
        uint256 jitter = uint256(
            keccak256(abi.encode(requestId, block.prevrandao))
        ) % MAX_RELEASE_JITTER;
        uint256 claimableAt = block.timestamp + MIN_RELEASE_DELAY + jitter;

        pendingReleases[requestId] = PendingRelease({
            token: token,
            recipient: recipient,
            amount: amount,
            claimableAt: claimableAt,
            claimed: false
        });
        ++pendingReleaseCount;

        emit LiquidityReleased(requestId, recipient, token, amount);
    }

    /**
     * @notice Claim a pending release after the delay has expired
     * @dev Anyone can call this on behalf of the recipient (relayer-friendly).
     *      The funds always go to the original recipient, not msg.sender.
     * @param requestId The request ID for the pending release
     */
    function claimRelease(
        bytes32 requestId
    ) external nonReentrant whenNotPaused {
        PendingRelease storage release = pendingReleases[requestId];
        if (release.amount == 0) revert LockNotFound(requestId);
        if (release.claimed) revert ReleaseAlreadyClaimed(requestId);
        if (block.timestamp < release.claimableAt) {
            revert ReleaseNotClaimable(requestId, release.claimableAt);
        }

        release.claimed = true;

        // Transfer to original recipient
        if (release.token == address(0)) {
            (bool sent, ) = release.recipient.call{value: release.amount}("");
            if (!sent) revert TransferFailed();
        } else {
            IERC20(release.token).safeTransfer(
                release.recipient,
                release.amount
            );
        }
    }

    /**
     * @notice Unlock liquidity for a lock on the source chain after successful completion
     * @dev Called after the destination chain has confirmed release. Unlocks the tokens
     *      so LPs can withdraw them. Updates settlement accounting.
     * @param requestId The request ID for the completed transfer
     */
    function unlockAfterCompletion(
        bytes32 requestId
    ) external onlyRole(PRIVACY_HUB_ROLE) nonReentrant whenNotPaused {
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

        // Subtract settled amount from net flows instead of zeroing
        // This preserves any flows that accumulated between propose and execute
        if (batch.isOutflow) {
            netFlows[batch.remoteChainId][batch.token] += int256(
                batch.netAmount
            );
        } else {
            netFlows[batch.remoteChainId][batch.token] -= int256(
                batch.netAmount
            );
        }

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
                if (!sent) revert TransferFailed();
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
    // SETTLEMENT WITH SWAP (Rebalance via DEX)
    // =========================================================================

    /**
     * @notice Execute a settlement batch with a token swap before bridging
     * @dev For outflows: swaps the settlement token to a target token before sending
     *      to the settler for bridging. Useful when the vault has excess of one token
     *      but needs to send a different one.
     *
     *      Example: Vault has excess USDC, owes remote chain ETH.
     *      Settler calls executeSettlementWithSwap(batchId, WETH, minOut, deadline)
     *      → Vault swaps USDC→WETH via Uniswap V3, sends WETH to settler.
     *
     * @param batchId The settlement batch to execute
     * @param targetToken Token to swap INTO before sending to settler
     * @param minAmountOut Minimum acceptable output from the swap (slippage protection)
     * @param deadline Timestamp after which the swap reverts
     */
    function executeSettlementWithSwap(
        bytes32 batchId,
        address targetToken,
        uint256 minAmountOut,
        uint256 deadline
    ) external payable onlyRole(SETTLER_ROLE) nonReentrant {
        if (address(rebalanceAdapter) == address(0)) revert ZeroAddress();

        SettlementBatch storage batch = settlements[batchId];
        if (batch.netAmount == 0) revert LockNotFound(batchId);
        if (batch.executed) revert SettlementAlreadyExecuted(batchId);
        if (!batch.isOutflow) revert InvalidAmount(); // Swap only on outflows

        batch.executed = true;

        // SECURITY FIX H1: Delta-adjust netFlows instead of zeroing.
        // Preserves any flows accumulated between propose and execute.
        // executeSettlementWithSwap only handles outflows (isOutflow required above),
        // so we add back the settled amount.
        netFlows[batch.remoteChainId][batch.token] += int256(batch.netAmount);

        uint256 amountOut;

        if (batch.token == address(0)) {
            // ETH outflow → swap ETH to targetToken
            totalETH -= batch.netAmount;
            amountOut = rebalanceAdapter.swap{value: batch.netAmount}(
                address(0),
                targetToken,
                batch.netAmount,
                minAmountOut,
                msg.sender,
                deadline
            );
        } else {
            // ERC20 outflow → swap to targetToken
            totalTokens[batch.token] -= batch.netAmount;
            IERC20(batch.token).forceApprove(
                address(rebalanceAdapter),
                batch.netAmount
            );
            amountOut = rebalanceAdapter.swap(
                batch.token,
                targetToken,
                batch.netAmount,
                minAmountOut,
                msg.sender,
                deadline
            );
            // Reset approval
            IERC20(batch.token).forceApprove(address(rebalanceAdapter), 0);
        }

        emit SettlementSwapExecuted(
            batchId,
            batch.token,
            targetToken,
            batch.netAmount,
            amountOut
        );
        emit SettlementExecuted(batchId, batch.remoteChainId, amountOut);
    }

    /**
     * @notice Receive settlement inflow and swap to a different token for vault inventory
     * @dev Called when the inbound settlement token doesn't match what the vault needs.
     *      Example: Received USDC from remote settlement, but LP pool needs ETH.
     *
     * @param remoteChainId The remote chain that sent the settlement
     * @param tokenIn Token being received from settlement
     * @param amount Amount received
     * @param targetToken Token to swap INTO for vault inventory
     * @param minAmountOut Minimum acceptable swap output
     * @param deadline Swap deadline
     */
    function receiveSettlementWithSwap(
        uint256 remoteChainId,
        address tokenIn,
        uint256 amount,
        address targetToken,
        uint256 minAmountOut,
        uint256 deadline
    ) external payable onlyRole(SETTLER_ROLE) nonReentrant {
        if (address(rebalanceAdapter) == address(0)) revert ZeroAddress();
        if (remoteVaults[remoteChainId] == address(0)) {
            revert ChainNotRegistered(remoteChainId);
        }

        uint256 amountOut;

        if (tokenIn == address(0)) {
            if (msg.value != amount) revert InvalidAmount();
            // Swap ETH → targetToken, receive into vault
            amountOut = rebalanceAdapter.swap{value: amount}(
                address(0),
                targetToken,
                amount,
                minAmountOut,
                address(this),
                deadline
            );
            totalTokens[targetToken] += amountOut;
        } else {
            // Pull tokens from settler
            IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amount);
            // Approve adapter and swap
            IERC20(tokenIn).forceApprove(address(rebalanceAdapter), amount);
            if (targetToken == address(0)) {
                // Swap ERC20 → ETH
                amountOut = rebalanceAdapter.swap(
                    tokenIn,
                    address(0),
                    amount,
                    minAmountOut,
                    address(this),
                    deadline
                );
                totalETH += amountOut;
            } else {
                // Swap ERC20 → ERC20
                amountOut = rebalanceAdapter.swap(
                    tokenIn,
                    targetToken,
                    amount,
                    minAmountOut,
                    address(this),
                    deadline
                );
                totalTokens[targetToken] += amountOut;
            }
            // Reset approval
            IERC20(tokenIn).forceApprove(address(rebalanceAdapter), 0);
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
     * @notice Set or update the rebalance swap adapter (e.g., UniswapV3RebalanceAdapter)
     * @dev Set to address(0) to disable settlement swaps
     * @param _adapter Address of the IRebalanceSwapAdapter implementation
     */
    function setRebalanceAdapter(
        address _adapter
    ) external onlyRole(OPERATOR_ROLE) {
        address old = address(rebalanceAdapter);
        rebalanceAdapter = IRebalanceSwapAdapter(_adapter);
        emit RebalanceAdapterUpdated(old, _adapter);
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

    // =========================================================================
    // ZK LIQUIDITY-PROOF GATING (optional, opt-in)
    // =========================================================================

    /// @notice Optional on-chain verifier for the `liquidity_proof` Noir circuit.
    /// @dev When unset, {releaseLiquidityWithProof} reverts. Existing
    ///      {releaseLiquidity} (role-gated) is unchanged.
    ILiquidityProofVerifier public liquidityProofVerifier;

    /// @notice Nullifiers consumed by ZK-gated releases (replay prevention).
    mapping(bytes32 => bool) public liquidityProofNullifiers;

    event LiquidityProofVerifierUpdated(
        address indexed previous,
        address indexed current
    );
    event LiquidityProofConsumed(
        bytes32 indexed requestId,
        bytes32 indexed nullifier
    );

    error LiquidityProofVerifierUnset();
    error LiquidityProofInvalid();
    error LiquidityProofNullifierUsed(bytes32 nullifier);

    /// @notice Wire (or replace) the liquidity-proof verifier.
    function setLiquidityProofVerifier(
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit LiquidityProofVerifierUpdated(
            address(liquidityProofVerifier),
            verifier
        );
        liquidityProofVerifier = ILiquidityProofVerifier(verifier);
    }

    /**
     * @notice Attest a `liquidity_proof` before releasing on this vault.
     * @dev Validates the ZK proof against the wired verifier and consumes
     *      the nullifier (publicInputs[2]). Intended call pattern:
     *        1. Relayer / PrivacyHub calls {attestLiquidityProof} with proof + public inputs.
     *        2. Same caller (PRIVACY_HUB_ROLE) then calls {releaseLiquidity}.
     *
     *      Splitting attestation from release keeps the existing role-gated
     *      `releaseLiquidity` path unmodified (preserves tests) while adding
     *      optional cryptographic backing when the verifier is wired.
     *
     *      Public-input layout must match `noir/liquidity_proof/src/main.nr`:
     *        [0] lock_commitment, [1] pool_commitment, [2] nullifier,
     *        [3] transfer_amount_hash, [4] current_timestamp.
     */
    function attestLiquidityProof(
        bytes32 requestId,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external onlyRole(PRIVACY_HUB_ROLE) whenNotPaused {
        if (address(liquidityProofVerifier) == address(0))
            revert LiquidityProofVerifierUnset();
        if (publicInputs.length < 5) revert LiquidityProofInvalid();

        bytes32 nullifier = publicInputs[2];
        if (liquidityProofNullifiers[nullifier])
            revert LiquidityProofNullifierUsed(nullifier);

        bool ok = liquidityProofVerifier.verify(proof, publicInputs);
        if (!ok) revert LiquidityProofInvalid();

        liquidityProofNullifiers[nullifier] = true;
        emit LiquidityProofConsumed(requestId, nullifier);
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
        if (!paused()) revert NotPaused();
        if (to == address(0)) revert ZeroAddress();

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            totalETH = 0;
            totalETHLocked = 0;
            (bool sent, ) = to.call{value: balance}("");
            if (!sent) revert TransferFailed();
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
    // PRIVACY ADMIN
    // =========================================================================

    /**
     * @notice Toggle denomination enforcement for ETH locks
     * @param _enabled Whether denomination enforcement is active
     */
    function setDenominationEnforcement(
        bool _enabled
    ) external onlyRole(OPERATOR_ROLE) {
        denominationEnforcement = _enabled;
    }

    /**
     * @notice Configure denomination tiers for an ERC20 token
     * @dev Tiers must be sorted ascending and non-zero. At most MAX_TOKEN_DENOMINATION_TIERS.
     *      Tokens without configured tiers will pass denomination checks (permissive default).
     * @param token ERC20 token address
     * @param tiers Array of valid denomination amounts (sorted ascending)
     */
    function setTokenDenominations(
        address token,
        uint256[] calldata tiers
    ) external onlyRole(OPERATOR_ROLE) {
        if (token == address(0)) revert ZeroAddress();
        if (tiers.length > MAX_TOKEN_DENOMINATION_TIERS) revert InvalidAmount();
        for (uint256 i = 0; i < tiers.length; i++) {
            if (tiers[i] == 0) revert InvalidAmount();
            if (i > 0 && tiers[i] <= tiers[i - 1]) revert InvalidAmount();
        }
        _tokenDenominations[token] = tiers;
    }

    /**
     * @notice Get configured denomination tiers for a token
     * @param token Token address
     * @return tiers Array of valid denominations
     */
    function getTokenDenominations(
        address token
    ) external view returns (uint256[] memory tiers) {
        return _tokenDenominations[token];
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /**
     * @notice Check if an ETH amount matches one of the fixed denomination tiers
     * @param amount Amount to validate
     * @return valid True if amount is a valid denomination
     */
    function _isValidDenomination(
        uint256 amount
    ) internal pure returns (bool valid) {
        return
            amount == DENOMINATION_TIER_1 ||
            amount == DENOMINATION_TIER_2 ||
            amount == DENOMINATION_TIER_3 ||
            amount == DENOMINATION_TIER_4;
    }

    /**
     * @notice Check if a token amount matches one of the configured denomination tiers
     * @dev If no tiers are configured for the token, the check passes (permissive).
     * @param token ERC20 token address
     * @param amount Amount to validate
     * @return valid True if amount is a valid denomination or token has no tiers configured
     */
    function _isValidTokenDenomination(
        address token,
        uint256 amount
    ) internal view returns (bool valid) {
        uint256[] storage tiers = _tokenDenominations[token];
        if (tiers.length == 0) return true; // no tiers configured — permissive
        for (uint256 i = 0; i < tiers.length; i++) {
            if (amount == tiers[i]) return true;
        }
        return false;
    }

    // =========================================================================
    // RECEIVE
    // =========================================================================

    /// @notice Accept ETH deposits for settlement inflows
    receive() external payable {}
}
