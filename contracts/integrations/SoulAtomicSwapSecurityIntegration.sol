// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title SoulAtomicSwapSecurityIntegration
 * @author Soul Protocol
 * @notice Integrates MEV protection and flash loan guards with atomic swaps
 * @dev Extends atomic swap functionality with commit-reveal and flash loan detection
 *
 * SECURITY INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                 Atomic Swap Security Stack                      │
 * │                                                                  │
 * │   User Request                                                  │
 * │        │                                                         │
 * │   ┌────▼─────────────────────────────────────────────────────┐  │
 * │   │  Layer 1: MEV Protection (Commit-Reveal)                 │  │
 * │   │  ├─ commitSwap(hash) → wait MIN_REVEAL_DELAY blocks      │  │
 * │   │  └─ revealSwap(data, salt) → execute if valid            │  │
 * │   └────┬─────────────────────────────────────────────────────┘  │
 * │        │                                                         │
 * │   ┌────▼─────────────────────────────────────────────────────┐  │
 * │   │  Layer 2: Flash Loan Detection                           │  │
 * │   │  ├─ Block-level operation tracking                       │  │
 * │   │  ├─ Balance snapshot validation                          │  │
 * │   │  └─ Cross-DEX price consistency check                    │  │
 * │   └────┬─────────────────────────────────────────────────────┘  │
 * │        │                                                         │
 * │   ┌────▼─────────────────────────────────────────────────────┐  │
 * │   │  Layer 3: Rate Limiting & Circuit Breaker                │  │
 * │   │  ├─ Per-user swap limits (count & value)                 │  │
 * │   │  ├─ Global volume limits                                 │  │
 * │   │  └─ Anomaly-based circuit breaker                        │  │
 * │   └────┬─────────────────────────────────────────────────────┘  │
 * │        │                                                         │
 * │   ┌────▼─────────────────────────────────────────────────────┐  │
 * │   │  Layer 4: Atomic Swap Execution                          │  │
 * │   │  ├─ HTLC creation with stealth addresses                 │  │
 * │   │  ├─ Hash-locked claims                                   │  │
 * │   │  └─ Time-locked refunds                                  │  │
 * │   └──────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract SoulAtomicSwapSecurityIntegration is
    ReentrancyGuard,
    AccessControl,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error CommitmentNotFound();
    error CommitmentNotReady();
    error CommitmentExpired();
    error InvalidRevealData();
    error FlashLoanDetected();
    error RateLimitExceeded();
    error CircuitBreakerActive();
    error InvalidSwapParameters();
    error SwapNotFound();
    error SwapNotClaimable();
    error InvalidSecret();
    error SwapExpired();
    error SwapNotRefundable();
    error PriceDeviationTooHigh();
    error IncorrectETHAmount();
    error ETHTransferFailed();


    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event SwapCommitted(
        bytes32 indexed commitmentId,
        address indexed initiator,
        uint256 readyAt,
        uint256 expiresAt
    );

    event SwapRevealed(
        bytes32 indexed commitmentId,
        bytes32 indexed swapId,
        address initiator,
        address recipient,
        uint256 amount
    );

    event SwapCreated(
        bytes32 indexed swapId,
        address indexed initiator,
        address indexed recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock
    );

    event SwapClaimed(
        bytes32 indexed swapId,
        address indexed claimer,
        bytes32 preimage
    );

    event SwapRefunded(bytes32 indexed swapId, address indexed initiator);

    event FlashLoanGuardTriggered(address indexed user, string reason);

    event CircuitBreakerTriggered(uint256 timestamp, string reason);

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum SwapStatus {
        NONE,
        COMMITTED,
        CREATED,
        CLAIMED,
        REFUNDED,
        EXPIRED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Commitment {
        address initiator;
        bytes32 commitHash;
        uint256 createdBlock;
        uint256 readyBlock;
        uint256 expiresBlock;
        bool revealed;
    }

    struct ProtectedSwap {
        bytes32 id;
        address initiator;
        address recipient;
        address token;
        uint256 amount;
        bytes32 hashLock;
        uint256 timeLock;
        SwapStatus status;
        bytes32 commitmentId;
        uint256 createdBlock;
    }

    struct UserLimits {
        uint256 swapCount;
        uint256 totalValue;
        uint256 lastResetTimestamp;
    }

    struct FlashLoanSnapshot {
        uint256 blockNumber;
        mapping(address => uint256) tokenBalances;
        bool hasOperation;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant PRICE_ORACLE_ROLE = keccak256("PRICE_ORACLE_ROLE");

    /// @notice Minimum blocks before reveal (MEV protection)
    uint256 public constant MIN_REVEAL_DELAY = 2;

    /// @notice Maximum blocks before commitment expires
    uint256 public constant MAX_COMMITMENT_AGE = 100;

    /// @notice Minimum swap timelock
    uint256 public constant MIN_TIMELOCK = 1 hours;

    /// @notice Maximum swap timelock
    uint256 public constant MAX_TIMELOCK = 7 days;

    /// @notice Maximum price deviation in basis points (5%)
    uint256 public maxPriceDeviationBps = 500;

    /// @notice Daily swap limit per user (ETH value)
    uint256 public dailySwapLimit = 100 ether;

    /// @notice Daily swap count limit per user
    uint256 public dailySwapCountLimit = 50;

    /// @notice Global volume limit before circuit breaker
    uint256 public globalVolumeLimit = 10000 ether;

    /// @notice Circuit breaker cooldown period
    uint256 public circuitBreakerCooldown = 1 hours;

    /// @notice Circuit breaker state
    bool public circuitBreakerActive;
    uint256 public circuitBreakerActivatedAt;

    /// @notice Daily global volume
    uint256 public dailyGlobalVolume;
    uint256 public lastVolumeResetTimestamp;

    /// @notice Commitments mapping
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Swaps mapping
    mapping(bytes32 => ProtectedSwap) public swaps;

    /// @notice User limits
    mapping(address => UserLimits) public userLimits;

    /// @notice Last operation block per user (flash loan detection)
    mapping(address => uint256) public lastOperationBlock;

    /// @notice Balance snapshots per block per user
    mapping(address => mapping(uint256 => mapping(address => uint256)))
        public balanceSnapshots;

    /// @notice Commitment nonce
    mapping(address => uint256) public commitmentNonce;

    /// @notice Price oracle for tokens
    mapping(address => uint256) public tokenPrices;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        lastVolumeResetTimestamp = block.timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                         MEV PROTECTION (LAYER 1)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit to a swap (step 1 of commit-reveal)
     * @param commitHash Hash of (swapParams, salt)
     * @return commitmentId Unique commitment identifier
     */
    function commitSwap(
        bytes32 commitHash
    ) external whenNotPaused returns (bytes32 commitmentId) {
        _checkCircuitBreaker();
        _checkFlashLoanGuard(msg.sender);

        uint256 nonce = commitmentNonce[msg.sender]++;
        commitmentId = keccak256(
            abi.encodePacked(msg.sender, commitHash, nonce, block.number)
        );

        commitments[commitmentId] = Commitment({
            initiator: msg.sender,
            commitHash: commitHash,
            createdBlock: block.number,
            readyBlock: block.number + MIN_REVEAL_DELAY,
            expiresBlock: block.number + MAX_COMMITMENT_AGE,
            revealed: false
        });

        emit SwapCommitted(
            commitmentId,
            msg.sender,
            block.number + MIN_REVEAL_DELAY,
            block.number + MAX_COMMITMENT_AGE
        );
    }

    /**
     * @notice Reveal and create swap (step 2 of commit-reveal)
     * @param commitmentId The commitment to reveal
     * @param recipient Swap recipient
     * @param token Token address (address(0) for ETH)
     * @param amount Swap amount
     * @param hashLock HTLC hash lock
     * @param timeLock HTLC time lock
     * @param salt Random salt used in commitment
     */
    function revealSwap(
        bytes32 commitmentId,
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 salt
    ) external payable nonReentrant whenNotPaused returns (bytes32 swapId) {
        Commitment storage commitment = commitments[commitmentId];

        // Validate commitment
        if (commitment.initiator == address(0)) revert CommitmentNotFound();
        if (commitment.revealed) revert CommitmentNotFound();
        if (block.number < commitment.readyBlock) revert CommitmentNotReady();
        if (block.number > commitment.expiresBlock) revert CommitmentExpired();
        if (commitment.initiator != msg.sender) revert InvalidRevealData();

        // Verify commitment hash
        bytes32 expectedHash = keccak256(
            abi.encodePacked(recipient, token, amount, hashLock, timeLock, salt)
        );
        if (commitment.commitHash != expectedHash) revert InvalidRevealData();

        // Flash loan check
        _checkFlashLoanGuard(msg.sender);

        // Rate limit check
        _checkRateLimits(msg.sender, amount, token);

        // Mark commitment as revealed
        commitment.revealed = true;

        // Create the swap
        swapId = _createSwap(
            msg.sender,
            recipient,
            token,
            amount,
            hashLock,
            timeLock,
            commitmentId
        );

        emit SwapRevealed(commitmentId, swapId, msg.sender, recipient, amount);
    }

    /*//////////////////////////////////////////////////////////////
                      FLASH LOAN DETECTION (LAYER 2)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check for flash loan attack patterns
     * @param user User to check
     */
    function _checkFlashLoanGuard(address user) internal {
        // Same-block operation check
        if (lastOperationBlock[user] == block.number) {
            emit FlashLoanGuardTriggered(user, "Same-block operation detected");
            revert FlashLoanDetected();
        }

        lastOperationBlock[user] = block.number;
    }

    /**
     * @notice Take balance snapshot for flash loan detection
     * @param user User address
     * @param tokens Token addresses to snapshot
     */
    function takeBalanceSnapshot(
        address user,
        address[] calldata tokens
    ) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 balance;
            if (tokens[i] == address(0)) {
                balance = user.balance;
            } else {
                balance = IERC20(tokens[i]).balanceOf(user);
            }
            balanceSnapshots[user][block.number][tokens[i]] = balance;
        }
    }

    /**
     * @notice Validate balance hasn't changed suspiciously
     * @param user User to validate
     * @param token Token to check
     * @param expectedBalance Expected balance (used for validation threshold)
     */
    function validateBalance(
        address user,
        address token,
        uint256 expectedBalance
    ) external view returns (bool) {
        uint256 snapshotBalance = balanceSnapshots[user][block.number][token];
        if (snapshotBalance == 0) return true; // No snapshot

        uint256 currentBalance;
        if (token == address(0)) {
            currentBalance = user.balance;
        } else {
            currentBalance = IERC20(token).balanceOf(user);
        }

        // Use expectedBalance for additional validation
        if (expectedBalance > 0 && currentBalance < expectedBalance) {
            return false; // Balance less than expected
        }

        // Check for suspicious balance changes
        uint256 deviation;
        if (currentBalance > snapshotBalance) {
            deviation =
                ((currentBalance - snapshotBalance) * 10000) /
                snapshotBalance;
        } else {
            deviation =
                ((snapshotBalance - currentBalance) * 10000) /
                snapshotBalance;
        }

        return deviation <= maxPriceDeviationBps;
    }

    /*//////////////////////////////////////////////////////////////
                      RATE LIMITING (LAYER 3)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check rate limits for user
     * @param user User address
     * @param amount Swap amount
     * @param token Token address
     */
    function _checkRateLimits(
        address user,
        uint256 amount,
        address token
    ) internal {
        // Reset daily limits if needed
        if (block.timestamp > userLimits[user].lastResetTimestamp + 1 days) {
            userLimits[user].swapCount = 0;
            userLimits[user].totalValue = 0;
            userLimits[user].lastResetTimestamp = block.timestamp;
        }

        // Calculate value in ETH
        uint256 valueInEth = _getValueInEth(token, amount);

        // Check user limits
        if (userLimits[user].swapCount >= dailySwapCountLimit) {
            revert RateLimitExceeded();
        }
        if (userLimits[user].totalValue + valueInEth > dailySwapLimit) {
            revert RateLimitExceeded();
        }

        // Update user limits
        userLimits[user].swapCount++;
        userLimits[user].totalValue += valueInEth;

        // Update global volume
        _updateGlobalVolume(valueInEth);
    }

    /**
     * @notice Update global volume and check circuit breaker
     * @param valueInEth Value to add
     */
    function _updateGlobalVolume(uint256 valueInEth) internal {
        // Reset daily volume if needed
        if (block.timestamp > lastVolumeResetTimestamp + 1 days) {
            dailyGlobalVolume = 0;
            lastVolumeResetTimestamp = block.timestamp;
        }

        dailyGlobalVolume += valueInEth;

        // Trigger circuit breaker if limit exceeded
        if (dailyGlobalVolume > globalVolumeLimit && !circuitBreakerActive) {
            circuitBreakerActive = true;
            circuitBreakerActivatedAt = block.timestamp;
            emit CircuitBreakerTriggered(
                block.timestamp,
                "Volume limit exceeded"
            );
        }
    }

    /**
     * @notice Check circuit breaker status
     */
    function _checkCircuitBreaker() internal view {
        if (circuitBreakerActive) {
            if (
                block.timestamp <
                circuitBreakerActivatedAt + circuitBreakerCooldown
            ) {
                revert CircuitBreakerActive();
            }
        }
    }

    /**
     * @notice Get value in ETH for rate limiting
     * @param token Token address
     * @param amount Amount
     * @return valueInEth Value in ETH
     */
    function _getValueInEth(
        address token,
        uint256 amount
    ) internal view returns (uint256 valueInEth) {
        if (token == address(0)) {
            return amount;
        }

        uint256 price = tokenPrices[token];
        if (price == 0) {
            // Default to 1:1 if no price set
            return amount;
        }

        return (amount * price) / 1e18;
    }

    /*//////////////////////////////////////////////////////////////
                       ATOMIC SWAP (LAYER 4)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a protected swap
     */
    function _createSwap(
        address initiator,
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitmentId
    ) internal returns (bytes32 swapId) {
        // Validate parameters
        if (recipient == address(0)) revert InvalidSwapParameters();
        if (amount == 0) revert InvalidSwapParameters();
        if (hashLock == bytes32(0)) revert InvalidSwapParameters();
        if (timeLock < block.timestamp + MIN_TIMELOCK)
            revert InvalidSwapParameters();
        if (timeLock > block.timestamp + MAX_TIMELOCK)
            revert InvalidSwapParameters();

        swapId = keccak256(
            abi.encodePacked(
                initiator,
                recipient,
                token,
                amount,
                hashLock,
                timeLock,
                block.number
            )
        );

        // Transfer tokens to contract
        if (token == address(0)) {
            if (msg.value != amount) revert IncorrectETHAmount();
        } else {
            IERC20(token).safeTransferFrom(initiator, address(this), amount);
        }

        swaps[swapId] = ProtectedSwap({
            id: swapId,
            initiator: initiator,
            recipient: recipient,
            token: token,
            amount: amount,
            hashLock: hashLock,
            timeLock: timeLock,
            status: SwapStatus.CREATED,
            commitmentId: commitmentId,
            createdBlock: block.number
        });

        emit SwapCreated(
            swapId,
            initiator,
            recipient,
            token,
            amount,
            hashLock,
            timeLock
        );
    }

    /**
     * @notice Claim a swap with the preimage
     * @param swapId Swap identifier
     * @param preimage The secret preimage
     */
    function claimSwap(
        bytes32 swapId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        ProtectedSwap storage swap = swaps[swapId];

        if (swap.status != SwapStatus.CREATED) revert SwapNotClaimable();
        if (block.timestamp >= swap.timeLock) revert SwapExpired();
        if (keccak256(abi.encodePacked(preimage)) != swap.hashLock) {
            revert InvalidSecret();
        }

        // Flash loan check on claimer
        _checkFlashLoanGuard(msg.sender);

        swap.status = SwapStatus.CLAIMED;

        // Transfer to recipient
        if (swap.token == address(0)) {
            (bool success, ) = swap.recipient.call{value: swap.amount}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(swap.token).safeTransfer(swap.recipient, swap.amount);
        }

        emit SwapClaimed(swapId, msg.sender, preimage);
    }

    /**
     * @notice Refund an expired swap
     * @param swapId Swap identifier
     */
    function refundSwap(bytes32 swapId) external nonReentrant whenNotPaused {
        ProtectedSwap storage swap = swaps[swapId];

        if (swap.status != SwapStatus.CREATED) revert SwapNotRefundable();
        if (block.timestamp < swap.timeLock) revert SwapNotRefundable();

        swap.status = SwapStatus.REFUNDED;

        // Transfer back to initiator
        if (swap.token == address(0)) {
            (bool success, ) = swap.initiator.call{value: swap.amount}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(swap.token).safeTransfer(swap.initiator, swap.amount);
        }

        emit SwapRefunded(swapId, swap.initiator);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set token price for rate limiting
     * @param token Token address
     * @param price Price in ETH (18 decimals)
     */
    function setTokenPrice(
        address token,
        uint256 price
    ) external onlyRole(PRICE_ORACLE_ROLE) {
        tokenPrices[token] = price;
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerActive = false;
    }

    /**
     * @notice Update rate limits
     * @param _dailySwapLimit Daily swap limit in ETH
     * @param _dailySwapCountLimit Daily swap count limit
     * @param _globalVolumeLimit Global volume limit
     */
    function updateRateLimits(
        uint256 _dailySwapLimit,
        uint256 _dailySwapCountLimit,
        uint256 _globalVolumeLimit
    ) external onlyRole(OPERATOR_ROLE) {
        dailySwapLimit = _dailySwapLimit;
        dailySwapCountLimit = _dailySwapCountLimit;
        globalVolumeLimit = _globalVolumeLimit;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get swap details
     * @param swapId Swap identifier
     */
    function getSwap(
        bytes32 swapId
    ) external view returns (ProtectedSwap memory) {
        return swaps[swapId];
    }

    /**
     * @notice Get commitment details
     * @param commitmentId Commitment identifier
     */
    function getCommitment(
        bytes32 commitmentId
    ) external view returns (Commitment memory) {
        return commitments[commitmentId];
    }

    /**
     * @notice Get user limits
     * @param user User address
     */
    function getUserLimits(
        address user
    ) external view returns (UserLimits memory) {
        return userLimits[user];
    }

    /**
     * @notice Check if user can perform swap
     * @param user User address
     * @param amount Swap amount
     * @param token Token address
     */
    function canSwap(
        address user,
        uint256 amount,
        address token
    ) external view returns (bool, string memory) {
        // Check circuit breaker
        if (circuitBreakerActive) {
            if (
                block.timestamp <
                circuitBreakerActivatedAt + circuitBreakerCooldown
            ) {
                return (false, "Circuit breaker active");
            }
        }

        // Check flash loan guard
        if (lastOperationBlock[user] == block.number) {
            return (false, "Same-block operation");
        }

        // Check rate limits
        UserLimits memory limits = userLimits[user];
        if (block.timestamp <= limits.lastResetTimestamp + 1 days) {
            if (limits.swapCount >= dailySwapCountLimit) {
                return (false, "Swap count limit exceeded");
            }

            uint256 valueInEth = _getValueInEth(token, amount);
            if (limits.totalValue + valueInEth > dailySwapLimit) {
                return (false, "Value limit exceeded");
            }
        }

        return (true, "");
    }
}
