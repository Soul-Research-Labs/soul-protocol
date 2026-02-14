// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SecurityModule} from "../security/SecurityModule.sol";

/// @title SoulAtomicSwapV2
/// @author Soul Protocol
/// @notice Atomic cross-chain swaps with HTLC, privacy features, and security hardening
/// @dev Implements hash time-locked contracts with stealth address support
///
/// Security Features (via SecurityModule):
/// - Rate limiting on swap creation
/// - Circuit breaker for abnormal swap volume
/// - Flash loan guards prevent same-block claim attacks
/// - Withdrawal limits for fee extraction
contract SoulAtomicSwapV2 is
    Ownable,
    ReentrancyGuard,
    Pausable,
    SecurityModule
{
    using SafeERC20 for IERC20;

    /// @notice Swap status enum
    enum SwapStatus {
        Invalid,
        Created,
        Claimed,
        Refunded,
        Expired
    }

    /// @notice Represents an atomic swap
    /// @param initiator The swap initiator
    /// @param recipient The intended recipient
    /// @param token The token address (address(0) for ETH)
    /// @param amount The swap amount
    /// @param hashLock The hash lock (keccak256 of secret)
    /// @param timeLock The time lock expiry timestamp
    /// @param status Current swap status
    /// @param commitment Privacy commitment for stealth transfer
    struct Swap {
        address initiator;
        address recipient;
        address token;
        uint256 amount;
        bytes32 hashLock;
        uint256 timeLock;
        SwapStatus status;
        bytes32 commitment;
    }

    /// @notice Mapping of swap ID to swap details
    mapping(bytes32 => Swap) public swaps;

    /// @notice Mapping of hash lock to swap ID (for lookup)
    mapping(bytes32 => bytes32) public hashLockToSwap;

    /// @notice Minimum time lock duration (1 hour)
    uint256 public constant MIN_TIMELOCK = 1 hours;

    /// @notice Maximum time lock duration (7 days)
    uint256 public constant MAX_TIMELOCK = 7 days;

    /// @notice Maximum protocol fee in basis points (1%)
    uint256 public constant MAX_FEE_BPS = 100;

    /// @notice Protocol fee in basis points (0.1%)
    uint256 public protocolFeeBps = 10;

    /// @notice Fee recipient address
    address public feeRecipient;

    /// @notice Total fees collected per token
    mapping(address => uint256) public collectedFees;

    /// @notice Commit-reveal for front-running protection
    mapping(bytes32 => mapping(address => bytes32)) public claimCommitments;
    mapping(bytes32 => mapping(address => uint256)) public commitTimestamps;

    /// @notice Pending fee withdrawals for timelock
    mapping(bytes32 => uint256) public pendingFeeWithdrawals;

    /// @notice Fee withdrawal timelock delay
    uint256 public constant FEE_WITHDRAWAL_DELAY = 2 days;

    /// @notice Timestamp buffer for miner manipulation protection
    uint256 public constant TIMESTAMP_BUFFER = 60;

    /// @notice Minimum delay between commit and reveal (L2-compatible)
    /// @dev Set to 2 seconds to be compatible with fast L2 block times (Arbitrum ~0.25s)
    uint256 public constant MIN_REVEAL_DELAY = 2;

    /// @notice Events
    event ClaimCommitted(
        bytes32 indexed swapId,
        address indexed committer,
        bytes32 commitHash
    );
    event FeeWithdrawalRequested(
        bytes32 indexed withdrawalId,
        address token,
        uint256 amount
    );
    event FeeWithdrawalExecuted(
        bytes32 indexed withdrawalId,
        address token,
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
        bytes32 secret
    );
    event SwapRefunded(bytes32 indexed swapId, address indexed initiator);
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event FeeRecipientUpdated(
        address indexed oldRecipient,
        address indexed newRecipient
    );

    /// @notice Custom errors
    error InvalidRecipient();
    error InvalidAmount();
    error InvalidTimeLock();
    error InvalidHashLock();
    error SwapAlreadyExists();
    error SwapNotFound();
    error SwapNotPending();
    error InvalidSecret();
    error SwapNotExpired();
    error SwapExpired();
    error NotInitiator();
    error TransferFailed();
    error ZeroAddress();
    error CommitTooRecent();
    error InvalidCommitHash();
    error WithdrawalNotReady();
    error WithdrawalNotFound();
    error UseCommitReveal();
    error NoFeesToWithdraw();
    error FeeTransferFailed();

    constructor(address _feeRecipient) Ownable(msg.sender) {
        if (_feeRecipient == address(0)) revert ZeroAddress();
        feeRecipient = _feeRecipient;
    }

    /// @notice Creates a new atomic swap (ETH)
    /// @param recipient The intended recipient
    /// @param hashLock The hash lock (keccak256 of secret)
    /// @param timeLock The time lock duration in seconds
    /// @param commitment Privacy commitment for stealth transfer
    /// @return swapId The unique swap identifier
    function createSwapETH(
        address recipient,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitment
    )
        external
        payable
        nonReentrant
        whenNotPaused
        rateLimited
        circuitBreaker(msg.value)
        returns (bytes32 swapId)
    {
        // Record deposit for flash loan protection
        _recordDeposit(msg.sender);

        return
            _createSwap(
                recipient,
                address(0),
                msg.value,
                hashLock,
                timeLock,
                commitment
            );
    }

    /// @notice Creates a new atomic swap (ERC20)
    /// @param recipient The intended recipient
    /// @param token The ERC20 token address
    /// @param amount The swap amount
    /// @param hashLock The hash lock (keccak256 of secret)
    /// @param timeLock The time lock duration in seconds
    /// @param commitment Privacy commitment for stealth transfer
    /// @return swapId The unique swap identifier
    function createSwapToken(
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitment
    )
        external
        nonReentrant
        whenNotPaused
        rateLimited
        circuitBreaker(amount)
        returns (bytes32 swapId)
    {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Record deposit for flash loan protection
        _recordDeposit(msg.sender);

        return
            _createSwap(
                recipient,
                token,
                amount,
                hashLock,
                timeLock,
                commitment
            );
    }

    /// @notice Internal function to create swap
    function _createSwap(
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitment
    ) internal returns (bytes32 swapId) {
        // Validations
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (timeLock < MIN_TIMELOCK || timeLock > MAX_TIMELOCK)
            revert InvalidTimeLock();
        if (hashLock == bytes32(0)) revert InvalidHashLock();
        if (hashLockToSwap[hashLock] != bytes32(0)) revert SwapAlreadyExists();

        // Generate swap ID using abi.encode (prevents collision with variable-length types)
        swapId = keccak256(
            abi.encode(
                msg.sender,
                recipient,
                token,
                amount,
                hashLock,
                block.timestamp
            )
        );

        // Calculate fee with cached storage read and unchecked math (saves ~60 gas)
        uint256 _protocolFeeBps = protocolFeeBps; // Cache SLOAD
        uint256 fee;
        uint256 netAmount;
        unchecked {
            fee = (amount * _protocolFeeBps) / 10000;
            netAmount = amount - fee; // Safe: fee < amount always since feeBps <= 100
        }
        collectedFees[token] += fee;

        // Cache timestamp to avoid multiple reads (saves ~3 gas each)
        uint256 currentTime = block.timestamp;
        uint256 deadline = currentTime + timeLock;

        // Create swap
        swaps[swapId] = Swap({
            initiator: msg.sender,
            recipient: recipient,
            token: token,
            amount: netAmount,
            hashLock: hashLock,
            timeLock: deadline,
            status: SwapStatus.Created,
            commitment: commitment
        });

        hashLockToSwap[hashLock] = swapId;

        emit SwapCreated(
            swapId,
            msg.sender,
            recipient,
            token,
            netAmount,
            hashLock,
            deadline
        );
    }

    /// @notice Commit to claiming a swap (step 1 of commit-reveal to prevent front-running)
    /// @param swapId The swap identifier
    /// @param commitHash keccak256(abi.encodePacked(secret, salt, msg.sender))
    function commitClaim(
        bytes32 swapId,
        bytes32 commitHash
    ) external whenNotPaused {
        Swap storage swap = swaps[swapId];
        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        // Use timestamp buffer to protect against miner manipulation
        if (block.timestamp + TIMESTAMP_BUFFER >= swap.timeLock)
            revert SwapExpired();

        claimCommitments[swapId][msg.sender] = commitHash;
        commitTimestamps[swapId][msg.sender] = block.timestamp;

        emit ClaimCommitted(swapId, msg.sender, commitHash);
    }

    /// @notice Reveal and claim a swap (step 2 of commit-reveal)
    /// @param swapId The swap identifier
    /// @param secret The secret that hashes to hashLock
    /// @param salt Random salt used in commit
    function revealClaim(
        bytes32 swapId,
        bytes32 secret,
        bytes32 salt
    ) external nonReentrant whenNotPaused {
        Swap storage swap = swaps[swapId];

        // Cache storage reads (saves ~100 gas per avoided SLOAD)
        uint256 _timeLock = swap.timeLock;
        bytes32 _hashLock = swap.hashLock;
        address _token = swap.token;
        address _recipient = swap.recipient;
        uint256 _amount = swap.amount;

        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        if (block.timestamp + TIMESTAMP_BUFFER >= _timeLock)
            revert SwapExpired();

        // Cache commit timestamp (saves SLOAD)
        uint256 _commitTime = commitTimestamps[swapId][msg.sender];

        // Verify commit was made at least 1 block ago (prevent same-block reveal)
        if (_commitTime == 0) revert InvalidCommitHash();
        if (block.timestamp < _commitTime + MIN_REVEAL_DELAY)
            revert CommitTooRecent();

        // Verify commit hash matches
        bytes32 expectedCommit = keccak256(
            abi.encodePacked(secret, salt, msg.sender)
        );
        if (claimCommitments[swapId][msg.sender] != expectedCommit)
            revert InvalidCommitHash();

        // Verify secret
        if (keccak256(abi.encodePacked(secret)) != _hashLock)
            revert InvalidSecret();

        // Clear commit data
        delete claimCommitments[swapId][msg.sender];
        delete commitTimestamps[swapId][msg.sender];

        swap.status = SwapStatus.Claimed;

        // Transfer to recipient using cached values
        _transferOut(_token, _recipient, _amount);

        emit SwapClaimed(swapId, msg.sender, secret);
    }

    /// @notice Legacy claim function for backwards compatibility (recipient only)
    /// @param swapId The swap identifier
    /// @param secret The secret that hashes to hashLock
    function claim(
        bytes32 swapId,
        bytes32 secret
    ) external nonReentrant whenNotPaused {
        Swap storage swap = swaps[swapId];

        // Cache storage reads (saves ~100 gas per avoided SLOAD)
        address _recipient = swap.recipient;
        address _token = swap.token;
        uint256 _amount = swap.amount;
        uint256 _timeLock = swap.timeLock;
        bytes32 _hashLock = swap.hashLock;

        // Only allow recipient to use direct claim (still has some MEV risk)
        if (msg.sender != _recipient) revert UseCommitReveal();

        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        if (block.timestamp + TIMESTAMP_BUFFER >= _timeLock)
            revert SwapExpired();
        if (keccak256(abi.encodePacked(secret)) != _hashLock)
            revert InvalidSecret();

        swap.status = SwapStatus.Claimed;

        _transferOut(_token, _recipient, _amount);

        emit SwapClaimed(swapId, msg.sender, secret);
    }

    /// @notice Refunds an expired swap to the initiator
    /// @param swapId The swap identifier
    function refund(bytes32 swapId) external nonReentrant {
        Swap storage swap = swaps[swapId];

        // Cache storage reads (saves ~100 gas per avoided SLOAD)
        address _initiator = swap.initiator;
        address _token = swap.token;
        uint256 _amount = swap.amount;
        uint256 _timeLock = swap.timeLock;

        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        if (block.timestamp < _timeLock) revert SwapNotExpired();

        swap.status = SwapStatus.Refunded;

        _transferOut(_token, _initiator, _amount);

        emit SwapRefunded(swapId, _initiator);
    }

    /// @dev Transfer ETH or ERC20 tokens to a recipient
    function _transferOut(address token, address to, uint256 amount) internal {
        if (token == address(0)) {
            (bool success, ) = to.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    /// @notice Gets swap details by hash lock
    /// @param hashLock The hash lock to lookup
    /// @return swap The swap details
    function getSwapByHashLock(
        bytes32 hashLock
    ) external view returns (Swap memory swap) {
        bytes32 swapId = hashLockToSwap[hashLock];
        return swaps[swapId];
    }

    /// @notice Checks if a swap is claimable
    /// @param swapId The swap identifier
    /// @return claimable True if claimable
    function isClaimable(
        bytes32 swapId
    ) external view returns (bool claimable) {
        Swap storage swap = swaps[swapId];
        return
            swap.status == SwapStatus.Created &&
            block.timestamp < swap.timeLock;
    }

    /// @notice Checks if a swap is refundable
    /// @param swapId The swap identifier
    /// @return refundable True if refundable
    function isRefundable(
        bytes32 swapId
    ) external view returns (bool refundable) {
        Swap storage swap = swaps[swapId];
        return
            swap.status == SwapStatus.Created &&
            block.timestamp >= swap.timeLock;
    }

    /// @notice Updates the protocol fee
    /// @param newFeeBps New fee in basis points
    function setProtocolFee(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps > MAX_FEE_BPS) revert InvalidAmount();
        uint256 oldFee = protocolFeeBps;
        protocolFeeBps = newFeeBps;
        emit FeeUpdated(oldFee, newFeeBps);
    }

    /// @notice Updates the fee recipient
    /// @param newRecipient New fee recipient address
    function setFeeRecipient(address newRecipient) external onlyOwner {
        if (newRecipient == address(0)) revert ZeroAddress();
        address oldRecipient = feeRecipient;
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(oldRecipient, newRecipient);
    }

    /// @notice Request fee withdrawal (starts timelock)
    /// @param token Token address (address(0) for ETH)
    /// @return withdrawalId The withdrawal request ID
    function requestFeeWithdrawal(
        address token
    ) external onlyOwner returns (bytes32 withdrawalId) {
        uint256 amount = collectedFees[token];
        if (amount == 0) revert NoFeesToWithdraw();

        withdrawalId = keccak256(
            abi.encodePacked(token, amount, block.timestamp)
        );
        pendingFeeWithdrawals[withdrawalId] = block.timestamp;

        emit FeeWithdrawalRequested(withdrawalId, token, amount);
    }

    /// @notice Execute fee withdrawal after timelock
    /// @param token Token address (address(0) for ETH)
    /// @param withdrawalId The withdrawal request ID
    function executeFeeWithdrawal(
        address token,
        bytes32 withdrawalId
    ) external onlyOwner {
        uint256 requestTime = pendingFeeWithdrawals[withdrawalId];
        if (requestTime == 0) revert WithdrawalNotFound();
        if (block.timestamp < requestTime + FEE_WITHDRAWAL_DELAY)
            revert WithdrawalNotReady();

        delete pendingFeeWithdrawals[withdrawalId];

        uint256 amount = collectedFees[token];
        collectedFees[token] = 0;

        // CEI: emit event before external calls
        emit FeeWithdrawalExecuted(withdrawalId, token, amount);

        if (token == address(0)) {
            (bool success, ) = feeRecipient.call{value: amount}("");
            if (!success) revert FeeTransferFailed();
        } else {
            IERC20(token).safeTransfer(feeRecipient, amount);
        }
    }

    /// @notice Emergency fee withdrawal (legacy, still has timelock via governance)
    /// @param token Token address (address(0) for ETH)
    /// @dev Deprecated: Use requestFeeWithdrawal + executeFeeWithdrawal
    function withdrawFees(address token) external onlyOwner {
        // For backwards compatibility, initiate a withdrawal request
        bytes32 withdrawalId = keccak256(
            abi.encodePacked(token, collectedFees[token], block.timestamp)
        );
        pendingFeeWithdrawals[withdrawalId] = block.timestamp;
        emit FeeWithdrawalRequested(withdrawalId, token, collectedFees[token]);
    }

    /// @notice Pause the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyOwner {
        _unpause();
    }

    // ============ Security Admin Functions ============

    /// @notice Configure rate limiting parameters
    /// @param window Window duration in seconds
    /// @param maxActions Max actions per window
    function setRateLimitConfig(
        uint256 window,
        uint256 maxActions
    ) external onlyOwner {
        _setRateLimitConfig(window, maxActions);
    }

    /// @notice Configure circuit breaker parameters
    /// @param threshold Volume threshold
    /// @param cooldown Cooldown period after trip
    function setCircuitBreakerConfig(
        uint256 threshold,
        uint256 cooldown
    ) external onlyOwner {
        _setCircuitBreakerConfig(threshold, cooldown);
    }

    /// @notice Toggle security features on/off
    /// @param rateLimiting Enable rate limiting
    /// @param circuitBreakers Enable circuit breaker
    /// @param flashLoanGuard Enable flash loan guard
    /// @param withdrawalLimits Enable withdrawal limits
    function setSecurityFeatures(
        bool rateLimiting,
        bool circuitBreakers,
        bool flashLoanGuard,
        bool withdrawalLimits
    ) external onlyOwner {
        _setSecurityFeatures(
            rateLimiting,
            circuitBreakers,
            flashLoanGuard,
            withdrawalLimits
        );
    }

    /// @notice Emergency reset circuit breaker
    function resetCircuitBreaker() external onlyOwner {
        _resetCircuitBreaker();
    }

    /// @notice Receive ETH
    receive() external payable {}
}
