// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SecurityModule} from "../security/SecurityModule.sol";

/**
 * @title SoulAtomicSwapV2Upgradeable
 * @author Soul Protocol
 * @notice UUPS-upgradeable version of SoulAtomicSwapV2 for proxy deployments
 * @dev Atomic cross-chain swaps with HTLC, privacy features, and security hardening.
 *
 * UPGRADE NOTES:
 * - AccessControlUpgradeable used for role-based permissioning
 * - Constructor replaced with `initialize(address admin, address _feeRecipient)`
 * - All OZ base contracts replaced with upgradeable variants
 * - SecurityModule retained as-is (abstract, no constructor)
 * - UUPS upgrade restricted to UPGRADER_ROLE
 * - Storage gap (`__gap[50]`) reserved for future upgrades
 * - `contractVersion` tracks upgrade count
 *
 * Security Features (via SecurityModule):
 * - Rate limiting on swap creation
 * - Circuit breaker for abnormal swap volume
 * - Flash loan guards prevent same-block claim attacks
 * - Withdrawal limits for fee extraction
 *
 * @custom:oz-upgrades-from SoulAtomicSwapV2
 */
contract SoulAtomicSwapV2Upgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    SecurityModule
{
    /// @notice Role for upgrade authorization
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    /// @notice Role for operational admin functions (fees, config)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    /// @notice Role for emergency actions (pause/unpause, circuit breaker reset)
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Swap status enum
    enum SwapStatus {
        Invalid,
        Created,
        Claimed,
        Refunded,
        Expired
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Represents an atomic swap
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

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

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
    uint256 public protocolFeeBps;

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
    uint256 public constant MIN_REVEAL_DELAY = 2;

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the upgradeable SoulAtomicSwapV2
     * @param admin Admin address granted all roles
     * @param _feeRecipient Fee recipient address
     */
    function initialize(
        address admin,
        address _feeRecipient
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_feeRecipient == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);

        feeRecipient = _feeRecipient;
        protocolFeeBps = 10; // 0.1%

        // Initialize SecurityModule defaults (field initializers don't execute through proxy)
        __initSecurityModule();

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          SWAP CREATION
    //////////////////////////////////////////////////////////////*/

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
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (timeLock < MIN_TIMELOCK || timeLock > MAX_TIMELOCK)
            revert InvalidTimeLock();
        if (hashLock == bytes32(0)) revert InvalidHashLock();
        if (hashLockToSwap[hashLock] != bytes32(0)) revert SwapAlreadyExists();

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

        uint256 _protocolFeeBps = protocolFeeBps;
        uint256 fee;
        uint256 netAmount;
        unchecked {
            fee = (amount * _protocolFeeBps) / 10000;
            netAmount = amount - fee;
        }
        collectedFees[token] += fee;

        uint256 currentTime = block.timestamp;
        uint256 deadline = currentTime + timeLock;

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

    /*//////////////////////////////////////////////////////////////
                          SWAP CLAIMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Commit to claiming a swap (step 1 of commit-reveal)
    /// @param swapId The swap identifier
    /// @param commitHash keccak256(abi.encodePacked(secret, salt, msg.sender))
    function commitClaim(
        bytes32 swapId,
        bytes32 commitHash
    ) external whenNotPaused {
        Swap storage swap = swaps[swapId];
        if (swap.status != SwapStatus.Created) revert SwapNotPending();
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

        uint256 _timeLock = swap.timeLock;
        bytes32 _hashLock = swap.hashLock;
        address _token = swap.token;
        address _recipient = swap.recipient;
        uint256 _amount = swap.amount;

        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        if (block.timestamp + TIMESTAMP_BUFFER >= _timeLock)
            revert SwapExpired();

        uint256 _commitTime = commitTimestamps[swapId][msg.sender];
        if (_commitTime == 0) revert InvalidCommitHash();
        if (block.timestamp < _commitTime + MIN_REVEAL_DELAY)
            revert CommitTooRecent();

        bytes32 expectedCommit = keccak256(
            abi.encodePacked(secret, salt, msg.sender)
        );
        if (claimCommitments[swapId][msg.sender] != expectedCommit)
            revert InvalidCommitHash();

        if (keccak256(abi.encodePacked(secret)) != _hashLock)
            revert InvalidSecret();

        delete claimCommitments[swapId][msg.sender];
        delete commitTimestamps[swapId][msg.sender];

        swap.status = SwapStatus.Claimed;

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

        address _recipient = swap.recipient;
        address _token = swap.token;
        uint256 _amount = swap.amount;
        uint256 _timeLock = swap.timeLock;
        bytes32 _hashLock = swap.hashLock;

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

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets swap details by hash lock
    function getSwapByHashLock(
        bytes32 hashLock
    ) external view returns (Swap memory swap) {
        bytes32 swapId = hashLockToSwap[hashLock];
        return swaps[swapId];
    }

    /// @notice Checks if a swap is claimable
    function isClaimable(
        bytes32 swapId
    ) external view returns (bool claimable) {
        Swap storage swap = swaps[swapId];
        return
            swap.status == SwapStatus.Created &&
            block.timestamp < swap.timeLock;
    }

    /// @notice Checks if a swap is refundable
    function isRefundable(
        bytes32 swapId
    ) external view returns (bool refundable) {
        Swap storage swap = swaps[swapId];
        return
            swap.status == SwapStatus.Created &&
            block.timestamp >= swap.timeLock;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates the protocol fee
    function setProtocolFee(
        uint256 newFeeBps
    ) external onlyRole(OPERATOR_ROLE) {
        if (newFeeBps > MAX_FEE_BPS) revert InvalidAmount();
        uint256 oldFee = protocolFeeBps;
        protocolFeeBps = newFeeBps;
        emit FeeUpdated(oldFee, newFeeBps);
    }

    /// @notice Updates the fee recipient
    function setFeeRecipient(
        address newRecipient
    ) external onlyRole(OPERATOR_ROLE) {
        if (newRecipient == address(0)) revert ZeroAddress();
        address oldRecipient = feeRecipient;
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(oldRecipient, newRecipient);
    }

    /// @notice Request fee withdrawal (starts timelock)
    function requestFeeWithdrawal(
        address token
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 withdrawalId) {
        uint256 amount = collectedFees[token];
        if (amount == 0) revert NoFeesToWithdraw();

        withdrawalId = keccak256(
            abi.encodePacked(token, amount, block.timestamp)
        );
        pendingFeeWithdrawals[withdrawalId] = block.timestamp;

        emit FeeWithdrawalRequested(withdrawalId, token, amount);
    }

    /// @notice Execute fee withdrawal after timelock
    function executeFeeWithdrawal(
        address token,
        bytes32 withdrawalId
    ) external onlyRole(OPERATOR_ROLE) {
        uint256 requestTime = pendingFeeWithdrawals[withdrawalId];
        if (requestTime == 0) revert WithdrawalNotFound();
        if (block.timestamp < requestTime + FEE_WITHDRAWAL_DELAY)
            revert WithdrawalNotReady();

        delete pendingFeeWithdrawals[withdrawalId];

        uint256 amount = collectedFees[token];
        collectedFees[token] = 0;

        emit FeeWithdrawalExecuted(withdrawalId, token, amount);

        if (token == address(0)) {
            (bool success, ) = feeRecipient.call{value: amount}("");
            if (!success) revert FeeTransferFailed();
        } else {
            IERC20(token).safeTransfer(feeRecipient, amount);
        }
    }

    /// @notice Emergency fee withdrawal (legacy)
    /// @dev Deprecated: Use requestFeeWithdrawal + executeFeeWithdrawal
    function withdrawFees(address token) external onlyRole(OPERATOR_ROLE) {
        bytes32 withdrawalId = keccak256(
            abi.encodePacked(token, collectedFees[token], block.timestamp)
        );
        pendingFeeWithdrawals[withdrawalId] = block.timestamp;
        emit FeeWithdrawalRequested(withdrawalId, token, collectedFees[token]);
    }

    /// @notice Pause the contract
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                       SECURITY ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configure rate limiting parameters
    function setRateLimitConfig(
        uint256 window,
        uint256 maxActions
    ) external onlyRole(OPERATOR_ROLE) {
        _setRateLimitConfig(window, maxActions);
    }

    /// @notice Configure circuit breaker parameters
    function setCircuitBreakerConfig(
        uint256 threshold,
        uint256 cooldown
    ) external onlyRole(OPERATOR_ROLE) {
        _setCircuitBreakerConfig(threshold, cooldown);
    }

    /// @notice Toggle security features on/off
    function setSecurityFeatures(
        bool rateLimiting,
        bool circuitBreakers,
        bool flashLoanGuard,
        bool withdrawalLimits
    ) external onlyRole(OPERATOR_ROLE) {
        _setSecurityFeatures(
            rateLimiting,
            circuitBreakers,
            flashLoanGuard,
            withdrawalLimits
        );
    }

    /// @notice Emergency reset circuit breaker
    function resetCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        _resetCircuitBreaker();
    }

    /*//////////////////////////////////////////////////////////////
                            UUPS UPGRADE
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Authorize UUPS upgrade — restricted to UPGRADER_ROLE
     * @param newImplementation Address of the new implementation contract
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        contractVersion++;
    }

    /// @notice Receive ETH
    receive() external payable {}
}
