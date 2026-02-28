// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title GriefingProtection
 * @author ZASEON
 * @notice Protection against griefing and DoS attacks
 * @dev Implements gas limits, refund caps, and anti-DoS mechanisms
 *
 * Security Properties:
 * 1. Gas Limits: Caps gas for external calls and callbacks
 * 2. Refund Caps: Limits refunds for failed operations
 * 3. Batch Limits: Restricts batch operation sizes
 * 4. Failure Rate Limiting: Tracks and limits failed transactions
 * 5. Cost Recovery: Ensures attackers pay for their attacks
 */
contract GriefingProtection is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error GasLimitExceeded();
    error RefundCapExceeded();
    error BatchSizeTooLarge();
    error TooManyFailedAttempts();
    error CooldownActive();
    error InsufficientDeposit();
    error CallbackGasExceeded();
    error SuspiciousActivity();
    error NotWhitelisted();
    error WithdrawalFailed();

    error DepositRequired();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event GasLimitUpdated(bytes32 indexed operationType, uint256 newLimit);
    event RefundIssued(
        address indexed recipient,
        uint256 amount,
        bytes32 reason
    );
    event RefundDenied(
        address indexed recipient,
        uint256 requested,
        string reason
    );
    event UserSuspended(address indexed user, uint256 until, string reason);
    event FailedAttemptRecorded(address indexed user, uint256 failCount);
    event DepositReceived(address indexed user, uint256 amount);
    event DepositRefunded(address indexed user, uint256 amount);
    event SuspiciousActivityDetected(
        address indexed user,
        bytes32 activityType
    );
    event BatchLimitUpdated(uint256 newLimit);

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct UserGriefingStats {
        uint256 failedAttempts;
        uint256 lastFailedAttempt;
        uint256 totalRefundsReceived;
        uint256 suspendedUntil;
        uint256 depositBalance;
        uint256 gasUsedThisEpoch;
        uint256 epochStartBlock;
        bool isWhitelisted;
    }

    struct OperationLimits {
        uint256 maxGas;
        uint256 maxRefund;
        uint256 maxBatchSize;
        uint256 minDeposit;
        bool requiresDeposit;
    }

    struct CallbackConfig {
        uint256 maxGas;
        uint256 maxRetries;
        uint256 retryDelay;
        bool enabled;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Maximum failed attempts before suspension
    uint256 public maxFailedAttempts;

    /// @notice Suspension duration in seconds
    uint256 public suspensionDuration;

    /// @notice Epoch length in blocks for gas tracking
    uint256 public constant EPOCH_LENGTH = 100;

    /// @notice Maximum gas per epoch per user
    uint256 public maxGasPerEpoch;

    /// @notice Global refund pool
    uint256 public refundPool;

    /// @notice Maximum refund pool percentage for single user
    uint256 public maxRefundPoolPercentage;

    /// @notice Default batch limit
    uint256 public defaultBatchLimit;

    /// @notice User griefing statistics
    mapping(address => UserGriefingStats) public userStats;

    /// @notice Operation type limits
    mapping(bytes32 => OperationLimits) public operationLimits;

    /// @notice Callback configurations
    mapping(address => CallbackConfig) public callbackConfigs;

    /// @notice Protected contracts that use this module
    mapping(address => bool) public protectedContracts;

    /// @notice Collected deposits
    uint256 public totalDeposits;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _maxFailedAttempts,
        uint256 _suspensionDuration,
        uint256 _maxGasPerEpoch,
        address admin
    ) {
        maxFailedAttempts = _maxFailedAttempts; // e.g., 5
        suspensionDuration = _suspensionDuration; // e.g., 1 hours
        maxGasPerEpoch = _maxGasPerEpoch; // e.g., 10_000_000
        maxRefundPoolPercentage = 1000; // 10%
        defaultBatchLimit = 50;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        // Default operation limits
        _setOperationLimit(
            keccak256("PROOF_RELAY"),
            500_000, // max gas
            0.01 ether, // max refund
            10, // max batch
            0, // min deposit
            false // requires deposit
        );

        _setOperationLimit(
            keccak256("PROOF_VERIFICATION"),
            1_000_000,
            0.005 ether,
            5,
            0,
            false
        );

        _setOperationLimit(
            keccak256("WITHDRAWAL"),
            300_000,
            0.02 ether,
            20,
            0.01 ether,
            true
        );
    }

    /*//////////////////////////////////////////////////////////////
                           PROTECTION CHECKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if user can perform operation
     * @param user User address
     * @param operationType Type of operation
     * @param batchSize Size of batch (1 for single)
     * @return allowed Whether operation is allowed
     * @return reason Reason if not allowed
     */
    function canPerformOperation(
        address user,
        bytes32 operationType,
        uint256 batchSize
    ) external view returns (bool allowed, string memory reason) {
        UserGriefingStats storage stats = userStats[user];
        OperationLimits storage limits = operationLimits[operationType];

        // Check suspension
        if (stats.suspendedUntil > block.timestamp) {
            return (false, "User suspended");
        }

        // Check failed attempts
        if (stats.failedAttempts >= maxFailedAttempts) {
            // Check if cooldown has passed
            if (
                block.timestamp < stats.lastFailedAttempt + suspensionDuration
            ) {
                return (false, "Too many failed attempts");
            }
        }

        // Check batch size
        if (batchSize > limits.maxBatchSize && limits.maxBatchSize > 0) {
            return (false, "Batch size exceeded");
        }

        // Check deposit requirement
        if (
            limits.requiresDeposit && stats.depositBalance < limits.minDeposit
        ) {
            return (false, "Deposit required");
        }

        // Check epoch gas limit
        if (_isNewEpoch(stats)) {
            // New epoch, gas limit reset
            return (true, "");
        }

        if (stats.gasUsedThisEpoch + limits.maxGas > maxGasPerEpoch) {
            return (false, "Epoch gas limit exceeded");
        }

        return (true, "");
    }

    /**
     * @notice Validate and prepare for operation
     * @param user User performing operation
     * @param operationType Type of operation
     * @param estimatedGas Estimated gas usage
          * @return valid The valid
     */
    function validateOperation(
        address user,
        bytes32 operationType,
        uint256 estimatedGas
    ) external onlyProtectedContract returns (bool valid) {
        UserGriefingStats storage stats = userStats[user];
        OperationLimits storage limits = operationLimits[operationType];

        // Check suspension
        if (stats.suspendedUntil > block.timestamp) {
            revert SuspiciousActivity();
        }

        // Check and reset epoch
        if (_isNewEpoch(stats)) {
            stats.epochStartBlock = block.number;
            stats.gasUsedThisEpoch = 0;
        }

        // Validate gas
        if (estimatedGas > limits.maxGas) {
            revert GasLimitExceeded();
        }

        if (stats.gasUsedThisEpoch + estimatedGas > maxGasPerEpoch) {
            revert GasLimitExceeded();
        }

        // Check deposit
        if (
            limits.requiresDeposit && stats.depositBalance < limits.minDeposit
        ) {
            revert DepositRequired();
        }

        // Update gas usage
        stats.gasUsedThisEpoch += estimatedGas;

        return true;
    }

    /**
     * @notice Record a failed operation
     * @param user User who failed

     */
    function recordFailure(
        address user,
        bytes32 /* operationType */
    ) external onlyProtectedContract {
        UserGriefingStats storage stats = userStats[user];

        stats.failedAttempts++;
        stats.lastFailedAttempt = block.timestamp;

        emit FailedAttemptRecorded(user, stats.failedAttempts);

        // Auto-suspend if too many failures
        if (stats.failedAttempts >= maxFailedAttempts) {
            stats.suspendedUntil = block.timestamp + suspensionDuration;
            emit UserSuspended(user, stats.suspendedUntil, "Too many failures");
        }
    }

    /**
     * @notice Record a successful operation (reset failure count)
     * @param user User who succeeded
     */
    function recordSuccess(address user) external onlyProtectedContract {
        UserGriefingStats storage stats = userStats[user];

        // Gradually reduce failure count on success
        if (stats.failedAttempts > 0) {
            stats.failedAttempts--;
        }
    }

    /*//////////////////////////////////////////////////////////////
                           DEPOSIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit funds for anti-griefing protection
     */
    function deposit() external payable nonReentrant {
        UserGriefingStats storage stats = userStats[msg.sender];
        stats.depositBalance += msg.value;
        totalDeposits += msg.value;

        emit DepositReceived(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw deposit (if not suspended)
     * @param amount Amount to withdraw
     */
    function withdrawDeposit(uint256 amount) external nonReentrant {
        UserGriefingStats storage stats = userStats[msg.sender];

        if (stats.suspendedUntil > block.timestamp) {
            revert SuspiciousActivity();
        }

        if (amount > stats.depositBalance) {
            revert InsufficientDeposit();
        }

        stats.depositBalance -= amount;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit DepositRefunded(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           REFUND FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request a refund for failed operation
     * @param user User requesting refund
     * @param amount Requested amount
     * @param operationType Type of operation
     * @param reason Reason for refund
     * @return approved Whether refund was approved
     */
    function requestRefund(
        address user,
        uint256 amount,
        bytes32 operationType,
        bytes32 reason
    ) external onlyProtectedContract returns (bool approved) {
        UserGriefingStats storage stats = userStats[user];
        OperationLimits storage limits = operationLimits[operationType];

        // Check if user is suspended (griefing protection)
        if (stats.suspendedUntil > block.timestamp) {
            emit RefundDenied(user, amount, "User suspended");
            return false;
        }

        // Check max refund for operation type
        if (amount > limits.maxRefund) {
            amount = limits.maxRefund;
        }

        // Check refund pool limits
        uint256 maxFromPool = (refundPool * maxRefundPoolPercentage) / 10000;
        if (amount > maxFromPool) {
            emit RefundDenied(user, amount, "Exceeds pool limit");
            return false;
        }

        // Check user's total refunds (anti-griefing)
        if (stats.totalRefundsReceived > 1 ether) {
            // High refund history - reduce refund
            amount = amount / 2;
        }

        if (amount > refundPool) {
            emit RefundDenied(user, amount, "Insufficient pool");
            return false;
        }

        refundPool -= amount;
        stats.totalRefundsReceived += amount;

        (bool success, ) = user.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit RefundIssued(user, amount, reason);
        return true;
    }

    /**
     * @notice Add funds to refund pool
     */
    function fundRefundPool() external payable {
        refundPool += msg.value;
    }

    /*//////////////////////////////////////////////////////////////
                         CALLBACK PROTECTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute a protected callback with gas limits
     * @param target Callback target
     * @param data Callback data
     * @return success Whether callback succeeded
     * @return returnData Return data from callback
     */
    function executeProtectedCallback(
        address target,
        bytes calldata data
    )
        external
        onlyProtectedContract
        nonReentrant
        returns (bool success, bytes memory returnData)
    {
        CallbackConfig storage config = callbackConfigs[target];

        uint256 gasLimit = config.enabled ? config.maxGas : 100_000;

        (success, returnData) = target.call{gas: gasLimit}(data);

        if (!success) {
            // Don't revert, just return failure
            return (false, returnData);
        }

        return (true, returnData);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get user's griefing stats
     * @param user User address
     * @return failedAttempts Number of failed attempts
     * @return suspendedUntil Suspension end time
     * @return depositBalance Current deposit
     */
    function getUserStats(
        address user
    )
        external
        view
        returns (
            uint256 failedAttempts,
            uint256 suspendedUntil,
            uint256 depositBalance
        )
    {
        UserGriefingStats storage stats = userStats[user];
        return (
            stats.failedAttempts,
            stats.suspendedUntil,
            stats.depositBalance
        );
    }

    /**
     * @notice Check if user is currently suspended
     * @param user User address
     * @return suspended Whether user is suspended
     */
    function isSuspended(address user) external view returns (bool suspended) {
        return userStats[user].suspendedUntil > block.timestamp;
    }

    /**
     * @notice Get remaining gas allowance for user this epoch
     * @param user User address
     * @return remaining Remaining gas
     */
    function getRemainingGasAllowance(
        address user
    ) external view returns (uint256 remaining) {
        UserGriefingStats storage stats = userStats[user];

        if (_isNewEpoch(stats)) {
            return maxGasPerEpoch;
        }

        if (stats.gasUsedThisEpoch >= maxGasPerEpoch) {
            return 0;
        }

        return maxGasPerEpoch - stats.gasUsedThisEpoch;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _isNewEpoch(
        UserGriefingStats storage stats
    ) internal view returns (bool) {
        return block.number >= stats.epochStartBlock + EPOCH_LENGTH;
    }

    function _setOperationLimit(
        bytes32 operationType,
        uint256 maxGas,
        uint256 maxRefund,
        uint256 maxBatchSize,
        uint256 minDeposit,
        bool requiresDeposit
    ) internal {
        operationLimits[operationType] = OperationLimits({
            maxGas: maxGas,
            maxRefund: maxRefund,
            maxBatchSize: maxBatchSize,
            minDeposit: minDeposit,
            requiresDeposit: requiresDeposit
        });
    }

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyProtectedContract() {
        if (
            !protectedContracts[msg.sender] &&
            !hasRole(OPERATOR_ROLE, msg.sender)
        ) {
            revert NotWhitelisted();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a protected contract
     * @param contractAddr Contract address
     */
    function registerProtectedContract(
        address contractAddr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        protectedContracts[contractAddr] = true;
    }

    /**
     * @notice Update operation limits
     * @param operationType Operation type
     * @param maxGas Max gas limit
     * @param maxRefund Max refund amount
     * @param maxBatchSize Max batch size
          * @param minDeposit The minDeposit bound
     * @param requiresDeposit The requires deposit
     */
    function setOperationLimits(
        bytes32 operationType,
        uint256 maxGas,
        uint256 maxRefund,
        uint256 maxBatchSize,
        uint256 minDeposit,
        bool requiresDeposit
    ) external onlyRole(OPERATOR_ROLE) {
        _setOperationLimit(
            operationType,
            maxGas,
            maxRefund,
            maxBatchSize,
            minDeposit,
            requiresDeposit
        );
        emit GasLimitUpdated(operationType, maxGas);
    }

    /**
     * @notice Configure callback settings
     * @param target Callback target
     * @param maxGas Max gas for callback
     * @param maxRetries Max retry attempts
     * @param enabled Whether callbacks are enabled
          * @param retryDelay The retry delay
     */
    function configureCallback(
        address target,
        uint256 maxGas,
        uint256 maxRetries,
        uint256 retryDelay,
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        callbackConfigs[target] = CallbackConfig({
            maxGas: maxGas,
            maxRetries: maxRetries,
            retryDelay: retryDelay,
            enabled: enabled
        });
    }

    /**
     * @notice Manually suspend a user
     * @param user User to suspend
     * @param duration Suspension duration
     * @param reason Reason for suspension
     */
    function suspendUser(
        address user,
        uint256 duration,
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        userStats[user].suspendedUntil = block.timestamp + duration;
        emit UserSuspended(user, block.timestamp + duration, reason);
    }

    /**
     * @notice Unsuspend a user
     * @param user User to unsuspend
     */
    function unsuspendUser(address user) external onlyRole(GUARDIAN_ROLE) {
        userStats[user].suspendedUntil = 0;
        userStats[user].failedAttempts = 0;
    }

    /**
     * @notice Whitelist a user (bypass some checks)
     * @param user User to whitelist
     */
    function whitelistUser(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        userStats[user].isWhitelisted = true;
    }

    /**
     * @notice Update global parameters
     * @param _maxFailedAttempts New max failed attempts
     * @param _suspensionDuration New suspension duration
     * @param _maxGasPerEpoch New max gas per epoch
     */
    function updateParameters(
        uint256 _maxFailedAttempts,
        uint256 _suspensionDuration,
        uint256 _maxGasPerEpoch
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxFailedAttempts = _maxFailedAttempts;
        suspensionDuration = _suspensionDuration;
        maxGasPerEpoch = _maxGasPerEpoch;
    }

    /**
     * @notice Pause the module
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the module
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH for refund pool
     */
    receive() external payable {
        refundPool += msg.value;
    }
}
