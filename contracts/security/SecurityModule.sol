// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecurityModule
 * @author Soul Protocol
 * @notice Comprehensive security module providing zero-day attack mitigations
 * @dev Inherit this contract to add rate limiting, circuit breakers, flash loan guards,
 *      and withdrawal limits to any contract
 *
 * Security Features:
 * - Rate Limiting: Prevents spam attacks and DoS
 * - Circuit Breaker: Halts operations when volume thresholds exceeded
 * - Flash Loan Guard: Prevents same-block deposit/withdrawal attacks
 * - Withdrawal Limits: Caps single and daily withdrawal amounts
 *
 * @custom:security-contact security@soul.network
 */
abstract contract SecurityModule {
    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when rate limit exceeded
    error RateLimitExceeded(
        address account,
        uint256 actionCount,
        uint256 maxActions
    );

    /// @notice Thrown when circuit breaker triggers
    error CircuitBreakerTriggered(uint256 currentVolume, uint256 threshold);

    /// @notice Thrown when flash loan attack detected
    error FlashLoanDetected(
        address account,
        uint256 depositBlock,
        uint256 currentBlock
    );

    /// @notice Thrown when single withdrawal exceeds limit
    error SingleWithdrawalLimitExceeded(uint256 amount, uint256 maxAmount);

    /// @notice Thrown when daily withdrawal limit exceeded
    error DailyWithdrawalLimitExceeded(uint256 requested, uint256 remaining);

    /// @notice Thrown when cooldown period not elapsed
    error CooldownNotElapsed(uint256 remaining);

    error WindowTooShort();
    error WindowTooLong();
    error MaxActionsTooLow();
    error MaxActionsTooHigh();
    error ThresholdTooLow();
    error CooldownTooShort(uint256 minCooldown);
    error CooldownTooLong(uint256 maxCooldown);
    error InvalidWithdrawalLimits();


    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    // ============ Rate Limiting ============

    /// @notice Last action timestamp per account
    mapping(address => uint256) public lastActionTime;

    /// @notice Action count per account in current window
    mapping(address => uint256) public actionCount;

    /// @notice Rate limit window duration (default: 1 hour)
    uint256 public rateLimitWindow = 1 hours;

    /// @notice Maximum actions per window (default: 50)
    uint256 public maxActionsPerWindow = 50;

    /// @notice Whether rate limiting is enabled
    bool public rateLimitingEnabled = true;

    // ============ Circuit Breaker ============

    /// @notice Hourly volume tracker
    uint256 public lastHourlyVolume;

    /// @notice Last hour timestamp for volume tracking
    uint256 public lastHourTimestamp;

    /// @notice Volume threshold before circuit breaker trips (default: 10M tokens)
    uint256 public volumeThreshold = 10_000_000 * 1e18;

    /// @notice Whether circuit breaker is enabled
    bool public circuitBreakerEnabled = true;

    /// @notice Whether circuit breaker is currently tripped
    bool public circuitBreakerTripped;

    /// @notice Cooldown after circuit breaker trip
    uint256 public circuitBreakerCooldown = 1 hours;

    /// @notice Timestamp when circuit breaker was last tripped
    uint256 public circuitBreakerTrippedAt;

    // ============ Flash Loan Guard ============

    /// @notice Block number of last deposit per account
    mapping(address => uint256) public lastDepositBlock;

    /// @notice Block number of last significant action per account
    mapping(address => uint256) public lastActionBlock;

    /// @notice Minimum blocks between deposit and withdrawal (default: 1)
    /// @dev slither-disable-next-line constable-states
    uint256 public minBlocksForWithdrawal = 1;

    /// @notice Whether flash loan guard is enabled
    bool public flashLoanGuardEnabled = true;

    // ============ Withdrawal Limits ============

    /// @notice Maximum single withdrawal amount
    uint256 public maxSingleWithdrawal = 100_000 * 1e18;

    /// @notice Maximum daily withdrawal amount
    uint256 public maxDailyWithdrawal = 1_000_000 * 1e18;

    /// @notice Daily withdrawal tracker
    uint256 public dailyWithdrawn;

    /// @notice Last withdrawal day (days since epoch)
    uint256 public lastWithdrawalDay;

    /// @notice Whether withdrawal limits are enabled
    bool public withdrawalLimitsEnabled = true;

    // ============ Per-Account Tracking ============

    /// @notice Per-account daily withdrawal amounts
    mapping(address => uint256) public accountDailyWithdrawn;

    /// @notice Per-account last withdrawal day
    mapping(address => uint256) public accountLastWithdrawalDay;

    /// @notice Per-account maximum daily withdrawal
    uint256 public accountMaxDailyWithdrawal = 100_000 * 1e18;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event RateLimitTriggered(address indexed account, uint256 actionCount);
    event CircuitBreakerActivated(uint256 volume, uint256 threshold);
    event CircuitBreakerReset();
    event FlashLoanAttemptBlocked(address indexed account);
    event WithdrawalLimitApplied(address indexed account, uint256 amount);
    event SecurityConfigUpdated(
        string parameter,
        uint256 oldValue,
        uint256 newValue
    );

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Rate limiting modifier - limits actions per time window
     * @dev Resets counter when window expires
     */
    modifier rateLimited() {
        if (rateLimitingEnabled) {
            // Reset counter if window expired
            if (
                block.timestamp > lastActionTime[msg.sender] + rateLimitWindow
            ) {
                actionCount[msg.sender] = 0;
                lastActionTime[msg.sender] = block.timestamp;
            }

            // Check limit
            if (actionCount[msg.sender] >= maxActionsPerWindow) {
                revert RateLimitExceeded(
                    msg.sender,
                    actionCount[msg.sender],
                    maxActionsPerWindow
                );
            }

            // Increment counter
            unchecked {
                ++actionCount[msg.sender];
            }
        }
        _;
    }

    /**
     * @notice Circuit breaker modifier - halts on abnormal volume
     * @param value The value being processed
     */
    modifier circuitBreaker(uint256 value) {
        if (circuitBreakerEnabled) {
            // Check if currently tripped
            if (circuitBreakerTripped) {
                if (
                    block.timestamp <
                    circuitBreakerTrippedAt + circuitBreakerCooldown
                ) {
                    revert CooldownNotElapsed(
                        circuitBreakerTrippedAt +
                            circuitBreakerCooldown -
                            block.timestamp
                    );
                }
                // Reset after cooldown
                circuitBreakerTripped = false;
                lastHourlyVolume = 0;
                emit CircuitBreakerReset();
            }

            // Reset hourly volume if new hour
            if (block.timestamp > lastHourTimestamp + 1 hours) {
                lastHourlyVolume = 0;
                lastHourTimestamp = block.timestamp;
            }

            // Add to volume
            lastHourlyVolume += value;

            // Check threshold
            if (lastHourlyVolume > volumeThreshold) {
                circuitBreakerTripped = true;
                circuitBreakerTrippedAt = block.timestamp;
                emit CircuitBreakerActivated(lastHourlyVolume, volumeThreshold);
                revert CircuitBreakerTriggered(
                    lastHourlyVolume,
                    volumeThreshold
                );
            }
        }
        _;
    }

    /**
     * @notice Flash loan guard - prevents same-block attacks
     * @dev Requires at least minBlocksForWithdrawal between deposit and withdrawal
     */
    modifier noFlashLoan() {
        if (flashLoanGuardEnabled) {
            uint256 depositBlock = lastDepositBlock[msg.sender];
            if (
                depositBlock > 0 &&
                block.number <= depositBlock + minBlocksForWithdrawal
            ) {
                emit FlashLoanAttemptBlocked(msg.sender);
                revert FlashLoanDetected(
                    msg.sender,
                    depositBlock,
                    block.number
                );
            }
        }
        _;
    }

    /**
     * @notice Withdrawal limit modifier - caps extraction amounts
     * @param amount The withdrawal amount
     */
    modifier withdrawalLimited(uint256 amount) {
        if (withdrawalLimitsEnabled) {
            // Check single withdrawal limit
            if (amount > maxSingleWithdrawal) {
                revert SingleWithdrawalLimitExceeded(
                    amount,
                    maxSingleWithdrawal
                );
            }

            // Reset daily counter if new day
            uint256 currentDay = block.timestamp / 1 days;
            if (currentDay > lastWithdrawalDay) {
                dailyWithdrawn = 0;
                lastWithdrawalDay = currentDay;
            }

            // Check global daily limit
            if (dailyWithdrawn + amount > maxDailyWithdrawal) {
                revert DailyWithdrawalLimitExceeded(
                    amount,
                    maxDailyWithdrawal - dailyWithdrawn
                );
            }

            // Update global counter
            dailyWithdrawn += amount;
            emit WithdrawalLimitApplied(msg.sender, amount);
        }
        _;
    }

    /**
     * @notice Per-account withdrawal limit modifier
     * @param amount The withdrawal amount
     */
    modifier accountWithdrawalLimited(uint256 amount) {
        if (withdrawalLimitsEnabled) {
            // Reset account daily counter if new day
            uint256 currentDay = block.timestamp / 1 days;
            if (currentDay > accountLastWithdrawalDay[msg.sender]) {
                accountDailyWithdrawn[msg.sender] = 0;
                accountLastWithdrawalDay[msg.sender] = currentDay;
            }

            // Check account daily limit
            if (
                accountDailyWithdrawn[msg.sender] + amount >
                accountMaxDailyWithdrawal
            ) {
                revert DailyWithdrawalLimitExceeded(
                    amount,
                    accountMaxDailyWithdrawal -
                        accountDailyWithdrawn[msg.sender]
                );
            }

            // Update account counter
            accountDailyWithdrawn[msg.sender] += amount;
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record a deposit for flash loan tracking
     * @param account The depositor address
     * @dev slither-disable-next-line dead-code
     */
    function _recordDeposit(address account) internal {
        lastDepositBlock[account] = block.number;
    }

    /**
     * @notice Record significant action for tracking
     * @param account The account performing action
     * @dev slither-disable-next-line dead-code
     */
    function _recordAction(address account) internal {
        lastActionBlock[account] = block.number;
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION (INTERNAL)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update rate limit configuration
     * @param window New window duration in seconds
     * @param maxActions New maximum actions per window
     * @dev slither-disable-next-line dead-code
     */
    function _setRateLimitConfig(uint256 window, uint256 maxActions) internal {
        if (window < 5 minutes) revert WindowTooShort();
        if (window > 24 hours) revert WindowTooLong();
        if (maxActions < 1) revert MaxActionsTooLow();
        if (maxActions > 1000) revert MaxActionsTooHigh();

        emit SecurityConfigUpdated("rateLimitWindow", rateLimitWindow, window);
        emit SecurityConfigUpdated(
            "maxActionsPerWindow",
            maxActionsPerWindow,
            maxActions
        );

        rateLimitWindow = window;
        maxActionsPerWindow = maxActions;
    }

    /**
     * @notice Update circuit breaker configuration
     * @param threshold New volume threshold
     * @param cooldown New cooldown period
     * @dev slither-disable-next-line dead-code
     */
    function _setCircuitBreakerConfig(
        uint256 threshold,
        uint256 cooldown
    ) internal {
        if (threshold < 1000 * 1e18) revert ThresholdTooLow();
        if (cooldown < 15 minutes) revert CooldownTooShort(15 minutes);
        if (cooldown > 24 hours) revert CooldownTooLong(24 hours);

        emit SecurityConfigUpdated(
            "volumeThreshold",
            volumeThreshold,
            threshold
        );
        emit SecurityConfigUpdated(
            "circuitBreakerCooldown",
            circuitBreakerCooldown,
            cooldown
        );

        volumeThreshold = threshold;
        circuitBreakerCooldown = cooldown;
    }

    /**
     * @notice Update withdrawal limits
     * @param singleMax New single withdrawal max
     * @param dailyMax New daily withdrawal max
     * @param accountDailyMax New per-account daily max
     * @dev slither-disable-next-line dead-code
     */
    function _setWithdrawalLimits(
        uint256 singleMax,
        uint256 dailyMax,
        uint256 accountDailyMax
    ) internal {
        if (singleMax > dailyMax) revert InvalidWithdrawalLimits();
        if (accountDailyMax > dailyMax) revert InvalidWithdrawalLimits();

        emit SecurityConfigUpdated(
            "maxSingleWithdrawal",
            maxSingleWithdrawal,
            singleMax
        );
        emit SecurityConfigUpdated(
            "maxDailyWithdrawal",
            maxDailyWithdrawal,
            dailyMax
        );
        emit SecurityConfigUpdated(
            "accountMaxDailyWithdrawal",
            accountMaxDailyWithdrawal,
            accountDailyMax
        );

        maxSingleWithdrawal = singleMax;
        maxDailyWithdrawal = dailyMax;
        accountMaxDailyWithdrawal = accountDailyMax;
    }

    /**
     * @notice Toggle security features
     * @param rateLimiting Enable/disable rate limiting
     * @param circuitBreakers Enable/disable circuit breaker
     * @param flashLoanGuard Enable/disable flash loan guard
     * @param withdrawalLimits Enable/disable withdrawal limits
     * @dev slither-disable-next-line dead-code
     */
    function _setSecurityFeatures(
        bool rateLimiting,
        bool circuitBreakers,
        bool flashLoanGuard,
        bool withdrawalLimits
    ) internal {
        rateLimitingEnabled = rateLimiting;
        circuitBreakerEnabled = circuitBreakers;
        flashLoanGuardEnabled = flashLoanGuard;
        withdrawalLimitsEnabled = withdrawalLimits;
    }

    /**
     * @notice Emergency reset circuit breaker (admin only - implement in child)
     * @dev slither-disable-next-line dead-code
     */
    function _resetCircuitBreaker() internal {
        circuitBreakerTripped = false;
        lastHourlyVolume = 0;
        emit CircuitBreakerReset();
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get remaining actions in current window for account
     * @param account The account to check
     * @return remaining Number of remaining actions
     */
    function getRemainingActions(
        address account
    ) external view returns (uint256 remaining) {
        if (block.timestamp > lastActionTime[account] + rateLimitWindow) {
            return maxActionsPerWindow;
        }
        if (actionCount[account] >= maxActionsPerWindow) {
            return 0;
        }
        return maxActionsPerWindow - actionCount[account];
    }

    /**
     * @notice Get remaining daily withdrawal allowance
     * @return globalRemaining Global remaining
     * @return accountRemaining Account-specific remaining for caller
     */
    function getRemainingWithdrawal()
        external
        view
        returns (uint256 globalRemaining, uint256 accountRemaining)
    {
        uint256 currentDay = block.timestamp / 1 days;

        // Global
        if (currentDay > lastWithdrawalDay) {
            globalRemaining = maxDailyWithdrawal;
        } else {
            globalRemaining = maxDailyWithdrawal > dailyWithdrawn
                ? maxDailyWithdrawal - dailyWithdrawn
                : 0;
        }

        // Account
        if (currentDay > accountLastWithdrawalDay[msg.sender]) {
            accountRemaining = accountMaxDailyWithdrawal;
        } else {
            accountRemaining = accountMaxDailyWithdrawal >
                accountDailyWithdrawn[msg.sender]
                ? accountMaxDailyWithdrawal - accountDailyWithdrawn[msg.sender]
                : 0;
        }
    }

    /**
     * @notice Check if circuit breaker is active
     * @return isTripped Whether circuit breaker is tripped
     * @return cooldownRemaining Seconds until reset (0 if not tripped)
     * @return currentVolume Current hourly volume
     */
    function getCircuitBreakerStatus()
        external
        view
        returns (
            bool isTripped,
            uint256 cooldownRemaining,
            uint256 currentVolume
        )
    {
        isTripped = circuitBreakerTripped;

        if (isTripped) {
            uint256 resetTime = circuitBreakerTrippedAt +
                circuitBreakerCooldown;
            cooldownRemaining = block.timestamp < resetTime
                ? resetTime - block.timestamp
                : 0;
        }

        // Return current hour's volume
        if (block.timestamp > lastHourTimestamp + 1 hours) {
            currentVolume = 0;
        } else {
            currentVolume = lastHourlyVolume;
        }
    }

    /**
     * @notice Check if account can withdraw (flash loan check)
     * @param account The account to check
     * @return canWithdraw Whether account can withdraw
     * @return blocksRemaining Blocks until withdrawal allowed
     */
    function canWithdrawFlashLoanCheck(
        address account
    ) external view returns (bool canWithdraw, uint256 blocksRemaining) {
        uint256 depositBlock = lastDepositBlock[account];

        if (depositBlock == 0) {
            return (true, 0);
        }

        uint256 requiredBlock = depositBlock + minBlocksForWithdrawal;

        if (block.number > requiredBlock) {
            return (true, 0);
        }

        return (false, requiredBlock - block.number + 1);
    }
}
