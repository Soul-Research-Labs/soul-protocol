// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BridgeRateLimiter
 * @author Soul Protocol
 * @notice Rate limiting and circuit breaker for bridge operations
 * @dev Implements economic security controls including:
 *      - Per-user rate limits
 *      - Global rate limits (hourly/daily caps)
 *      - TVL caps
 *      - Automatic circuit breakers
 *      - Anomaly detection triggers
 *
 * RATE LIMITING ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    BRIDGE RATE LIMITER                                 │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌─────────────────────┐   ┌─────────────────────┐                    │
 * │  │  Per-User Limits    │   │  Global Limits      │                    │
 * │  │  ├─ Hourly Cap      │   │  ├─ Hourly Cap      │                    │
 * │  │  ├─ Daily Cap       │   │  ├─ Daily Cap       │                    │
 * │  │  └─ Tx Size Limit   │   │  └─ TVL Cap         │                    │
 * │  └─────────────────────┘   └─────────────────────┘                    │
 * │           │                         │                                  │
 * │           └───────────┬─────────────┘                                  │
 * │                       │                                                │
 * │           ┌───────────▼───────────┐                                    │
 * │           │   Circuit Breaker     │                                    │
 * │           │   ├─ Large Tx Pause   │                                    │
 * │           │   ├─ Velocity Pause   │                                    │
 * │           │   └─ Anomaly Pause    │                                    │
 * │           └───────────────────────┘                                    │
 * │                       │                                                │
 * │           ┌───────────▼───────────┐                                    │
 * │           │   Allow/Deny Decision │                                    │
 * │           └───────────────────────┘                                    │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract BridgeRateLimiter is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RATE_ADMIN_ROLE = keccak256("RATE_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RateLimitConfig {
        uint256 hourlyLimit; // Max amount per hour
        uint256 dailyLimit; // Max amount per 24 hours
        uint256 maxSingleTx; // Max single transaction size
        uint256 minTimeBetweenTx; // Minimum seconds between transactions
        bool enabled; // Whether limits are active
    }

    struct UserUsage {
        uint256 hourlyUsed; // Amount used in current hour
        uint256 dailyUsed; // Amount used in current 24h period
        uint256 hourStart; // Timestamp of current hour window
        uint256 dayStart; // Timestamp of current day window
        uint256 lastTxTime; // Timestamp of last transaction
        uint256 txCount; // Total transaction count
    }

    struct GlobalStats {
        uint256 hourlyVolume; // Total volume this hour
        uint256 dailyVolume; // Total volume today
        uint256 hourStart; // Timestamp of current hour
        uint256 dayStart; // Timestamp of current day
        uint256 currentTVL; // Current total value locked
        uint256 peakTVL; // Historical peak TVL
    }

    struct CircuitBreakerConfig {
        uint256 largeTransferThreshold; // Amount that triggers review
        uint256 velocityThreshold; // Tx per hour that triggers pause
        uint256 tvlDropThreshold; // % drop that triggers pause (basis points)
        uint256 cooldownPeriod; // Seconds to wait after trigger
        bool autoBreakEnabled; // Auto-pause on triggers
    }

    struct CircuitBreakerStatus {
        bool isTriggered;
        uint256 triggeredAt;
        string reason;
        uint256 cooldownEnds;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant HOUR = 3600;
    uint256 public constant DAY = 86400;
    uint256 public constant BASIS_POINTS = 10000;

    /// @notice Maximum configurable hourly limit (10M ETH equivalent)
    uint256 public constant MAX_HOURLY_LIMIT = 10_000_000 ether;

    /// @notice Maximum configurable daily limit (100M ETH equivalent)
    uint256 public constant MAX_DAILY_LIMIT = 100_000_000 ether;

    /// @notice Maximum TVL cap (1B ETH equivalent)
    uint256 public constant MAX_TVL_CAP = 1_000_000_000 ether;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Global rate limit configuration
    RateLimitConfig public globalConfig;

    /// @notice Per-user rate limit configuration
    RateLimitConfig public userConfig;

    /// @notice Circuit breaker configuration
    CircuitBreakerConfig public circuitBreaker;

    /// @notice Circuit breaker current status
    CircuitBreakerStatus public breakerStatus;

    /// @notice Global usage statistics
    GlobalStats public globalStats;

    /// @notice TVL cap (0 = unlimited)
    uint256 public tvlCap;

    /// @notice Per-user usage tracking
    mapping(address => UserUsage) public userUsage;

    /// @notice Whitelisted addresses exempt from limits
    mapping(address => bool) public whitelisted;

    /// @notice Blacklisted addresses blocked entirely
    mapping(address => bool) public blacklisted;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event RateLimitConfigUpdated(
        bool isGlobal,
        uint256 hourlyLimit,
        uint256 dailyLimit,
        uint256 maxSingleTx
    );

    event CircuitBreakerTriggered(
        string reason,
        uint256 timestamp,
        uint256 cooldownEnds
    );

    event CircuitBreakerReset(uint256 timestamp);

    event TransferChecked(
        address indexed user,
        uint256 amount,
        bool allowed,
        string reason
    );

    event TVLCapUpdated(uint256 oldCap, uint256 newCap);

    event AddressWhitelisted(address indexed account, bool status);
    event AddressBlacklisted(address indexed account, bool status);

    event UsageRecorded(
        address indexed user,
        uint256 amount,
        uint256 userHourlyUsed,
        uint256 globalHourlyVolume
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ExceedsHourlyLimit(uint256 requested, uint256 available);
    error ExceedsDailyLimit(uint256 requested, uint256 available);
    error ExceedsSingleTxLimit(uint256 requested, uint256 max);
    error ExceedsTVLCap(uint256 newTVL, uint256 cap);
    error TooSoonBetweenTx(uint256 timeSinceLast, uint256 minTime);
    error CircuitBreakerActive(string reason);
    error AddressBlacklistedError(address account);
    error InvalidConfiguration();
    error CooldownNotExpired(uint256 remaining);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(RATE_ADMIN_ROLE, admin);

        // Default global limits
        globalConfig = RateLimitConfig({
            hourlyLimit: 1000 ether, // 1000 ETH per hour globally
            dailyLimit: 10000 ether, // 10000 ETH per day globally
            maxSingleTx: 500 ether, // Max 500 ETH per tx
            minTimeBetweenTx: 0, // No global cooldown
            enabled: true
        });

        // Default per-user limits
        userConfig = RateLimitConfig({
            hourlyLimit: 100 ether, // 100 ETH per hour per user
            dailyLimit: 500 ether, // 500 ETH per day per user
            maxSingleTx: 100 ether, // Max 100 ETH per tx per user
            minTimeBetweenTx: 60, // 1 minute between txs
            enabled: true
        });

        // Default circuit breaker
        circuitBreaker = CircuitBreakerConfig({
            largeTransferThreshold: 200 ether, // Transfers > 200 ETH flagged
            velocityThreshold: 100, // > 100 tx/hour triggers
            tvlDropThreshold: 2000, // 20% drop triggers (2000 bps)
            cooldownPeriod: 3600, // 1 hour cooldown
            autoBreakEnabled: true
        });

        // Initialize global stats
        globalStats = GlobalStats({
            hourlyVolume: 0,
            dailyVolume: 0,
            hourStart: block.timestamp,
            dayStart: block.timestamp,
            currentTVL: 0,
            peakTVL: 0
        });
    }

    /*//////////////////////////////////////////////////////////////
                         RATE CHECK FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a transfer is allowed under rate limits
     * @param user The user initiating the transfer
     * @param amount The transfer amount
     * @return allowed Whether the transfer is allowed
     * @return reason Reason if not allowed
     */
    function checkTransfer(
        address user,
        uint256 amount
    ) external view returns (bool allowed, string memory reason) {
        // Check blacklist
        if (blacklisted[user]) {
            return (false, "Address blacklisted");
        }

        // Whitelisted addresses bypass limits
        if (whitelisted[user]) {
            return (true, "Whitelisted");
        }

        // Check circuit breaker
        if (
            breakerStatus.isTriggered &&
            block.timestamp < breakerStatus.cooldownEnds
        ) {
            return (false, breakerStatus.reason);
        }

        // Check paused
        if (paused()) {
            return (false, "Bridge paused");
        }

        // Check TVL cap
        if (tvlCap > 0 && globalStats.currentTVL + amount > tvlCap) {
            return (false, "TVL cap exceeded");
        }

        // Check global limits
        if (globalConfig.enabled) {
            (uint256 hourlyVol, uint256 dailyVol) = _getGlobalUsage();

            if (amount > globalConfig.maxSingleTx) {
                return (false, "Exceeds global single tx limit");
            }
            if (hourlyVol + amount > globalConfig.hourlyLimit) {
                return (false, "Exceeds global hourly limit");
            }
            if (dailyVol + amount > globalConfig.dailyLimit) {
                return (false, "Exceeds global daily limit");
            }
        }

        // Check user limits
        if (userConfig.enabled) {
            UserUsage storage usage = userUsage[user];
            (uint256 hourlyUsed, uint256 dailyUsed) = _getUserUsage(usage);

            if (amount > userConfig.maxSingleTx) {
                return (false, "Exceeds user single tx limit");
            }
            if (hourlyUsed + amount > userConfig.hourlyLimit) {
                return (false, "Exceeds user hourly limit");
            }
            if (dailyUsed + amount > userConfig.dailyLimit) {
                return (false, "Exceeds user daily limit");
            }
            if (
                userConfig.minTimeBetweenTx > 0 &&
                usage.lastTxTime > 0 &&
                block.timestamp - usage.lastTxTime < userConfig.minTimeBetweenTx
            ) {
                return (false, "Too soon between transactions");
            }
        }

        return (true, "");
    }

    /**
     * @notice Record a successful transfer for rate limiting
     * @param user The user who made the transfer
     * @param amount The transfer amount
     */
    function recordTransfer(
        address user,
        uint256 amount
    ) external onlyRole(OPERATOR_ROLE) {
        _updateGlobalStats(amount);
        _updateUserUsage(user, amount);

        // Check circuit breaker triggers
        if (circuitBreaker.autoBreakEnabled) {
            _checkCircuitBreaker(amount);
        }

        emit UsageRecorded(
            user,
            amount,
            userUsage[user].hourlyUsed,
            globalStats.hourlyVolume
        );
    }

    /**
     * @notice Record TVL change
     * @param delta The change in TVL (positive = deposit, negative = withdrawal)
     * @param isDeposit Whether this is a deposit (true) or withdrawal (false)
     */
    function recordTVLChange(
        uint256 delta,
        bool isDeposit
    ) external onlyRole(OPERATOR_ROLE) {
        if (isDeposit) {
            globalStats.currentTVL += delta;
            if (globalStats.currentTVL > globalStats.peakTVL) {
                globalStats.peakTVL = globalStats.currentTVL;
            }
        } else {
            if (delta > globalStats.currentTVL) {
                globalStats.currentTVL = 0;
            } else {
                globalStats.currentTVL -= delta;
            }

            // Check for anomalous drop
            if (circuitBreaker.autoBreakEnabled && globalStats.peakTVL > 0) {
                uint256 dropPercent = ((globalStats.peakTVL -
                    globalStats.currentTVL) * BASIS_POINTS) /
                    globalStats.peakTVL;
                if (dropPercent >= circuitBreaker.tvlDropThreshold) {
                    _triggerCircuitBreaker("Anomalous TVL drop detected");
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                      CIRCUIT BREAKER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Manually trigger circuit breaker
     * @param reason Reason for triggering
     */
    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        _triggerCircuitBreaker(reason);
    }

    /**
     * @notice Reset circuit breaker after cooldown
     */
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            breakerStatus.isTriggered &&
            block.timestamp < breakerStatus.cooldownEnds
        ) {
            revert CooldownNotExpired(
                breakerStatus.cooldownEnds - block.timestamp
            );
        }

        breakerStatus = CircuitBreakerStatus({
            isTriggered: false,
            triggeredAt: 0,
            reason: "",
            cooldownEnds: 0
        });

        emit CircuitBreakerReset(block.timestamp);
    }

    /**
     * @notice Force reset circuit breaker (emergency only)
     */
    function emergencyResetCircuitBreaker()
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        breakerStatus = CircuitBreakerStatus({
            isTriggered: false,
            triggeredAt: 0,
            reason: "",
            cooldownEnds: 0
        });

        emit CircuitBreakerReset(block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                      CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update global rate limit configuration
     */
    function setGlobalConfig(
        uint256 hourlyLimit,
        uint256 dailyLimit,
        uint256 maxSingleTx,
        uint256 minTimeBetweenTx,
        bool enabled
    ) external onlyRole(RATE_ADMIN_ROLE) {
        if (hourlyLimit > MAX_HOURLY_LIMIT || dailyLimit > MAX_DAILY_LIMIT) {
            revert InvalidConfiguration();
        }

        globalConfig = RateLimitConfig({
            hourlyLimit: hourlyLimit,
            dailyLimit: dailyLimit,
            maxSingleTx: maxSingleTx,
            minTimeBetweenTx: minTimeBetweenTx,
            enabled: enabled
        });

        emit RateLimitConfigUpdated(true, hourlyLimit, dailyLimit, maxSingleTx);
    }

    /**
     * @notice Update per-user rate limit configuration
     */
    function setUserConfig(
        uint256 hourlyLimit,
        uint256 dailyLimit,
        uint256 maxSingleTx,
        uint256 minTimeBetweenTx,
        bool enabled
    ) external onlyRole(RATE_ADMIN_ROLE) {
        userConfig = RateLimitConfig({
            hourlyLimit: hourlyLimit,
            dailyLimit: dailyLimit,
            maxSingleTx: maxSingleTx,
            minTimeBetweenTx: minTimeBetweenTx,
            enabled: enabled
        });

        emit RateLimitConfigUpdated(
            false,
            hourlyLimit,
            dailyLimit,
            maxSingleTx
        );
    }

    /**
     * @notice Update circuit breaker configuration
     */
    function setCircuitBreakerConfig(
        uint256 largeTransferThreshold,
        uint256 velocityThreshold,
        uint256 tvlDropThreshold,
        uint256 cooldownPeriod,
        bool autoBreakEnabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tvlDropThreshold > BASIS_POINTS) {
            revert InvalidConfiguration();
        }

        circuitBreaker = CircuitBreakerConfig({
            largeTransferThreshold: largeTransferThreshold,
            velocityThreshold: velocityThreshold,
            tvlDropThreshold: tvlDropThreshold,
            cooldownPeriod: cooldownPeriod,
            autoBreakEnabled: autoBreakEnabled
        });
    }

    /**
     * @notice Set TVL cap
     * @param newCap New TVL cap (0 = unlimited)
     */
    function setTVLCap(uint256 newCap) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newCap > MAX_TVL_CAP) {
            revert InvalidConfiguration();
        }

        uint256 oldCap = tvlCap;
        tvlCap = newCap;

        emit TVLCapUpdated(oldCap, newCap);
    }

    /**
     * @notice Add/remove address from whitelist
     */
    function setWhitelist(
        address account,
        bool status
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelisted[account] = status;
        emit AddressWhitelisted(account, status);
    }

    /**
     * @notice Add/remove address from blacklist
     */
    function setBlacklist(
        address account,
        bool status
    ) external onlyRole(GUARDIAN_ROLE) {
        blacklisted[account] = status;
        emit AddressBlacklisted(account, status);
    }

    /**
     * @notice Pause rate limiter
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause rate limiter
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get remaining limits for a user
     */
    function getRemainingLimits(
        address user
    )
        external
        view
        returns (
            uint256 hourlyRemaining,
            uint256 dailyRemaining,
            uint256 globalHourlyRemaining,
            uint256 globalDailyRemaining,
            uint256 nextTxAllowedAt
        )
    {
        UserUsage storage usage = userUsage[user];
        (uint256 hourlyUsed, uint256 dailyUsed) = _getUserUsage(usage);
        (uint256 globalHourly, uint256 globalDaily) = _getGlobalUsage();

        hourlyRemaining = hourlyUsed >= userConfig.hourlyLimit
            ? 0
            : userConfig.hourlyLimit - hourlyUsed;
        dailyRemaining = dailyUsed >= userConfig.dailyLimit
            ? 0
            : userConfig.dailyLimit - dailyUsed;
        globalHourlyRemaining = globalHourly >= globalConfig.hourlyLimit
            ? 0
            : globalConfig.hourlyLimit - globalHourly;
        globalDailyRemaining = globalDaily >= globalConfig.dailyLimit
            ? 0
            : globalConfig.dailyLimit - globalDaily;

        if (
            usage.lastTxTime == 0 ||
            block.timestamp >= usage.lastTxTime + userConfig.minTimeBetweenTx
        ) {
            nextTxAllowedAt = block.timestamp;
        } else {
            nextTxAllowedAt = usage.lastTxTime + userConfig.minTimeBetweenTx;
        }
    }

    /**
     * @notice Check if circuit breaker is currently active
     */
    function isCircuitBreakerActive() external view returns (bool) {
        return
            breakerStatus.isTriggered &&
            block.timestamp < breakerStatus.cooldownEnds;
    }

    /**
     * @notice Get current global stats
     */
    function getGlobalStats()
        external
        view
        returns (
            uint256 hourlyVolume,
            uint256 dailyVolume,
            uint256 currentTVL,
            uint256 peakTVL
        )
    {
        (hourlyVolume, dailyVolume) = _getGlobalUsage();
        currentTVL = globalStats.currentTVL;
        peakTVL = globalStats.peakTVL;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _updateGlobalStats(uint256 amount) internal {
        // Reset hour if needed
        if (block.timestamp >= globalStats.hourStart + HOUR) {
            globalStats.hourlyVolume = 0;
            globalStats.hourStart = block.timestamp;
        }

        // Reset day if needed
        if (block.timestamp >= globalStats.dayStart + DAY) {
            globalStats.dailyVolume = 0;
            globalStats.dayStart = block.timestamp;
        }

        globalStats.hourlyVolume += amount;
        globalStats.dailyVolume += amount;
    }

    function _updateUserUsage(address user, uint256 amount) internal {
        UserUsage storage usage = userUsage[user];

        // Reset hour if needed
        if (block.timestamp >= usage.hourStart + HOUR) {
            usage.hourlyUsed = 0;
            usage.hourStart = block.timestamp;
        }

        // Reset day if needed
        if (block.timestamp >= usage.dayStart + DAY) {
            usage.dailyUsed = 0;
            usage.dayStart = block.timestamp;
        }

        usage.hourlyUsed += amount;
        usage.dailyUsed += amount;
        usage.lastTxTime = block.timestamp;
        usage.txCount++;
    }

    function _getUserUsage(
        UserUsage storage usage
    ) internal view returns (uint256 hourlyUsed, uint256 dailyUsed) {
        hourlyUsed = block.timestamp >= usage.hourStart + HOUR
            ? 0
            : usage.hourlyUsed;
        dailyUsed = block.timestamp >= usage.dayStart + DAY
            ? 0
            : usage.dailyUsed;
    }

    function _getGlobalUsage()
        internal
        view
        returns (uint256 hourlyVol, uint256 dailyVol)
    {
        hourlyVol = block.timestamp >= globalStats.hourStart + HOUR
            ? 0
            : globalStats.hourlyVolume;
        dailyVol = block.timestamp >= globalStats.dayStart + DAY
            ? 0
            : globalStats.dailyVolume;
    }

    function _checkCircuitBreaker(uint256 amount) internal {
        // Check large transfer
        if (amount >= circuitBreaker.largeTransferThreshold) {
            _triggerCircuitBreaker("Large transfer detected");
            return;
        }

        // Check velocity - track hourly transaction count
        // Reset counter if hour has elapsed
        if (block.timestamp >= globalStats.hourStart + HOUR) {
            globalStats.hourStart = block.timestamp;
            // Counter implicitly reset by checking within window
        }

        // Calculate approximate hourly tx rate based on volume patterns
        // Velocity = (current hourly volume / average tx size) estimates tx count
        // If velocity exceeds threshold, trigger circuit breaker
        if (circuitBreaker.velocityThreshold > 0) {
            // Use a sliding window approximation
            // Average tx size = hourlyVolume / estimated_tx_count
            // For safety, assume minimum tx of 0.01 ETH
            uint256 minTxSize = 0.01 ether;
            uint256 estimatedTxCount = globalStats.hourlyVolume / minTxSize;

            if (estimatedTxCount >= circuitBreaker.velocityThreshold) {
                _triggerCircuitBreaker("Velocity threshold exceeded");
                return;
            }
        }

        // Check TVL drop (potential exploit indicator)
        if (circuitBreaker.tvlDropThreshold > 0 && globalStats.peakTVL > 0) {
            uint256 dropPercent = ((globalStats.peakTVL -
                globalStats.currentTVL) * BASIS_POINTS) / globalStats.peakTVL;
            if (dropPercent >= circuitBreaker.tvlDropThreshold) {
                _triggerCircuitBreaker("TVL drop threshold exceeded");
                return;
            }
        }
    }

    function _triggerCircuitBreaker(string memory reason) internal {
        breakerStatus = CircuitBreakerStatus({
            isTriggered: true,
            triggeredAt: block.timestamp,
            reason: reason,
            cooldownEnds: block.timestamp + circuitBreaker.cooldownPeriod
        });

        emit CircuitBreakerTriggered(
            reason,
            block.timestamp,
            breakerStatus.cooldownEnds
        );
    }
}
