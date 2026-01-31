// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
abstract contract SecurityModule {
    error RateLimitExceeded(address, uint256, uint256);
    error CircuitBreakerTriggered(uint256, uint256);
    error FlashLoanDetected(address, uint256, uint256);
    error SingleWithdrawalLimitExceeded(uint256, uint256);
    error DailyWithdrawalLimitExceeded(uint256, uint256);
    error CooldownNotElapsed(uint256);
    error WindowTooShort();
    error WindowTooLong();
    error MaxActionsTooLow();
    error MaxActionsTooHigh();
    error ThresholdTooLow();
    error CooldownTooShort(uint256);
    error CooldownTooLong(uint256);
    error InvalidWithdrawalLimits();

    mapping(address => uint256) public lastActionTime;
    mapping(address => uint256) public actionCount;
    uint256 public rateLimitWindow = 1 hours;
    uint256 public maxActionsPerWindow = 50;
    bool public rateLimitingEnabled = true;

    uint256 public lastHourlyVolume;
    uint256 public lastHourTimestamp;
    uint256 public volumeThreshold = 10_000_000 * 1e18;
    bool public circuitBreakerEnabled = true;
    bool public circuitBreakerTripped;
    uint256 public circuitBreakerCooldown = 1 hours;
    uint256 public circuitBreakerTrippedAt;

    mapping(address => uint256) public lastDepositBlock;
    mapping(address => uint256) public lastActionBlock;
    uint256 public minBlocksForWithdrawal = 1;
    bool public flashLoanGuardEnabled = true;

    uint256 public maxSingleWithdrawal = 100_000 * 1e18;
    uint256 public maxDailyWithdrawal = 1_000_000 * 1e18;
    uint256 public dailyWithdrawn;
    uint256 public lastWithdrawalDay;
    bool public withdrawalLimitsEnabled = true;
    mapping(address => uint256) public accountDailyWithdrawn;
    mapping(address => uint256) public accountLastWithdrawalDay;
    uint256 public accountMaxDailyWithdrawal = 100_000 * 1e18;

    event RateLimitTriggered(address indexed account, uint256 actionCount);
    event CircuitBreakerActivated(uint256 volume, uint256 threshold);
    event CircuitBreakerReset();
    event FlashLoanAttemptBlocked(address indexed account);
    event WithdrawalLimitApplied(address indexed account, uint256 amount);
    event SecurityConfigUpdated(string parameter, uint256 oldValue, uint256 newValue);

    modifier rateLimited() { _; }
    modifier circuitBreaker(uint256) { _; }
    modifier noFlashLoan() { _; }
    modifier withdrawalLimited(uint256) { _; }
    modifier accountWithdrawalLimited(uint256) { _; }

    function getRemainingActions(address) external pure returns (uint256) { return 50; }
    function getRemainingWithdrawal() external pure returns (uint256, uint256) { return (0, 0); }
    function getCircuitBreakerStatus() external pure returns (bool, uint256, uint256) { return (false, 0, 0); }
    function canWithdrawFlashLoanCheck(address) external pure returns (bool, uint256) { return (true, 0); }

    function _setRateLimitConfig(uint256 w, uint256 m) internal { rateLimitWindow = w; maxActionsPerWindow = m; }
    function _setCircuitBreakerConfig(uint256 t, uint256 c) internal { volumeThreshold = t; circuitBreakerCooldown = c; }
    function _setWithdrawalLimits(uint256 s, uint256 d, uint256 a) internal { maxSingleWithdrawal = s; maxDailyWithdrawal = d; accountMaxDailyWithdrawal = a; }
    function _setSecurityFeatures(bool r, bool c, bool f, bool w) internal { rateLimitingEnabled = r; circuitBreakerEnabled = c; flashLoanGuardEnabled = f; withdrawalLimitsEnabled = w; }
    function _resetCircuitBreaker() internal { circuitBreakerTripped = false; }
    function _recordDeposit(address a) internal { lastDepositBlock[a] = block.number; }
    function _recordAction(address a) internal { lastActionBlock[a] = block.number; }
}
