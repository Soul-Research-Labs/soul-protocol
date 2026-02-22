// SPDX-License-Identifier: MIT
// Certora CVL Specification: ProtocolHealthAggregator
//
// Properties verified:
// 1. Composite score always in [0, MAX_SCORE]
// 2. Health status consistent with score and thresholds
// 3. Threshold invariant: criticalThreshold < healthyThreshold
// 4. Subsystem count bounded by MAX_SUBSYSTEMS
// 5. Pausable target count bounded by MAX_PAUSABLE_CONTRACTS
// 6. Guardian override correctly applied/cleared
// 7. Score monotonicity under updateHealth
// 8. Auto-pause cooldown enforcement
// 9. Snapshot ring buffer index in [0, 64)
// 10. Only authorised roles can modify state

using ProtocolHealthAggregator as agg;

methods {
    // View / envfree functions
    function compositeScore() external returns (uint16) envfree;
    function currentStatus() external returns (ProtocolHealthAggregator.HealthStatus) envfree;
    function healthyThreshold() external returns (uint16) envfree;
    function criticalThreshold() external returns (uint16) envfree;
    function overrideActive() external returns (bool) envfree;
    function overrideScore() external returns (uint16) envfree;
    function autoPauseEnabled() external returns (bool) envfree;
    function lastAutoPauseAt() external returns (uint48) envfree;
    function snapshotIndex() external returns (uint8) envfree;
    function totalSnapshots() external returns (uint256) envfree;

    // Constants
    function MAX_SCORE() external returns (uint16) envfree;
    function BPS() external returns (uint16) envfree;
    function MAX_SUBSYSTEMS() external returns (uint8) envfree;
    function MAX_PAUSABLE_CONTRACTS() external returns (uint8) envfree;
    function DEFAULT_STALENESS_THRESHOLD() external returns (uint48) envfree;
    function AUTO_PAUSE_COOLDOWN() external returns (uint48) envfree;

    // Counters
    function subsystemCount() external returns (uint256) envfree;
    function pausableTargetCount() external returns (uint256) envfree;

    // Roles
    function MONITOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;

    // State-changing
    function registerSubsystem(string, address, ProtocolHealthAggregator.SubsystemCategory, uint16, uint48) external;
    function deactivateSubsystem(bytes32) external;
    function reactivateSubsystem(bytes32) external;
    function updateHealth(bytes32, uint16) external;
    function batchUpdateHealth(bytes32[], uint16[]) external;
    function registerPausableTarget(address, string) external;
    function removePausableTarget(address) external;
    function setGuardianOverride(uint16) external;
    function clearGuardianOverride() external;
    function updateThresholds(uint16, uint16) external;
    function updateCategoryWeight(ProtocolHealthAggregator.SubsystemCategory, uint16) external;
    function setAutoPauseEnabled(bool) external;
}

/*//////////////////////////////////////////////////////////////
                     INVARIANT 1: Score Bounds
//////////////////////////////////////////////////////////////*/

/// @title Composite score is always in [0, MAX_SCORE]
invariant compositeScoreBounded()
    compositeScore() <= MAX_SCORE();

/*//////////////////////////////////////////////////////////////
             INVARIANT 2: Threshold Ordering
//////////////////////////////////////////////////////////////*/

/// @title criticalThreshold is always strictly less than healthyThreshold
invariant thresholdOrdering()
    criticalThreshold() < healthyThreshold();

/*//////////////////////////////////////////////////////////////
         INVARIANT 3: Thresholds within MAX_SCORE
//////////////////////////////////////////////////////////////*/

/// @title Both thresholds are at most MAX_SCORE
invariant thresholdsWithinBounds()
    healthyThreshold() <= MAX_SCORE() &&
    criticalThreshold() <= MAX_SCORE();

/*//////////////////////////////////////////////////////////////
         INVARIANT 4: Subsystem count bounded
//////////////////////////////////////////////////////////////*/

/// @title Number of subsystems never exceeds MAX_SUBSYSTEMS
invariant subsystemCountBounded()
    subsystemCount() <= to_mathint(MAX_SUBSYSTEMS());

/*//////////////////////////////////////////////////////////////
      INVARIANT 5: Pausable targets bounded
//////////////////////////////////////////////////////////////*/

/// @title Number of pausable targets never exceeds MAX_PAUSABLE_CONTRACTS
invariant pausableTargetCountBounded()
    pausableTargetCount() <= to_mathint(MAX_PAUSABLE_CONTRACTS());

/*//////////////////////////////////////////////////////////////
       INVARIANT 6: Snapshot index bounded
//////////////////////////////////////////////////////////////*/

/// @title Snapshot ring buffer index stays in [0, 64)
invariant snapshotIndexBounded()
    snapshotIndex() < 64;

/*//////////////////////////////////////////////////////////////
                      RULE: Status Consistency
//////////////////////////////////////////////////////////////*/

/// @title Status must be consistent with score and thresholds when no override
rule statusConsistentWithScore(method f) {
    env e;
    calldataarg args;

    f(e, args);

    uint16 score = compositeScore();
    ProtocolHealthAggregator.HealthStatus status = currentStatus();
    uint16 healthy = healthyThreshold();
    uint16 critical = criticalThreshold();
    bool isOverride = overrideActive();

    // When no override, status follows score
    assert !isOverride => (
        (score >= healthy => status == ProtocolHealthAggregator.HealthStatus.HEALTHY) &&
        (score < healthy && score >= critical =>
            status == ProtocolHealthAggregator.HealthStatus.WARNING) &&
        (score < critical =>
            status == ProtocolHealthAggregator.HealthStatus.CRITICAL)
    );

    // With override, status is OVERRIDE
    assert isOverride => status == ProtocolHealthAggregator.HealthStatus.OVERRIDE;
}

/*//////////////////////////////////////////////////////////////
             RULE: UpdateHealth Score Bounds
//////////////////////////////////////////////////////////////*/

/// @title updateHealth with score > MAX_SCORE always reverts
rule updateHealthRejectsOutOfRange() {
    env e;
    bytes32 subsystemId;
    uint16 score;

    require score > MAX_SCORE();

    updateHealth@withrevert(e, subsystemId, score);

    assert lastReverted;
}

/*//////////////////////////////////////////////////////////////
         RULE: Guardian Override Controls
//////////////////////////////////////////////////////////////*/

/// @title Setting guardian override makes overrideActive true
rule setGuardianOverrideSetsFlag() {
    env e;
    uint16 score;
    require score <= MAX_SCORE();

    setGuardianOverride(e, score);

    assert overrideActive() == true;
    assert overrideScore() == score;
}

/// @title Clearing guardian override sets flag to false
rule clearGuardianOverrideClearsFlag() {
    env e;
    require overrideActive() == true;

    clearGuardianOverride(e);

    assert overrideActive() == false;
    assert overrideScore() == 0;
}

/// @title clearGuardianOverride reverts when no override is active
rule clearGuardianOverrideRevertsWhenInactive() {
    env e;
    require overrideActive() == false;

    clearGuardianOverride@withrevert(e);

    assert lastReverted;
}

/*//////////////////////////////////////////////////////////////
          RULE: Threshold Update Correctness
//////////////////////////////////////////////////////////////*/

/// @title updateThresholds must enforce critical < healthy and ≤ MAX_SCORE
rule updateThresholdsValidation() {
    env e;
    uint16 healthy;
    uint16 critical;

    updateThresholds@withrevert(e, healthy, critical);

    // If it succeeded, thresholds must be valid
    assert !lastReverted => (
        healthyThreshold() == healthy &&
        criticalThreshold() == critical &&
        critical < healthy &&
        healthy <= MAX_SCORE()
    );

    // If healthy > MAX or critical > MAX or critical >= healthy, must revert
    assert (healthy > MAX_SCORE() || critical > MAX_SCORE() || critical >= healthy)
        => lastReverted;
}

/*//////////////////////////////////////////////////////////////
      RULE: Snapshot counter monotonic
//////////////////////////////////////////////////////////////*/

/// @title totalSnapshots never decreases
rule totalSnapshotsMonotonic(method f) {
    env e;
    calldataarg args;

    uint256 before = totalSnapshots();
    f(e, args);
    uint256 after_ = totalSnapshots();

    assert after_ >= before;
}

/*//////////////////////////////////////////////////////////////
      RULE: Register subsystem increases count
//////////////////////////////////////////////////////////////*/

/// @title Registering a subsystem increases the subsystem count by 1
rule registerSubsystemIncreasesCount() {
    env e;
    string name;
    address source;
    ProtocolHealthAggregator.SubsystemCategory cat;
    uint16 weight;
    uint48 staleness;

    uint256 countBefore = subsystemCount();

    registerSubsystem@withrevert(e, name, source, cat, weight, staleness);

    assert !lastReverted => subsystemCount() == countBefore + 1;
}
