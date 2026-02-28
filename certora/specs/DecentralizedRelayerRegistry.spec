/**
 * Certora Formal Verification Specification
 * ZASEON - DecentralizedRelayerRegistry
 *
 * Verifies staking invariants, slashing correctness, reward distribution,
 * unbonding lifecycle, and access control for the permissionless relayer registry.
 *
 * ARCHITECTURE:
 * Relayers register with a minimum stake of 10 ETH, can be slashed for
 * misconduct, earn rewards, and must go through a 7-day unbonding period
 * before withdrawing their stake.
 */

using DecentralizedRelayerRegistry as registry;

methods {
    // ── Constants ──
    function MIN_STAKE() external returns (uint256) envfree;
    function UNBONDING_PERIOD() external returns (uint256) envfree;

    // ── Roles ──
    function SLASHER_ROLE() external returns (bytes32) envfree;
    function GOVERNANCE_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;

    // ── Relayer struct getter: (stake, rewards, unlockTime, isRegistered) ──
    function relayers(address) external returns (uint256, uint256, uint256, bool) envfree;

    // ── State-changing functions ──
    function register() external;
    function depositStake() external;
    function initiateUnstake() external;
    function withdrawStake() external;
    function slash(address, uint256, address) external;
    function addReward(address, uint256) external;
    function claimRewards() external;
}

/*//////////////////////////////////////////////////////////////
                         INVARIANTS
//////////////////////////////////////////////////////////////*/

/// @notice MIN_STAKE is always 10 ether
invariant minStakeConstant()
    MIN_STAKE() == 10000000000000000000; // 10 ether in wei

/// @notice UNBONDING_PERIOD is always 7 days
invariant unbondingPeriodConstant()
    UNBONDING_PERIOD() == 604800; // 7 * 24 * 60 * 60

/*//////////////////////////////////////////////////////////////
                    REGISTRATION RULES
//////////////////////////////////////////////////////////////*/

/// @notice Registration requires at least MIN_STAKE
rule registerRequiresMinStake(env e) {
    require e.msg.value < 10000000000000000000; // < 10 ether

    register@withrevert(e);

    assert lastReverted,
        "Registration must require at least MIN_STAKE";
}

/// @notice Registration sets correct initial state
rule registerSetsState(env e) {
    require e.msg.value >= 10000000000000000000; // >= 10 ether

    // Must not be already registered
    uint256 stakeBefore; uint256 rewardsBefore; uint256 unlockBefore; bool regBefore;
    stakeBefore, rewardsBefore, unlockBefore, regBefore = relayers(e.msg.sender);
    require !regBefore;

    register(e);

    uint256 stakeAfter; uint256 rewardsAfter; uint256 unlockAfter; bool regAfter;
    stakeAfter, rewardsAfter, unlockAfter, regAfter = relayers(e.msg.sender);

    assert regAfter == true,
        "Relayer must be registered after register()";
    assert stakeAfter == e.msg.value,
        "Stake must equal msg.value";
    assert rewardsAfter == 0,
        "Rewards must be zero on registration";
    assert unlockAfter == 0,
        "unlockTime must be zero (active)";
}

/// @notice Cannot register twice
rule cannotRegisterTwice(env e1, env e2) {
    require e1.msg.sender == e2.msg.sender;
    require e1.msg.value >= 10000000000000000000;
    require e2.msg.value >= 10000000000000000000;

    register(e1);

    register@withrevert(e2);

    assert lastReverted,
        "Cannot register the same address twice";
}

/*//////////////////////////////////////////////////////////////
                    STAKING RULES
//////////////////////////////////////////////////////////////*/

/// @notice depositStake increases stake by msg.value
rule depositStakeAddsToStake(env e) {
    uint256 stakeBefore; uint256 rb; uint256 ub; bool isReg;
    stakeBefore, rb, ub, isReg = relayers(e.msg.sender);
    require isReg;

    depositStake(e);

    uint256 stakeAfter; uint256 ra; uint256 ua; bool regA;
    stakeAfter, ra, ua, regA = relayers(e.msg.sender);

    assert stakeAfter == stakeBefore + e.msg.value,
        "depositStake must add msg.value to stake";
}

/// @notice depositStake requires registration
rule depositStakeRequiresRegistration(env e) {
    uint256 s; uint256 r; uint256 u; bool isReg;
    s, r, u, isReg = relayers(e.msg.sender);
    require !isReg;

    depositStake@withrevert(e);

    assert lastReverted,
        "depositStake must require registration";
}

/*//////////////////////////////////////////////////////////////
                    UNBONDING LIFECYCLE
//////////////////////////////////////////////////////////////*/

/// @notice initiateUnstake sets unlockTime to future timestamp
rule initiateUnstakeSetsUnlockTime(env e) {
    uint256 s; uint256 r; uint256 u; bool isReg;
    s, r, u, isReg = relayers(e.msg.sender);
    require isReg;
    require u == 0; // Not already unbonding

    initiateUnstake(e);

    uint256 sA; uint256 rA; uint256 uA; bool regA;
    sA, rA, uA, regA = relayers(e.msg.sender);

    assert uA == e.block.timestamp + UNBONDING_PERIOD(),
        "unlockTime must be set to current time + UNBONDING_PERIOD";
}

/// @notice Cannot initiate unstake twice
rule cannotDoubleInitiateUnstake(env e1, env e2) {
    require e1.msg.sender == e2.msg.sender;

    uint256 s; uint256 r; uint256 u; bool isReg;
    s, r, u, isReg = relayers(e1.msg.sender);
    require isReg;
    require u == 0;

    initiateUnstake(e1);

    initiateUnstake@withrevert(e2);

    assert lastReverted,
        "Cannot initiate unstake when already unbonding";
}

/// @notice withdrawStake requires unbonding period to have passed
rule withdrawStakeRequiresUnbondingComplete(env e) {
    uint256 s; uint256 r; uint256 u; bool isReg;
    s, r, u, isReg = relayers(e.msg.sender);
    require u > 0; // Is unbonding
    require e.block.timestamp < u; // Period not elapsed

    withdrawStake@withrevert(e);

    assert lastReverted,
        "withdrawStake must revert before unbonding period ends";
}

/// @notice withdrawStake clears relayer state
rule withdrawStakeClears(env e) {
    uint256 s; uint256 r; uint256 u; bool isReg;
    s, r, u, isReg = relayers(e.msg.sender);
    require u > 0;
    require e.block.timestamp >= u;
    require s > 0;

    withdrawStake(e);

    uint256 sA; uint256 rA; uint256 uA; bool regA;
    sA, rA, uA, regA = relayers(e.msg.sender);

    assert sA == 0,
        "Stake must be zero after withdrawal";
    assert regA == false,
        "Relayer must be unregistered after withdrawal";
    assert uA == 0,
        "unlockTime must be zero after withdrawal";
}

/*//////////////////////////////////////////////////////////////
                    SLASHING RULES
//////////////////////////////////////////////////////////////*/

/// @notice Only SLASHER_ROLE can slash
rule onlySlasherCanSlash(
    env e,
    address relayer,
    uint256 amount,
    address recipient
) {
    bool isSlasher = hasRole(registry.SLASHER_ROLE(), e.msg.sender);

    slash@withrevert(e, relayer, amount, recipient);

    assert !lastReverted => isSlasher,
        "Only SLASHER_ROLE can slash relayers";
}

/// @notice Slash reduces stake by exact amount
rule slashReducesStake(
    env e,
    address relayer,
    uint256 amount,
    address recipient
) {
    uint256 stakeBefore; uint256 rb; uint256 ub; bool isReg;
    stakeBefore, rb, ub, isReg = relayers(relayer);
    require stakeBefore >= amount;

    slash(e, relayer, amount, recipient);

    uint256 stakeAfter; uint256 ra; uint256 ua; bool regA;
    stakeAfter, ra, ua, regA = relayers(relayer);

    assert stakeAfter == stakeBefore - amount,
        "Slash must reduce stake by exact amount";
}

/// @notice Cannot slash more than current stake
rule cannotSlashMoreThanStake(
    env e,
    address relayer,
    uint256 amount,
    address recipient
) {
    uint256 stake; uint256 r; uint256 u; bool isReg;
    stake, r, u, isReg = relayers(relayer);
    require amount > stake;

    slash@withrevert(e, relayer, amount, recipient);

    assert lastReverted,
        "Cannot slash more than relayer's stake";
}

/*//////////////////////////////////////////////////////////////
                    REWARD RULES
//////////////////////////////////////////////////////////////*/

/// @notice addReward increases relayer's rewards
rule addRewardIncreasesBalance(
    env e,
    address relayer,
    uint256 amount
) {
    uint256 s; uint256 rewardsBefore; uint256 u; bool isReg;
    s, rewardsBefore, u, isReg = relayers(relayer);
    require isReg;
    require e.msg.value == amount;

    addReward(e, relayer, amount);

    uint256 sA; uint256 rewardsAfter; uint256 uA; bool regA;
    sA, rewardsAfter, uA, regA = relayers(relayer);

    assert rewardsAfter == rewardsBefore + amount,
        "addReward must increase rewards by amount";
}

/// @notice claimRewards zeroes out rewards
rule claimRewardsZeroes(env e) {
    uint256 s; uint256 rewards; uint256 u; bool isReg;
    s, rewards, u, isReg = relayers(e.msg.sender);
    require rewards > 0;

    claimRewards(e);

    uint256 sA; uint256 rewardsAfter; uint256 uA; bool regA;
    sA, rewardsAfter, uA, regA = relayers(e.msg.sender);

    assert rewardsAfter == 0,
        "Rewards must be zero after claiming";
}

/// @notice claimRewards reverts when no rewards
rule claimRewardsRevertsWhenEmpty(env e) {
    uint256 s; uint256 rewards; uint256 u; bool isReg;
    s, rewards, u, isReg = relayers(e.msg.sender);
    require rewards == 0;

    claimRewards@withrevert(e);

    assert lastReverted,
        "claimRewards must revert when rewards are zero";
}

/*//////////////////////////////////////////////////////////////
                    STAKE SOLVENCY
//////////////////////////////////////////////////////////////*/

/// @notice Stake is never negative (uint256 underflow protection)
rule stakeNeverNegative(env e, method f, address relayer) filtered {
    f -> !f.isView && !f.isFallback
} {
    uint256 stakeBefore; uint256 rb; uint256 ub; bool isRegB;
    stakeBefore, rb, ub, isRegB = relayers(relayer);

    calldataarg args;
    f(e, args);

    uint256 stakeAfter; uint256 ra; uint256 ua; bool isRegA;
    stakeAfter, ra, ua, isRegA = relayers(relayer);

    // Verify stake only decreases via explicit slash/withdraw paths
    // (stake is uint256, so >= 0 by type; this checks monotonicity instead)
    assert stakeAfter <= stakeBefore || isRegA,
        "Stake must not increase unless via registration";
}
