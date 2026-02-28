// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/RelayerStaking.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Minimal ERC20 for testing
contract MockZaseonToken is ERC20 {
    constructor() ERC20("Zaseon Token", "ZASEON") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract RelayerStakingTest is Test {
    RelayerStaking public staking;
    MockZaseonToken public token;

    address public admin = address(this);
    address public relayerA = address(0xA);
    address public relayerB = address(0xB);
    address public relayerC = address(0xC);
    address public slasher = address(0xD);

    uint256 public constant MIN_STAKE = 100 ether;

    function setUp() public {
        token = new MockZaseonToken();
        staking = new RelayerStaking(address(token), MIN_STAKE, admin);

        // Fund relayers
        token.mint(relayerA, 1000 ether);
        token.mint(relayerB, 1000 ether);
        token.mint(relayerC, 1000 ether);

        // Approve staking contract
        vm.prank(relayerA);
        token.approve(address(staking), type(uint256).max);
        vm.prank(relayerB);
        token.approve(address(staking), type(uint256).max);
        vm.prank(relayerC);
        token.approve(address(staking), type(uint256).max);
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    function test_constructor() public view {
        assertEq(address(staking.stakingToken()), address(token));
        assertEq(staking.minStake(), MIN_STAKE);
        assertTrue(staking.hasRole(staking.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(staking.hasRole(staking.ADMIN_ROLE(), admin));
        assertTrue(staking.hasRole(staking.SLASHER_ROLE(), admin));
    }

    // =========================================================================
    // STAKE
    // =========================================================================

    function test_stake_basic() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        (uint256 stakedAmount, , , , , , bool isActive, ) = staking.relayers(
            relayerA
        );
        assertEq(stakedAmount, 200 ether);
        assertTrue(isActive);
        assertEq(staking.totalStaked(), 200 ether);
        assertEq(staking.getActiveRelayerCount(), 1);
    }

    function test_stake_emitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit RelayerStaking.Staked(relayerA, 200 ether);
        vm.prank(relayerA);
        staking.stake(200 ether);
    }

    function test_stake_revertOnZero() public {
        vm.prank(relayerA);
        vm.expectRevert(RelayerStaking.InvalidAmount.selector);
        staking.stake(0);
    }

    function test_stake_belowMinNotActivated() public {
        vm.prank(relayerA);
        staking.stake(50 ether);

        (uint256 stakedAmount, , , , , , bool isActive, ) = staking.relayers(
            relayerA
        );
        assertEq(stakedAmount, 50 ether);
        assertFalse(isActive);
        assertEq(staking.getActiveRelayerCount(), 0);
    }

    function test_stake_incrementalActivation() public {
        vm.startPrank(relayerA);
        staking.stake(50 ether);
        assertFalse(staking.isActiveRelayer(relayerA));

        staking.stake(60 ether);
        assertTrue(staking.isActiveRelayer(relayerA));
        vm.stopPrank();
    }

    function test_stake_tokenTransfer() public {
        uint256 balBefore = token.balanceOf(relayerA);

        vm.prank(relayerA);
        staking.stake(200 ether);

        assertEq(token.balanceOf(relayerA), balBefore - 200 ether);
        assertEq(token.balanceOf(address(staking)), 200 ether);
    }

    function test_stake_setsTimestamp() public {
        vm.warp(1000);
        vm.prank(relayerA);
        staking.stake(200 ether);

        assertEq(staking.stakingTimestamp(relayerA), 1000);
    }

    function test_stake_incrementalDoesNotResetTimestamp() public {
        vm.warp(1000);
        vm.prank(relayerA);
        staking.stake(100 ether);
        assertEq(staking.stakingTimestamp(relayerA), 1000);

        vm.warp(5000);
        vm.prank(relayerA);
        staking.stake(100 ether);
        // Timestamp should not change since stakedAmount was already > 0
        assertEq(staking.stakingTimestamp(relayerA), 1000);
    }

    // =========================================================================
    // REQUEST UNSTAKE
    // =========================================================================

    function test_requestUnstake_basic() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        vm.prank(relayerA);
        staking.requestUnstake(100 ether);

        (
            uint256 stakedAmount,
            uint256 pendingUnstake,
            uint256 unstakeRequestTime,
            ,
            ,
            ,
            ,

        ) = staking.relayers(relayerA);
        assertEq(stakedAmount, 100 ether);
        assertEq(pendingUnstake, 100 ether);
        assertGt(unstakeRequestTime, 0);
        assertEq(staking.totalStaked(), 100 ether);
    }

    function test_requestUnstake_emitsEvent() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        vm.expectEmit(true, false, false, true);
        emit RelayerStaking.UnstakeRequested(relayerA, 100 ether);
        vm.prank(relayerA);
        staking.requestUnstake(100 ether);
    }

    function test_requestUnstake_revertOnInsufficientStake() public {
        vm.prank(relayerA);
        staking.stake(100 ether);

        vm.prank(relayerA);
        vm.expectRevert(RelayerStaking.InsufficientStake.selector);
        staking.requestUnstake(200 ether);
    }

    function test_requestUnstake_revertOnPendingExists() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        vm.prank(relayerA);
        staking.requestUnstake(50 ether);

        vm.prank(relayerA);
        vm.expectRevert(RelayerStaking.PendingUnstakeExists.selector);
        staking.requestUnstake(50 ether);
    }

    function test_requestUnstake_deactivatesIfBelowMin() public {
        vm.prank(relayerA);
        staking.stake(150 ether);
        assertTrue(staking.isActiveRelayer(relayerA));

        vm.prank(relayerA);
        staking.requestUnstake(100 ether);
        assertFalse(staking.isActiveRelayer(relayerA));
        assertEq(staking.getActiveRelayerCount(), 0);
    }

    // =========================================================================
    // COMPLETE UNSTAKE
    // =========================================================================

    function test_completeUnstake_basic() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        vm.prank(relayerA);
        staking.requestUnstake(100 ether);

        vm.warp(block.timestamp + 7 days + 1);

        uint256 balBefore = token.balanceOf(relayerA);
        vm.prank(relayerA);
        staking.completeUnstake();

        assertEq(token.balanceOf(relayerA), balBefore + 100 ether);
        (
            ,
            uint256 pendingUnstake,
            uint256 unstakeRequestTime,
            ,
            ,
            ,
            ,

        ) = staking.relayers(relayerA);
        assertEq(pendingUnstake, 0);
        assertEq(unstakeRequestTime, 0);
    }

    function test_completeUnstake_emitsEvent() public {
        vm.prank(relayerA);
        staking.stake(200 ether);
        vm.prank(relayerA);
        staking.requestUnstake(100 ether);
        vm.warp(block.timestamp + 7 days + 1);

        vm.expectEmit(true, false, false, true);
        emit RelayerStaking.Unstaked(relayerA, 100 ether);
        vm.prank(relayerA);
        staking.completeUnstake();
    }

    function test_completeUnstake_revertOnNoPending() public {
        vm.prank(relayerA);
        vm.expectRevert(RelayerStaking.NoPendingUnstake.selector);
        staking.completeUnstake();
    }

    function test_completeUnstake_revertBeforeUnbonding() public {
        vm.prank(relayerA);
        staking.stake(200 ether);
        vm.prank(relayerA);
        staking.requestUnstake(100 ether);

        // Move forward but not enough
        vm.warp(block.timestamp + 6 days);

        vm.prank(relayerA);
        vm.expectRevert(RelayerStaking.UnbondingPeriodNotComplete.selector);
        staking.completeUnstake();
    }

    function test_completeUnstake_exactBoundary() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        uint256 requestTime = block.timestamp;
        vm.prank(relayerA);
        staking.requestUnstake(100 ether);

        // One second before 7 days - should revert (< comparison in contract)
        vm.warp(requestTime + 7 days - 1);
        vm.prank(relayerA);
        vm.expectRevert(RelayerStaking.UnbondingPeriodNotComplete.selector);
        staking.completeUnstake();

        // Exactly at 7 days - should succeed (contract uses strict <)
        vm.warp(requestTime + 7 days);
        vm.prank(relayerA);
        staking.completeUnstake();
    }

    // =========================================================================
    // SLASH
    // =========================================================================

    function test_slash_basic() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        staking.slash(relayerA, "misbehavior");

        // 10% of 200 = 20 slashed
        (uint256 stakedAmount, , , , , uint256 failedRelays, , ) = staking
            .relayers(relayerA);
        assertEq(stakedAmount, 180 ether);
        assertEq(failedRelays, 1);
        assertEq(staking.totalStaked(), 180 ether);
    }

    function test_slash_emitsEvent() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        vm.expectEmit(true, false, false, true);
        emit RelayerStaking.Slashed(relayerA, 20 ether, "reason");
        staking.slash(relayerA, "reason");
    }

    function test_slash_revertOnNoStake() public {
        vm.expectRevert(RelayerStaking.NoStakeFound.selector);
        staking.slash(relayerA, "reason");
    }

    function test_slash_accessControl() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        vm.prank(relayerC); // Not a slasher
        vm.expectRevert();
        staking.slash(relayerA, "reason");
    }

    function test_slash_deactivatesIfBelowMin() public {
        vm.prank(relayerA);
        staking.stake(100 ether);
        assertTrue(staking.isActiveRelayer(relayerA));

        // Slash 10% = 10 ether → remaining 90 < 100 min
        staking.slash(relayerA, "reason");
        assertFalse(staking.isActiveRelayer(relayerA));
    }

    function test_slash_redistributesToRewardPool() public {
        vm.prank(relayerA);
        staking.stake(200 ether);
        vm.prank(relayerB);
        staking.stake(200 ether);

        // Slash A (10% * 200 = 20)
        staking.slash(relayerA, "reason");

        // B should see pending rewards from slash redistribution
        // rewardPerShare = 20 * 1e18 / 380 (totalStaked after slash = 180 + 200 = 380)
        uint256 pending = staking.pendingRewards(relayerB);
        assertGt(pending, 0);
    }

    // =========================================================================
    // REWARDS
    // =========================================================================

    function test_addRewards() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        token.approve(address(staking), 50 ether);
        staking.addRewards(50 ether);

        assertEq(staking.rewardPool(), 50 ether);
    }

    function test_addRewards_revertOnZero() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        token.approve(address(staking), 50 ether);
        vm.expectRevert(RelayerStaking.InvalidAmount.selector);
        staking.addRewards(0);
    }

    function test_addRewards_revertOnNoStakers() public {
        token.approve(address(staking), 50 ether);
        vm.expectRevert(RelayerStaking.NoStakers.selector);
        staking.addRewards(50 ether);
    }

    function test_claimRewards_afterMinDuration() public {
        vm.warp(1000);
        vm.prank(relayerA);
        staking.stake(200 ether);

        // Add rewards
        token.approve(address(staking), 50 ether);
        staking.addRewards(50 ether);

        // Too early - silently returns
        vm.warp(1000 + 12 hours);
        uint256 pendingBefore = staking.pendingRewards(relayerA);
        assertGt(pendingBefore, 0);

        // After MIN_STAKE_DURATION
        vm.warp(1000 + 1 days + 1);
        uint256 balBefore = token.balanceOf(relayerA);
        vm.prank(relayerA);
        staking.claimRewards();
        assertGt(token.balanceOf(relayerA), balBefore);
    }

    function test_claimRewards_flashLoanProtection() public {
        vm.warp(1000);
        vm.prank(relayerA);
        staking.stake(200 ether);

        token.approve(address(staking), 50 ether);
        staking.addRewards(50 ether);

        // Try to claim immediately (within MIN_STAKE_DURATION)
        uint256 balBefore = token.balanceOf(relayerA);
        vm.prank(relayerA);
        staking.claimRewards();
        // Flash loan protection: reward claim silently skipped
        assertEq(token.balanceOf(relayerA), balBefore);
    }

    function test_claimRewards_proportionalDistribution() public {
        vm.warp(1000);

        // A stakes 300, B stakes 100 (3:1 ratio)
        vm.prank(relayerA);
        staking.stake(300 ether);
        vm.prank(relayerB);
        staking.stake(100 ether);

        // Add 100 ether rewards
        token.approve(address(staking), 100 ether);
        staking.addRewards(100 ether);

        // Check rewards are roughly 3:1
        uint256 pendingA = staking.pendingRewards(relayerA);
        uint256 pendingB = staking.pendingRewards(relayerB);
        assertApproxEqAbs(pendingA, 75 ether, 1); // 75%
        assertApproxEqAbs(pendingB, 25 ether, 1); // 25%
    }

    // =========================================================================
    // RECORD SUCCESSFUL RELAY
    // =========================================================================

    function test_recordSuccessfulRelay() public {
        vm.prank(relayerA);
        staking.stake(200 ether);

        staking.recordSuccessfulRelay(relayerA);
        (, , , , uint256 successfulRelays, , , ) = staking.relayers(relayerA);
        assertEq(successfulRelays, 1);
    }

    function test_recordSuccessfulRelay_accessControl() public {
        vm.prank(relayerC); // Not admin
        vm.expectRevert();
        staking.recordSuccessfulRelay(relayerA);
    }

    // =========================================================================
    // ADMIN SETTERS
    // =========================================================================

    function test_setMinStake() public {
        staking.setMinStake(200 ether);
        assertEq(staking.minStake(), 200 ether);
    }

    function test_setMinStake_accessControl() public {
        vm.prank(relayerA);
        vm.expectRevert();
        staking.setMinStake(200 ether);
    }

    function test_setSlashingPercentage() public {
        staking.setSlashingPercentage(2000); // 20%
        assertEq(staking.slashingPercentage(), 2000);
    }

    function test_setSlashingPercentage_revertOver50() public {
        vm.expectRevert(RelayerStaking.InvalidSlashingPercentage.selector);
        staking.setSlashingPercentage(5001);
    }

    function test_setSlashingPercentage_accessControl() public {
        vm.prank(relayerA);
        vm.expectRevert();
        staking.setSlashingPercentage(2000);
    }

    // =========================================================================
    // UPDATE METADATA
    // =========================================================================

    function test_updateMetadata() public {
        vm.prank(relayerA);
        staking.updateMetadata("ipfs://QmTest");
        (, , , , , , , string memory metadata) = staking.relayers(relayerA);
        assertEq(metadata, "ipfs://QmTest");
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_getActiveRelayers() public {
        vm.prank(relayerA);
        staking.stake(200 ether);
        vm.prank(relayerB);
        staking.stake(200 ether);

        address[] memory actives = staking.getActiveRelayers();
        assertEq(actives.length, 2);
    }

    function test_isActiveRelayer() public {
        assertFalse(staking.isActiveRelayer(relayerA));
        vm.prank(relayerA);
        staking.stake(200 ether);
        assertTrue(staking.isActiveRelayer(relayerA));
    }

    // =========================================================================
    // DEACTIVATION SWAP-AND-POP
    // =========================================================================

    function test_deactivation_swapAndPop() public {
        // Stake 3 relayers
        vm.prank(relayerA);
        staking.stake(200 ether);
        vm.prank(relayerB);
        staking.stake(200 ether);
        vm.prank(relayerC);
        staking.stake(200 ether);
        assertEq(staking.getActiveRelayerCount(), 3);

        // Deactivate middle one (A = index 0)
        vm.prank(relayerA);
        staking.requestUnstake(200 ether);
        assertEq(staking.getActiveRelayerCount(), 2);

        // Verify remaining relayers are correct
        address[] memory actives = staking.getActiveRelayers();
        assertEq(actives.length, 2);
        // After swap-and-pop, C should be at index 0, B at index 1
        assertEq(actives[0], relayerC);
        assertEq(actives[1], relayerB);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_stake(uint256 amount) public {
        amount = bound(amount, 1, 500 ether);
        token.mint(relayerA, amount);
        vm.startPrank(relayerA);
        token.approve(address(staking), amount);
        staking.stake(amount);
        vm.stopPrank();

        (uint256 stakedAmount, , , , , , , ) = staking.relayers(relayerA);
        assertEq(stakedAmount, amount);
    }

    function testFuzz_slashPercentage(uint256 percentage) public {
        percentage = bound(percentage, 0, 5000);
        staking.setSlashingPercentage(percentage);
        assertEq(staking.slashingPercentage(), percentage);
    }
}
