// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";
import {IDecentralizedRelayerRegistry} from "../../contracts/interfaces/IDecentralizedRelayerRegistry.sol";

contract DecentralizedRelayerRegistryTest is Test {
    DecentralizedRelayerRegistry public registry;
    address public admin = address(this);
    address public relayer = makeAddr("relayer");
    address public relayer2 = makeAddr("relayer2");
    address public slasher = makeAddr("slasher");
    address public insuranceFund = makeAddr("insurance");

    function setUp() public {
        registry = new DecentralizedRelayerRegistry(admin);

        // Grant slasher role
        registry.grantRole(registry.SLASHER_ROLE(), slasher);

        // Fund relayers
        vm.deal(relayer, 100 ether);
        vm.deal(relayer2, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                       REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RegisterWithStake() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();
        vm.stopPrank();

        (uint256 stake, , , bool isRegistered) = registry.relayers(relayer);
        assertEq(stake, 10 ether);
        assertTrue(isRegistered);
        assertEq(registry.activeRelayers(0), relayer);
    }

    function test_RegisterBelowMinStake() public {
        vm.startPrank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.InsufficientStake.selector,
                5 ether,
                10 ether
            )
        );
        registry.register{value: 5 ether}();
        vm.stopPrank();
    }

    function test_RegisterTwice() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();

        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.AlreadyRegistered.selector,
                relayer
            )
        );
        registry.register{value: 10 ether}();
        vm.stopPrank();
    }

    function test_RegisterMultipleRelayers() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        vm.prank(relayer2);
        registry.register{value: 15 ether}();

        assertEq(registry.activeRelayers(0), relayer);
        assertEq(registry.activeRelayers(1), relayer2);
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT STAKE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_DepositStake() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();
        registry.depositStake{value: 5 ether}();
        vm.stopPrank();

        (uint256 stake, , , ) = registry.relayers(relayer);
        assertEq(stake, 15 ether);
    }

    function test_DepositStakeUnregistered() public {
        vm.startPrank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.NotRegistered.selector,
                relayer
            )
        );
        registry.depositStake{value: 5 ether}();
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       UNSTAKE & WITHDRAW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UnstakeWaitPeriod() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();

        registry.initiateUnstake();

        (, , uint256 unlockTime, ) = registry.relayers(relayer);
        assertEq(unlockTime, block.timestamp + 7 days);

        // Try withdraw too early
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.StillLocked.selector,
                unlockTime,
                block.timestamp
            )
        );
        registry.withdrawStake();

        // Wait
        vm.warp(unlockTime + 1);

        uint256 balanceBefore = relayer.balance;
        registry.withdrawStake();
        uint256 balanceAfter = relayer.balance;

        assertEq(balanceAfter - balanceBefore, 10 ether);

        (uint256 stake, , , bool isRegistered) = registry.relayers(relayer);
        assertEq(stake, 0);
        assertFalse(isRegistered);
        vm.stopPrank();
    }

    function test_InitiateUnstakeTwice() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();
        registry.initiateUnstake();

        (, , uint256 unlockTime, ) = registry.relayers(relayer);

        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.AlreadyUnbonding.selector,
                relayer,
                unlockTime
            )
        );
        registry.initiateUnstake();
        vm.stopPrank();
    }

    function test_InitiateUnstakeUnregistered() public {
        vm.startPrank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.NotRegistered.selector,
                relayer
            )
        );
        registry.initiateUnstake();
        vm.stopPrank();
    }

    function test_WithdrawWithoutInitiate() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();

        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.NotUnbonding.selector,
                relayer
            )
        );
        registry.withdrawStake();
        vm.stopPrank();
    }

    function test_WithdrawCleansActiveRelayers() public {
        // Register two relayers
        vm.prank(relayer);
        registry.register{value: 10 ether}();
        vm.prank(relayer2);
        registry.register{value: 10 ether}();

        // Withdraw first relayer
        vm.startPrank(relayer);
        registry.initiateUnstake();
        (, , uint256 unlockTime, ) = registry.relayers(relayer);
        vm.warp(unlockTime + 1);
        registry.withdrawStake();
        vm.stopPrank();

        // activeRelayers should now only contain relayer2 (swap-and-pop)
        assertEq(registry.activeRelayers(0), relayer2);
    }

    /*//////////////////////////////////////////////////////////////
                          SLASHING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Slash() public {
        vm.prank(relayer);
        registry.register{value: 20 ether}();

        vm.prank(slasher);
        registry.slash(relayer, 5 ether, insuranceFund);

        (uint256 stake, , , ) = registry.relayers(relayer);
        assertEq(stake, 15 ether);
        assertEq(insuranceFund.balance, 5 ether);
    }

    function test_SlashExceedsStake() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        vm.prank(slasher);
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry
                    .InsufficientStakeForSlash
                    .selector,
                10 ether,
                15 ether
            )
        );
        registry.slash(relayer, 15 ether, insuranceFund);
    }

    function test_SlashAccessControl() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        // Non-slasher should revert
        vm.prank(relayer2);
        vm.expectRevert();
        registry.slash(relayer, 1 ether, insuranceFund);
    }

    function test_SlashDuringUnbonding() public {
        vm.startPrank(relayer);
        registry.register{value: 20 ether}();
        registry.initiateUnstake();
        vm.stopPrank();

        // Slashing during unbonding should succeed (design requirement)
        vm.prank(slasher);
        registry.slash(relayer, 5 ether, insuranceFund);

        (uint256 stake, , , ) = registry.relayers(relayer);
        assertEq(stake, 15 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          REWARDS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AddReward() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        // Anyone can add rewards
        registry.addReward{value: 1 ether}(relayer, 1 ether);

        (, uint256 rewards, , ) = registry.relayers(relayer);
        assertEq(rewards, 1 ether);
    }

    function test_AddRewardValueMismatch() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.ValueMismatch.selector,
                2 ether,
                1 ether
            )
        );
        registry.addReward{value: 2 ether}(relayer, 1 ether);
    }

    function test_AddRewardUnregistered() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.NotRegistered.selector,
                relayer
            )
        );
        registry.addReward{value: 1 ether}(relayer, 1 ether);
    }

    function test_ClaimRewards() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        registry.addReward{value: 3 ether}(relayer, 3 ether);

        uint256 balBefore = relayer.balance;
        vm.prank(relayer);
        registry.claimRewards();
        uint256 balAfter = relayer.balance;

        assertEq(balAfter - balBefore, 3 ether);

        (, uint256 rewards, , ) = registry.relayers(relayer);
        assertEq(rewards, 0);
    }

    function test_ClaimRewardsEmpty() public {
        vm.prank(relayer);
        registry.register{value: 10 ether}();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.NoRewards.selector,
                relayer
            )
        );
        registry.claimRewards();
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_StakeDeposit(uint256 extra) public {
        extra = bound(extra, 0, 90 ether);

        vm.startPrank(relayer);
        registry.register{value: 10 ether}();

        if (extra > 0) {
            registry.depositStake{value: extra}();
        }
        vm.stopPrank();

        (uint256 stake, , , ) = registry.relayers(relayer);
        assertEq(stake, 10 ether + extra);
    }

    function testFuzz_SlashAmount(uint256 slashAmt) public {
        vm.prank(relayer);
        registry.register{value: 20 ether}();

        slashAmt = bound(slashAmt, 1, 20 ether);

        vm.prank(slasher);
        registry.slash(relayer, slashAmt, insuranceFund);

        (uint256 stake, , , ) = registry.relayers(relayer);
        assertEq(stake, 20 ether - slashAmt);
        assertEq(insuranceFund.balance, slashAmt);
    }
}
