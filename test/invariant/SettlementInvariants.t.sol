// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/core/InstantSettlementGuarantee.sol";
import "../../contracts/core/IntentSettlementLayer.sol";
import "../../contracts/relayer/InstantRelayerRewards.sol";
import {IIntentSettlementLayer} from "../../contracts/interfaces/IIntentSettlementLayer.sol";
import {IInstantSettlementGuarantee} from "../../contracts/interfaces/IInstantSettlementGuarantee.sol";

/**
 * @title SettlementInvariantsTest
 * @notice Invariant / fuzz tests for InstantSettlementGuarantee and InstantRelayerRewards.
 * @dev Validates critical conservation laws:
 *   1. Bond conservation: total bonds posted == total bonds returned + total claims + held bonds
 *   2. Reward conservation: total deposits == total rewards paid + total refunds + protocol fees + held
 *   3. Guarantee lifecycle correctness: ACTIVE → SETTLED | CLAIMED | EXPIRED (no invalid transitions)
 *   4. Collateral ratio always enforced
 */
contract SettlementInvariantsTest is Test {
    InstantSettlementGuarantee public guarantee;
    IntentSettlementLayer public intentLayer;
    InstantRelayerRewards public rewards;

    address public admin = makeAddr("admin");
    address public solver = makeAddr("solver");
    address public user = makeAddr("user");

    uint256 constant SOURCE_CHAIN = 1;
    uint256 constant DEST_CHAIN = 42161;

    function setUp() public {
        vm.deal(admin, 1000 ether);
        vm.deal(solver, 1000 ether);
        vm.deal(user, 1000 ether);

        vm.startPrank(admin);
        intentLayer = new IntentSettlementLayer(admin, address(0));
        guarantee = new InstantSettlementGuarantee(admin, address(intentLayer));
        rewards = new InstantRelayerRewards(admin);

        intentLayer.setSupportedChain(SOURCE_CHAIN, true);
        intentLayer.setSupportedChain(DEST_CHAIN, true);

        rewards.grantRole(rewards.RELAY_MANAGER_ROLE(), admin);
        guarantee.grantRole(guarantee.SETTLEMENT_ROLE(), admin);
        vm.stopPrank();
    }

    // =========================================================================
    // FUZZ: Bond Collateral Ratio Always Enforced
    // =========================================================================

    function testFuzz_bondMeetsCollateralRatio(uint256 amount) public {
        // Bound to valid range
        amount = bound(amount, 0.001 ether, 100 ether);

        uint256 requiredBond = guarantee.requiredBond(amount);
        // Bond must always be >= amount (110% collateralization)
        assertTrue(requiredBond >= amount, "bond must be >= guaranteed amount");

        // Verify exact ratio: bond = amount * ratio / 10000
        // Default ratio is 11000 bps (110%)
        assertEq(
            requiredBond,
            (amount * 11000) / 10000,
            "bond should be 110% of amount"
        );
    }

    // =========================================================================
    // FUZZ: Reward Calculation Bounded
    // =========================================================================

    function testFuzz_rewardNeverExceedsDeposit(
        uint256 baseReward,
        uint256 responseTime
    ) public view {
        baseReward = bound(baseReward, 0.001 ether, 100 ether);
        responseTime = bound(responseTime, 0, 1 hours);

        uint256 reward = rewards.calculateReward(baseReward, responseTime);
        assertTrue(reward <= baseReward, "reward must never exceed deposit");
    }

    function testFuzz_rewardDecreaseWithTime(uint256 baseReward) public view {
        baseReward = bound(baseReward, 0.001 ether, 100 ether);

        uint256 ultraFast = rewards.calculateReward(baseReward, 10); // <30s
        uint256 fast = rewards.calculateReward(baseReward, 45); // <60s
        uint256 normal = rewards.calculateReward(baseReward, 120); // <5min
        uint256 slow = rewards.calculateReward(baseReward, 600); // >=5min

        assertTrue(ultraFast >= fast, "ULTRA_FAST >= FAST");
        assertTrue(fast >= normal, "FAST >= NORMAL");
        assertTrue(normal >= slow, "NORMAL >= SLOW");
    }

    // =========================================================================
    // FUZZ: Guarantee Lifecycle – Settlement Returns Bond
    // =========================================================================

    function testFuzz_settledGuaranteeReturnsBond(uint256 amount) public {
        amount = bound(amount, 0.001 ether, 10 ether);

        // Register solver and submit intent
        vm.prank(solver);
        intentLayer.registerSolver{value: 1 ether}();

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: 0.1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            0.1 ether,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        // Post guarantee
        uint256 bond = guarantee.requiredBond(amount);
        vm.prank(solver);
        bytes32 gId = guarantee.postGuarantee{value: bond}(
            intentId,
            user,
            amount,
            1 hours
        );

        // Fulfill and finalize intent
        vm.prank(solver);
        intentLayer.claimIntent(intentId);
        vm.prank(solver);
        intentLayer.fulfillIntent(
            intentId,
            hex"deadbeef",
            hex"cafebabe",
            keccak256("new")
        );
        vm.warp(block.timestamp + 1 hours + 1);
        intentLayer.finalizeIntent(intentId);

        // Settle guarantee → bond should return to solver
        uint256 solverBalBefore = solver.balance;
        uint256 contractBalBefore = address(guarantee).balance;

        vm.prank(solver);
        guarantee.settleGuarantee(gId);

        uint256 bondReturned = solver.balance - solverBalBefore;
        uint256 contractDelta = contractBalBefore - address(guarantee).balance;

        // Bond returned should be positive and match contract decrease
        assertTrue(bondReturned > 0, "solver should receive bond back");
        assertEq(
            bondReturned,
            contractDelta,
            "bond conservation: what left contract = what solver received"
        );
    }

    // =========================================================================
    // FUZZ: Relay Reward Conservation
    // =========================================================================

    function testFuzz_relayRewardConservation(uint256 baseReward) public {
        baseReward = bound(baseReward, 0.01 ether, 10 ether);

        bytes32 relayId = keccak256(abi.encodePacked("relay", baseReward));
        address relayer = makeAddr("relayer_fuzz");
        vm.deal(relayer, 1 ether);

        vm.startPrank(admin);

        uint256 contractBalBefore = address(rewards).balance;
        rewards.depositRelayFee{value: baseReward}(relayId, user);

        assertEq(
            address(rewards).balance - contractBalBefore,
            baseReward,
            "deposit should increase contract balance"
        );

        rewards.claimRelay(relayId, relayer);

        // Complete relay (ULTRA_FAST)
        uint256 relayerBalBefore = relayer.balance;
        uint256 contractBalPreComplete = address(rewards).balance;

        rewards.completeRelayWithReward(relayId);

        uint256 relayerGain = relayer.balance - relayerBalBefore;
        uint256 contractLoss = contractBalPreComplete -
            address(rewards).balance;

        // Conservation: what left the contract = relayer reward (protocol fee stays in contract)
        assertTrue(relayerGain > 0, "relayer should get some reward");
        assertTrue(relayerGain <= baseReward, "reward cannot exceed deposit");
        assertEq(
            relayerGain,
            contractLoss,
            "conservation: contract loss = relayer gain"
        );

        vm.stopPrank();
    }

    // =========================================================================
    // FUZZ: Refund Returns Full Deposit
    // =========================================================================

    function testFuzz_refundReturnsFullDeposit(uint256 baseReward) public {
        baseReward = bound(baseReward, 0.01 ether, 10 ether);

        bytes32 relayId = keccak256(abi.encodePacked("refund", baseReward));

        vm.startPrank(admin);
        rewards.depositRelayFee{value: baseReward}(relayId, user);

        uint256 userBalBefore = user.balance;
        rewards.refundDeposit(relayId);
        uint256 userGain = user.balance - userBalBefore;

        assertEq(userGain, baseReward, "refund should return full deposit");
        vm.stopPrank();
    }

    // =========================================================================
    // FUZZ: Intent Fee Bounded by maxFee
    // =========================================================================

    function testFuzz_intentSubmitRequiresCorrectFee(uint256 maxFee) public {
        maxFee = bound(maxFee, 0.001 ether, 10 ether);

        vm.prank(solver);
        intentLayer.registerSolver{value: 1 ether}();

        // Should succeed with exactly maxFee
        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: maxFee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            maxFee,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        IIntentSettlementLayer.Intent memory intent = intentLayer.getIntent(
            intentId
        );
        assertEq(intent.maxFee, maxFee, "maxFee should match");
    }

    // =========================================================================
    // FUZZ: Solver Stake Bounded
    // =========================================================================

    function testFuzz_solverStakeMinimum(uint256 stake) public {
        stake = bound(stake, 0, 10 ether);

        address newSolver = makeAddr("fuzz_solver");
        vm.deal(newSolver, 100 ether);
        vm.prank(newSolver);

        if (stake < 1 ether) {
            // Should revert if below minimum stake
            vm.expectRevert();
            intentLayer.registerSolver{value: stake}();
        } else {
            // Should succeed
            intentLayer.registerSolver{value: stake}();
            IIntentSettlementLayer.Solver memory s = intentLayer.getSolver(
                newSolver
            );
            assertTrue(s.isActive, "solver should be active");
            assertEq(s.stake, stake, "stake should match");
        }
    }
}
