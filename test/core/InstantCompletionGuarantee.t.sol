// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {InstantCompletionGuarantee} from "../../contracts/core/InstantCompletionGuarantee.sol";
import {IInstantCompletionGuarantee} from "../../contracts/interfaces/IInstantCompletionGuarantee.sol";
import {IIntentCompletionLayer} from "../../contracts/interfaces/IIntentCompletionLayer.sol";

/// @dev Mock IntentCompletionLayer for testing
contract MockIntentLayer {
    mapping(bytes32 => bool) public finalized;

    function setFinalized(bytes32 intentId, bool _finalized) external {
        finalized[intentId] = _finalized;
    }

    function canFinalize(bytes32 intentId) external view returns (bool) {
        return finalized[intentId];
    }

    // Minimal stubs for IIntentCompletionLayer
    function getIntent(
        bytes32
    ) external pure returns (IIntentCompletionLayer.Intent memory intent) {
        return intent;
    }

    function getSolver(
        address
    ) external pure returns (IIntentCompletionLayer.Solver memory solver) {
        return solver;
    }

    function submitIntent(
        uint256,
        uint256,
        bytes32,
        bytes32,
        uint256,
        uint256,
        bytes32
    ) external payable returns (bytes32) {
        return bytes32(0);
    }

    function cancelIntent(bytes32) external {}

    function registerSolver() external payable {}

    function deactivateSolver() external {}

    function claimIntent(bytes32) external {}

    function fulfillIntent(
        bytes32,
        bytes calldata,
        bytes calldata,
        bytes32
    ) external {}

    function finalizeIntent(bytes32) external {}
}

contract InstantCompletionGuaranteeTest is Test {
    InstantCompletionGuarantee public guarantee;
    MockIntentLayer public mockLayer;

    address admin = address(0x1A);
    address solver1 = address(0x1B);
    address solver2 = address(0x1C);
    address user1 = address(0x1D);
    address user2 = address(0x1E);

    bytes32 constant INTENT_ID_1 = keccak256("intent1");
    bytes32 constant INTENT_ID_2 = keccak256("intent2");

    function setUp() public {
        vm.warp(1740000000);

        mockLayer = new MockIntentLayer();
        guarantee = new InstantCompletionGuarantee(admin, address(mockLayer));

        vm.deal(solver1, 100 ether);
        vm.deal(solver2, 100 ether);
        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
        vm.deal(admin, 10 ether);
    }

    // ──────────────────────────────────────────────────────────
    //  Post Guarantee
    // ──────────────────────────────────────────────────────────

    function test_PostGuarantee() public {
        vm.prank(solver1);
        bytes32 gId = guarantee.postGuarantee{value: 1.1 ether}(
            INTENT_ID_1,
            user1,
            1 ether,
            1 hours
        );

        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            gId
        );
        assertEq(g.intentId, INTENT_ID_1);
        assertEq(g.guarantor, solver1);
        assertEq(g.beneficiary, user1);
        assertEq(g.amount, 1 ether);
        assertEq(g.bond, 1.1 ether);
        assertEq(
            uint(g.status),
            uint(IInstantCompletionGuarantee.GuaranteeStatus.ACTIVE)
        );
        assertEq(guarantee.totalGuarantees(), 1);
        assertEq(guarantee.guarantorActiveCount(solver1), 1);
    }

    function test_RevertOnPost_ZeroBeneficiary() public {
        vm.prank(solver1);
        vm.expectRevert(IInstantCompletionGuarantee.ZeroAddress.selector);
        guarantee.postGuarantee{value: 1.1 ether}(
            INTENT_ID_1,
            address(0),
            1 ether,
            1 hours
        );
    }

    function test_RevertOnPost_AmountTooSmall() public {
        vm.prank(solver1);
        vm.expectRevert(IInstantCompletionGuarantee.InvalidAmount.selector);
        guarantee.postGuarantee{value: 0.0001 ether}(
            INTENT_ID_1,
            user1,
            0.0001 ether,
            1 hours
        );
    }

    function test_RevertOnPost_InsufficientBond() public {
        // 110% of 1 ether = 1.1 ether, sending only 1 ether
        vm.prank(solver1);
        vm.expectRevert(IInstantCompletionGuarantee.InsufficientBond.selector);
        guarantee.postGuarantee{value: 1 ether}(
            INTENT_ID_1,
            user1,
            1 ether,
            1 hours
        );
    }

    function test_RevertOnPost_DurationTooShort() public {
        vm.prank(solver1);
        vm.expectRevert(IInstantCompletionGuarantee.InvalidDuration.selector);
        guarantee.postGuarantee{value: 1.1 ether}(
            INTENT_ID_1,
            user1,
            1 ether,
            10 minutes
        );
    }

    function test_RevertOnPost_DurationTooLong() public {
        vm.prank(solver1);
        vm.expectRevert(IInstantCompletionGuarantee.InvalidDuration.selector);
        guarantee.postGuarantee{value: 1.1 ether}(
            INTENT_ID_1,
            user1,
            1 ether,
            8 days
        );
    }

    function test_RevertOnPost_ZeroIntentId() public {
        vm.prank(solver1);
        vm.expectRevert(IInstantCompletionGuarantee.IntentNotLinked.selector);
        guarantee.postGuarantee{value: 1.1 ether}(
            bytes32(0),
            user1,
            1 ether,
            1 hours
        );
    }

    // ──────────────────────────────────────────────────────────
    //  Settle Guarantee
    // ──────────────────────────────────────────────────────────

    function test_SettleGuarantee() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        // Mark intent as finalized
        mockLayer.setFinalized(INTENT_ID_1, true);

        uint256 solverBal = solver1.balance;
        vm.prank(solver1);
        guarantee.settleGuarantee(gId);

        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            gId
        );
        assertEq(
            uint(g.status),
            uint(IInstantCompletionGuarantee.GuaranteeStatus.SETTLED)
        );

        // Solver gets full bond back (profit comes from IntentCompletionLayer)
        assertEq(solver1.balance, solverBal + 1.1 ether);
        assertEq(guarantee.totalSettled(), 1);
        assertEq(guarantee.guarantorActiveCount(solver1), 0);
    }

    function test_RevertOnSettle_NotFinalized() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        vm.prank(solver1);
        vm.expectRevert(
            IInstantCompletionGuarantee.TransferNotFinalized.selector
        );
        guarantee.settleGuarantee(gId);
    }

    function test_RevertOnSettle_NotGuarantor() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        mockLayer.setFinalized(INTENT_ID_1, true);

        vm.prank(solver2);
        vm.expectRevert(IInstantCompletionGuarantee.NotGuarantor.selector);
        guarantee.settleGuarantee(gId);
    }

    function test_RevertOnSettle_NotActive() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        mockLayer.setFinalized(INTENT_ID_1, true);

        vm.prank(solver1);
        guarantee.settleGuarantee(gId);

        vm.prank(solver1);
        vm.expectRevert(
            IInstantCompletionGuarantee.GuaranteeNotActive.selector
        );
        guarantee.settleGuarantee(gId);
    }

    // ──────────────────────────────────────────────────────────
    //  Claim Guarantee
    // ──────────────────────────────────────────────────────────

    function test_ClaimGuarantee() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        // Advance past expiry
        vm.warp(block.timestamp + 1 hours + 1);

        // Intent NOT finalized (transfer failed)
        uint256 userBal = user1.balance;
        vm.prank(user1);
        guarantee.claimGuarantee(gId);

        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            gId
        );
        assertEq(
            uint(g.status),
            uint(IInstantCompletionGuarantee.GuaranteeStatus.CLAIMED)
        );

        // User gets the guaranteed amount
        assertEq(user1.balance, userBal + 1 ether);

        // Surplus goes to insurance pool: 1.1 - 1.0 = 0.1 ether
        assertEq(guarantee.insurancePoolBalance(), 0.1 ether);
        assertEq(guarantee.totalClaimed(), 1);
    }

    function test_RevertOnClaim_NotExpired() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        vm.prank(user1);
        vm.expectRevert(
            IInstantCompletionGuarantee.GuaranteeNotExpired.selector
        );
        guarantee.claimGuarantee(gId);
    }

    function test_RevertOnClaim_TransferFinalized() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        mockLayer.setFinalized(INTENT_ID_1, true);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(user1);
        vm.expectRevert(
            IInstantCompletionGuarantee.TransferAlreadyFinalized.selector
        );
        guarantee.claimGuarantee(gId);
    }

    function test_RevertOnClaim_NotBeneficiary() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(user2);
        vm.expectRevert(IInstantCompletionGuarantee.NotBeneficiary.selector);
        guarantee.claimGuarantee(gId);
    }

    // ──────────────────────────────────────────────────────────
    //  Expire Guarantee
    // ──────────────────────────────────────────────────────────

    function test_ExpireGuarantee_IntentFinalized() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        mockLayer.setFinalized(INTENT_ID_1, true);

        vm.warp(block.timestamp + 1 hours + 1);

        uint256 solverBal = solver1.balance;
        guarantee.expireGuarantee(gId);

        // Intent was finalized — treated as settled, bond returned
        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            gId
        );
        assertEq(
            uint(g.status),
            uint(IInstantCompletionGuarantee.GuaranteeStatus.SETTLED)
        );
        assertEq(solver1.balance, solverBal + 1.1 ether);
    }

    function test_ExpireGuarantee_IntentNotFinalized() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        vm.warp(block.timestamp + 1 hours + guarantee.CLAIM_GRACE_PERIOD() + 1);

        guarantee.expireGuarantee(gId);

        // Intent not finalized — bond goes to insurance pool
        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            gId
        );
        assertEq(
            uint(g.status),
            uint(IInstantCompletionGuarantee.GuaranteeStatus.EXPIRED)
        );
        assertEq(guarantee.insurancePoolBalance(), 1.1 ether);
    }

    function test_RevertOnExpire_NotExpiredYet() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);

        vm.expectRevert(
            IInstantCompletionGuarantee.GuaranteeNotExpired.selector
        );
        guarantee.expireGuarantee(gId);
    }

    // ──────────────────────────────────────────────────────────
    //  Admin Functions
    // ──────────────────────────────────────────────────────────

    function test_SetCollateralRatio() public {
        vm.prank(admin);
        guarantee.setCollateralRatio(12000); // 120%
        assertEq(guarantee.collateralRatioBps(), 12000);
    }

    function test_RevertOnSetRatio_TooLow() public {
        vm.prank(admin);
        vm.expectRevert(
            IInstantCompletionGuarantee.InvalidCollateralRatio.selector
        );
        guarantee.setCollateralRatio(9000); // Below 100%
    }

    function test_RevertOnSetRatio_TooHigh() public {
        vm.prank(admin);
        vm.expectRevert(
            IInstantCompletionGuarantee.InvalidCollateralRatio.selector
        );
        guarantee.setCollateralRatio(31000); // Above 300%
    }

    function test_MarkIntentFinalized() public {
        vm.prank(admin);
        guarantee.markIntentFinalized(INTENT_ID_1);
        assertTrue(guarantee.intentFinalized(INTENT_ID_1));
    }

    function test_WithdrawInsurance() public {
        // Fund insurance via expired guarantee
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        vm.warp(block.timestamp + 1 hours + guarantee.CLAIM_GRACE_PERIOD() + 1);
        guarantee.expireGuarantee(gId);

        uint256 pool = guarantee.insurancePoolBalance();
        assertGt(pool, 0);

        uint256 adminBal = admin.balance;
        vm.prank(admin);
        guarantee.withdrawInsurance(admin, pool);
        assertEq(admin.balance, adminBal + pool);
        assertEq(guarantee.insurancePoolBalance(), 0);
    }

    function test_RevertOnWithdrawInsurance_ZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IInstantCompletionGuarantee.ZeroAddress.selector);
        guarantee.withdrawInsurance(address(0), 1 ether);
    }

    function test_RevertOnWithdrawInsurance_ZeroAmount() public {
        vm.prank(admin);
        vm.expectRevert(IInstantCompletionGuarantee.InvalidAmount.selector);
        guarantee.withdrawInsurance(admin, 0);
    }

    function test_SetIntentLayer() public {
        MockIntentLayer newLayer = new MockIntentLayer();
        vm.prank(admin);
        guarantee.setIntentLayer(address(newLayer));
    }

    // ──────────────────────────────────────────────────────────
    //  View Functions
    // ──────────────────────────────────────────────────────────

    function test_CanSettle_True() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        mockLayer.setFinalized(INTENT_ID_1, true);
        assertTrue(guarantee.canSettle(gId));
    }

    function test_CanSettle_False() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        assertFalse(guarantee.canSettle(gId));
    }

    function test_CanClaim_True() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        vm.warp(block.timestamp + 1 hours + 1);
        assertTrue(guarantee.canClaim(gId));
    }

    function test_CanClaim_False_NotExpired() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        assertFalse(guarantee.canClaim(gId));
    }

    function test_CanClaim_False_Finalized() public {
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 1 ether);
        mockLayer.setFinalized(INTENT_ID_1, true);
        vm.warp(block.timestamp + 1 hours + 1);
        assertFalse(guarantee.canClaim(gId));
    }

    function test_RequiredBond() public view {
        // 110% of 1 ether = 1.1 ether
        assertEq(guarantee.requiredBond(1 ether), 1.1 ether);
    }

    function test_RequiredBond_CustomRatio() public {
        vm.prank(admin);
        guarantee.setCollateralRatio(15000); // 150%
        assertEq(guarantee.requiredBond(1 ether), 1.5 ether);
    }

    // ──────────────────────────────────────────────────────────
    //  Receive ETH (Insurance Pool)
    // ──────────────────────────────────────────────────────────

    function test_ReceiveETH_InsurancePool() public {
        (bool success, ) = address(guarantee).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(guarantee.insurancePoolBalance(), 1 ether);
    }

    // ──────────────────────────────────────────────────────────
    //  Full Lifecycle
    // ──────────────────────────────────────────────────────────

    function test_FullLifecycle_Settle() public {
        // 1. Solver posts guarantee
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 2 ether);
        assertEq(guarantee.guarantorActiveCount(solver1), 1);

        // 2. Transfer completes (simulated)
        mockLayer.setFinalized(INTENT_ID_1, true);

        // 3. Solver settles
        uint256 solverBal = solver1.balance;
        vm.prank(solver1);
        guarantee.settleGuarantee(gId);

        // Solver gets: 2.2 bond (profit comes from IntentCompletionLayer)
        assertEq(solver1.balance, solverBal + 2.2 ether);
        assertEq(guarantee.guarantorActiveCount(solver1), 0);
    }

    function test_FullLifecycle_Claim() public {
        // 1. Solver posts guarantee
        bytes32 gId = _postGuarantee(solver1, INTENT_ID_1, user1, 2 ether);

        // 2. Transfer fails (deadline passes)
        vm.warp(block.timestamp + 1 hours + 1);

        // 3. User claims
        uint256 userBal = user1.balance;
        vm.prank(user1);
        guarantee.claimGuarantee(gId);

        // User gets 2 ether, insurance gets 0.2 ether surplus
        assertEq(user1.balance, userBal + 2 ether);
        assertEq(guarantee.insurancePoolBalance(), 0.2 ether);
    }

    // ──────────────────────────────────────────────────────────
    //  Fuzz Tests
    // ──────────────────────────────────────────────────────────

    function testFuzz_PostAndSettle(uint96 amount) public {
        amount = uint96(bound(amount, 0.001 ether, 10 ether));
        uint256 bond = (uint256(amount) * 11000) / 10000;
        vm.deal(solver1, bond + 1 ether);

        vm.prank(solver1);
        bytes32 gId = guarantee.postGuarantee{value: bond}(
            INTENT_ID_1,
            user1,
            amount,
            1 hours
        );

        mockLayer.setFinalized(INTENT_ID_1, true);

        uint256 solverBal = solver1.balance;
        vm.prank(solver1);
        guarantee.settleGuarantee(gId);

        // Solver gets full bond back
        assertEq(solver1.balance, solverBal + bond);
    }

    function testFuzz_PostAndClaim(uint96 amount) public {
        amount = uint96(bound(amount, 0.001 ether, 10 ether));
        uint256 bond = (uint256(amount) * 11000) / 10000;
        vm.deal(solver1, bond + 1 ether);

        vm.prank(solver1);
        bytes32 gId = guarantee.postGuarantee{value: bond}(
            INTENT_ID_1,
            user1,
            amount,
            1 hours
        );

        vm.warp(block.timestamp + 1 hours + 1);

        uint256 userBal = user1.balance;
        vm.prank(user1);
        guarantee.claimGuarantee(gId);

        assertEq(user1.balance, userBal + uint256(amount));
        assertEq(guarantee.insurancePoolBalance(), bond - uint256(amount));
    }

    function testFuzz_MultipleGuarantees(uint8 count) public {
        count = uint8(bound(count, 1, 10));
        vm.deal(solver1, uint256(count) * 2 ether);

        for (uint8 i = 0; i < count; i++) {
            bytes32 iId = keccak256(abi.encodePacked("intent", i));
            vm.prank(solver1);
            guarantee.postGuarantee{value: 1.1 ether}(
                iId,
                user1,
                1 ether,
                1 hours
            );
        }

        assertEq(guarantee.guarantorActiveCount(solver1), count);
        assertEq(guarantee.totalGuarantees(), count);
    }

    // ──────────────────────────────────────────────────────────
    //  Helpers
    // ──────────────────────────────────────────────────────────

    function _postGuarantee(
        address solver,
        bytes32 intentId,
        address beneficiary,
        uint256 amount
    ) internal returns (bytes32) {
        uint256 bond = (amount * 11000) / 10000; // 110%
        vm.prank(solver);
        return
            guarantee.postGuarantee{value: bond}(
                intentId,
                beneficiary,
                amount,
                1 hours
            );
    }
}
