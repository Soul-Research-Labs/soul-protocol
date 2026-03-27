// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntentCompletionLayer} from "../../contracts/core/IntentCompletionLayer.sol";
import {IIntentCompletionLayer} from "../../contracts/interfaces/IIntentCompletionLayer.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

/// @dev Mock verifier for testing
contract MockIntentVerifier is IProofVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldPass;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 4;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

contract IntentCompletionLayerTest is Test {
    IntentCompletionLayer public layer;
    MockIntentVerifier public verifier;

    address admin = address(0x1A);
    address user1 = address(0x1B);
    address user2 = address(0x1C);
    address solver1 = address(0x1D);
    address solver2 = address(0x1E);
    address challenger = address(0x1F);

    uint256 constant SOURCE_CHAIN = 1;
    uint256 constant DEST_CHAIN = 42161;
    bytes32 constant COMMITMENT = keccak256("commitment");
    bytes32 constant DESIRED_STATE = keccak256("desired");
    bytes32 constant POLICY_HASH = keccak256("policy");

    function setUp() public {
        vm.warp(1740000000);

        verifier = new MockIntentVerifier();
        layer = new IntentCompletionLayer(admin, address(verifier));

        // Setup roles
        vm.startPrank(admin);
        layer.setSupportedChain(SOURCE_CHAIN, true);
        layer.setSupportedChain(DEST_CHAIN, true);
        layer.grantRole(layer.CHALLENGER_ROLE(), challenger);
        vm.stopPrank();

        // Fund accounts
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(solver1, 100 ether);
        vm.deal(solver2, 100 ether);
    }

    // ──────────────────────────────────────────────────────────
    //  Intent Submission
    // ──────────────────────────────────────────────────────────

    function test_SubmitIntent() public {
        vm.prank(user1);
        bytes32 intentId = layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );

        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(intent.user, user1);
        assertEq(intent.sourceChainId, SOURCE_CHAIN);
        assertEq(intent.destChainId, DEST_CHAIN);
        assertEq(intent.maxFee, 1 ether);
        assertEq(
            uint(intent.status),
            uint(IIntentCompletionLayer.IntentStatus.PENDING)
        );
        assertEq(layer.totalIntents(), 1);
    }

    function test_SubmitIntent_RefundsExcess() public {
        uint256 balBefore = user1.balance;
        vm.prank(user1);
        layer.submitIntent{value: 2 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
        assertEq(user1.balance, balBefore - 1 ether);
    }

    function test_RevertOnSubmit_InvalidSourceChain() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InvalidChainId.selector);
        layer.submitIntent{value: 1 ether}(
            0,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
    }

    function test_RevertOnSubmit_SameChain() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InvalidChainId.selector);
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            SOURCE_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
    }

    function test_RevertOnSubmit_UnsupportedChain() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InvalidChainId.selector);
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            999,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
    }

    function test_RevertOnSubmit_InsufficientFee() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InsufficientFee.selector);
        layer.submitIntent{value: 0.5 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
    }

    function test_RevertOnSubmit_DeadlineTooSoon() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InvalidDeadline.selector);
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 minutes,
            POLICY_HASH
        );
    }

    function test_RevertOnSubmit_DeadlineTooFar() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InvalidDeadline.selector);
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 8 days,
            POLICY_HASH
        );
    }

    function test_RevertOnSubmit_ZeroCommitment() public {
        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.InvalidAmount.selector);
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(0),
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
    }

    // ──────────────────────────────────────────────────────────
    //  Intent Cancellation
    // ──────────────────────────────────────────────────────────

    function test_CancelIntent() public {
        vm.prank(user1);
        bytes32 intentId = layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        layer.cancelIntent(intentId);

        assertEq(user1.balance, balBefore + 1 ether);
        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.CANCELLED)
        );
    }

    function test_RevertOnCancel_NotUser() public {
        vm.prank(user1);
        bytes32 intentId = layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );

        vm.prank(user2);
        vm.expectRevert(IIntentCompletionLayer.NotIntentUser.selector);
        layer.cancelIntent(intentId);
    }

    function test_RevertOnCancel_NotPending() public {
        bytes32 intentId = _submitIntent(user1);

        // Register solver and claim
        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();
        vm.prank(solver1);
        layer.claimIntent(intentId);

        vm.prank(user1);
        vm.expectRevert(IIntentCompletionLayer.IntentNotPending.selector);
        layer.cancelIntent(intentId);
    }

    // ──────────────────────────────────────────────────────────
    //  Solver Registration
    // ──────────────────────────────────────────────────────────

    function test_RegisterSolver() public {
        vm.prank(solver1);
        layer.registerSolver{value: 2 ether}();

        IIntentCompletionLayer.Solver memory s = layer.getSolver(solver1);
        assertEq(s.stake, 2 ether);
        assertTrue(s.isActive);
        assertEq(layer.activeSolverCount(), 1);
    }

    function test_RevertOnRegister_InsufficientStake() public {
        vm.prank(solver1);
        vm.expectRevert(IIntentCompletionLayer.InsufficientStake.selector);
        layer.registerSolver{value: 0.5 ether}();
    }

    function test_RevertOnRegister_AlreadyRegistered() public {
        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();

        vm.prank(solver1);
        vm.expectRevert(
            IIntentCompletionLayer.SolverAlreadyRegistered.selector
        );
        layer.registerSolver{value: 1 ether}();
    }

    function test_DeactivateSolver() public {
        vm.prank(solver1);
        layer.registerSolver{value: 2 ether}();

        uint256 balBefore = solver1.balance;
        vm.prank(solver1);
        layer.deactivateSolver();

        IIntentCompletionLayer.Solver memory s = layer.getSolver(solver1);
        assertEq(s.stake, 0);
        assertFalse(s.isActive);
        assertEq(solver1.balance, balBefore + 2 ether);
        assertEq(layer.activeSolverCount(), 0);
    }

    // ──────────────────────────────────────────────────────────
    //  Intent Claiming
    // ──────────────────────────────────────────────────────────

    function test_ClaimIntent() public {
        bytes32 intentId = _submitIntent(user1);

        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();

        vm.prank(solver1);
        layer.claimIntent(intentId);

        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(intent.solver, solver1);
        assertEq(
            uint(intent.status),
            uint(IIntentCompletionLayer.IntentStatus.CLAIMED)
        );
    }

    function test_RevertOnClaim_NotPending() public {
        bytes32 intentId = _submitIntent(user1);

        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();
        vm.prank(solver1);
        layer.claimIntent(intentId);

        vm.prank(solver2);
        layer.registerSolver{value: 1 ether}();
        vm.prank(solver2);
        vm.expectRevert(IIntentCompletionLayer.IntentNotPending.selector);
        layer.claimIntent(intentId);
    }

    function test_RevertOnClaim_SolverNotActive() public {
        bytes32 intentId = _submitIntent(user1);

        vm.prank(solver1);
        vm.expectRevert(IIntentCompletionLayer.SolverNotActive.selector);
        layer.claimIntent(intentId);
    }

    function test_RevertOnClaim_DeadlinePassed() public {
        bytes32 intentId = _submitIntent(user1);

        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();

        vm.warp(block.timestamp + 2 hours);

        vm.prank(solver1);
        vm.expectRevert(IIntentCompletionLayer.DeadlinePassed.selector);
        layer.claimIntent(intentId);
    }

    // ──────────────────────────────────────────────────────────
    //  Intent Fulfillment
    // ──────────────────────────────────────────────────────────

    function test_FulfillIntent() public {
        bytes32 intentId = _claimIntent(user1, solver1);

        vm.prank(solver1);
        layer.fulfillIntent(
            intentId,
            hex"1234",
            hex"5678",
            keccak256("newcommit")
        );

        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(
            uint(intent.status),
            uint(IIntentCompletionLayer.IntentStatus.FULFILLED)
        );
        assertTrue(intent.fulfillmentProofId != bytes32(0));
    }

    function test_RevertOnFulfill_NotAssignedSolver() public {
        bytes32 intentId = _claimIntent(user1, solver1);

        vm.prank(solver2);
        layer.registerSolver{value: 1 ether}();

        vm.prank(solver2);
        vm.expectRevert(IIntentCompletionLayer.NotAssignedSolver.selector);
        layer.fulfillIntent(
            intentId,
            hex"1234",
            hex"5678",
            keccak256("newcommit")
        );
    }

    function test_RevertOnFulfill_InvalidProof() public {
        bytes32 intentId = _claimIntent(user1, solver1);

        verifier.setShouldPass(false);

        vm.prank(solver1);
        vm.expectRevert(IIntentCompletionLayer.InvalidProof.selector);
        layer.fulfillIntent(
            intentId,
            hex"1234",
            hex"5678",
            keccak256("newcommit")
        );
    }

    function test_FulfillIntent_ClaimTimeout_Resets() public {
        bytes32 intentId = _claimIntent(user1, solver1);

        // Advance past claim timeout (30 minutes)
        vm.warp(block.timestamp + 31 minutes);

        // Calling fulfillIntent after claim timeout resets intent to PENDING
        // (no revert — state change persists)
        vm.prank(solver1);
        layer.fulfillIntent(
            intentId,
            hex"1234",
            hex"5678",
            keccak256("newcommit")
        );

        // Intent should be reset to PENDING for another solver
        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(
            uint(intent.status),
            uint(IIntentCompletionLayer.IntentStatus.PENDING)
        );
        assertEq(intent.solver, address(0));
    }

    // ──────────────────────────────────────────────────────────
    //  Intent Finalization
    // ──────────────────────────────────────────────────────────

    function test_FinalizeIntent() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);

        // Advance past challenge period
        vm.warp(block.timestamp + 1 hours + 1);

        uint256 solverBalBefore = solver1.balance;

        layer.finalizeIntent(intentId);

        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(
            uint(intent.status),
            uint(IIntentCompletionLayer.IntentStatus.FINALIZED)
        );

        // Solver gets payout (97% of maxFee after 3% protocol fee)
        uint256 expectedPayout = (1 ether * 9700) / 10000;
        assertEq(solver1.balance, solverBalBefore + expectedPayout);
        assertEq(layer.totalFinalized(), 1);

        // Protocol fees accumulated
        uint256 expectedProtocol = (1 ether * 300) / 10000;
        assertEq(layer.protocolFees(), expectedProtocol);
    }

    function test_RevertOnFinalize_ChallengePeriodActive() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);

        vm.expectRevert(IIntentCompletionLayer.ChallengePeriodActive.selector);
        layer.finalizeIntent(intentId);
    }

    function test_RevertOnFinalize_NotFulfilled() public {
        bytes32 intentId = _submitIntent(user1);

        vm.expectRevert(IIntentCompletionLayer.IntentNotFulfilled.selector);
        layer.finalizeIntent(intentId);
    }

    // ──────────────────────────────────────────────────────────
    //  Dispute
    // ──────────────────────────────────────────────────────────

    function test_DisputeIntent() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);

        uint256 userBalBefore = user1.balance;
        uint256 challengerBalBefore = challenger.balance;

        vm.prank(challenger);
        layer.disputeIntent(
            intentId,
            bytes("disputeproof"),
            bytes("inputdata00")
        );

        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(
            uint(intent.status),
            uint(IIntentCompletionLayer.IntentStatus.DISPUTED)
        );

        // User gets refund
        assertEq(user1.balance, userBalBefore + 1 ether);

        // Challenger gets slash reward (5% of solver stake)
        IIntentCompletionLayer.Solver memory s = layer.getSolver(solver1);
        assertEq(s.failedFills, 1);
        assertGt(challenger.balance, challengerBalBefore);
    }

    function test_RevertOnDispute_NotChallenger() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);

        vm.prank(user2);
        vm.expectRevert(); // AccessControl revert
        layer.disputeIntent(
            intentId,
            bytes("disputeproof"),
            bytes("inputdata00")
        );
    }

    function test_RevertOnDispute_AfterChallengePeriod() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(challenger);
        vm.expectRevert(IIntentCompletionLayer.ChallengePeriodExpired.selector);
        layer.disputeIntent(
            intentId,
            bytes("disputeproof"),
            bytes("inputdata00")
        );
    }

    // ──────────────────────────────────────────────────────────
    //  Expiration
    // ──────────────────────────────────────────────────────────

    function test_ExpireIntent_Pending() public {
        bytes32 intentId = _submitIntent(user1);

        vm.warp(block.timestamp + 2 hours);

        uint256 balBefore = user1.balance;
        layer.expireIntent(intentId);

        assertEq(user1.balance, balBefore + 1 ether);
        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.EXPIRED)
        );
    }

    function test_ExpireIntent_Claimed_SlashesSolver() public {
        bytes32 intentId = _claimIntent(user1, solver1);

        vm.warp(block.timestamp + 2 hours);

        IIntentCompletionLayer.Solver memory sBefore = layer.getSolver(solver1);
        layer.expireIntent(intentId);

        IIntentCompletionLayer.Solver memory sAfter = layer.getSolver(solver1);
        assertLt(sAfter.stake, sBefore.stake);
        assertEq(sAfter.failedFills, 1);
    }

    // ──────────────────────────────────────────────────────────
    //  Admin Functions
    // ──────────────────────────────────────────────────────────

    function test_SetIntentVerifier() public {
        MockIntentVerifier newVerifier = new MockIntentVerifier();
        vm.prank(admin);
        layer.setIntentVerifier(address(newVerifier));
        assertEq(address(layer.intentVerifier()), address(newVerifier));
    }

    function test_RevertOnSetVerifier_ZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IIntentCompletionLayer.ZeroAddress.selector);
        layer.setIntentVerifier(address(0));
    }

    function test_SetSupportedChain() public {
        vm.prank(admin);
        layer.setSupportedChain(8453, true);
        assertTrue(layer.supportedChains(8453));
    }

    function test_WithdrawProtocolFees() public {
        // Generate fees via full lifecycle
        bytes32 intentId = _fulfillIntent(user1, solver1);
        vm.warp(block.timestamp + 1 hours + 1);
        layer.finalizeIntent(intentId);

        uint256 fees = layer.protocolFees();
        assertGt(fees, 0);

        uint256 adminBal = admin.balance;
        vm.prank(admin);
        layer.withdrawProtocolFees(admin);
        assertEq(admin.balance, adminBal + fees);
        assertEq(layer.protocolFees(), 0);
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        layer.pause();

        vm.prank(user1);
        vm.expectRevert(); // EnforcedPause
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );

        vm.prank(admin);
        layer.unpause();

        // Should work now
        vm.prank(user1);
        layer.submitIntent{value: 1 ether}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            1 ether,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
    }

    // ──────────────────────────────────────────────────────────
    //  View Functions
    // ──────────────────────────────────────────────────────────

    function test_CanFinalize_True() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);
        vm.warp(block.timestamp + 1 hours + 1);
        assertTrue(layer.canFinalize(intentId));
    }

    function test_CanFinalize_False_TooEarly() public {
        bytes32 intentId = _fulfillIntent(user1, solver1);
        assertFalse(layer.canFinalize(intentId));
    }

    function test_IntentStatus_NotFound() public {
        assertEq(
            uint(layer.intentStatus(keccak256("nonexistent"))),
            uint(IIntentCompletionLayer.IntentStatus.PENDING)
        );
    }

    function test_ActiveSolverCount() public {
        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();
        vm.prank(solver2);
        layer.registerSolver{value: 1 ether}();

        assertEq(layer.activeSolverCount(), 2);

        vm.prank(solver1);
        layer.deactivateSolver();
        assertEq(layer.activeSolverCount(), 1);
    }

    // ──────────────────────────────────────────────────────────
    //  Full Lifecycle
    // ──────────────────────────────────────────────────────────

    function test_FullLifecycle() public {
        // 1. Submit
        bytes32 intentId = _submitIntent(user1);
        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.PENDING)
        );

        // 2. Register solver
        vm.prank(solver1);
        layer.registerSolver{value: 2 ether}();

        // 3. Claim
        vm.prank(solver1);
        layer.claimIntent(intentId);
        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.CLAIMED)
        );

        // 4. Fulfill
        vm.prank(solver1);
        layer.fulfillIntent(intentId, hex"1234", hex"5678", keccak256("new"));
        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.FULFILLED)
        );

        // 5. Wait challenge period
        vm.warp(block.timestamp + 1 hours + 1);

        // 6. Finalize
        layer.finalizeIntent(intentId);
        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.FINALIZED)
        );
        assertEq(layer.totalFinalized(), 1);

        IIntentCompletionLayer.Solver memory s = layer.getSolver(solver1);
        assertEq(s.successfulFills, 1);
        assertGt(s.totalEarnings, 0);
    }

    // ──────────────────────────────────────────────────────────
    //  Fuzz Tests
    // ──────────────────────────────────────────────────────────

    function testFuzz_SubmitIntent_VaryingFees(uint96 fee) public {
        fee = uint96(bound(fee, 1, 50 ether));
        vm.deal(user1, uint256(fee) + 1 ether);
        vm.prank(user1);
        bytes32 intentId = layer.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            COMMITMENT,
            DESIRED_STATE,
            fee,
            block.timestamp + 1 hours,
            POLICY_HASH
        );
        IIntentCompletionLayer.Intent memory intent = layer.getIntent(intentId);
        assertEq(intent.maxFee, fee);
    }

    function testFuzz_RegisterSolver_VaryingStakes(uint96 stake) public {
        stake = uint96(bound(stake, 1 ether, 100 ether));
        vm.deal(solver1, uint256(stake) + 1 ether);
        vm.prank(solver1);
        layer.registerSolver{value: stake}();
        IIntentCompletionLayer.Solver memory s = layer.getSolver(solver1);
        assertEq(s.stake, stake);
        assertTrue(s.isActive);
    }

    function testFuzz_FullLifecycle_VaryingTimestamps(
        uint32 claimDelay,
        uint32 fulfillDelay
    ) public {
        claimDelay = uint32(bound(claimDelay, 0, 30 minutes - 1));
        fulfillDelay = uint32(bound(fulfillDelay, 0, 30 minutes - 1));

        bytes32 intentId = _submitIntent(user1);

        vm.prank(solver1);
        layer.registerSolver{value: 1 ether}();

        vm.warp(block.timestamp + claimDelay);
        vm.prank(solver1);
        layer.claimIntent(intentId);

        vm.warp(block.timestamp + fulfillDelay);
        vm.prank(solver1);
        layer.fulfillIntent(intentId, hex"1234", hex"5678", keccak256("new"));

        vm.warp(block.timestamp + 1 hours + 1);
        layer.finalizeIntent(intentId);

        assertEq(
            uint(layer.intentStatus(intentId)),
            uint(IIntentCompletionLayer.IntentStatus.FINALIZED)
        );
    }

    function testFuzz_MultipleIntents(uint8 count) public {
        count = uint8(bound(count, 1, 10));
        vm.deal(user1, uint256(count) * 2 ether);

        for (uint8 i = 0; i < count; i++) {
            vm.prank(user1);
            bytes32 intentId = layer.submitIntent{value: 1 ether}(
                SOURCE_CHAIN,
                DEST_CHAIN,
                keccak256(abi.encodePacked("commit", i)),
                keccak256(abi.encodePacked("desired", i)),
                1 ether,
                block.timestamp + 1 hours,
                POLICY_HASH
            );
            assertTrue(intentId != bytes32(0));
        }
        assertEq(layer.totalIntents(), count);
    }

    // ──────────────────────────────────────────────────────────
    //  Helpers
    // ──────────────────────────────────────────────────────────

    function _submitIntent(address user) internal returns (bytes32) {
        vm.prank(user);
        return
            layer.submitIntent{value: 1 ether}(
                SOURCE_CHAIN,
                DEST_CHAIN,
                COMMITMENT,
                DESIRED_STATE,
                1 ether,
                block.timestamp + 1 hours,
                POLICY_HASH
            );
    }

    function _claimIntent(
        address user,
        address solver
    ) internal returns (bytes32) {
        bytes32 intentId = _submitIntent(user);
        vm.prank(solver);
        layer.registerSolver{value: 1 ether}();
        vm.prank(solver);
        layer.claimIntent(intentId);
        return intentId;
    }

    function _fulfillIntent(
        address user,
        address solver
    ) internal returns (bytes32) {
        bytes32 intentId = _claimIntent(user, solver);
        vm.prank(solver);
        layer.fulfillIntent(
            intentId,
            hex"1234",
            hex"5678",
            keccak256("newcommit")
        );
        return intentId;
    }
}
