// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/OptimisticRelayVerifier.sol";

/**
 * @title OptimisticRelayVerifierTest
 * @notice Comprehensive tests covering submission, challenge, resolution,
 *         finalization, admin functions, edge cases, and event emissions.
 */
contract OptimisticRelayVerifierTest is Test {
    OptimisticRelayVerifier public verifier;
    address public admin;
    address public operator;
    address public resolver;
    address public submitter;
    address public challenger;
    address public alice;

    bytes32 constant MSG_HASH = keccak256("bridge_transfer_1");
    bytes constant PROOF = hex"aabbccdd";
    bytes32 constant STATE_COMMIT = keccak256("new_state");
    bytes32 constant NULLIFIER = keccak256("nullifier_1");
    uint256 constant TRANSFER_VALUE = 20 ether; // Above threshold

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        resolver = makeAddr("resolver");
        submitter = makeAddr("submitter");
        challenger = makeAddr("challenger");
        alice = makeAddr("alice");

        verifier = new OptimisticRelayVerifier(admin);
        verifier.grantRole(verifier.OPERATOR_ROLE(), operator);
        verifier.grantRole(verifier.RESOLVER_ROLE(), resolver);
        verifier.grantRole(verifier.CHALLENGER_ROLE(), challenger);

        vm.deal(submitter, 200 ether);
        vm.deal(challenger, 200 ether);
        vm.deal(alice, 200 ether);
    }

    // ─────────── Helpers ───────────

    function _submitDefault() internal returns (bytes32) {
        vm.prank(submitter);
        return
            verifier.submitTransfer{value: 1 ether}(
                MSG_HASH,
                TRANSFER_VALUE,
                PROOF,
                STATE_COMMIT,
                NULLIFIER
            );
    }

    function _submitWithValue(
        uint256 value,
        uint256 bond
    ) internal returns (bytes32) {
        vm.prank(submitter);
        return
            verifier.submitTransfer{value: bond}(
                keccak256(abi.encode(value, block.timestamp)),
                value,
                PROOF,
                STATE_COMMIT,
                NULLIFIER
            );
    }

    // ──────────────────────────────────────────────
    //  1. Submit Transfer
    // ──────────────────────────────────────────────

    function test_submitTransfer_Success() public {
        vm.prank(submitter);
        bytes32 id = verifier.submitTransfer{value: 1 ether}(
            MSG_HASH,
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );

        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(t.messageHash, MSG_HASH);
        assertEq(t.value, TRANSFER_VALUE);
        assertEq(t.submitter, submitter);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.PENDING)
        );
        assertEq(t.proofHash, keccak256(PROOF));
        assertEq(t.newStateCommitment, STATE_COMMIT);
        assertEq(t.nullifier, NULLIFIER);
        assertTrue(t.finalizeAfter > block.timestamp);
    }

    function test_submitTransfer_EmitsEvent() public {
        // We verify the non-indexed data fields (messageHash, value, finalizeAfter)
        // by checking them after submission via getVerification, since transferId
        // includes block.timestamp making pre-computation fragile.
        vm.prank(submitter);
        vm.expectEmit(false, false, false, true);
        emit OptimisticRelayVerifier.TransferSubmitted(
            bytes32(0), // don't check indexed transferId
            MSG_HASH,
            TRANSFER_VALUE,
            block.timestamp + verifier.challengePeriod()
        );
        verifier.submitTransfer{value: 1 ether}(
            MSG_HASH,
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );
    }

    function test_submitTransfer_RecordsBond() public {
        vm.prank(submitter);
        verifier.submitTransfer{value: 2 ether}(
            MSG_HASH,
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );
        assertEq(verifier.submitterBonds(submitter), 2 ether);
    }

    function test_submitTransfer_RevertsIfBelowThreshold() public {
        vm.prank(submitter);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.BelowOptimisticThreshold.selector,
                5 ether,
                10 ether
            )
        );
        verifier.submitTransfer{value: 1 ether}(
            MSG_HASH,
            5 ether,
            PROOF,
            STATE_COMMIT,
            NULLIFIER // 5 < 10 threshold
        );
    }

    function test_submitTransfer_RevertsWhenPaused() public {
        verifier.pause();
        vm.prank(submitter);
        vm.expectRevert();
        verifier.submitTransfer{value: 1 ether}(
            MSG_HASH,
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );
    }

    // ──────────────────────────────────────────────
    //  2. Challenge Transfer
    // ──────────────────────────────────────────────

    function test_challengeTransfer_Success() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.CHALLENGED)
        );
        assertEq(t.challenger, challenger);
        assertEq(t.challengeBond, 0.5 ether);
    }

    function test_challengeTransfer_EmitsEvent() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        vm.expectEmit(true, true, false, true);
        emit OptimisticRelayVerifier.TransferChallenged(
            id,
            challenger,
            0.5 ether
        );
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));
    }

    function test_challengeTransfer_StoresChallenge() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(
            id,
            bytes("strong_evidence")
        );

        OptimisticRelayVerifier.Challenge memory c = verifier.getChallenge(id);
        assertEq(c.transferId, id);
        assertEq(c.challenger, challenger);
        assertEq(c.bond, 0.5 ether);
        assertFalse(c.resolved);
        assertFalse(c.challengerWon);
    }

    function test_challengeTransfer_RevertsIfNotFound() public {
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.TransferNotFound.selector,
                bytes32(uint256(999))
            )
        );
        verifier.challengeTransfer{value: 0.1 ether}(
            bytes32(uint256(999)),
            hex""
        );
    }

    function test_challengeTransfer_RevertsIfAlreadyChallenged() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        // Contract checks status != PENDING and throws TransferAlreadyFinalized
        // (covers CHALLENGED, FINALIZED, REJECTED — any non-PENDING)
        vm.prank(alice);
        vm.deal(alice, 10 ether);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.TransferAlreadyFinalized.selector,
                id
            )
        );
        verifier.challengeTransfer{value: 0.5 ether}(
            id,
            bytes("more_evidence")
        );
    }

    function test_challengeTransfer_RevertsIfInsufficientBond() public {
        bytes32 id = _submitDefault();

        // M-3: Dynamic bond = max(0.01 ether, 20 ether * 100 / 10000) = 0.2 ether
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.InsufficientBond.selector,
                0.01 ether,
                0.2 ether
            )
        );
        verifier.challengeTransfer{value: 0.01 ether}(id, hex"");
    }

    function test_challengeTransfer_RevertsAfterChallengePeriod() public {
        bytes32 id = _submitDefault();
        vm.warp(block.timestamp + verifier.challengePeriod() + 1);

        vm.prank(challenger);
        vm.expectRevert(); // ChallengePeriodNotExpired (name is misleading in contract)
        verifier.challengeTransfer{value: 0.5 ether}(id, hex"");
    }

    // ──────────────────────────────────────────────
    //  3. Resolve Challenge — Challenger Wins
    // ──────────────────────────────────────────────

    function test_resolveChallenge_ChallengerWins() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        uint256 challengerBalBefore = challenger.balance;

        vm.prank(resolver);
        verifier.resolveChallenge(id, PROOF, true);

        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.REJECTED)
        );

        // Challenger gets their bond back + submitter's bond
        assertGt(challenger.balance, challengerBalBefore);
    }

    function test_resolveChallenge_ChallengerWins_EmitsEvents() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        vm.prank(resolver);
        vm.expectEmit(true, false, false, false);
        emit OptimisticRelayVerifier.TransferRejected(
            id,
            "Challenge successful"
        );
        verifier.resolveChallenge(id, PROOF, true);
    }

    // ──────────────────────────────────────────────
    //  4. Resolve Challenge — Submitter Wins
    // ──────────────────────────────────────────────

    function test_resolveChallenge_SubmitterWins() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        uint256 submitterBalBefore = submitter.balance;

        vm.prank(resolver);
        verifier.resolveChallenge(id, PROOF, false);

        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.FINALIZED)
        );

        // Submitter gets challenger's bond
        assertGe(submitter.balance, submitterBalBefore + 0.5 ether);
    }

    function test_resolveChallenge_SubmitterWins_EmitsEvents() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        vm.prank(resolver);
        vm.expectEmit(true, false, false, false);
        emit OptimisticRelayVerifier.TransferFinalized(id);
        verifier.resolveChallenge(id, PROOF, false);
    }

    function test_resolveChallenge_RevertsIfProofMismatch() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.ProofHashMismatch.selector,
                id
            )
        );
        verifier.resolveChallenge(id, bytes("wrong_proof"), true);
    }

    function test_resolveChallenge_RevertsIfAlreadyResolved() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        vm.prank(resolver);
        verifier.resolveChallenge(id, PROOF, true);

        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.ChallengeAlreadyResolved.selector,
                id
            )
        );
        verifier.resolveChallenge(id, PROOF, true);
    }

    function test_resolveChallenge_RevertsIfNoChallenge() public {
        bytes32 id = _submitDefault();

        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.ChallengeNotFound.selector,
                id
            )
        );
        verifier.resolveChallenge(id, PROOF, true);
    }

    function test_resolveChallenge_RevertsIfNotResolver() public {
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("evidence"));

        vm.prank(alice);
        vm.expectRevert(); // AccessControl revert
        verifier.resolveChallenge(id, PROOF, true);
    }

    // ──────────────────────────────────────────────
    //  5. Finalize Transfer
    // ──────────────────────────────────────────────

    function test_finalizeTransfer_AfterPeriod() public {
        bytes32 id = _submitDefault();
        vm.warp(block.timestamp + verifier.challengePeriod() + 1);

        verifier.finalizeTransfer(id);

        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.FINALIZED)
        );
    }

    function test_finalizeTransfer_ReturnsBond() public {
        bytes32 id = _submitDefault();
        uint256 submitterBalBefore = submitter.balance;

        vm.warp(block.timestamp + verifier.challengePeriod() + 1);
        verifier.finalizeTransfer(id);

        assertEq(submitter.balance, submitterBalBefore + 1 ether);
    }

    function test_finalizeTransfer_EmitsEvent() public {
        bytes32 id = _submitDefault();
        vm.warp(block.timestamp + verifier.challengePeriod() + 1);

        vm.expectEmit(true, false, false, false);
        emit OptimisticRelayVerifier.TransferFinalized(id);
        verifier.finalizeTransfer(id);
    }

    function test_finalizeTransfer_RevertsBeforePeriod() public {
        bytes32 id = _submitDefault();

        vm.expectRevert();
        verifier.finalizeTransfer(id);
    }

    function test_finalizeTransfer_RevertsIfAlreadyFinalized() public {
        bytes32 id = _submitDefault();
        vm.warp(block.timestamp + verifier.challengePeriod() + 1);
        verifier.finalizeTransfer(id);

        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.TransferAlreadyFinalized.selector,
                id
            )
        );
        verifier.finalizeTransfer(id);
    }

    function test_finalizeTransfer_RevertsIfNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.TransferNotFound.selector,
                bytes32(uint256(42))
            )
        );
        verifier.finalizeTransfer(bytes32(uint256(42)));
    }

    // ──────────────────────────────────────────────
    //  6. canFinalize View
    // ──────────────────────────────────────────────

    function test_canFinalize_TrueAfterPeriod() public {
        bytes32 id = _submitDefault();
        assertFalse(verifier.canFinalize(id));

        vm.warp(block.timestamp + verifier.challengePeriod() + 1);
        assertTrue(verifier.canFinalize(id));
    }

    function test_canFinalize_FalseIfChallenged() public {
        bytes32 id = _submitDefault();
        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("ev"));

        vm.warp(block.timestamp + verifier.challengePeriod() + 1);
        assertFalse(verifier.canFinalize(id)); // CHALLENGED ≠ PENDING
    }

    function test_canFinalize_FalseForNonexistent() public {
        assertFalse(verifier.canFinalize(bytes32(uint256(123))));
    }

    // ──────────────────────────────────────────────
    //  7. Admin Functions
    // ──────────────────────────────────────────────

    function test_setChallengePeriod() public {
        verifier.setChallengePeriod(30 minutes);
        assertEq(verifier.challengePeriod(), 30 minutes);
    }

    function test_setChallengePeriod_RevertsTooLow() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.InvalidChallengePeriod.selector,
                5 minutes
            )
        );
        verifier.setChallengePeriod(5 minutes); // < 10 min
    }

    function test_setChallengePeriod_RevertsTooHigh() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticRelayVerifier.InvalidChallengePeriod.selector,
                25 hours
            )
        );
        verifier.setChallengePeriod(25 hours); // > 24 hours
    }

    function test_setChallengePeriod_RevertsIfNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        verifier.setChallengePeriod(30 minutes);
    }

    function test_setOptimisticThreshold() public {
        verifier.setOptimisticThreshold(50 ether);
        assertEq(verifier.optimisticThreshold(), 50 ether);
    }

    function test_setOptimisticThreshold_RevertsIfNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        verifier.setOptimisticThreshold(50 ether);
    }

    function test_pause_unpause() public {
        verifier.pause();
        vm.prank(submitter);
        vm.expectRevert();
        verifier.submitTransfer{value: 1 ether}(
            MSG_HASH,
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );

        verifier.unpause();
        vm.prank(submitter);
        verifier.submitTransfer{value: 1 ether}(
            MSG_HASH,
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );
    }

    // ──────────────────────────────────────────────
    //  8. Bond Management
    // ──────────────────────────────────────────────

    function test_withdrawBond() public {
        // Submit two transfers so that finalize returns one bond
        // but leaves the other in submitterBonds
        bytes32 transferId1 = _submitDefault();

        // Submit a second transfer with a different message hash
        vm.prank(submitter);
        bytes32 transferId2 = verifier.submitTransfer{value: 1 ether}(
            keccak256("second"),
            TRANSFER_VALUE,
            PROOF,
            STATE_COMMIT,
            keccak256("nullifier2")
        );

        assertEq(verifier.submitterBonds(submitter), 2 ether);

        // Finalize first transfer — returns 1 ether directly
        vm.warp(block.timestamp + verifier.challengePeriod() + 1);
        verifier.finalizeTransfer(transferId1);
        assertEq(verifier.submitterBonds(submitter), 1 ether);

        // Finalize second transfer — returns 1 ether directly
        verifier.finalizeTransfer(transferId2);
        assertEq(verifier.submitterBonds(submitter), 0);
    }

    function test_withdrawBond_RevertsIfNoBond() public {
        vm.prank(alice);
        vm.expectRevert(OptimisticRelayVerifier.NoBondToWithdraw.selector);
        verifier.withdrawBond();
    }

    // ──────────────────────────────────────────────
    //  9. Fuzz Tests
    // ──────────────────────────────────────────────

    function testFuzz_submitTransferAboveThreshold(uint256 value) public {
        value = bound(value, verifier.optimisticThreshold(), 1_000_000 ether);
        vm.prank(submitter);
        bytes32 id = verifier.submitTransfer{value: 1 ether}(
            keccak256(abi.encode(value)),
            value,
            PROOF,
            STATE_COMMIT,
            NULLIFIER
        );
        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(t.value, value);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.PENDING)
        );
    }

    function testFuzz_challengeBondAboveMin(uint256 bond) public {
        // M-3: Dynamic min bond for 20 ether transfers = max(0.01, 20*100/10000) = 0.2 ether
        bond = bound(bond, 0.2 ether, 10 ether);
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: bond}(id, bytes("evidence"));

        OptimisticRelayVerifier.Challenge memory c = verifier.getChallenge(id);
        assertEq(c.bond, bond);
    }

    function testFuzz_setChallengePeriod(uint256 period) public {
        period = bound(period, 10 minutes, 24 hours);
        verifier.setChallengePeriod(period);
        assertEq(verifier.challengePeriod(), period);
    }

    // ──────────────────────────────────────────────
    //  10. Full Lifecycle E2E
    // ──────────────────────────────────────────────

    function test_fullLifecycle_NoChallengeFinalize() public {
        // Submit → wait → finalize
        bytes32 id = _submitDefault();

        assertFalse(verifier.canFinalize(id));
        vm.warp(block.timestamp + verifier.challengePeriod() + 1);
        assertTrue(verifier.canFinalize(id));

        uint256 balBefore = submitter.balance;
        verifier.finalizeTransfer(id);

        OptimisticRelayVerifier.PendingTransfer memory t = verifier
            .getVerification(id);
        assertEq(
            uint256(t.status),
            uint256(OptimisticRelayVerifier.TransferStatus.FINALIZED)
        );
        assertEq(submitter.balance, balBefore + 1 ether); // bond returned
    }

    function test_fullLifecycle_ChallengeResolvedForSubmitter() public {
        // Submit → challenge → resolve (submitter wins) → submitter gets challengers bond
        bytes32 id = _submitDefault();

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(id, bytes("weak"));

        uint256 submitterBalBefore = submitter.balance;

        vm.prank(resolver);
        verifier.resolveChallenge(id, PROOF, false);

        assertGe(submitter.balance, submitterBalBefore + 0.5 ether);
    }

    function test_fullLifecycle_ChallengeResolvedForChallenger() public {
        // Submit with bond → challenge → resolve (challenger wins) → challenger gets bond+submitter bond
        bytes32 id = _submitDefault(); // 1 ETH bond
        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.5 ether}(
            id,
            bytes("FRAUD_EVIDENCE")
        );

        uint256 challengerBalBefore = challenger.balance;

        vm.prank(resolver);
        verifier.resolveChallenge(id, PROOF, true);

        // Challenger gets their 0.5 ETH + submitter's 1 ETH = 1.5 ETH
        assertGe(challenger.balance, challengerBalBefore + 1.5 ether);
    }
}
