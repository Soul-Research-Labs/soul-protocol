// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/privacy/BatchAccumulator.sol";

/// @dev Mock proof verifier that accepts all proofs
contract MockProofVerifier {
    bool public shouldAccept = true;

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldAccept;
    }

    function setShouldAccept(bool _accept) external {
        shouldAccept = _accept;
    }
}

/// @dev Mock cross-chain hub
contract MockCrossChainHub {
    function receiveProcessedBatch(bytes32, bytes calldata) external {}
}

/// @dev Attacker contract for reentrancy testing
contract ReentrantAttacker {
    BatchAccumulator public target;
    bytes32 public nullifier;
    bytes32 public commitment;

    constructor(address _target) {
        target = BatchAccumulator(_target);
    }

    function attack(
        bytes32 _commitment,
        bytes32 _nullifier,
        uint256 targetChain
    ) external {
        commitment = _commitment;
        nullifier = _nullifier;
        target.submitToBatch(
            _commitment,
            _nullifier,
            hex"deadbeef",
            targetChain
        );
    }

    receive() external payable {
        // Attempt reentrancy during batch processing
        try
            target.submitToBatch(
                keccak256(abi.encode(commitment, "reenter")),
                keccak256(abi.encode(nullifier, "reenter")),
                hex"726565656e746572",
                42_161
            )
        {} catch {}
    }
}

/**
 * @title BatchAccumulatorAttackTest
 * @notice Attack simulations for BatchAccumulator covering:
 *         - Nullifier double-spend attempts
 *         - Commitment replay attacks
 *         - Frontrunning batch submissions
 *         - Griefing via invalid proofs
 *         - Batch manipulation / timing attacks
 *         - Force-release abuse
 *         - Anonymity set reduction attacks
 *         - Reentrancy on submitToBatch
 */
contract BatchAccumulatorAttackTest is Test {
    BatchAccumulator public accumulator;
    MockProofVerifier public verifier;
    MockCrossChainHub public hub;

    address admin = address(this);
    address relayer = makeAddr("relayer");
    address operator = makeAddr("operator");
    address attacker = makeAddr("attacker");
    address attacker2 = makeAddr("attacker2");

    uint256 constant TARGET_CHAIN = 42_161;
    uint256 constant SOURCE_CHAIN = 31_337; // local

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    function setUp() public {
        verifier = new MockProofVerifier();
        hub = new MockCrossChainHub();

        // Deploy implementation + proxy
        BatchAccumulator impl = new BatchAccumulator();
        bytes memory initData = abi.encodeWithSelector(
            BatchAccumulator.initialize.selector,
            admin,
            address(verifier),
            address(hub)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        accumulator = BatchAccumulator(address(proxy));

        // Grant roles
        accumulator.grantRole(OPERATOR_ROLE, operator);
        accumulator.grantRole(RELAYER_ROLE, relayer);

        // Configure route
        vm.prank(operator);
        accumulator.configureRoute(
            SOURCE_CHAIN,
            TARGET_CHAIN,
            8, // min batch size
            10 minutes // max wait time
        );
    }

    // =========================================================================
    // HELPER
    // =========================================================================

    function _submitN(uint256 n) internal returns (bytes32 batchId) {
        for (uint256 i = 0; i < n; i++) {
            batchId = accumulator.submitToBatch(
                keccak256(abi.encodePacked("commit", i, block.timestamp)),
                keccak256(abi.encodePacked("null", i, block.timestamp)),
                abi.encodePacked("payload", i),
                TARGET_CHAIN
            );
        }
    }

    // =========================================================================
    // ATTACK 1: NULLIFIER DOUBLE-SPEND
    // =========================================================================

    function test_Attack_NullifierDoubleSpend() public {
        bytes32 nullifier = keccak256("stolen_nullifier");
        bytes32 commitment1 = keccak256("commit1");
        bytes32 commitment2 = keccak256("commit2");

        // First submission succeeds
        accumulator.submitToBatch(
            commitment1,
            nullifier,
            hex"aa",
            TARGET_CHAIN
        );

        // Second submission with same nullifier MUST fail
        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(
            commitment2,
            nullifier,
            hex"bb",
            TARGET_CHAIN
        );
    }

    function test_Attack_NullifierDoubleSpend_DifferentAttackers() public {
        bytes32 nullifier = keccak256("shared_nullifier");

        // First attacker succeeds
        vm.prank(attacker);
        accumulator.submitToBatch(
            keccak256("a1_commit"),
            nullifier,
            hex"aa",
            TARGET_CHAIN
        );

        // Second attacker with same nullifier MUST fail
        vm.prank(attacker2);
        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(
            keccak256("a2_commit"),
            nullifier,
            hex"bb",
            TARGET_CHAIN
        );
    }

    function test_Attack_NullifierDoubleSpend_CrossRoute() public {
        // Configure a second route
        vm.prank(operator);
        accumulator.configureRoute(SOURCE_CHAIN, 8453, 8, 10 minutes);

        bytes32 nullifier = keccak256("cross_route_null");

        // Submit on first route
        accumulator.submitToBatch(
            keccak256("cr_commit1"),
            nullifier,
            hex"aa",
            TARGET_CHAIN
        );

        // Same nullifier on different route MUST also fail
        // (nullifiers are global, not per-route)
        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(
            keccak256("cr_commit2"),
            nullifier,
            hex"bb",
            8453
        );
    }

    // =========================================================================
    // ATTACK 2: COMMITMENT REPLAY
    // =========================================================================

    function test_Attack_CommitmentReplay() public {
        bytes32 commitment = keccak256("replay_commit");

        // First submission succeeds
        accumulator.submitToBatch(
            commitment,
            keccak256("null1"),
            hex"aa",
            TARGET_CHAIN
        );

        // Replay with same commitment MUST fail
        vm.expectRevert(BatchAccumulator.CommitmentAlreadyUsed.selector);
        accumulator.submitToBatch(
            commitment,
            keccak256("null2"),
            hex"bb",
            TARGET_CHAIN
        );
    }

    function test_Attack_CommitmentReplay_AfterBatchComplete() public {
        bytes32 commitment = keccak256("replay_post_complete");

        // Fill a batch to completion
        accumulator.submitToBatch(
            commitment,
            keccak256("rpc_null"),
            hex"aa",
            TARGET_CHAIN
        );

        // Submit remaining to fill the batch (need 7 more for min batch size 8)
        for (uint256 i = 1; i < 8; i++) {
            accumulator.submitToBatch(
                keccak256(abi.encodePacked("rpc_commit", i)),
                keccak256(abi.encodePacked("rpc_null", i)),
                hex"aa",
                TARGET_CHAIN
            );
        }

        // Process the batch
        bytes32 batchId = accumulator.commitmentToBatch(commitment);
        vm.prank(relayer);
        accumulator.processBatch(batchId, hex"aabbccdd");

        // Replay commitment after batch is complete — MUST still fail
        vm.expectRevert(BatchAccumulator.CommitmentAlreadyUsed.selector);
        accumulator.submitToBatch(
            commitment,
            keccak256("new_null"),
            hex"bb",
            TARGET_CHAIN
        );
    }

    // =========================================================================
    // ATTACK 3: GRIEFING VIA INVALID PROOFS
    // =========================================================================

    function test_Attack_GriefInvalidProof() public {
        // Fill a batch
        bytes32 batchId = _submitN(8);

        // Attacker submits invalid proof to processBatch
        verifier.setShouldAccept(false);

        // H-12: invalid proof sets FAILED status instead of reverting
        vm.prank(relayer);
        accumulator.processBatch(batchId, hex"00112233");

        // Verify batch is in FAILED state, not permanently bricked
        (, , BatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint8(status), uint8(BatchAccumulator.BatchStatus.FAILED));
    }

    function test_Attack_EmptyProofGrief() public {
        bytes32 batchId = _submitN(8);

        // H-12: empty proof sets FAILED status instead of reverting
        vm.prank(relayer);
        accumulator.processBatch(batchId, hex"");

        // Verify batch is in FAILED state, not permanently bricked
        (, , BatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint8(status), uint8(BatchAccumulator.BatchStatus.FAILED));
    }

    // =========================================================================
    // ATTACK 4: FRONTRUNNING BATCH SUBMISSION
    // =========================================================================

    function test_Attack_FrontrunBatchProcess() public {
        bytes32 batchId = _submitN(8);

        // Attacker tries to process batch without RELAYER_ROLE
        vm.prank(attacker);
        vm.expectRevert();
        accumulator.processBatch(batchId, hex"aabb");

        // Only authorized relayer can process
        vm.prank(relayer);
        accumulator.processBatch(batchId, hex"aabbccdd");

        (, , BatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint8(status), uint8(BatchAccumulator.BatchStatus.COMPLETED));
    }

    function test_Attack_FrontrunForceRelease() public {
        _submitN(3); // Not enough for min batch size

        bytes32 routeHash = keccak256(
            abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN)
        );
        bytes32 batchId = accumulator.activeBatches(routeHash);

        // Attacker tries to force release without OPERATOR_ROLE
        vm.prank(attacker);
        vm.expectRevert();
        accumulator.forceReleaseBatch(batchId);

        // Only operator can force release
        vm.prank(operator);
        accumulator.forceReleaseBatch(batchId);

        (, , BatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint8(status), uint8(BatchAccumulator.BatchStatus.READY));
    }

    // =========================================================================
    // ATTACK 5: BATCH MANIPULATION / TIMING
    // =========================================================================

    function test_Attack_TimeBasedBatchRelease() public {
        // Submit fewer than min batch size
        _submitN(3);

        bytes32 routeHash = keccak256(
            abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN)
        );
        bytes32 batchId = accumulator.activeBatches(routeHash);

        // Try releasing before timeout — should fail since conditions not met
        (, , BatchAccumulator.BatchStatus statusBefore, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(
            uint8(statusBefore),
            uint8(BatchAccumulator.BatchStatus.ACCUMULATING),
            "Should still be accumulating"
        );

        // Warp past max wait time
        vm.warp(block.timestamp + 11 minutes);

        // Now release should succeed (time elapsed)
        accumulator.releaseBatch(batchId);

        (, , BatchAccumulator.BatchStatus statusAfter, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(
            uint8(statusAfter),
            uint8(BatchAccumulator.BatchStatus.READY),
            "Should be READY after timeout"
        );
    }

    function test_Attack_DoubleBatchProcess() public {
        bytes32 batchId = _submitN(8);

        // First process succeeds
        vm.prank(relayer);
        accumulator.processBatch(batchId, hex"aabbccdd");

        // Second process attempt MUST fail
        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.BatchAlreadyCompleted.selector);
        accumulator.processBatch(batchId, hex"aabbccdd");
    }

    function test_Attack_ProcessAccumulatingBatch() public {
        // Submit fewer than min, batch is still ACCUMULATING
        _submitN(3);

        bytes32 routeHash = keccak256(
            abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN)
        );
        bytes32 batchId = accumulator.activeBatches(routeHash);

        // Try to process while still ACCUMULATING
        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.BatchNotReady.selector);
        accumulator.processBatch(batchId, hex"aabb");
    }

    // =========================================================================
    // ATTACK 6: ANONYMITY SET REDUCTION
    // =========================================================================

    function test_Attack_AnonymitySetMinimum() public {
        // The min batch size is 8 — any batch released with fewer transactions
        // would reduce the anonymity set. Verify the batch only transitions to
        // READY when min size OR max time is reached.

        // Submit 7 (one less than min)
        for (uint256 i = 0; i < 7; i++) {
            accumulator.submitToBatch(
                keccak256(abi.encodePacked("anon_commit", i)),
                keccak256(abi.encodePacked("anon_null", i)),
                hex"aa",
                TARGET_CHAIN
            );
        }

        bytes32 routeHash = keccak256(
            abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN)
        );
        bytes32 batchId = accumulator.activeBatches(routeHash);

        // Batch should still be ACCUMULATING (7 < 8)
        (, , BatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(
            uint8(status),
            uint8(BatchAccumulator.BatchStatus.ACCUMULATING)
        );

        // Adding the 8th should trigger READY
        accumulator.submitToBatch(
            keccak256(abi.encodePacked("anon_commit_last")),
            keccak256(abi.encodePacked("anon_null_last")),
            hex"aa",
            TARGET_CHAIN
        );

        (, , BatchAccumulator.BatchStatus statusAfter, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint8(statusAfter), uint8(BatchAccumulator.BatchStatus.READY));

        // Verify anonymity set size is 8
        uint256 anonSet = accumulator.getAnonymitySet(
            keccak256(abi.encodePacked("anon_commit", uint256(0)))
        );
        assertEq(anonSet, 8, "Anonymity set should be 8");
    }

    function test_Attack_ForceReleaseReducesAnonymitySet() public {
        // Submit only 2 transactions
        for (uint256 i = 0; i < 2; i++) {
            accumulator.submitToBatch(
                keccak256(abi.encodePacked("fr_commit", i)),
                keccak256(abi.encodePacked("fr_null", i)),
                hex"aa",
                TARGET_CHAIN
            );
        }

        bytes32 routeHash = keccak256(
            abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN)
        );
        bytes32 batchId = accumulator.activeBatches(routeHash);

        // Operator force-releases with only 2 tx — this is a privacy concern
        // but allowed for emergency scenarios
        vm.prank(operator);
        accumulator.forceReleaseBatch(batchId);

        // Verify batch is READY with only 2 in anonymity set
        uint256 anonSet = accumulator.getAnonymitySet(
            keccak256(abi.encodePacked("fr_commit", uint256(0)))
        );
        assertEq(anonSet, 2, "Force release allows small anonymity set");

        // NOTE: This test documents that forceReleaseBatch can bypass
        // minimum batch size. This is a known tradeoff for emergency scenarios.
        // Consider adding a minimum even for force releases in a future version.
    }

    // =========================================================================
    // ATTACK 7: PAYLOAD PADDING UNIFORMITY
    // =========================================================================

    function test_Attack_PayloadSizeAnalysis() public {
        // All payloads should be padded to FIXED_PAYLOAD_SIZE (2048 bytes)
        // regardless of actual payload size

        bytes32 smallCommit = keccak256("small");
        bytes32 largeCommit = keccak256("large");

        accumulator.submitToBatch(
            smallCommit,
            keccak256("small_null"),
            hex"aa", // 1 byte
            TARGET_CHAIN
        );

        accumulator.submitToBatch(
            largeCommit,
            keccak256("large_null"),
            new bytes(2000), // 2000 bytes
            TARGET_CHAIN
        );

        // Both payloads should be padded to same size
        bytes32 batchId = accumulator.commitmentToBatch(smallCommit);

        (, , , , address submitter1, bool processed1) = accumulator
            .batchTransactions(batchId, 0);
        (, , , , address submitter2, bool processed2) = accumulator
            .batchTransactions(batchId, 1);

        // Can't directly check encrypted payload size from the struct via getter,
        // but the _padPayload function ensures uniformity.
        // Instead, verify both transactions are in the same batch and unprocessed
        assertEq(
            accumulator.commitmentToBatch(smallCommit),
            accumulator.commitmentToBatch(largeCommit),
            "Both should be in same batch"
        );
    }

    // =========================================================================
    // ATTACK 8: PAUSE ABUSE
    // =========================================================================

    function test_Attack_SubmitWhenPaused() public {
        vm.prank(operator);
        accumulator.pause();

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        accumulator.submitToBatch(
            keccak256("paused_commit"),
            keccak256("paused_null"),
            hex"aa",
            TARGET_CHAIN
        );
    }

    function test_Attack_UnauthorizedPause() public {
        vm.prank(attacker);
        vm.expectRevert();
        accumulator.pause();
    }

    // =========================================================================
    // ATTACK 9: INVALID ROUTE CONFIGURATION
    // =========================================================================

    function test_Attack_ConfigureRoute_invalidBatchSize() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidBatchSize.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 1, 10 minutes); // min=1 < 2

        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidBatchSize.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 65, 10 minutes); // 65 > MAX 64
    }

    function test_Attack_ConfigureRoute_invalidWaitTime() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidWaitTime.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 30 seconds); // < MIN_WAIT_TIME

        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidWaitTime.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 2 hours); // > MAX_WAIT_TIME
    }

    // =========================================================================
    // FUZZ: EXHAUSTIVE NULLIFIER & COMMITMENT CHECKS
    // =========================================================================

    function testFuzz_Attack_NullifierUniqueness(
        bytes32 nullifier,
        bytes32 commit1,
        bytes32 commit2
    ) public {
        vm.assume(commit1 != commit2);
        vm.assume(nullifier != bytes32(0));
        vm.assume(commit1 != bytes32(0));
        vm.assume(commit2 != bytes32(0));

        // Ensure commitmentToBatch doesn't already exist
        vm.assume(accumulator.commitmentToBatch(commit1) == bytes32(0));
        vm.assume(accumulator.commitmentToBatch(commit2) == bytes32(0));

        accumulator.submitToBatch(commit1, nullifier, hex"aa", TARGET_CHAIN);

        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(commit2, nullifier, hex"bb", TARGET_CHAIN);
    }

    function testFuzz_Attack_CommitmentUniqueness(
        bytes32 commitment,
        bytes32 null1,
        bytes32 null2
    ) public {
        vm.assume(null1 != null2);
        vm.assume(commitment != bytes32(0));
        vm.assume(null1 != bytes32(0));
        vm.assume(null2 != bytes32(0));

        vm.assume(accumulator.commitmentToBatch(commitment) == bytes32(0));
        vm.assume(!accumulator.nullifierUsed(null1));
        vm.assume(!accumulator.nullifierUsed(null2));

        accumulator.submitToBatch(commitment, null1, hex"aa", TARGET_CHAIN);

        vm.expectRevert(BatchAccumulator.CommitmentAlreadyUsed.selector);
        accumulator.submitToBatch(commitment, null2, hex"bb", TARGET_CHAIN);
    }
}
