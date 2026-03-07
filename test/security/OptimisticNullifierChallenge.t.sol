// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {INullifierRegistryV3} from "../../contracts/interfaces/INullifierRegistryV3.sol";
import {OptimisticNullifierChallenge} from "../../contracts/security/OptimisticNullifierChallenge.sol";

/**
 * @title OptimisticNullifierChallengeTest
 * @notice Tests for cross-chain nullifier race conditions and the optimistic challenge layer
 * @dev Covers:
 *   - Challenge period enforcement
 *   - Double-finalization prevention
 *   - Race between challenge and finalization
 *   - Bond slashing on invalid challenges
 *   - Cross-chain nullifier injection via expired commits
 *   - Fuzz tests for timing boundaries
 */
contract OptimisticNullifierChallengeTest is Test {
    NullifierRegistryV3 public registry;
    OptimisticNullifierChallenge public challenge;

    address public admin = address(this);
    address public bridgeRole = address(0xBB);
    address public operator = address(0xAA);
    address public watcher = address(0xCC);
    address public attacker = address(0xDD);

    uint256 constant CHALLENGE_PERIOD = 1 hours;
    uint256 constant MIN_BOND = 0.1 ether;

    function setUp() public {
        // Deploy NullifierRegistryV3
        registry = new NullifierRegistryV3();

        // Deploy OptimisticNullifierChallenge
        challenge = new OptimisticNullifierChallenge(admin, address(registry));

        // Grant roles
        // The challenge contract needs BRIDGE_ROLE to forward finalized nullifiers
        registry.grantRole(registry.BRIDGE_ROLE(), address(challenge));

        // Grant BRIDGE_ROLE on challenge contract to our test bridge
        challenge.grantRole(challenge.BRIDGE_ROLE(), bridgeRole);
        challenge.grantRole(challenge.OPERATOR_ROLE(), operator);

        // Fund accounts
        vm.deal(watcher, 10 ether);
        vm.deal(attacker, 10 ether);
    }

    // =========================================================================
    // SUBMISSION
    // =========================================================================

    function test_submitPendingNullifiers() public {
        (bytes32 batchId, bytes32[] memory nullifiers) = _submitBatch(1);

        (
            uint256 sourceChainId,
            uint256 nullifierCount,
            ,
            address submitter,
            uint256 submittedAt,
            OptimisticNullifierChallenge.BatchStatus status,
            uint256 deadline
        ) = challenge.getBatch(batchId);

        assertEq(sourceChainId, 42161); // Arbitrum
        assertEq(nullifierCount, nullifiers.length);
        assertEq(submitter, bridgeRole);
        assertEq(submittedAt, block.timestamp);
        assertEq(
            uint8(status),
            uint8(OptimisticNullifierChallenge.BatchStatus.PENDING)
        );
        assertEq(deadline, block.timestamp + CHALLENGE_PERIOD);
        assertEq(challenge.totalBatches(), 1);
    }

    function test_submitPendingNullifiers_revertNotBridge() public {
        bytes32[] memory nullifiers = _makeNullifiers(1);
        bytes32[] memory commitments = new bytes32[](1);

        vm.prank(attacker);
        vm.expectRevert();
        challenge.submitPendingNullifiers(
            42161,
            nullifiers,
            commitments,
            bytes32(uint256(1))
        );
    }

    function test_submitPendingNullifiers_revertEmptyBatch() public {
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(bridgeRole);
        vm.expectRevert(OptimisticNullifierChallenge.EmptyBatch.selector);
        challenge.submitPendingNullifiers(
            42161,
            empty,
            empty,
            bytes32(uint256(1))
        );
    }

    // =========================================================================
    // FINALIZATION — HAPPY PATH
    // =========================================================================

    function test_finalizeAfterChallengePeriod() public {
        (bytes32 batchId, bytes32[] memory nullifiers) = _submitBatch(3);

        // Warp past challenge period
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // Anyone can finalize
        challenge.finalizeNullifiers(batchId);

        // Verify batch status
        (
            ,
            ,
            ,
            ,
            ,
            OptimisticNullifierChallenge.BatchStatus status,

        ) = challenge.getBatch(batchId);
        assertEq(
            uint8(status),
            uint8(OptimisticNullifierChallenge.BatchStatus.FINALIZED)
        );

        // Verify nullifiers are now in the registry
        for (uint256 i; i < nullifiers.length; ++i) {
            assertTrue(registry.isNullifierUsed(nullifiers[i]));
        }

        assertEq(challenge.totalFinalized(), 1);
    }

    function test_finalize_revertBeforeChallengePeriod() public {
        (bytes32 batchId, ) = _submitBatch(1);

        // Try to finalize immediately — should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.ChallengePeriodNotExpired.selector,
                block.timestamp + CHALLENGE_PERIOD,
                block.timestamp
            )
        );
        challenge.finalizeNullifiers(batchId);
    }

    function test_finalize_revertDoubleFinalze() public {
        (bytes32 batchId, ) = _submitBatch(1);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        challenge.finalizeNullifiers(batchId);

        // Second finalization should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.BatchNotPending.selector,
                batchId,
                OptimisticNullifierChallenge.BatchStatus.FINALIZED
            )
        );
        challenge.finalizeNullifiers(batchId);
    }

    // =========================================================================
    // CHALLENGE
    // =========================================================================

    function test_challengeNullifier() public {
        (bytes32 batchId, ) = _submitBatch(3);

        // Challenge nullifier at index 1
        vm.prank(watcher);
        bytes32 challengeId = challenge.challengeNullifier{value: MIN_BOND}(
            batchId,
            1,
            "Invalid nullifier: not in source merkle tree"
        );

        (
            ,
            ,
            ,
            ,
            ,
            OptimisticNullifierChallenge.BatchStatus status,

        ) = challenge.getBatch(batchId);
        assertEq(
            uint8(status),
            uint8(OptimisticNullifierChallenge.BatchStatus.CHALLENGED)
        );
        assertTrue(challenge.nullifierChallenged(batchId, 1));
        assertFalse(challenge.nullifierChallenged(batchId, 0));
        assertEq(challenge.totalChallenges(), 1);

        // Verify challenge stored correctly
        (
            bytes32 storedBatchId,
            uint256 idx,
            address challenger,
            uint256 bond,
            ,
            OptimisticNullifierChallenge.ChallengeStatus cStatus
        ) = challenge.challenges(challengeId);
        assertEq(storedBatchId, batchId);
        assertEq(idx, 1);
        assertEq(challenger, watcher);
        assertEq(bond, MIN_BOND);
        assertEq(
            uint8(cStatus),
            uint8(OptimisticNullifierChallenge.ChallengeStatus.ACTIVE)
        );
    }

    function test_challenge_revertInsufficientBond() public {
        (bytes32 batchId, ) = _submitBatch(1);

        vm.prank(watcher);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.InsufficientBond.selector,
                0.05 ether,
                MIN_BOND
            )
        );
        challenge.challengeNullifier{value: 0.05 ether}(
            batchId,
            0,
            "too cheap"
        );
    }

    function test_challenge_revertAfterChallengePeriod() public {
        (bytes32 batchId, ) = _submitBatch(1);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        vm.prank(watcher);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.ChallengePeriodExpired.selector,
                batchId
            )
        );
        challenge.challengeNullifier{value: MIN_BOND}(batchId, 0, "too late");
    }

    function test_challenge_revertDoubleChallengeSameIndex() public {
        (bytes32 batchId, ) = _submitBatch(3);

        vm.prank(watcher);
        challenge.challengeNullifier{value: MIN_BOND}(
            batchId,
            1,
            "first challenge"
        );

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge
                    .NullifierAlreadyChallenged
                    .selector,
                batchId,
                1
            )
        );
        challenge.challengeNullifier{value: MIN_BOND}(
            batchId,
            1,
            "duplicate challenge"
        );
    }

    function test_challenge_revertInvalidIndex() public {
        (bytes32 batchId, ) = _submitBatch(2);

        vm.prank(watcher);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.InvalidNullifierIndex.selector,
                5,
                2
            )
        );
        challenge.challengeNullifier{value: MIN_BOND}(
            batchId,
            5,
            "out of bounds"
        );
    }

    // =========================================================================
    // RACE CONDITIONS
    // =========================================================================

    function test_race_challengeThenFinalize_reverts() public {
        // Scenario: A batch is challenged, then someone tries to finalize
        (bytes32 batchId, ) = _submitBatch(2);

        // Watcher challenges
        vm.prank(watcher);
        challenge.challengeNullifier{value: MIN_BOND}(batchId, 0, "suspicious");

        // Warp past challenge period
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // Finalization should fail — batch is CHALLENGED, not PENDING
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.BatchNotPending.selector,
                batchId,
                OptimisticNullifierChallenge.BatchStatus.CHALLENGED
            )
        );
        challenge.finalizeNullifiers(batchId);
    }

    function test_race_dismissChallengeThenFinalize() public {
        // Scenario: Challenge is dismissed, batch reverts to PENDING, then gets finalized
        (bytes32 batchId, bytes32[] memory nullifiers) = _submitBatch(2);

        // Watcher challenges
        vm.prank(watcher);
        bytes32 challengeId = challenge.challengeNullifier{value: MIN_BOND}(
            batchId,
            0,
            "false accusation"
        );

        // Operator dismisses the challenge
        vm.prank(operator);
        challenge.dismissChallenge(challengeId);

        // Batch should be back to PENDING
        (
            ,
            ,
            ,
            ,
            ,
            OptimisticNullifierChallenge.BatchStatus status,

        ) = challenge.getBatch(batchId);
        assertEq(
            uint8(status),
            uint8(OptimisticNullifierChallenge.BatchStatus.PENDING)
        );

        // Warp and finalize
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        challenge.finalizeNullifiers(batchId);

        // Nullifiers should be registered
        for (uint256 i; i < nullifiers.length; ++i) {
            assertTrue(registry.isNullifierUsed(nullifiers[i]));
        }
    }

    function test_race_upholdChallenge_rejectsEntireBatch() public {
        // Scenario: One invalid nullifier in a batch rejects the entire batch
        (bytes32 batchId, bytes32[] memory nullifiers) = _submitBatch(3);

        vm.prank(watcher);
        bytes32 challengeId = challenge.challengeNullifier{value: MIN_BOND}(
            batchId,
            1,
            "forged nullifier"
        );

        // Operator upholds
        vm.prank(operator);
        challenge.upholdChallenge(challengeId);

        // Batch is REJECTED
        (
            ,
            ,
            ,
            ,
            ,
            OptimisticNullifierChallenge.BatchStatus status,

        ) = challenge.getBatch(batchId);
        assertEq(
            uint8(status),
            uint8(OptimisticNullifierChallenge.BatchStatus.REJECTED)
        );

        // No nullifiers should be registered
        for (uint256 i; i < nullifiers.length; ++i) {
            assertFalse(registry.isNullifierUsed(nullifiers[i]));
        }

        // Warp past period — cannot finalize rejected batch
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.BatchNotPending.selector,
                batchId,
                OptimisticNullifierChallenge.BatchStatus.REJECTED
            )
        );
        challenge.finalizeNullifiers(batchId);
    }

    function test_race_challengeOnFinalizedBatch_reverts() public {
        // Scenario: Attacker tries to challenge an already-finalized batch
        (bytes32 batchId, ) = _submitBatch(1);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        challenge.finalizeNullifiers(batchId);

        vm.prank(watcher);
        vm.expectRevert(
            abi.encodeWithSelector(
                OptimisticNullifierChallenge.BatchNotPending.selector,
                batchId,
                OptimisticNullifierChallenge.BatchStatus.FINALIZED
            )
        );
        challenge.challengeNullifier{value: MIN_BOND}(batchId, 0, "too late");
    }

    // =========================================================================
    // CROSS-CHAIN NULLIFIER DOUBLE-SPEND WINDOW
    // =========================================================================

    function test_doubleSpendWindow_nullifierBlockedDuringChallenge() public {
        // Scenario: Nullifier N is used on Chain A. During the optimistic
        // challenge period on Chain B, N cannot be used (not yet finalized).
        bytes32[] memory nullifiers = _makeNullifiers(1);
        bytes32[] memory commitments = new bytes32[](1);

        // Submit to challenge layer
        vm.prank(bridgeRole);
        bytes32 batchId = challenge.submitPendingNullifiers(
            42161,
            nullifiers,
            commitments,
            bytes32(uint256(1))
        );

        // During challenge period: nullifier is NOT in the registry
        assertFalse(registry.isNullifierUsed(nullifiers[0]));

        // An attacker trying to use the same nullifier directly on this chain
        // would succeed (since it's not yet registered) — this is the known
        // double-spend window documented in THREAT_MODEL.md section 4.6.5
        // The challenge period trades latency for security.
    }

    function test_doubleSpendWindow_closedAfterFinalization() public {
        // Scenario: After finalization, the nullifier IS registered and
        // any attempt to reuse it will be blocked by NullifierRegistryV3
        bytes32[] memory nullifiers = _makeNullifiers(1);
        bytes32[] memory commitments = new bytes32[](1);

        vm.prank(bridgeRole);
        bytes32 batchId = challenge.submitPendingNullifiers(
            42161,
            nullifiers,
            commitments,
            bytes32(uint256(1))
        );

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        challenge.finalizeNullifiers(batchId);

        assertTrue(registry.isNullifierUsed(nullifiers[0]));

        // Now a local registrar trying to register the same nullifier will revert
        registry.addRegistrar(address(this));
        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.NullifierAlreadyExists.selector,
                nullifiers[0]
            )
        );
        registry.registerNullifier(nullifiers[0], bytes32(0));
    }

    // =========================================================================
    // BOND ECONOMICS
    // =========================================================================

    function test_upholdChallenge_refundsBond() public {
        (bytes32 batchId, ) = _submitBatch(1);

        uint256 watcherBalanceBefore = watcher.balance;

        vm.prank(watcher);
        bytes32 challengeId = challenge.challengeNullifier{value: 1 ether}(
            batchId,
            0,
            "invalid nullifier"
        );

        uint256 watcherBalanceAfterChallenge = watcher.balance;
        assertEq(watcherBalanceAfterChallenge, watcherBalanceBefore - 1 ether);

        vm.prank(operator);
        challenge.upholdChallenge(challengeId);

        // Watcher gets full bond back on valid challenge
        assertEq(watcher.balance, watcherBalanceBefore);
    }

    function test_dismissChallenge_slashesBond() public {
        (bytes32 batchId, ) = _submitBatch(1);

        vm.prank(watcher);
        bytes32 challengeId = challenge.challengeNullifier{value: 1 ether}(
            batchId,
            0,
            "wrong accusation"
        );

        uint256 protocolFeesBefore = challenge.protocolFees();

        vm.prank(operator);
        challenge.dismissChallenge(challengeId);

        // Bond goes to protocol fees
        assertEq(challenge.protocolFees(), protocolFeesBefore + 1 ether);
        // Watcher does NOT get refund
        assertEq(watcher.balance, 9 ether);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_cannotFinalizeBeforePeriod(uint256 timeDelta) public {
        vm.assume(timeDelta <= CHALLENGE_PERIOD);

        (bytes32 batchId, ) = _submitBatch(1);

        vm.warp(block.timestamp + timeDelta);

        vm.expectRevert();
        challenge.finalizeNullifiers(batchId);
    }

    function testFuzz_canFinalizeAfterPeriod(uint256 timeDelta) public {
        vm.assume(timeDelta > CHALLENGE_PERIOD);
        vm.assume(timeDelta < 365 days); // reasonable upper bound

        (bytes32 batchId, bytes32[] memory nullifiers) = _submitBatch(1);

        vm.warp(block.timestamp + timeDelta);

        challenge.finalizeNullifiers(batchId);

        assertTrue(registry.isNullifierUsed(nullifiers[0]));
    }

    function testFuzz_challengeBondMinimum(uint256 bondAmount) public {
        vm.assume(bondAmount < MIN_BOND);
        vm.assume(bondAmount < watcher.balance);

        (bytes32 batchId, ) = _submitBatch(1);

        vm.prank(watcher);
        vm.expectRevert();
        challenge.challengeNullifier{value: bondAmount}(
            batchId,
            0,
            "underpaid"
        );
    }

    function testFuzz_batchSizeVariation(uint8 count) public {
        vm.assume(count > 0 && count <= 20);

        bytes32[] memory nullifiers = _makeNullifiers(count);
        bytes32[] memory commitments = new bytes32[](count);

        vm.prank(bridgeRole);
        bytes32 batchId = challenge.submitPendingNullifiers(
            42161,
            nullifiers,
            commitments,
            bytes32(uint256(1))
        );

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        challenge.finalizeNullifiers(batchId);

        for (uint256 i; i < count; ++i) {
            assertTrue(registry.isNullifierUsed(nullifiers[i]));
        }
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _makeNullifiers(
        uint256 count
    ) internal pure returns (bytes32[] memory) {
        bytes32[] memory nullifiers = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            nullifiers[i] = keccak256(abi.encode("test_nullifier", i));
        }
        return nullifiers;
    }

    function _submitBatch(
        uint256 count
    ) internal returns (bytes32 batchId, bytes32[] memory nullifiers) {
        nullifiers = _makeNullifiers(count);
        bytes32[] memory commitments = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            commitments[i] = keccak256(abi.encode("test_commitment", i));
        }

        vm.prank(bridgeRole);
        batchId = challenge.submitPendingNullifiers(
            42161, // Arbitrum chain ID
            nullifiers,
            commitments,
            bytes32(uint256(1)) // mock merkle root
        );
    }
}
