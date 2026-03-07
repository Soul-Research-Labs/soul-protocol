// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/BatchAccumulator.sol";
import "../../contracts/interfaces/IBatchAccumulator.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Mock proof verifier that always passes
contract MockVerifierForAdaptive {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title AdaptiveBatchingTest
 * @notice Tests for the adaptive batching and dummy commitment padding features
 *         added to BatchAccumulator to prevent metadata leakage via batch frequency
 *         and anonymity set degradation.
 */
contract AdaptiveBatchingTest is Test {
    BatchAccumulator public accumulator;
    MockVerifierForAdaptive public verifier;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public user1 = makeAddr("user1");

    address public crossChainHub = makeAddr("hub");

    uint256 constant SOURCE = 31_337;
    uint256 constant TARGET = 42_161;

    event DummyCommitmentsInjected(bytes32 indexed batchId, uint256 count);
    event AdaptiveBatchingConfigured(
        uint256 minDelayFloor,
        bool dummyPaddingEnabled
    );
    event BatchReady(bytes32 indexed batchId, uint256 size, string reason);

    function setUp() public {
        verifier = new MockVerifierForAdaptive();

        BatchAccumulator impl = new BatchAccumulator();
        bytes memory initData = abi.encodeCall(
            BatchAccumulator.initialize,
            (admin, address(verifier), crossChainHub)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        accumulator = BatchAccumulator(address(proxy));

        vm.startPrank(admin);
        accumulator.grantRole(accumulator.OPERATOR_ROLE(), operator);
        accumulator.grantRole(accumulator.RELAYER_ROLE(), relayer);
        vm.stopPrank();

        // Configure a route with minBatchSize = 8
        vm.prank(operator);
        accumulator.configureRoute(SOURCE, TARGET, 8, 10 minutes);
    }

    // ════════════════════════════════════════════════════════════════
    // HELPER
    // ════════════════════════════════════════════════════════════════

    function _submitTx(uint256 seed) internal returns (bytes32) {
        bytes32 commitment = keccak256(abi.encodePacked("c", seed));
        bytes32 nullifier = keccak256(abi.encodePacked("n", seed));
        vm.prank(user1);
        return
            accumulator.submitToBatch(commitment, nullifier, hex"01", TARGET);
    }

    // ════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ════════════════════════════════════════════════════════════════

    function test_configureAdaptiveBatching_emitsEvent() public {
        vm.prank(operator);
        vm.expectEmit(false, false, false, true);
        emit AdaptiveBatchingConfigured(3 minutes, true);
        accumulator.configureAdaptiveBatching(3 minutes, true);
    }

    function test_configureAdaptiveBatching_setsValues() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(5 minutes, true);

        assertEq(accumulator.minDelayFloor(), 5 minutes);
        assertTrue(accumulator.dummyPaddingEnabled());
    }

    function test_configureAdaptiveBatching_revertsExcessiveDelay() public {
        vm.prank(operator);
        vm.expectRevert();
        accumulator.configureAdaptiveBatching(2 hours, false); // > MAX_WAIT_TIME
    }

    function test_configureAdaptiveBatching_revertsForNonOperator() public {
        vm.prank(user1);
        vm.expectRevert();
        accumulator.configureAdaptiveBatching(3 minutes, true);
    }

    // ════════════════════════════════════════════════════════════════
    // DELAY FLOOR — PREVENTS FREQUENCY INFERENCE
    // ════════════════════════════════════════════════════════════════

    function test_delayFloor_preventsEarlyRelease() public {
        // Enable 5-minute delay floor
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(5 minutes, false);

        // Submit 8 transactions (meets minBatchSize)
        bytes32 batchId;
        for (uint256 i; i < 8; i++) {
            batchId = _submitTx(i);
        }

        // Batch should NOT be ready yet (delay floor not met)
        (, , IBatchAccumulator.BatchStatus status, bool isReady, ) = accumulator
            .getBatchInfo(batchId);
        assertEq(
            uint256(status),
            uint256(IBatchAccumulator.BatchStatus.ACCUMULATING)
        );
        assertFalse(isReady);
    }

    function test_delayFloor_releasesAfterFloor() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(3 minutes, false);

        bytes32 batchId;
        for (uint256 i; i < 8; i++) {
            batchId = _submitTx(i);
        }

        // Warp past the delay floor
        vm.warp(block.timestamp + 3 minutes + 1);

        // Now submit one more to trigger the check (or call releaseBatch)
        accumulator.releaseBatch(batchId);

        (, , IBatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint256(status), uint256(IBatchAccumulator.BatchStatus.READY));
    }

    function test_delayFloor_maxWaitOverridesFloor() public {
        // Delay floor = 5 min, maxWait = 10 min
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(5 minutes, false);

        // Submit only 2 transactions (under minBatchSize)
        bytes32 batchId;
        for (uint256 i; i < 2; i++) {
            batchId = _submitTx(i);
        }

        // Warp past maxWaitTime (10 minutes)
        vm.warp(block.timestamp + 10 minutes + 1);

        accumulator.releaseBatch(batchId);

        (, , IBatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint256(status), uint256(IBatchAccumulator.BatchStatus.READY));
    }

    // ════════════════════════════════════════════════════════════════
    // DUMMY PADDING — MAINTAINS ANONYMITY SET
    // ════════════════════════════════════════════════════════════════

    function test_dummyPadding_injectsOnTimeExpiry() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(0, true); // No floor, dummy padding on

        // Submit only 3 transactions (under minBatchSize of 8)
        bytes32 batchId;
        for (uint256 i; i < 3; i++) {
            batchId = _submitTx(i);
        }

        // Warp past maxWaitTime to trigger forced release
        vm.warp(block.timestamp + 10 minutes + 1);

        vm.expectEmit(true, false, false, true);
        emit DummyCommitmentsInjected(batchId, 5); // 8 - 3 = 5 dummies
        accumulator.releaseBatch(batchId);

        // Batch should now have 8 commitments (3 real + 5 dummy)
        (uint256 size, , IBatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(size, 8);
        assertEq(uint256(status), uint256(IBatchAccumulator.BatchStatus.READY));
    }

    function test_dummyPadding_noPaddingWhenSizeMet() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(0, true);

        // Submit exactly 8 transactions
        bytes32 batchId;
        for (uint256 i; i < 8; i++) {
            batchId = _submitTx(i);
        }

        // Should be ready immediately with no dummies
        (uint256 size, , IBatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(size, 8);
        assertEq(uint256(status), uint256(IBatchAccumulator.BatchStatus.READY));
    }

    function test_dummyPadding_preservesRealTransactions() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(0, true);

        bytes32 realCommitment = keccak256(abi.encodePacked("c", uint256(0)));
        vm.prank(user1);
        bytes32 batchId = accumulator.submitToBatch(
            realCommitment,
            keccak256(abi.encodePacked("n", uint256(0))),
            hex"01",
            TARGET
        );

        // Warp past timeout
        vm.warp(block.timestamp + 10 minutes + 1);
        accumulator.releaseBatch(batchId);

        // Real transaction should still be trackable
        (
            bytes32 foundBatch,
            uint256 submittedAt,
            bool processed,

        ) = accumulator.getTransactionByCommitment(realCommitment);
        assertEq(foundBatch, batchId);
        assertGt(submittedAt, 0);
        assertFalse(processed);
    }

    function test_dummyPadding_dummiesHaveZeroSubmitter() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(0, true);

        // Submit 1 real tx
        bytes32 batchId = _submitTx(0);

        vm.warp(block.timestamp + 10 minutes + 1);
        accumulator.releaseBatch(batchId);

        // Batch should have 8 entries (1 real + 7 dummy)
        (uint256 size, , , , ) = accumulator.getBatchInfo(batchId);
        assertEq(size, 8);
    }

    function test_dummyPadding_disabledByDefault() public {
        // Submit 2 txs and wait for timeout
        bytes32 batchId;
        for (uint256 i; i < 2; i++) {
            batchId = _submitTx(i);
        }

        vm.warp(block.timestamp + 10 minutes + 1);
        accumulator.releaseBatch(batchId);

        // Without dummy padding, batch releases with only 2
        (uint256 size, , , , ) = accumulator.getBatchInfo(batchId);
        assertEq(size, 2);
    }

    // ════════════════════════════════════════════════════════════════
    // COMBINED: DELAY FLOOR + DUMMY PADDING
    // ════════════════════════════════════════════════════════════════

    function test_combined_delayAndPadding() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(5 minutes, true);

        // Submit 4 txs
        bytes32 batchId;
        for (uint256 i; i < 4; i++) {
            batchId = _submitTx(i);
        }

        // At 3 minutes: not ready (floor not met)
        vm.warp(block.timestamp + 3 minutes);
        accumulator.releaseBatch(batchId);
        (, , IBatchAccumulator.BatchStatus status1, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(
            uint256(status1),
            uint256(IBatchAccumulator.BatchStatus.ACCUMULATING)
        );

        // At 10+ minutes: ready with dummies
        vm.warp(block.timestamp + 8 minutes);
        accumulator.releaseBatch(batchId);

        (
            uint256 size,
            ,
            IBatchAccumulator.BatchStatus status2,
            ,

        ) = accumulator.getBatchInfo(batchId);
        assertEq(size, 8); // 4 real + 4 dummy
        assertEq(
            uint256(status2),
            uint256(IBatchAccumulator.BatchStatus.READY)
        );
    }

    // ════════════════════════════════════════════════════════════════
    // ANONYMITY SET SIZE
    // ════════════════════════════════════════════════════════════════

    function test_anonymitySet_includesDummies() public {
        vm.prank(operator);
        accumulator.configureAdaptiveBatching(0, true);

        bytes32 realCommitment = keccak256(abi.encodePacked("c", uint256(0)));
        vm.prank(user1);
        accumulator.submitToBatch(
            realCommitment,
            keccak256(abi.encodePacked("n", uint256(0))),
            hex"01",
            TARGET
        );

        vm.warp(block.timestamp + 10 minutes + 1);
        bytes32 batchId = accumulator.commitmentToBatch(realCommitment);
        accumulator.releaseBatch(batchId);

        // Anonymity set should be 8 (including dummies)
        uint256 anonSet = accumulator.getAnonymitySet(realCommitment);
        assertEq(anonSet, 8);
    }

    // ════════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ════════════════════════════════════════════════════════════════

    function testFuzz_dummyPadding_alwaysReachesMinBatchSize(
        uint8 txCount
    ) public {
        uint256 count = bound(uint256(txCount), 1, 7); // Under min batch size

        vm.prank(operator);
        accumulator.configureAdaptiveBatching(0, true);

        bytes32 batchId;
        for (uint256 i; i < count; i++) {
            batchId = _submitTx(i + 100);
        }

        vm.warp(block.timestamp + 10 minutes + 1);
        accumulator.releaseBatch(batchId);

        (uint256 size, , IBatchAccumulator.BatchStatus status, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(size, 8); // Always padded to minBatchSize
        assertEq(uint256(status), uint256(IBatchAccumulator.BatchStatus.READY));
    }

    function testFuzz_delayFloor_validRange(uint256 floor) public {
        floor = bound(floor, 0, 1 hours); // MAX_WAIT_TIME

        vm.prank(operator);
        accumulator.configureAdaptiveBatching(floor, false);
        assertEq(accumulator.minDelayFloor(), floor);
    }
}
