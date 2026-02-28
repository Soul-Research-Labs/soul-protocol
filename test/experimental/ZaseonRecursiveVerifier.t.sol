// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/experimental/verifiers/ZaseonRecursiveVerifier.sol";
import {ExperimentalFeatureRegistry} from "../../contracts/security/ExperimentalFeatureRegistry.sol";

/// @dev Mock aggregated verifier
contract MockAggVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verify(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

/// @dev Mock single verifier
contract MockSingleVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verify(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

contract ZaseonRecursiveVerifierTest is Test {
    ZaseonRecursiveVerifier public rv;
    MockAggVerifier public aggV;
    MockSingleVerifier public singleV;

    address owner = address(0xAD01);
    address alice = address(0xBEEF);

    function setUp() public {
        vm.warp(10_000);
        aggV = new MockAggVerifier(true);
        singleV = new MockSingleVerifier(true);

        vm.startPrank(owner);
        ExperimentalFeatureRegistry efr = new ExperimentalFeatureRegistry(
            owner
        );
        rv = new ZaseonRecursiveVerifier(
            address(aggV),
            address(singleV),
            address(efr)
        );
        vm.stopPrank();
    }

    // ──────── Deployment ────────

    function test_deploy_ownerSet() public view {
        assertEq(rv.owner(), owner);
    }

    function test_deploy_verifiersSet() public view {
        assertEq(rv.aggregatedVerifier(), address(aggV));
        assertEq(rv.singleVerifier(), address(singleV));
    }

    function test_deploy_defaults() public view {
        assertEq(rv.minBatchSize(), 5);
        assertEq(rv.maxBatchSize(), 100);
        assertEq(rv.totalProofsVerified(), 0);
        assertEq(rv.totalBatchesVerified(), 0);
    }

    // ──────── Aggregated Proof Verification ────────

    function _makeTransferIds(
        uint256 count
    ) internal pure returns (bytes32[] memory) {
        bytes32[] memory ids = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            ids[i] = keccak256(abi.encode("transfer", i));
        }
        return ids;
    }

    function _makeNullifiers(
        uint256 count
    ) internal pure returns (bytes32[] memory) {
        bytes32[] memory ns = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            ns[i] = keccak256(abi.encode("nullifier", i));
        }
        return ns;
    }

    function test_verifyAggregated_success() public {
        uint256 count = 10;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 100
            });

        bytes32 batchId = rv.verifyAggregatedProof(
            bytes("proof"),
            data,
            tids,
            nulls
        );
        assertTrue(batchId != bytes32(0));

        assertEq(rv.totalBatchesVerified(), 1);
        assertEq(rv.totalProofsVerified(), count);

        // Check transfers are verified
        for (uint256 i = 0; i < count; i++) {
            (bool verified, bytes32 bid) = rv.isTransferVerified(tids[i]);
            assertTrue(verified);
            assertEq(bid, batchId);
        }

        // Check nullifiers used
        for (uint256 i = 0; i < count; i++) {
            assertTrue(rv.isNullifierUsed(nulls[i]));
        }
    }

    function test_verifyAggregated_emitsBatchVerified() public {
        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 50
            });

        vm.expectEmit(false, false, false, false);
        emit ZaseonRecursiveVerifier.BatchVerified(
            bytes32(0),
            count,
            keccak256("init"),
            keccak256("final"),
            0
        );
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);
    }

    function test_verifyAggregated_batchTooSmallReverts() public {
        uint256 count = 3; // below minBatchSize(5)
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);
    }

    function test_verifyAggregated_batchTooLargeReverts() public {
        // Set max batch to 5 for easy testing
        vm.prank(owner);
        rv.setBatchLimits(1, 5);

        uint256 count = 6;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);
    }

    function test_verifyAggregated_transferCountMismatch() public {
        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count + 1); // mismatch
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);
    }

    function test_verifyAggregated_nullifierCountMismatch() public {
        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count + 1); // mismatch

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);
    }

    function test_verifyAggregated_duplicateNullifierReverts() public {
        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        // First batch succeeds
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);

        // Second batch with same nullifiers should revert
        bytes32[] memory tids2 = _makeTransferIds(count);
        // Shift by count to generate unique transfer IDs
        for (uint256 i = 0; i < count; i++) {
            tids2[i] = keccak256(abi.encode("transfer2", i));
        }

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data2 = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init2"),
                finalStateHash: keccak256("final2"),
                accumulatedInstanceHash: keccak256("acc2"),
                nullifierBatchRoot: keccak256("nullRoot2"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("proof2"), data2, tids2, nulls);
    }

    function test_verifyAggregated_invalidProofReverts() public {
        aggV.setResult(false);

        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("bad_proof"), data, tids, nulls);
    }

    function test_verifyAggregated_whenPausedReverts() public {
        vm.prank(owner);
        rv.pause();

        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        vm.expectRevert();
        rv.verifyAggregatedProof(bytes("proof"), data, tids, nulls);
    }

    // ──────── Single Proof Verification ────────

    function test_verifySingle_success() public {
        bytes32 nullifier = keccak256("single_null");
        bytes32 commitment = keccak256("commitment");
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("in0");
        inputs[1] = keccak256("in1");

        bytes32 proofId = rv.verifySingleProof(
            bytes("single_proof"),
            nullifier,
            commitment,
            inputs
        );
        assertTrue(proofId != bytes32(0));
        assertTrue(rv.isNullifierUsed(nullifier));
        assertEq(rv.totalProofsVerified(), 1);
    }

    function test_verifySingle_duplicateNullifierReverts() public {
        bytes32 nullifier = keccak256("dup_null");
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("in0");

        rv.verifySingleProof(bytes("p1"), nullifier, keccak256("c1"), inputs);

        vm.expectRevert();
        rv.verifySingleProof(bytes("p2"), nullifier, keccak256("c2"), inputs);
    }

    function test_verifySingle_invalidProofReverts() public {
        singleV.setResult(false);

        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("in0");

        vm.expectRevert();
        rv.verifySingleProof(
            bytes("bad"),
            keccak256("n"),
            keccak256("c"),
            inputs
        );
    }

    // ──────── Admin ────────

    function test_setAggregatedVerifier() public {
        address newV = address(0xFACE01);
        vm.prank(owner);
        rv.setAggregatedVerifier(newV);
        assertEq(rv.aggregatedVerifier(), newV);
    }

    function test_setAggregatedVerifier_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        rv.setAggregatedVerifier(address(0xFACE01));
    }

    function test_setSingleVerifier() public {
        address newV = address(0xFACE02);
        vm.prank(owner);
        rv.setSingleVerifier(newV);
        assertEq(rv.singleVerifier(), newV);
    }

    function test_setBatchLimits() public {
        vm.prank(owner);
        rv.setBatchLimits(2, 50);
        assertEq(rv.minBatchSize(), 2);
        assertEq(rv.maxBatchSize(), 50);
    }

    function test_setBatchLimits_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        rv.setBatchLimits(2, 50);
    }

    function test_pause_unpause() public {
        vm.startPrank(owner);
        rv.pause();
        assertTrue(rv.paused());
        rv.unpause();
        assertFalse(rv.paused());
        vm.stopPrank();
    }

    function test_pause_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        rv.pause();
    }

    // ──────── Gas Savings Calculator ────────

    function test_calculateGasSavings() public view {
        (uint256 savings, uint256 savingsPercent) = rv.calculateGasSavings(
            10,
            500_000
        );
        // Individual would cost 10 * 350_000 = 3_500_000
        // savings = 3_500_000 - 500_000 = 3_000_000
        assertTrue(savings > 0);
        assertTrue(savingsPercent > 0);
    }

    // ──────── Batch Result ────────

    function test_getBatchResult() public {
        uint256 count = 5;
        bytes32[] memory tids = _makeTransferIds(count);
        bytes32[] memory nulls = _makeNullifiers(count);

        ZaseonRecursiveVerifier.AggregatedProofData
            memory data = ZaseonRecursiveVerifier.AggregatedProofData({
                proofCount: count,
                initialStateHash: keccak256("init"),
                finalStateHash: keccak256("final"),
                accumulatedInstanceHash: keccak256("acc"),
                nullifierBatchRoot: keccak256("nullRoot"),
                batchVolume: 10
            });

        bytes32 batchId = rv.verifyAggregatedProof(
            bytes("proof"),
            data,
            tids,
            nulls
        );

        ZaseonRecursiveVerifier.VerificationResult memory res = rv.getBatchResult(
            batchId
        );
        assertTrue(res.valid);
        assertEq(res.batchId, batchId);
        assertEq(res.timestamp, block.timestamp);
        assertTrue(res.gasUsed > 0);
    }

    // ──────── Fuzz ────────

    function testFuzz_setBatchLimits(uint256 min, uint256 max) public {
        min = bound(min, 1, 50);
        max = bound(max, min, 1000);

        vm.prank(owner);
        rv.setBatchLimits(min, max);
        assertEq(rv.minBatchSize(), min);
        assertEq(rv.maxBatchSize(), max);
    }
}
