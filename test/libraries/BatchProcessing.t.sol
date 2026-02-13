// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/BatchProcessing.sol";

/// @dev Harness to expose internal BatchProcessing functions
contract BatchHarness {
    using BatchProcessing for *;

    // Storage for nullifier operations
    mapping(bytes32 => bool) public isSpent;
    mapping(bytes32 => bytes32) public nullifierToCommitment;
    bytes32[] public storageDest;

    /* ── Nullifier batch ops ────────────────────────── */

    function batchCheckNullifiers(
        bytes32[] calldata nullifiers
    ) external view returns (BatchProcessing.NullifierBatchResult memory) {
        return BatchProcessing.batchCheckNullifiers(nullifiers, isSpent);
    }

    function batchRegisterNullifiers(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external returns (uint256 registeredCount, uint256 failBitmap) {
        return
            BatchProcessing.batchRegisterNullifiers(
                nullifiers,
                commitments,
                isSpent,
                nullifierToCommitment
            );
    }

    function markSpent(bytes32 n) external {
        isSpent[n] = true;
    }

    /* ── Merkle batch ops ───────────────────────────── */

    function batchVerifyMerkleProofs(
        bytes32[] calldata leaves,
        bytes32[][] calldata proofs,
        bytes32 root
    ) external pure returns (uint256 validBitmap, uint256 validCount) {
        return BatchProcessing.batchVerifyMerkleProofs(leaves, proofs, root);
    }

    /* ── Hash batch ops ─────────────────────────────── */

    function batchHash(
        bytes32[] calldata dataA,
        bytes32[] calldata dataB
    ) external pure returns (bytes32[] memory) {
        return BatchProcessing.batchHash(dataA, dataB);
    }

    function batchCommitmentHash(
        bytes32[] calldata values,
        bytes32[] calldata blindings,
        address[] calldata owners
    ) external pure returns (bytes32[] memory) {
        return BatchProcessing.batchCommitmentHash(values, blindings, owners);
    }

    /* ── Gas-bounded context ────────────────────────── */

    function startBatch()
        external
        view
        returns (BatchProcessing.BatchContext memory)
    {
        return BatchProcessing.startBatch();
    }

    function canContinue_harness(
        BatchProcessing.BatchContext memory ctx,
        uint256 estimatedGas
    ) external view returns (bool) {
        return BatchProcessing.canContinue(ctx, estimatedGas);
    }

    function recordSuccess_harness(
        BatchProcessing.BatchContext memory ctx,
        uint256 index
    ) external pure returns (uint256 bitmap, uint256 processed) {
        BatchProcessing.recordSuccess(ctx, index);
        return (ctx.successBitmap, ctx.processed);
    }

    /* ── Array utilities ────────────────────────────── */

    function copyToStorage(bytes32[] calldata source) external {
        BatchProcessing.copyToStorage(source, storageDest);
    }

    function getStorageDest() external view returns (bytes32[] memory) {
        return storageDest;
    }

    function safeSum(
        uint256[] calldata values
    ) external pure returns (uint256) {
        return BatchProcessing.safeSum(values);
    }

    function allUnique(bytes32[] calldata values) external pure returns (bool) {
        return BatchProcessing.allUnique(values);
    }
}

contract BatchProcessingTest is Test {
    BatchHarness lib;

    function setUp() public {
        lib = new BatchHarness();
    }

    /* ══════════════════════════════════════════════════
                   NULLIFIER BATCH CHECK
       ══════════════════════════════════════════════════ */

    function test_batchCheckNullifiers_allUnspent() public view {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = bytes32(uint256(1));
        nullifiers[1] = bytes32(uint256(2));
        nullifiers[2] = bytes32(uint256(3));

        BatchProcessing.NullifierBatchResult memory r = lib
            .batchCheckNullifiers(nullifiers);
        assertTrue(r.allUnspent);
        assertEq(r.spentBitmap, 0);
        assertEq(r.checkedCount, 3);
    }

    function test_batchCheckNullifiers_someSpent() public {
        bytes32 n1 = bytes32(uint256(10));
        bytes32 n2 = bytes32(uint256(20));
        bytes32 n3 = bytes32(uint256(30));

        lib.markSpent(n2);

        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = n1;
        nullifiers[1] = n2;
        nullifiers[2] = n3;

        BatchProcessing.NullifierBatchResult memory r = lib
            .batchCheckNullifiers(nullifiers);
        assertFalse(r.allUnspent);
        assertEq(r.spentBitmap, 1 << 1); // bit 1 set
        assertEq(r.checkedCount, 3);
    }

    function test_batchCheckNullifiers_revertsEmpty() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(BatchProcessing.BatchEmpty.selector);
        lib.batchCheckNullifiers(empty);
    }

    /* ══════════════════════════════════════════════════
                  NULLIFIER BATCH REGISTER
       ══════════════════════════════════════════════════ */

    function test_batchRegisterNullifiers_basic() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = bytes32(uint256(0xA));
        nullifiers[1] = bytes32(uint256(0xB));
        nullifiers[2] = bytes32(uint256(0xC));

        bytes32[] memory commits = new bytes32[](3);
        commits[0] = bytes32(uint256(0x1A));
        commits[1] = bytes32(uint256(0x1B));
        commits[2] = bytes32(uint256(0x1C));

        (uint256 count, uint256 failBitmap) = lib.batchRegisterNullifiers(
            nullifiers,
            commits
        );
        assertEq(count, 3);
        assertEq(failBitmap, 0);

        // Verify marked as spent
        assertTrue(lib.isSpent(nullifiers[0]));
        assertTrue(lib.isSpent(nullifiers[1]));
        assertTrue(lib.isSpent(nullifiers[2]));

        // Verify commitments mapped
        assertEq(lib.nullifierToCommitment(nullifiers[0]), commits[0]);
    }

    function test_batchRegisterNullifiers_skipsDuplicates() public {
        bytes32 dup = bytes32(uint256(0xDD));
        lib.markSpent(dup);

        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = dup;
        nullifiers[1] = bytes32(uint256(0xEE));

        bytes32[] memory commits = new bytes32[](0); // no commitments

        (uint256 count, uint256 failBitmap) = lib.batchRegisterNullifiers(
            nullifiers,
            commits
        );
        assertEq(count, 1);
        assertEq(failBitmap, 1 << 0); // first one failed
    }

    function test_batchRegisterNullifiers_revertsLengthMismatch() public {
        bytes32[] memory ns = new bytes32[](2);
        ns[0] = bytes32(uint256(1));
        ns[1] = bytes32(uint256(2));
        bytes32[] memory cs = new bytes32[](3);
        cs[0] = bytes32(uint256(1));
        cs[1] = bytes32(uint256(2));
        cs[2] = bytes32(uint256(3));

        vm.expectRevert(BatchProcessing.ArrayLengthMismatch.selector);
        lib.batchRegisterNullifiers(ns, cs);
    }

    /* ══════════════════════════════════════════════════
                     BATCH HASH
       ══════════════════════════════════════════════════ */

    function test_batchHash_deterministic() public view {
        bytes32[] memory a = new bytes32[](2);
        a[0] = bytes32(uint256(1));
        a[1] = bytes32(uint256(2));
        bytes32[] memory b = new bytes32[](2);
        b[0] = bytes32(uint256(3));
        b[1] = bytes32(uint256(4));

        bytes32[] memory result = lib.batchHash(a, b);
        assertEq(result.length, 2);
        assertEq(result[0], keccak256(abi.encodePacked(a[0], b[0])));
        assertEq(result[1], keccak256(abi.encodePacked(a[1], b[1])));
    }

    function test_batchHash_revertsLengthMismatch() public {
        bytes32[] memory a = new bytes32[](1);
        a[0] = bytes32(uint256(1));
        bytes32[] memory b = new bytes32[](2);
        b[0] = bytes32(uint256(2));
        b[1] = bytes32(uint256(3));

        vm.expectRevert(BatchProcessing.ArrayLengthMismatch.selector);
        lib.batchHash(a, b);
    }

    /* ══════════════════════════════════════════════════
                  BATCH COMMITMENT HASH
       ══════════════════════════════════════════════════ */

    function test_batchCommitmentHash_consistentWithKeccak() public view {
        bytes32[] memory values = new bytes32[](1);
        values[0] = bytes32(uint256(100));
        bytes32[] memory blindings = new bytes32[](1);
        blindings[0] = bytes32(uint256(200));
        address[] memory owners = new address[](1);
        owners[0] = address(0xBEEF);

        bytes32[] memory hashes = lib.batchCommitmentHash(
            values,
            blindings,
            owners
        );
        assertEq(hashes.length, 1);

        bytes32 expected = keccak256(
            abi.encode(values[0], blindings[0], owners[0])
        );
        assertEq(hashes[0], expected);
    }

    /* ══════════════════════════════════════════════════
                  GAS-BOUNDED CONTEXT
       ══════════════════════════════════════════════════ */

    function test_startBatch_initialState() public view {
        BatchProcessing.BatchContext memory ctx = lib.startBatch();
        assertGt(ctx.startGas, 0);
        assertEq(ctx.processed, 0);
        assertEq(ctx.successBitmap, 0);
    }

    function test_recordSuccess_tracksBitmap() public view {
        BatchProcessing.BatchContext memory ctx;
        (uint256 bitmap, uint256 processed) = lib.recordSuccess_harness(ctx, 0);
        assertEq(bitmap, 1);
        assertEq(processed, 1);
    }

    function test_recordSuccess_multipleIndices() public view {
        BatchProcessing.BatchContext memory ctx;
        (uint256 bitmap, ) = lib.recordSuccess_harness(ctx, 5);
        assertEq(bitmap, 1 << 5);
    }

    function test_canContinue_enoughGas() public view {
        BatchProcessing.BatchContext memory ctx = lib.startBatch();
        assertTrue(lib.canContinue_harness(ctx, 1000));
    }

    /* ══════════════════════════════════════════════════
                   COPY TO STORAGE
       ══════════════════════════════════════════════════ */

    function test_copyToStorage_basic() public {
        bytes32[] memory source = new bytes32[](3);
        source[0] = bytes32(uint256(0xAA));
        source[1] = bytes32(uint256(0xBB));
        source[2] = bytes32(uint256(0xCC));

        lib.copyToStorage(source);

        bytes32[] memory stored = lib.getStorageDest();
        assertEq(stored.length, 3);
        assertEq(stored[0], source[0]);
        assertEq(stored[1], source[1]);
        assertEq(stored[2], source[2]);
    }

    function test_copyToStorage_overwrite() public {
        bytes32[] memory first = new bytes32[](2);
        first[0] = bytes32(uint256(1));
        first[1] = bytes32(uint256(2));
        lib.copyToStorage(first);

        bytes32[] memory second = new bytes32[](1);
        second[0] = bytes32(uint256(99));
        lib.copyToStorage(second);

        bytes32[] memory stored = lib.getStorageDest();
        assertEq(stored.length, 1);
        assertEq(stored[0], bytes32(uint256(99)));
    }

    /* ══════════════════════════════════════════════════
                      SAFE SUM
       ══════════════════════════════════════════════════ */

    function test_safeSum_normal() public view {
        uint256[] memory values = new uint256[](3);
        values[0] = 100;
        values[1] = 200;
        values[2] = 300;
        assertEq(lib.safeSum(values), 600);
    }

    function test_safeSum_empty() public view {
        uint256[] memory values = new uint256[](0);
        assertEq(lib.safeSum(values), 0);
    }

    function test_safeSum_overflow() public {
        uint256[] memory values = new uint256[](2);
        values[0] = type(uint256).max;
        values[1] = 1;
        vm.expectRevert("Overflow");
        lib.safeSum(values);
    }

    /* ══════════════════════════════════════════════════
                     ALL UNIQUE
       ══════════════════════════════════════════════════ */

    function test_allUnique_true() public view {
        bytes32[] memory vals = new bytes32[](3);
        vals[0] = bytes32(uint256(1));
        vals[1] = bytes32(uint256(2));
        vals[2] = bytes32(uint256(3));
        assertTrue(lib.allUnique(vals));
    }

    function test_allUnique_false() public view {
        bytes32[] memory vals = new bytes32[](3);
        vals[0] = bytes32(uint256(1));
        vals[1] = bytes32(uint256(2));
        vals[2] = bytes32(uint256(1));
        assertFalse(lib.allUnique(vals));
    }

    function test_allUnique_singleElement() public view {
        bytes32[] memory vals = new bytes32[](1);
        vals[0] = bytes32(uint256(42));
        assertTrue(lib.allUnique(vals));
    }

    function test_allUnique_emptyArray() public view {
        bytes32[] memory vals = new bytes32[](0);
        assertTrue(lib.allUnique(vals));
    }

    /* ══════════════════════════════════════════════════
                      CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_maxBatchSize() public pure {
        assertEq(BatchProcessing.MAX_BATCH_SIZE, 100);
    }
}
