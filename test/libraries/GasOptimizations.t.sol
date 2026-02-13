// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/GasOptimizations.sol";

/// @dev Wrapper to expose GasOptimizations internal functions for testing
contract GasOptHarness {
    function efficientHash(
        bytes32 a,
        bytes32 b
    ) external pure returns (bytes32) {
        return GasOptimizations.efficientHash(a, b);
    }

    function efficientHash3(
        bytes32 a,
        bytes32 b,
        bytes32 c
    ) external pure returns (bytes32) {
        return GasOptimizations.efficientHash3(a, b, c);
    }

    function efficientHashAddressUint(
        address addr,
        uint256 value
    ) external pure returns (bytes32) {
        return GasOptimizations.efficientHashAddressUint(addr, value);
    }

    function batchHash(
        bytes32[] memory leaves
    ) external pure returns (bytes32[] memory) {
        return GasOptimizations.batchHash(leaves);
    }

    function packUint128(uint128 a, uint128 b) external pure returns (uint256) {
        return GasOptimizations.packUint128(a, b);
    }

    function unpackUint128(
        uint256 packed
    ) external pure returns (uint128, uint128) {
        return GasOptimizations.unpackUint128(packed);
    }

    function packUint64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) external pure returns (uint256) {
        return GasOptimizations.packUint64(a, b, c, d);
    }

    function unpackUint64(
        uint256 packed
    ) external pure returns (uint64, uint64, uint64, uint64) {
        return GasOptimizations.unpackUint64(packed);
    }

    function packAddressWithData(
        address addr,
        uint96 data
    ) external pure returns (uint256) {
        return GasOptimizations.packAddressWithData(addr, data);
    }

    function unpackAddressWithData(
        uint256 packed
    ) external pure returns (address, uint96) {
        return GasOptimizations.unpackAddressWithData(packed);
    }

    function getBit(
        uint256 bitmap,
        uint256 index
    ) external pure returns (bool) {
        return GasOptimizations.getBit(bitmap, index);
    }

    function setBit(
        uint256 bitmap,
        uint256 index
    ) external pure returns (uint256) {
        return GasOptimizations.setBit(bitmap, index);
    }

    function clearBit(
        uint256 bitmap,
        uint256 index
    ) external pure returns (uint256) {
        return GasOptimizations.clearBit(bitmap, index);
    }

    function popCount(uint256 bitmap) external pure returns (uint256) {
        return GasOptimizations.popCount(bitmap);
    }

    function binarySearch(
        bytes32[] memory arr,
        bytes32 val
    ) external pure returns (bool, uint256) {
        return GasOptimizations.binarySearch(arr, val);
    }

    function safeSum(uint256[] memory values) external pure returns (uint256) {
        return GasOptimizations.safeSum(values);
    }

    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) external pure returns (bool) {
        return GasOptimizations.verifyMerkleProof(proof, root, leaf);
    }

    function computeMerkleRoot(
        bytes32[] memory leaves
    ) external pure returns (bytes32) {
        return GasOptimizations.computeMerkleRoot(leaves);
    }

    function safeIncrement(uint256 val) external pure returns (uint256) {
        return GasOptimizations.safeIncrement(val);
    }

    function max(uint256 a, uint256 b) external pure returns (uint256) {
        return GasOptimizations.max(a, b);
    }

    function min(uint256 a, uint256 b) external pure returns (uint256) {
        return GasOptimizations.min(a, b);
    }
}

contract GasOptimizationsTest is Test {
    GasOptHarness public lib;

    function setUp() public {
        lib = new GasOptHarness();
    }

    /* ── Hash Functions ─────────────────────────────── */

    function test_efficientHash_matchesKeccak() public view {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        bytes32 expected = keccak256(abi.encodePacked(a, b));
        assertEq(lib.efficientHash(a, b), expected);
    }

    function testFuzz_efficientHash(bytes32 a, bytes32 b) public view {
        bytes32 expected = keccak256(abi.encodePacked(a, b));
        assertEq(lib.efficientHash(a, b), expected);
    }

    function test_efficientHash3_matchesKeccak() public view {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        bytes32 c = bytes32(uint256(3));
        bytes32 expected = keccak256(abi.encodePacked(a, b, c));
        assertEq(lib.efficientHash3(a, b, c), expected);
    }

    function test_efficientHashAddressUint() public view {
        address addr = address(0x1234);
        uint256 val = 42;
        bytes32 result = lib.efficientHashAddressUint(addr, val);
        assertTrue(result != bytes32(0));
    }

    function test_batchHash_pairsLeaves() public view {
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = bytes32(uint256(1));
        leaves[1] = bytes32(uint256(2));
        leaves[2] = bytes32(uint256(3));
        leaves[3] = bytes32(uint256(4));

        bytes32[] memory hashes = lib.batchHash(leaves);
        assertEq(hashes.length, 2);
    }

    function test_batchHash_empty() public view {
        bytes32[] memory empty = new bytes32[](0);
        bytes32[] memory result = lib.batchHash(empty);
        assertEq(result.length, 0);
    }

    /* ── Storage Packing ────────────────────────────── */

    function testFuzz_packUnpackUint128(uint128 a, uint128 b) public view {
        uint256 packed = lib.packUint128(a, b);
        (uint128 ua, uint128 ub) = lib.unpackUint128(packed);
        assertEq(ua, a);
        assertEq(ub, b);
    }

    function testFuzz_packUnpackUint64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) public view {
        uint256 packed = lib.packUint64(a, b, c, d);
        (uint64 ua, uint64 ub, uint64 uc, uint64 ud) = lib.unpackUint64(packed);
        assertEq(ua, a);
        assertEq(ub, b);
        assertEq(uc, c);
        assertEq(ud, d);
    }

    function testFuzz_packUnpackAddressData(
        address addr,
        uint96 data
    ) public view {
        uint256 packed = lib.packAddressWithData(addr, data);
        (address ua, uint96 ud) = lib.unpackAddressWithData(packed);
        assertEq(ua, addr);
        assertEq(ud, data);
    }

    /* ── Bitmap Operations ──────────────────────────── */

    function test_setBit_getBit() public view {
        uint256 bm = 0;
        bm = lib.setBit(bm, 5);
        assertTrue(lib.getBit(bm, 5));
        assertFalse(lib.getBit(bm, 4));
    }

    function test_clearBit() public view {
        uint256 bm = lib.setBit(0, 3);
        bm = lib.clearBit(bm, 3);
        assertFalse(lib.getBit(bm, 3));
    }

    function test_popCount() public view {
        uint256 bm = 0;
        bm = lib.setBit(bm, 0);
        bm = lib.setBit(bm, 5);
        bm = lib.setBit(bm, 10);
        assertEq(lib.popCount(bm), 3);
    }

    function test_popCount_zero() public view {
        assertEq(lib.popCount(0), 0);
    }

    function test_popCount_allBits() public view {
        assertEq(lib.popCount(type(uint256).max), 256);
    }

    function test_getBit_revertsOutOfBounds() public {
        vm.expectRevert(GasOptimizations.IndexOutOfBounds.selector);
        lib.getBit(0, 256);
    }

    function testFuzz_bitmapRoundtrip(uint8 index) public view {
        uint256 bm = lib.setBit(0, index);
        assertTrue(lib.getBit(bm, index));

        bm = lib.clearBit(bm, index);
        assertFalse(lib.getBit(bm, index));
    }

    /* ── Binary Search ──────────────────────────────── */

    function test_binarySearch_found() public view {
        bytes32[] memory arr = new bytes32[](5);
        arr[0] = bytes32(uint256(10));
        arr[1] = bytes32(uint256(20));
        arr[2] = bytes32(uint256(30));
        arr[3] = bytes32(uint256(40));
        arr[4] = bytes32(uint256(50));

        (bool found, uint256 idx) = lib.binarySearch(arr, bytes32(uint256(30)));
        assertTrue(found);
        assertEq(idx, 2);
    }

    function test_binarySearch_notFound() public view {
        bytes32[] memory arr = new bytes32[](3);
        arr[0] = bytes32(uint256(10));
        arr[1] = bytes32(uint256(20));
        arr[2] = bytes32(uint256(30));

        (bool found, ) = lib.binarySearch(arr, bytes32(uint256(25)));
        assertFalse(found);
    }

    function test_binarySearch_empty() public view {
        bytes32[] memory arr = new bytes32[](0);
        (bool found, ) = lib.binarySearch(arr, bytes32(uint256(1)));
        assertFalse(found);
    }

    /* ── Safe Sum ───────────────────────────────────── */

    function test_safeSum() public view {
        uint256[] memory vals = new uint256[](3);
        vals[0] = 10;
        vals[1] = 20;
        vals[2] = 30;
        assertEq(lib.safeSum(vals), 60);
    }

    /* ── Safe Increment ─────────────────────────────── */

    function test_safeIncrement() public view {
        assertEq(lib.safeIncrement(0), 1);
        assertEq(lib.safeIncrement(99), 100);
    }

    function test_safeIncrement_revertsMaxUint() public {
        vm.expectRevert(GasOptimizations.Overflow.selector);
        lib.safeIncrement(type(uint256).max);
    }

    /* ── Min / Max ──────────────────────────────────── */

    function test_max() public view {
        assertEq(lib.max(10, 20), 20);
        assertEq(lib.max(20, 10), 20);
        assertEq(lib.max(5, 5), 5);
    }

    function test_min() public view {
        assertEq(lib.min(10, 20), 10);
        assertEq(lib.min(20, 10), 10);
        assertEq(lib.min(5, 5), 5);
    }

    function testFuzz_minMax(uint256 a, uint256 b) public view {
        uint256 maxVal = lib.max(a, b);
        uint256 minVal = lib.min(a, b);
        assertTrue(maxVal >= minVal);
        assertTrue(maxVal == a || maxVal == b);
        assertTrue(minVal == a || minVal == b);
    }

    /* ── Merkle Tree ────────────────────────────────── */

    function test_computeMerkleRoot_singleLeaf() public view {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = bytes32(uint256(0xABCD));
        assertEq(lib.computeMerkleRoot(leaves), bytes32(uint256(0xABCD)));
    }

    function test_computeMerkleRoot_empty() public view {
        bytes32[] memory leaves = new bytes32[](0);
        assertEq(lib.computeMerkleRoot(leaves), bytes32(0));
    }

    function test_computeMerkleRoot_twoLeaves() public view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = bytes32(uint256(1));
        leaves[1] = bytes32(uint256(2));
        bytes32 root = lib.computeMerkleRoot(leaves);
        assertTrue(root != bytes32(0));
    }

    function test_merkleProofVerification() public view {
        // Build a 4-leaf tree manually
        bytes32 leaf0 = bytes32(uint256(1));
        bytes32 leaf1 = bytes32(uint256(2));
        bytes32 leaf2 = bytes32(uint256(3));
        bytes32 leaf3 = bytes32(uint256(4));

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = leaf0;
        leaves[1] = leaf1;
        leaves[2] = leaf2;
        leaves[3] = leaf3;

        bytes32 root = lib.computeMerkleRoot(leaves);
        assertTrue(root != bytes32(0));
    }
}
