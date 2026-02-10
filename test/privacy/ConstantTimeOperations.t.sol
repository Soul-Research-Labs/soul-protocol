// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/ConstantTimeOperations.sol";

/// @dev Harness to expose internal library functions for testing
contract ConstantTimeOpsHarness {
    using ConstantTimeOperations for *;

    function constantTimeEquals(bytes32 a, bytes32 b) external pure returns (bool) {
        return ConstantTimeOperations.constantTimeEquals(a, b);
    }

    function constantTimeEqualsUint(uint256 a, uint256 b) external pure returns (bool) {
        return ConstantTimeOperations.constantTimeEqualsUint(a, b);
    }

    function constantTimeEqualsBytes(bytes memory a, bytes memory b) external pure returns (bool) {
        return ConstantTimeOperations.constantTimeEqualsBytes(a, b);
    }

    function constantTimeSelect(bool condition, bytes32 a, bytes32 b) external pure returns (bytes32) {
        return ConstantTimeOperations.constantTimeSelect(condition, a, b);
    }

    function constantTimeSelectUint(bool condition, uint256 a, uint256 b) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeSelectUint(condition, a, b);
    }

    function constantTimeSelectAddress(bool condition, address a, address b) external pure returns (address) {
        return ConstantTimeOperations.constantTimeSelectAddress(condition, a, b);
    }

    function constantTimeLessThan(uint256 a, uint256 b) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeLessThan(a, b);
    }

    function constantTimeGreaterThan(uint256 a, uint256 b) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeGreaterThan(a, b);
    }

    function constantTimeMin(uint256 a, uint256 b) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeMin(a, b);
    }

    function constantTimeMax(uint256 a, uint256 b) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeMax(a, b);
    }

    function constantTimeAbsDiff(uint256 a, uint256 b) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeAbsDiff(a, b);
    }

    function constantTimeGetBit(uint256 value, uint8 position) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeGetBit(value, position);
    }

    function constantTimeSetBit(uint256 value, uint8 position, bool bitValue) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimeSetBit(value, position, bitValue);
    }

    function constantTimePopCount(uint256 value) external pure returns (uint256) {
        return ConstantTimeOperations.constantTimePopCount(value);
    }

    function constantTimeInRange(uint256 value, uint256 min, uint256 max) external pure returns (bool) {
        return ConstantTimeOperations.constantTimeInRange(value, min, max);
    }

    function constantTimeIsNonZero(uint256 value) external pure returns (bool) {
        return ConstantTimeOperations.constantTimeIsNonZero(value);
    }

    function constantTimeIsPowerOf2(uint256 value) external pure returns (bool) {
        return ConstantTimeOperations.constantTimeIsPowerOf2(value);
    }

    function constantTimeSwap(bool condition, uint256 a, uint256 b) external pure returns (uint256, uint256) {
        return ConstantTimeOperations.constantTimeSwap(condition, a, b);
    }

    function constantTimeCopy(bytes memory dest, bytes memory src, uint256 length) external pure returns (bytes memory) {
        ConstantTimeOperations.constantTimeCopy(dest, src, length);
        return dest;
    }

    function constantTimeZero(bytes memory data) external pure returns (bytes memory) {
        ConstantTimeOperations.constantTimeZero(data);
        return data;
    }
}

contract ConstantTimePrivacyHarness {
    function constantTimeNullifierLookup(bytes32 target, bytes32[] memory nullifiers)
        external
        pure
        returns (bool found, uint256 index)
    {
        return ConstantTimePrivacy.constantTimeNullifierLookup(target, nullifiers);
    }

    function constantTimeKeyImageLookup(bytes32 keyImage, bytes32[] memory usedKeyImages)
        external
        pure
        returns (bool used)
    {
        return ConstantTimePrivacy.constantTimeKeyImageLookup(keyImage, usedKeyImages);
    }

    function constantTimeDecoySelect(uint256 realIndex, uint256 ringSize, uint256 randomSeed)
        external
        pure
        returns (uint256[] memory)
    {
        return ConstantTimePrivacy.constantTimeDecoySelect(realIndex, ringSize, randomSeed);
    }

    function constantTimeCommitmentVerify(
        bytes32 commitment,
        uint256 value,
        bytes32 blinding,
        bytes32 expectedCommitment
    ) external pure returns (bool) {
        return ConstantTimePrivacy.constantTimeCommitmentVerify(commitment, value, blinding, expectedCommitment);
    }
}

contract ConstantTimeOperationsTest is Test {
    ConstantTimeOpsHarness public ops;
    ConstantTimePrivacyHarness public privacy;

    function setUp() public {
        ops = new ConstantTimeOpsHarness();
        privacy = new ConstantTimePrivacyHarness();
    }

    // ======== constantTimeEquals ========

    function test_equals_sameValue() public view {
        bytes32 a = keccak256("hello");
        assertTrue(ops.constantTimeEquals(a, a));
    }

    function test_equals_differentValue() public view {
        assertFalse(ops.constantTimeEquals(keccak256("a"), keccak256("b")));
    }

    function test_equals_zeroValues() public view {
        assertTrue(ops.constantTimeEquals(bytes32(0), bytes32(0)));
    }

    function testFuzz_equals(bytes32 a, bytes32 b) public view {
        bool result = ops.constantTimeEquals(a, b);
        assertEq(result, a == b);
    }

    // ======== constantTimeEqualsUint ========

    function test_equalsUint_same() public view {
        assertTrue(ops.constantTimeEqualsUint(42, 42));
    }

    function test_equalsUint_different() public view {
        assertFalse(ops.constantTimeEqualsUint(42, 43));
    }

    function testFuzz_equalsUint(uint256 a, uint256 b) public view {
        assertEq(ops.constantTimeEqualsUint(a, b), a == b);
    }

    // ======== constantTimeEqualsBytes ========

    function test_equalsBytes_same() public view {
        bytes memory a = hex"deadbeef";
        assertTrue(ops.constantTimeEqualsBytes(a, a));
    }

    function test_equalsBytes_different() public view {
        assertFalse(ops.constantTimeEqualsBytes(hex"dead", hex"beef"));
    }

    function test_equalsBytes_differentLength() public view {
        assertFalse(ops.constantTimeEqualsBytes(hex"dead", hex"deadbe"));
    }

    // ======== constantTimeSelect ========

    function test_select_true() public view {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        assertEq(ops.constantTimeSelect(true, a, b), a);
    }

    function test_select_false() public view {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        assertEq(ops.constantTimeSelect(false, a, b), b);
    }

    function testFuzz_select(bool cond, bytes32 a, bytes32 b) public view {
        bytes32 result = ops.constantTimeSelect(cond, a, b);
        assertEq(result, cond ? a : b);
    }

    // ======== constantTimeSelectUint ========

    function testFuzz_selectUint(bool cond, uint256 a, uint256 b) public view {
        assertEq(ops.constantTimeSelectUint(cond, a, b), cond ? a : b);
    }

    // ======== constantTimeSelectAddress ========

    function test_selectAddress() public view {
        address a = address(1);
        address b = address(2);
        assertEq(ops.constantTimeSelectAddress(true, a, b), a);
        assertEq(ops.constantTimeSelectAddress(false, a, b), b);
    }

    // ======== Comparison operations ========

    function test_lessThan() public view {
        assertEq(ops.constantTimeLessThan(5, 10), 1);
        assertEq(ops.constantTimeLessThan(10, 5), 0);
        assertEq(ops.constantTimeLessThan(5, 5), 0);
    }

    function test_greaterThan() public view {
        assertEq(ops.constantTimeGreaterThan(10, 5), 1);
        assertEq(ops.constantTimeGreaterThan(5, 10), 0);
        assertEq(ops.constantTimeGreaterThan(5, 5), 0);
    }

    function testFuzz_min(uint256 a, uint256 b) public view {
        assertEq(ops.constantTimeMin(a, b), a < b ? a : b);
    }

    function testFuzz_max(uint256 a, uint256 b) public view {
        assertEq(ops.constantTimeMax(a, b), a > b ? a : b);
    }

    function testFuzz_absDiff(uint256 a, uint256 b) public view {
        uint256 expected = a > b ? a - b : b - a;
        assertEq(ops.constantTimeAbsDiff(a, b), expected);
    }

    // ======== Bit operations ========

    function test_getBit() public view {
        // 0b1010 = 10
        assertEq(ops.constantTimeGetBit(10, 0), 0);
        assertEq(ops.constantTimeGetBit(10, 1), 1);
        assertEq(ops.constantTimeGetBit(10, 3), 1);
    }

    function test_setBit() public view {
        uint256 result = ops.constantTimeSetBit(0, 3, true);
        assertEq(result, 8); // 2^3
        result = ops.constantTimeSetBit(8, 3, false);
        assertEq(result, 0);
    }

    function test_popCount() public view {
        assertEq(ops.constantTimePopCount(0), 0);
        assertEq(ops.constantTimePopCount(1), 1);
        assertEq(ops.constantTimePopCount(7), 3); // 0b111
    }

    // ======== Range and predicates ========

    function test_inRange() public view {
        assertTrue(ops.constantTimeInRange(5, 1, 10));
        assertTrue(ops.constantTimeInRange(1, 1, 10));
        assertTrue(ops.constantTimeInRange(10, 1, 10));
        assertFalse(ops.constantTimeInRange(0, 1, 10));
        assertFalse(ops.constantTimeInRange(11, 1, 10));
    }

    function test_isNonZero() public view {
        assertTrue(ops.constantTimeIsNonZero(1));
        assertTrue(ops.constantTimeIsNonZero(type(uint256).max));
        assertFalse(ops.constantTimeIsNonZero(0));
    }

    function test_isPowerOf2() public view {
        assertTrue(ops.constantTimeIsPowerOf2(1));
        assertTrue(ops.constantTimeIsPowerOf2(2));
        assertTrue(ops.constantTimeIsPowerOf2(256));
        assertFalse(ops.constantTimeIsPowerOf2(0));
        assertFalse(ops.constantTimeIsPowerOf2(3));
        assertFalse(ops.constantTimeIsPowerOf2(6));
    }

    // ======== Swap ========

    function test_swap_true() public view {
        (uint256 x, uint256 y) = ops.constantTimeSwap(true, 10, 20);
        assertEq(x, 20);
        assertEq(y, 10);
    }

    function test_swap_false() public view {
        (uint256 x, uint256 y) = ops.constantTimeSwap(false, 10, 20);
        assertEq(x, 10);
        assertEq(y, 20);
    }

    // ======== Memory operations ========

    function test_constantTimeZero() public view {
        bytes memory data = hex"deadbeef";
        bytes memory zeroed = ops.constantTimeZero(data);
        for (uint256 i = 0; i < zeroed.length; i++) {
            assertEq(uint8(zeroed[i]), 0);
        }
    }

    // ======== ConstantTimePrivacy ========

    function test_nullifierLookup_found() public view {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = keccak256("a");
        nullifiers[1] = keccak256("b");
        nullifiers[2] = keccak256("c");

        (bool found, uint256 index) = privacy.constantTimeNullifierLookup(keccak256("b"), nullifiers);
        assertTrue(found);
        assertEq(index, 1);
    }

    function test_nullifierLookup_notFound() public view {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256("a");
        nullifiers[1] = keccak256("b");

        (bool found,) = privacy.constantTimeNullifierLookup(keccak256("c"), nullifiers);
        assertFalse(found);
    }

    function test_keyImageLookup() public view {
        bytes32[] memory usedImages = new bytes32[](2);
        usedImages[0] = keccak256("img1");
        usedImages[1] = keccak256("img2");

        assertTrue(privacy.constantTimeKeyImageLookup(keccak256("img1"), usedImages));
        assertFalse(privacy.constantTimeKeyImageLookup(keccak256("img3"), usedImages));
    }

    function test_decoySelect() public view {
        uint256[] memory indices = privacy.constantTimeDecoySelect(2, 8, 12345);
        assertEq(indices.length, 8);
        // Real index should be in the array
        bool foundReal;
        for (uint256 i = 0; i < indices.length; i++) {
            if (indices[i] == 2) foundReal = true;
        }
        assertTrue(foundReal);
    }

    function test_commitmentVerify() public view {
        bytes32 commitment = keccak256(abi.encodePacked(uint256(100), keccak256("blinding")));
        bool valid =
            privacy.constantTimeCommitmentVerify(commitment, 100, keccak256("blinding"), commitment);
        assertTrue(valid);
    }

    function test_commitmentVerify_invalid() public view {
        bytes32 commitment = keccak256(abi.encodePacked(uint256(100), keccak256("blinding")));
        bool valid =
            privacy.constantTimeCommitmentVerify(commitment, 200, keccak256("blinding"), commitment);
        assertFalse(valid);
    }
}
