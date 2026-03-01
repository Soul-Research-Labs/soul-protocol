// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ConstantTimeOperations, ConstantTimePrivacy} from "../../contracts/experimental/privacy/ConstantTimeOperations.sol";

/**
 * @title ConstantTimeOperationsTest
 * @notice Tests for privacy-critical constant-time operations library
 */
contract ConstantTimeOperationsTest is Test {
    using ConstantTimeOperations for *;
    using ConstantTimePrivacy for *;

    // =========================================================================
    // constantTimeEquals
    // =========================================================================

    function test_constantTimeEquals_sameValues() public pure {
        bytes32 a = keccak256("hello");
        assertTrue(ConstantTimeOperations.constantTimeEquals(a, a));
    }

    function test_constantTimeEquals_differentValues() public pure {
        bytes32 a = keccak256("hello");
        bytes32 b = keccak256("world");
        assertFalse(ConstantTimeOperations.constantTimeEquals(a, b));
    }

    function testFuzz_constantTimeEquals(bytes32 a, bytes32 b) public pure {
        bool result = ConstantTimeOperations.constantTimeEquals(a, b);
        assertEq(result, a == b);
    }

    // =========================================================================
    // constantTimeEqualsUint
    // =========================================================================

    function test_constantTimeEqualsUint_same() public pure {
        assertTrue(ConstantTimeOperations.constantTimeEqualsUint(42, 42));
    }

    function test_constantTimeEqualsUint_different() public pure {
        assertFalse(ConstantTimeOperations.constantTimeEqualsUint(42, 43));
    }

    function testFuzz_constantTimeEqualsUint(uint256 a, uint256 b) public pure {
        assertEq(ConstantTimeOperations.constantTimeEqualsUint(a, b), a == b);
    }

    // =========================================================================
    // constantTimeSelect
    // =========================================================================

    function test_constantTimeSelect_trueCondition() public pure {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        assertEq(ConstantTimeOperations.constantTimeSelect(true, a, b), a);
    }

    function test_constantTimeSelect_falseCondition() public pure {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        assertEq(ConstantTimeOperations.constantTimeSelect(false, a, b), b);
    }

    function testFuzz_constantTimeSelect(bool cond, bytes32 a, bytes32 b) public pure {
        bytes32 result = ConstantTimeOperations.constantTimeSelect(cond, a, b);
        assertEq(result, cond ? a : b);
    }

    // =========================================================================
    // constantTimeSelectUint
    // =========================================================================

    function testFuzz_constantTimeSelectUint(bool cond, uint256 a, uint256 b) public pure {
        assertEq(ConstantTimeOperations.constantTimeSelectUint(cond, a, b), cond ? a : b);
    }

    // =========================================================================
    // constantTimeSelectAddress
    // =========================================================================

    function testFuzz_constantTimeSelectAddress(bool cond, address a, address b) public pure {
        assertEq(ConstantTimeOperations.constantTimeSelectAddress(cond, a, b), cond ? a : b);
    }

    // =========================================================================
    // constantTimeLessThan / GreaterThan
    // =========================================================================

    function test_constantTimeLessThan() public pure {
        assertEq(ConstantTimeOperations.constantTimeLessThan(1, 2), 1);
        assertEq(ConstantTimeOperations.constantTimeLessThan(2, 1), 0);
        assertEq(ConstantTimeOperations.constantTimeLessThan(1, 1), 0);
    }

    function test_constantTimeGreaterThan() public pure {
        assertEq(ConstantTimeOperations.constantTimeGreaterThan(2, 1), 1);
        assertEq(ConstantTimeOperations.constantTimeGreaterThan(1, 2), 0);
        assertEq(ConstantTimeOperations.constantTimeGreaterThan(1, 1), 0);
    }

    // =========================================================================
    // constantTimeMin / Max
    // =========================================================================

    function testFuzz_constantTimeMin(uint256 a, uint256 b) public pure {
        uint256 result = ConstantTimeOperations.constantTimeMin(a, b);
        assertEq(result, a < b ? a : b);
    }

    function testFuzz_constantTimeMax(uint256 a, uint256 b) public pure {
        uint256 result = ConstantTimeOperations.constantTimeMax(a, b);
        assertEq(result, a > b ? a : b);
    }

    // =========================================================================
    // constantTimeAbsDiff
    // =========================================================================

    function testFuzz_constantTimeAbsDiff(uint256 a, uint256 b) public pure {
        uint256 result = ConstantTimeOperations.constantTimeAbsDiff(a, b);
        uint256 expected = a > b ? a - b : b - a;
        assertEq(result, expected);
    }

    // =========================================================================
    // Bit operations
    // =========================================================================

    function test_constantTimeGetBit() public pure {
        uint256 value = 0x5; // binary: 101
        assertEq(ConstantTimeOperations.constantTimeGetBit(value, 0), 1);
        assertEq(ConstantTimeOperations.constantTimeGetBit(value, 1), 0);
        assertEq(ConstantTimeOperations.constantTimeGetBit(value, 2), 1);
    }

    function test_constantTimeSetBit() public pure {
        uint256 value = 0;
        value = ConstantTimeOperations.constantTimeSetBit(value, 3, true);
        assertEq(value, 8); // 2^3
        value = ConstantTimeOperations.constantTimeSetBit(value, 3, false);
        assertEq(value, 0);
    }

    function test_constantTimeIsNonZero() public pure {
        assertTrue(ConstantTimeOperations.constantTimeIsNonZero(1));
        assertTrue(ConstantTimeOperations.constantTimeIsNonZero(type(uint256).max));
        assertFalse(ConstantTimeOperations.constantTimeIsNonZero(0));
    }

    function test_constantTimeIsPowerOf2() public pure {
        assertTrue(ConstantTimeOperations.constantTimeIsPowerOf2(1));
        assertTrue(ConstantTimeOperations.constantTimeIsPowerOf2(2));
        assertTrue(ConstantTimeOperations.constantTimeIsPowerOf2(256));
        assertFalse(ConstantTimeOperations.constantTimeIsPowerOf2(3));
        assertFalse(ConstantTimeOperations.constantTimeIsPowerOf2(0));
    }

    function test_constantTimeInRange() public pure {
        assertTrue(ConstantTimeOperations.constantTimeInRange(5, 1, 10));
        assertTrue(ConstantTimeOperations.constantTimeInRange(1, 1, 10));
        assertTrue(ConstantTimeOperations.constantTimeInRange(10, 1, 10));
        assertFalse(ConstantTimeOperations.constantTimeInRange(0, 1, 10));
        assertFalse(ConstantTimeOperations.constantTimeInRange(11, 1, 10));
    }

    // =========================================================================
    // constantTimeSwap
    // =========================================================================

    function testFuzz_constantTimeSwap(bool cond, uint256 a, uint256 b) public pure {
        (uint256 x, uint256 y) = ConstantTimeOperations.constantTimeSwap(cond, a, b);
        if (cond) {
            assertEq(x, b);
            assertEq(y, a);
        } else {
            assertEq(x, a);
            assertEq(y, b);
        }
    }

    // =========================================================================
    // ConstantTimePrivacy - nullifier lookup
    // =========================================================================

    function test_constantTimeNullifierLookup_found() public pure {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = keccak256("n0");
        nullifiers[1] = keccak256("n1");
        nullifiers[2] = keccak256("n2");

        (bool found, uint256 index) = ConstantTimePrivacy.constantTimeNullifierLookup(
            keccak256("n1"),
            nullifiers
        );
        assertTrue(found);
        assertEq(index, 1);
    }

    function test_constantTimeNullifierLookup_notFound() public pure {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256("n0");
        nullifiers[1] = keccak256("n1");

        (bool found, ) = ConstantTimePrivacy.constantTimeNullifierLookup(
            keccak256("missing"),
            nullifiers
        );
        assertFalse(found);
    }

    // =========================================================================
    // ConstantTimePrivacy - key image lookup
    // =========================================================================

    function test_constantTimeKeyImageLookup() public pure {
        bytes32[] memory usedImages = new bytes32[](2);
        usedImages[0] = keccak256("img0");
        usedImages[1] = keccak256("img1");

        assertTrue(ConstantTimePrivacy.constantTimeKeyImageLookup(keccak256("img0"), usedImages));
        assertFalse(ConstantTimePrivacy.constantTimeKeyImageLookup(keccak256("unused"), usedImages));
    }

    // =========================================================================
    // ConstantTimePrivacy - commitment verify
    // =========================================================================

    function test_constantTimeCommitmentVerify() public pure {
        uint256 value = 100;
        bytes32 blinding = keccak256("blinding");
        bytes32 commitment = keccak256(abi.encodePacked(value, blinding));

        bool valid = ConstantTimePrivacy.constantTimeCommitmentVerify(
            commitment,
            value,
            blinding,
            commitment
        );
        assertTrue(valid);
    }
}
