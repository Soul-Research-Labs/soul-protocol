// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CryptoLib} from "../../contracts/libraries/CryptoLib.sol";
import {ValidationLib} from "../../contracts/libraries/ValidationLib.sol";

/// @title CryptoLib harness exposing internal functions
contract CryptoHarness {
    function g1Add(
        CryptoLib.G1Point memory p1,
        CryptoLib.G1Point memory p2
    ) external view returns (CryptoLib.G1Point memory) {
        return CryptoLib.g1Add(p1, p2);
    }

    function g1Mul(
        CryptoLib.G1Point memory p,
        uint256 scalar
    ) external view returns (CryptoLib.G1Point memory) {
        return CryptoLib.g1Mul(p, scalar);
    }

    function g1Neg(
        CryptoLib.G1Point memory p
    ) external pure returns (CryptoLib.G1Point memory) {
        return CryptoLib.g1Neg(p);
    }

    function g1Eq(
        CryptoLib.G1Point memory p1,
        CryptoLib.G1Point memory p2
    ) external pure returns (bool) {
        return CryptoLib.g1Eq(p1, p2);
    }

    function hashToPoint(
        bytes memory data
    ) external view returns (CryptoLib.G1Point memory) {
        return CryptoLib.hashToPoint(data);
    }
}

/// @title ValidationLib harness exposing internal functions
contract ValidationHarness {
    function requireNonZeroAddress(address addr) external pure {
        ValidationLib.requireNonZeroAddress(addr);
    }

    function requireNonZeroAddressesSingle(address a, address b) external pure {
        ValidationLib.requireNonZeroAddresses(a, b);
    }

    function requireNonZeroValue(uint256 value) external pure {
        ValidationLib.requireNonZeroValue(value);
    }

    function requireInBounds(
        uint256 value,
        uint256 min_,
        uint256 max_
    ) external pure {
        ValidationLib.requireInBounds(value, min_, max_);
    }

    function requireBelowThreshold(
        uint256 value,
        uint256 threshold
    ) external pure {
        ValidationLib.requireBelowThreshold(value, threshold);
    }

    function requireNonEmptyArray(uint256 length) external pure {
        ValidationLib.requireNonEmptyArray(length);
    }

    function requireMatchingLengths(uint256 a, uint256 b) external pure {
        ValidationLib.requireMatchingLengths(a, b);
    }

    function requireValidBatchSize(
        uint256 size,
        uint256 maxSize
    ) external pure {
        ValidationLib.requireValidBatchSize(size, maxSize);
    }

    function requireNotExpired(uint256 deadline) external view {
        ValidationLib.requireNotExpired(deadline);
    }

    function requireExpired(uint256 deadline) external view {
        ValidationLib.requireExpired(deadline);
    }

    function requireValidDestinationChain(uint256 chainId) external view {
        ValidationLib.requireValidDestinationChain(chainId);
    }

    function requireOnChain(uint256 expectedChainId) external view {
        ValidationLib.requireOnChain(expectedChainId);
    }

    function requireNonEmptyBytes(bytes calldata data) external pure {
        ValidationLib.requireNonEmptyBytes(data);
    }

    function requireNonZeroBytes32(bytes32 value) external pure {
        ValidationLib.requireNonZeroBytes32(value);
    }

    function validateTransfer(address recipient, uint256 amount) external pure {
        ValidationLib.validateTransfer(recipient, amount);
    }

    function validateProofParams(
        bytes calldata proof,
        bytes calldata publicInputs,
        uint64 sourceChainId,
        uint64 destChainId
    ) external view {
        ValidationLib.validateProofParams(
            proof,
            publicInputs,
            sourceChainId,
            destChainId
        );
    }
}

/**
 * @title CryptoValidationTest
 * @notice Tests for CryptoLib and ValidationLib
 */
contract CryptoValidationTest is Test {
    CryptoHarness public crypto;
    ValidationHarness public val;

    // BN254 generator point (G1)
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    function setUp() public {
        crypto = new CryptoHarness();
        val = new ValidationHarness();
    }

    // =========================================================================
    // CRYPTOLIB — POINT OPERATIONS
    // =========================================================================

    function test_G1Add_Identity() public view {
        CryptoLib.G1Point memory zero = CryptoLib.G1Point(0, 0);
        CryptoLib.G1Point memory g = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory result = crypto.g1Add(g, zero);
        assertTrue(crypto.g1Eq(result, g));
    }

    function test_G1Mul_Identity() public view {
        CryptoLib.G1Point memory g = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory result = crypto.g1Mul(g, 1);
        assertTrue(crypto.g1Eq(result, g));
    }

    function test_G1Mul_Zero() public view {
        CryptoLib.G1Point memory g = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory result = crypto.g1Mul(g, 0);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function test_G1Neg_DoubleNeg() public view {
        CryptoLib.G1Point memory g = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory negG = crypto.g1Neg(g);
        CryptoLib.G1Point memory doubleNeg = crypto.g1Neg(negG);
        assertTrue(crypto.g1Eq(doubleNeg, g));
    }

    function test_G1Neg_Identity() public pure {
        CryptoLib.G1Point memory zero = CryptoLib.G1Point(0, 0);
        CryptoLib.G1Point memory result = CryptoLib.g1Neg(zero);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function test_G1Add_Inverse() public view {
        CryptoLib.G1Point memory g = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory negG = crypto.g1Neg(g);
        CryptoLib.G1Point memory result = crypto.g1Add(g, negG);
        // P + (-P) = O (identity)
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function test_G1Eq_True() public pure {
        CryptoLib.G1Point memory a = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory b = CryptoLib.G1Point(G1_X, G1_Y);
        assertTrue(CryptoLib.g1Eq(a, b));
    }

    function test_G1Eq_False() public pure {
        CryptoLib.G1Point memory a = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory b = CryptoLib.G1Point(0, 0);
        assertFalse(CryptoLib.g1Eq(a, b));
    }

    function test_G1Mul_Scalar2_EqualsDoubling() public view {
        CryptoLib.G1Point memory g = CryptoLib.G1Point(G1_X, G1_Y);
        CryptoLib.G1Point memory doubled = crypto.g1Add(g, g);
        CryptoLib.G1Point memory scalar2 = crypto.g1Mul(g, 2);
        assertTrue(crypto.g1Eq(doubled, scalar2));
    }

    // =========================================================================
    // CRYPTOLIB — HASH TO POINT
    // =========================================================================

    function test_HashToPoint_Deterministic() public view {
        bytes memory data = "test data";
        CryptoLib.G1Point memory p1 = crypto.hashToPoint(data);
        CryptoLib.G1Point memory p2 = crypto.hashToPoint(data);
        assertTrue(crypto.g1Eq(p1, p2));
    }

    function test_HashToPoint_DifferentInputs() public view {
        CryptoLib.G1Point memory p1 = crypto.hashToPoint("hello");
        CryptoLib.G1Point memory p2 = crypto.hashToPoint("world");
        assertFalse(crypto.g1Eq(p1, p2));
    }

    function test_HashToPoint_NonZero() public view {
        CryptoLib.G1Point memory p = crypto.hashToPoint("zaseon");
        assertTrue(p.x != 0 || p.y != 0);
    }

    // =========================================================================
    // VALIDATION LIB — ADDRESS
    // =========================================================================

    function test_RequireNonZeroAddress_Valid() public view {
        val.requireNonZeroAddress(address(0x1));
        // No revert
    }

    function test_RequireNonZeroAddress_ZeroReverts() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        val.requireNonZeroAddress(address(0));
    }

    function test_RequireNonZeroAddresses_BothValid() public view {
        val.requireNonZeroAddressesSingle(address(0x1), address(0x2));
    }

    function test_RequireNonZeroAddresses_FirstZeroReverts() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        val.requireNonZeroAddressesSingle(address(0), address(0x1));
    }

    function test_RequireNonZeroAddresses_SecondZeroReverts() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        val.requireNonZeroAddressesSingle(address(0x1), address(0));
    }

    // =========================================================================
    // VALIDATION LIB — VALUE
    // =========================================================================

    function test_RequireNonZeroValue_Valid() public view {
        val.requireNonZeroValue(1);
    }

    function test_RequireNonZeroValue_ZeroReverts() public {
        vm.expectRevert(ValidationLib.ZeroValue.selector);
        val.requireNonZeroValue(0);
    }

    function test_RequireInBounds_Valid() public view {
        val.requireInBounds(5, 1, 10);
        val.requireInBounds(1, 1, 10);
        val.requireInBounds(10, 1, 10);
    }

    function test_RequireInBounds_TooLow() public {
        vm.expectRevert(
            abi.encodeWithSelector(ValidationLib.OutOfBounds.selector, 0, 1, 10)
        );
        val.requireInBounds(0, 1, 10);
    }

    function test_RequireInBounds_TooHigh() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.OutOfBounds.selector,
                11,
                1,
                10
            )
        );
        val.requireInBounds(11, 1, 10);
    }

    function test_RequireBelowThreshold_Valid() public view {
        val.requireBelowThreshold(5, 10);
    }

    function test_RequireBelowThreshold_Exceeds() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.AmountExceedsThreshold.selector,
                11,
                10
            )
        );
        val.requireBelowThreshold(11, 10);
    }

    // =========================================================================
    // VALIDATION LIB — ARRAY
    // =========================================================================

    function test_RequireNonEmptyArray_Valid() public view {
        val.requireNonEmptyArray(1);
    }

    function test_RequireNonEmptyArray_EmptyReverts() public {
        vm.expectRevert(bytes4(0x0a72b8ce)); // EmptyArray() via assembly
        val.requireNonEmptyArray(0);
    }

    function test_RequireMatchingLengths_Match() public view {
        val.requireMatchingLengths(3, 3);
    }

    function test_RequireMatchingLengths_Mismatch() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.ArrayLengthMismatch.selector,
                3,
                5
            )
        );
        val.requireMatchingLengths(3, 5);
    }

    function test_RequireValidBatchSize_Valid() public view {
        val.requireValidBatchSize(10, 100);
    }

    function test_RequireValidBatchSize_Zero() public {
        vm.expectRevert(bytes4(0x0a72b8ce)); // EmptyArray() via assembly
        val.requireValidBatchSize(0, 100);
    }

    function test_RequireValidBatchSize_TooLarge() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.BatchTooLarge.selector,
                101,
                100
            )
        );
        val.requireValidBatchSize(101, 100);
    }

    // =========================================================================
    // VALIDATION LIB — TIME
    // =========================================================================

    function test_RequireNotExpired_Valid() public view {
        val.requireNotExpired(block.timestamp + 1 hours);
    }

    function test_RequireNotExpired_Expired() public {
        vm.warp(1000);
        vm.expectRevert(
            abi.encodeWithSelector(ValidationLib.Expired.selector, 999, 1000)
        );
        val.requireNotExpired(999);
    }

    function test_RequireExpired_Valid() public {
        vm.warp(1000);
        val.requireExpired(999);
    }

    function test_RequireExpired_NotExpired() public {
        vm.warp(1000);
        vm.expectRevert(
            abi.encodeWithSelector(ValidationLib.Expired.selector, 1001, 1000)
        );
        val.requireExpired(1001);
    }

    // =========================================================================
    // VALIDATION LIB — CHAIN ID
    // =========================================================================

    function test_RequireValidDestinationChain_Valid() public view {
        // Current chain is 31337 in foundry
        val.requireValidDestinationChain(1); // Different chain
    }

    function test_RequireValidDestinationChain_Zero() public {
        vm.expectRevert(
            abi.encodeWithSelector(ValidationLib.InvalidChainId.selector, 0)
        );
        val.requireValidDestinationChain(0);
    }

    function test_RequireValidDestinationChain_SameChain() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.InvalidChainId.selector,
                block.chainid
            )
        );
        val.requireValidDestinationChain(block.chainid);
    }

    function test_RequireOnChain_Valid() public view {
        val.requireOnChain(block.chainid);
    }

    function test_RequireOnChain_WrongChain() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.InvalidChainId.selector,
                block.chainid
            )
        );
        val.requireOnChain(999);
    }

    // =========================================================================
    // VALIDATION LIB — BYTES
    // =========================================================================

    function test_RequireNonEmptyBytes_Valid() public view {
        val.requireNonEmptyBytes(hex"deadbeef");
    }

    function test_RequireNonEmptyBytes_EmptyReverts() public {
        vm.expectRevert(ValidationLib.EmptyArray.selector);
        val.requireNonEmptyBytes(hex"");
    }

    function test_RequireNonZeroBytes32_Valid() public view {
        val.requireNonZeroBytes32(bytes32(uint256(1)));
    }

    function test_RequireNonZeroBytes32_ZeroReverts() public {
        vm.expectRevert(ValidationLib.ZeroValue.selector);
        val.requireNonZeroBytes32(bytes32(0));
    }

    // =========================================================================
    // VALIDATION LIB — COMPOUND
    // =========================================================================

    function test_ValidateTransfer_Valid() public view {
        val.validateTransfer(address(0x1), 100);
    }

    function test_ValidateTransfer_ZeroAddress() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        val.validateTransfer(address(0), 100);
    }

    function test_ValidateTransfer_ZeroAmount() public {
        vm.expectRevert(ValidationLib.ZeroValue.selector);
        val.validateTransfer(address(0x1), 0);
    }

    function test_ValidateProofParams_Valid() public view {
        val.validateProofParams(hex"dead", hex"beef", 1, 42161);
    }

    function test_ValidateProofParams_EmptyProof() public {
        vm.expectRevert(ValidationLib.EmptyArray.selector);
        val.validateProofParams(hex"", hex"beef", 1, 42161);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_RequireNonZeroAddress(address addr) public {
        if (addr == address(0)) {
            vm.expectRevert(ValidationLib.ZeroAddress.selector);
        }
        val.requireNonZeroAddress(addr);
    }

    function testFuzz_RequireInBounds(
        uint256 value,
        uint256 min_,
        uint256 max_
    ) public {
        vm.assume(min_ <= max_);
        if (value < min_ || value > max_) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ValidationLib.OutOfBounds.selector,
                    value,
                    min_,
                    max_
                )
            );
        }
        val.requireInBounds(value, min_, max_);
    }

    function testFuzz_RequireNonZeroValue(uint256 value) public {
        if (value == 0) {
            vm.expectRevert(ValidationLib.ZeroValue.selector);
        }
        val.requireNonZeroValue(value);
    }
}
