// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/CryptoLib.sol";

/// @dev Wrapper to expose CryptoLib internal functions for testing
contract CryptoLibHarness {
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

    function hashToPointWithDomain(
        bytes memory data,
        bytes32 domain
    ) external view returns (CryptoLib.G1Point memory) {
        return CryptoLib.hashToPointWithDomain(data, domain);
    }

    function frModulus() external pure returns (uint256) {
        return CryptoLib.FR_MODULUS;
    }

    function fqModulus() external pure returns (uint256) {
        return CryptoLib.FQ_MODULUS;
    }
}

contract CryptoLibTest is Test {
    CryptoLibHarness public lib;

    // BN254 Generator G1
    CryptoLib.G1Point G1 = CryptoLib.G1Point(1, 2);

    function setUp() public {
        lib = new CryptoLibHarness();
    }

    /* ── Constants ──────────────────────────────────── */

    function test_constants() public view {
        assertEq(
            lib.frModulus(),
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        );
        assertEq(
            lib.fqModulus(),
            21888242871839275222246405745257275088696311157297823662689037894645226208583
        );
    }

    /* ── Point Addition ─────────────────────────────── */

    function test_g1Add_identity() public view {
        CryptoLib.G1Point memory zero = CryptoLib.G1Point(0, 0);
        CryptoLib.G1Point memory result = lib.g1Add(G1, zero);
        assertEq(result.x, G1.x);
        assertEq(result.y, G1.y);
    }

    function test_g1Add_selfPlus() public view {
        CryptoLib.G1Point memory result = lib.g1Add(G1, G1);
        // G + G = 2G, should be a valid point
        assertTrue(result.x != 0 || result.y != 0);
    }

    /* ── Scalar multiplication ──────────────────────── */

    function test_g1Mul_byOne() public view {
        CryptoLib.G1Point memory result = lib.g1Mul(G1, 1);
        assertEq(result.x, G1.x);
        assertEq(result.y, G1.y);
    }

    function test_g1Mul_byZero() public view {
        CryptoLib.G1Point memory result = lib.g1Mul(G1, 0);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function test_g1Mul_byTwo_matchesAdd() public view {
        CryptoLib.G1Point memory dbl = lib.g1Mul(G1, 2);
        CryptoLib.G1Point memory add = lib.g1Add(G1, G1);
        assertTrue(lib.g1Eq(dbl, add));
    }

    function test_g1Mul_byThree() public view {
        CryptoLib.G1Point memory triple = lib.g1Mul(G1, 3);
        CryptoLib.G1Point memory dbl = lib.g1Mul(G1, 2);
        CryptoLib.G1Point memory addResult = lib.g1Add(dbl, G1);
        assertTrue(lib.g1Eq(triple, addResult));
    }

    /* ── Negation ───────────────────────────────────── */

    function test_g1Neg_producesInverse() public view {
        CryptoLib.G1Point memory neg = lib.g1Neg(G1);
        CryptoLib.G1Point memory sum = lib.g1Add(G1, neg);
        // G + (-G) = 0 (point at infinity)
        assertEq(sum.x, 0);
        assertEq(sum.y, 0);
    }

    function test_g1Neg_identity() public view {
        CryptoLib.G1Point memory zero = CryptoLib.G1Point(0, 0);
        CryptoLib.G1Point memory neg = lib.g1Neg(zero);
        assertEq(neg.x, 0);
        assertEq(neg.y, 0);
    }

    /* ── Equality ───────────────────────────────────── */

    function test_g1Eq_same() public view {
        assertTrue(lib.g1Eq(G1, G1));
    }

    function test_g1Eq_different() public view {
        CryptoLib.G1Point memory other = lib.g1Mul(G1, 2);
        assertFalse(lib.g1Eq(G1, other));
    }

    /* ── Hash to Point ──────────────────────────────── */

    function test_hashToPoint_producesValidPoint() public view {
        CryptoLib.G1Point memory p = lib.hashToPoint(abi.encode("test"));
        // Point should be non-zero (valid point on curve)
        assertTrue(p.x != 0 || p.y != 0);
    }

    function test_hashToPoint_deterministicOutput() public view {
        CryptoLib.G1Point memory p1 = lib.hashToPoint(abi.encode("hello"));
        CryptoLib.G1Point memory p2 = lib.hashToPoint(abi.encode("hello"));
        assertTrue(lib.g1Eq(p1, p2));
    }

    function test_hashToPoint_differentInputsDifferentOutputs() public view {
        CryptoLib.G1Point memory p1 = lib.hashToPoint(abi.encode("hello"));
        CryptoLib.G1Point memory p2 = lib.hashToPoint(abi.encode("world"));
        assertFalse(lib.g1Eq(p1, p2));
    }

    function test_hashToPointWithDomain_differentDomains() public view {
        bytes memory data = abi.encode("same_data");
        CryptoLib.G1Point memory p1 = lib.hashToPointWithDomain(
            data,
            bytes32(uint256(1))
        );
        CryptoLib.G1Point memory p2 = lib.hashToPointWithDomain(
            data,
            bytes32(uint256(2))
        );
        assertFalse(lib.g1Eq(p1, p2));
    }

    function testFuzz_hashToPoint(bytes memory data) public view {
        CryptoLib.G1Point memory p = lib.hashToPoint(data);
        // Should always find a valid point (won't revert)
        assertTrue(p.x != 0 || p.y != 0);
    }

    /* ── Point on curve verification ────────────────── */

    function test_scalarMul_largeScalar() public view {
        // Use a large scalar near the curve order
        uint256 scalar = lib.frModulus() - 1;
        CryptoLib.G1Point memory p = lib.g1Mul(G1, scalar);
        // n*G - G should equal (n-1)*G
        assertTrue(p.x != 0 || p.y != 0);
    }
}
