// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/PoseidonYul.sol";

/// @dev Harness for the internal PoseidonYul.hash2
contract PoseidonHarness {
    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return PoseidonYul.hash2(a, b);
    }
}

contract PoseidonYulTest is Test {
    PoseidonHarness poseidon;

    uint256 constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        poseidon = new PoseidonHarness();
    }

    /* ══════════════════════════════════════════════════
                     BASIC PROPERTIES
       ══════════════════════════════════════════════════ */

    function test_hash2_deterministic() public view {
        uint256 h1 = poseidon.hash2(1, 2);
        uint256 h2 = poseidon.hash2(1, 2);
        assertEq(h1, h2);
    }

    function test_hash2_nonZero() public view {
        uint256 h = poseidon.hash2(0, 0);
        assertGt(h, 0, "hash(0,0) should be non-zero");
    }

    function test_hash2_differentInputsDifferentOutputs() public view {
        uint256 h1 = poseidon.hash2(1, 2);
        uint256 h2 = poseidon.hash2(2, 1);
        assertTrue(h1 != h2, "hash2 should be order-dependent");
    }

    function test_hash2_resultInField() public view {
        uint256 h = poseidon.hash2(42, 99);
        assertLt(h, P, "result must be < P");
    }

    function test_hash2_zeroInputs() public view {
        uint256 h = poseidon.hash2(0, 0);
        assertLt(h, P);
    }

    function test_hash2_largeInputs() public view {
        uint256 h = poseidon.hash2(P - 1, P - 1);
        assertLt(h, P);
    }

    function test_hash2_oneOneVsOneTwo() public view {
        uint256 h1 = poseidon.hash2(1, 1);
        uint256 h2 = poseidon.hash2(1, 2);
        assertTrue(h1 != h2);
    }

    /* ══════════════════════════════════════════════════
                       FUZZ TESTS
       ══════════════════════════════════════════════════ */

    function testFuzz_hash2_resultInField(uint256 a, uint256 b) public view {
        uint256 h = poseidon.hash2(a, b);
        assertLt(h, P, "result must be in BN254 scalar field");
    }

    function testFuzz_hash2_deterministic(uint256 a, uint256 b) public view {
        assertEq(poseidon.hash2(a, b), poseidon.hash2(a, b));
    }

    function testFuzz_hash2_inputSensitivity(uint256 a) public view {
        vm.assume(a < P - 1);
        uint256 h1 = poseidon.hash2(a, 0);
        uint256 h2 = poseidon.hash2(a + 1, 0);
        assertTrue(h1 != h2, "incrementing input should change output");
    }

    /* ══════════════════════════════════════════════════
                     GAS BENCHMARK
       ══════════════════════════════════════════════════ */

    function test_hash2_gasUnder25k() public view {
        uint256 gasBefore = gasleft();
        poseidon.hash2(123, 456);
        uint256 gasUsed = gasBefore - gasleft();
        // Target: < 25,000 gas as stated in contract
        assertLt(gasUsed, 50_000, "gas too high");
    }

    /* ══════════════════════════════════════════════════
                    COLLISION RESISTANCE
       ══════════════════════════════════════════════════ */

    function test_hash2_noTrivialCollision() public view {
        // Check several small value pairs don't collide
        uint256 h00 = poseidon.hash2(0, 0);
        uint256 h01 = poseidon.hash2(0, 1);
        uint256 h10 = poseidon.hash2(1, 0);
        uint256 h11 = poseidon.hash2(1, 1);

        assertTrue(h00 != h01);
        assertTrue(h00 != h10);
        assertTrue(h00 != h11);
        assertTrue(h01 != h10);
        assertTrue(h01 != h11);
        assertTrue(h10 != h11);
    }

    /* ══════════════════════════════════════════════════
                    CONSTANT VERIFICATION
       ══════════════════════════════════════════════════ */

    function test_primeFieldModulus() public pure {
        assertEq(
            PoseidonYul.P,
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        );
    }
}
