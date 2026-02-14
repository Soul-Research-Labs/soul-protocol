// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/StateCommitmentVerifier.sol";

/**
 * @title StateCommitmentVerifier Unit Tests
 * @notice Tests the snarkJS-generated Groth16 verifier for state commitments (3 public inputs)
 * @dev Tests deployment, field-boundary rejection, garbage-proof rejection, gas benchmarks,
 *      and ABI compatibility. Real proof verification requires actual Groth16 proofs from the
 *      matching circuit.
 */
contract StateCommitmentVerifierTest is Test {
    StateCommitmentVerifier verifier;

    // BN254 scalar field order r
    uint256 constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        verifier = new StateCommitmentVerifier();
    }

    /* ══════════════════════════════════════════════════
                    DEPLOYMENT
       ══════════════════════════════════════════════════ */

    function test_deployment_codeNonEmpty() public view {
        assertTrue(
            address(verifier).code.length > 0,
            "Verifier should have bytecode"
        );
    }

    /* ══════════════════════════════════════════════════
              FIELD BOUNDARY REJECTION
       ══════════════════════════════════════════════════ */

    /// @notice Public signal == r should be rejected (must be < r)
    function test_rejectsFieldOverflow_equalR() public view {
        uint[2] memory pA;
        uint[2][2] memory pB;
        uint[2] memory pC;
        uint[3] memory pubSignals;
        pubSignals[0] = FR;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Signal == r should be rejected");
    }

    /// @notice Public signal > r should be rejected
    function test_rejectsFieldOverflow_aboveR() public view {
        uint[2] memory pA;
        uint[2][2] memory pB;
        uint[2] memory pC;
        uint[3] memory pubSignals;
        pubSignals[1] = FR + 1;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Signal > r should be rejected");
    }

    /// @notice type(uint256).max should fail field check
    function test_rejectsFieldOverflow_maxUint() public view {
        uint[2] memory pA;
        uint[2][2] memory pB;
        uint[2] memory pC;
        uint[3] memory pubSignals;
        pubSignals[2] = type(uint256).max;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "uint256.max should be rejected");
    }

    /// @notice All 3 signal positions should independently enforce the field check
    function test_rejectsFieldOverflow_allPositions() public view {
        for (uint256 i = 0; i < 3; i++) {
            uint[2] memory pA;
            uint[2][2] memory pB;
            uint[2] memory pC;
            uint[3] memory pubSignals;
            pubSignals[i] = FR;

            bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
            assertFalse(
                result,
                string.concat(
                    "Position ",
                    vm.toString(i),
                    " should reject >= r"
                )
            );
        }
    }

    /// @notice FR-1 should pass field check but fail proof verification
    function test_maxValidFieldElement_stillFailsProof() public view {
        uint[2] memory pA = [uint256(1), uint256(2)];
        uint[2][2] memory pB = [
            [uint256(1), uint256(2)],
            [uint256(3), uint256(4)]
        ];
        uint[2] memory pC = [uint256(1), uint256(2)];
        uint[3] memory pubSignals = [FR - 1, FR - 1, FR - 1];

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(
            result,
            "Max valid field elements with garbage proof should fail"
        );
    }

    /* ══════════════════════════════════════════════════
              GARBAGE / ZERO PROOF REJECTION
       ══════════════════════════════════════════════════ */

    /// @notice All-zero proof and signals should return false
    function test_rejectsZeroProof() public view {
        uint[2] memory pA;
        uint[2][2] memory pB;
        uint[2] memory pC;
        uint[3] memory pubSignals;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Zero proof should return false");
    }

    /// @notice Arbitrary small numbers should not verify
    function test_rejectsGarbageProof() public view {
        uint[2] memory pA = [uint256(42), uint256(1337)];
        uint[2][2] memory pB = [
            [uint256(100), uint256(200)],
            [uint256(300), uint256(400)]
        ];
        uint[2] memory pC = [uint256(500), uint256(600)];
        uint[3] memory pubSignals = [uint256(1), uint256(2), uint256(3)];

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Garbage proof should return false");
    }

    /* ══════════════════════════════════════════════════
              RETURN VALUE & NON-REVERT
       ══════════════════════════════════════════════════ */

    /// @notice verifyProof should not revert on invalid inputs
    function test_doesNotRevert_onInvalidInput() public view {
        uint[2] memory pA = [type(uint256).max, type(uint256).max];
        uint[2][2] memory pB = [
            [type(uint256).max, type(uint256).max],
            [type(uint256).max, type(uint256).max]
        ];
        uint[2] memory pC = [type(uint256).max, type(uint256).max];
        uint[3] memory pubSignals; // zeros → pass field check

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Should return false, not revert");
    }

    /* ══════════════════════════════════════════════════
              GAS BENCHMARKS
       ══════════════════════════════════════════════════ */

    function test_gas_fieldOverflowRejection() public view {
        uint[2] memory pA;
        uint[2][2] memory pB;
        uint[2] memory pC;
        uint[3] memory pubSignals;
        pubSignals[0] = FR;

        uint256 gasBefore = gasleft();
        verifier.verifyProof(pA, pB, pC, pubSignals);
        uint256 gasUsed = gasBefore - gasleft();

        assertLt(gasUsed, 10_000, "Field check rejection should be < 10k gas");
    }

    function test_gas_garbageProof() public view {
        uint[2] memory pA = [uint256(1), uint256(2)];
        uint[2][2] memory pB = [
            [uint256(1), uint256(2)],
            [uint256(3), uint256(4)]
        ];
        uint[2] memory pC = [uint256(1), uint256(2)];
        uint[3] memory pubSignals = [uint256(1), uint256(2), uint256(3)];

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Garbage proof should return false");
    }

    /* ══════════════════════════════════════════════════
              FUZZ TESTS
       ══════════════════════════════════════════════════ */

    function testFuzz_rejectsOverflowSignal(
        uint256 overflowSeed,
        uint8 positionRaw
    ) public view {
        uint256 overflow = bound(overflowSeed, FR, type(uint256).max);
        uint8 position = positionRaw % 3;

        uint[2] memory pA;
        uint[2][2] memory pB;
        uint[2] memory pC;
        uint[3] memory pubSignals;
        pubSignals[position] = overflow;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Overflow signal should be rejected");
    }

    function testFuzz_randomProofNeverVerifies(
        uint256 a0,
        uint256 a1,
        uint256 c0,
        uint256 c1
    ) public view {
        uint[2] memory pA = [a0, a1];
        uint[2][2] memory pB = [
            [uint256(1), uint256(0)],
            [uint256(0), uint256(1)]
        ];
        uint[2] memory pC = [c0, c1];
        uint[3] memory pubSignals = [uint256(1), uint256(2), uint256(3)];

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Random proof should not verify");
    }

    /* ══════════════════════════════════════════════════
              ABI COMPATIBILITY
       ══════════════════════════════════════════════════ */

    /// @notice Verify the function selector — note: uses `uint` not `uint256` but they're equivalent
    function test_functionSelector() public pure {
        // uint and uint256 produce the same ABI selector
        bytes4 expected = bytes4(
            keccak256(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])"
            )
        );
        bytes4 actual = StateCommitmentVerifier.verifyProof.selector;
        assertEq(actual, expected, "Function selector mismatch");
    }
}
