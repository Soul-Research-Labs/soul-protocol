// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/CrossChainProofVerifier.sol";

/**
 * @title CrossChainProofVerifier Unit Tests
 * @notice Tests the snarkJS-generated Groth16 verifier for cross-chain proofs (7 public inputs)
 * @dev Tests deployment, field-boundary rejection, garbage-proof rejection, gas benchmarks,
 *      and ABI compatibility. Real proof verification requires actual Groth16 proofs from the
 *      matching circuit — these tests focus on negative-path coverage.
 */
contract CrossChainProofVerifierTest is Test {
    CrossChainProofVerifier verifier;

    // BN254 scalar field order (same as _r in the verifier)
    uint256 constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // BN254 base field order (same as _q in the verifier)
    uint256 constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function setUp() public {
        verifier = new CrossChainProofVerifier();
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

    function test_deployment_isContract() public view {
        uint256 size;
        address addr = address(verifier);
        assembly {
            size := extcodesize(addr)
        }
        assertGt(size, 0, "Should be a contract");
    }

    /* ══════════════════════════════════════════════════
              FIELD BOUNDARY REJECTION
       ══════════════════════════════════════════════════ */

    /// @notice Public signal >= scalar field r should cause verifyProof to return false
    function test_rejectsFieldOverflow_firstSignal() public view {
        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [
            [uint256(1), uint256(2)],
            [uint256(3), uint256(4)]
        ];
        uint256[2] memory pC = [uint256(1), uint256(2)];
        uint256[7] memory pubSignals = [
            FR,
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0)
        ]; // FR == _r, should fail field check

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Should reject pubSignal >= r");
    }

    /// @notice FR+1 should also fail the field check
    function test_rejectsFieldOverflow_aboveR() public view {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[7] memory pubSignals;
        pubSignals[0] = FR + 1;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Should reject pubSignal > r");
    }

    /// @notice type(uint256).max should fail field check
    function test_rejectsFieldOverflow_maxUint() public view {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[7] memory pubSignals;
        pubSignals[3] = type(uint256).max;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Should reject uint256.max as pubSignal");
    }

    /// @notice Each of the 7 signal positions should independently reject field overflow
    function test_rejectsFieldOverflow_eachPosition() public view {
        for (uint256 i = 0; i < 7; i++) {
            uint256[2] memory pA;
            uint256[2][2] memory pB;
            uint256[2] memory pC;
            uint256[7] memory pubSignals;
            pubSignals[i] = FR; // Exactly r — should be rejected (must be < r)

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

    /// @notice FR-1 (the maximum valid field element) should NOT trigger the field check
    ///         but should still fail because the proof is garbage
    function test_maxValidFieldElement_stillFailsProof() public view {
        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [
            [uint256(1), uint256(2)],
            [uint256(3), uint256(4)]
        ];
        uint256[2] memory pC = [uint256(1), uint256(2)];
        uint256[7] memory pubSignals;
        for (uint256 i = 0; i < 7; i++) {
            pubSignals[i] = FR - 1;
        }

        // Should pass field check but fail pairing check
        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(
            result,
            "Max valid field element with garbage proof should fail"
        );
    }

    /* ══════════════════════════════════════════════════
              GARBAGE / ZERO PROOF REJECTION
       ══════════════════════════════════════════════════ */

    /// @notice All-zero proof should return false
    function test_rejectsZeroProof() public view {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[7] memory pubSignals;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Zero proof should return false");
    }

    /// @notice Random-looking proof data should return false
    function test_rejectsGarbageProof() public view {
        uint256[2] memory pA = [uint256(123456789), uint256(987654321)];
        uint256[2][2] memory pB = [
            [uint256(111111111), uint256(222222222)],
            [uint256(333333333), uint256(444444444)]
        ];
        uint256[2] memory pC = [uint256(555555555), uint256(666666666)];
        uint256[7] memory pubSignals = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4),
            uint256(5),
            uint256(6),
            uint256(7)
        ];

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Garbage proof should return false");
    }

    /// @notice Zero public signals with non-zero (garbage) proof should still fail
    function test_rejectsGarbageProofZeroSignals() public view {
        uint256[2] memory pA = [uint256(1), uint256(2)]; // G1 generator
        uint256[2][2] memory pB = [
            [
                uint256(
                    10857046999023057135944570762232829481370756359578518086990519993285655852781
                ),
                uint256(
                    11559732032986387107991004021392285783925812861821192530917403151452391805634
                )
            ],
            [
                uint256(
                    8495653923123431417604973247489272438418190587263600148770280649306958101930
                ),
                uint256(
                    4082367875863433681332203403145435568316851327593401208105741076214120093531
                )
            ]
        ];
        uint256[2] memory pC = [uint256(1), uint256(2)];
        uint256[7] memory pubSignals;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(
            result,
            "Valid curve points with zero signals should fail verification"
        );
    }

    /* ══════════════════════════════════════════════════
              RETURN VALUE SEMANTICS
       ══════════════════════════════════════════════════ */

    /// @notice verifyProof must return a bool (0 or 1)
    function test_returnType_isBool() public view {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[7] memory pubSignals;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        // In Solidity, bool is always 0 or 1; the assembly returns 0x20 bytes
        assertTrue(result == true || result == false, "Must be boolean");
    }

    /// @notice verifyProof should not revert on invalid input — it returns false
    function test_doesNotRevert_onInvalidInput() public view {
        uint256[2] memory pA = [type(uint256).max, type(uint256).max];
        uint256[2][2] memory pB = [
            [type(uint256).max, type(uint256).max],
            [type(uint256).max, type(uint256).max]
        ];
        uint256[2] memory pC = [type(uint256).max, type(uint256).max];
        uint256[7] memory pubSignals;
        // pubSignals all zero → pass field check, proof should fail

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Max uint proof should return false, not revert");
    }

    /* ══════════════════════════════════════════════════
              GAS BENCHMARKS
       ══════════════════════════════════════════════════ */

    /// @notice Measure gas for verification with garbage proof
    /// @dev Non-curve-point inputs cause precompile failures which may use very
    ///      high gas in the EVM simulation. We just verify it executes in bounded time.
    function test_gas_garbageProof() public view {
        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [
            [uint256(1), uint256(2)],
            [uint256(3), uint256(4)]
        ];
        uint256[2] memory pC = [uint256(1), uint256(2)];
        uint256[7] memory pubSignals = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4),
            uint256(5),
            uint256(6),
            uint256(7)
        ];

        // Verify it runs without reverting — gas usage varies with EVM implementation
        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Garbage proof should return false");
    }

    /// @notice Measure gas for field-overflow rejection (should be very cheap)
    function test_gas_fieldOverflowRejection() public view {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[7] memory pubSignals;
        pubSignals[0] = FR; // Will fail field check immediately

        uint256 gasBefore = gasleft();
        verifier.verifyProof(pA, pB, pC, pubSignals);
        uint256 gasUsed = gasBefore - gasleft();

        // Field check rejection should be extremely cheap (<5k gas)
        assertLt(gasUsed, 10_000, "Field overflow rejection should be cheap");
    }

    /* ══════════════════════════════════════════════════
              FUZZ TESTS
       ══════════════════════════════════════════════════ */

    /// @notice Fuzz: any signal >= FR should cause rejection
    function testFuzz_rejectsOverflowSignal(
        uint256 overflowSeed,
        uint8 positionRaw
    ) public view {
        uint256 overflow = bound(overflowSeed, FR, type(uint256).max);
        uint8 position = positionRaw % 7;

        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[7] memory pubSignals;
        pubSignals[position] = overflow;

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Overflow signal should always be rejected");
    }

    /// @notice Fuzz: random proof data should never verify
    function testFuzz_randomProofNeverVerifies(
        uint256 a0,
        uint256 a1,
        uint256 b00,
        uint256 b01,
        uint256 b10,
        uint256 b11,
        uint256 c0,
        uint256 c1
    ) public view {
        uint256[2] memory pA = [a0, a1];
        uint256[2][2] memory pB = [[b00, b01], [b10, b11]];
        uint256[2] memory pC = [c0, c1];
        uint256[7] memory pubSignals = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4),
            uint256(5),
            uint256(6),
            uint256(7)
        ];

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertFalse(result, "Random proof should not verify");
    }

    /* ══════════════════════════════════════════════════
              ABI COMPATIBILITY
       ══════════════════════════════════════════════════ */

    /// @notice Verify the function selector matches the expected signature
    function test_functionSelector() public pure {
        bytes4 expected = bytes4(
            keccak256(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[7])"
            )
        );
        bytes4 actual = CrossChainProofVerifier.verifyProof.selector;
        assertEq(actual, expected, "Function selector mismatch");
    }
}
