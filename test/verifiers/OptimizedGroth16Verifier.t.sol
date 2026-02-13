// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/OptimizedGroth16Verifier.sol";

contract OptimizedGroth16VerifierTest is Test {
    OptimizedGroth16Verifier public verifier;

    // BN254 curve constants
    uint256 constant Q_MOD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant R_MOD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // G1 generator
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    function setUp() public {
        // Create a simple verification key with known valid points
        // Using G1 generator as alpha
        uint256[2] memory alpha = [G1_X, G1_Y];

        // Using G2 generator components for beta, gamma, delta
        uint256[4] memory beta = [
            uint256(
                11559732032986387107991004021392285783925812861821192530917403151452391805634
            ),
            uint256(
                10857046999023057135944570762232829481370756359578518086990519993285655852781
            ),
            uint256(
                4082367875863433681332203403145435568316851327593401208105741076214120093531
            ),
            uint256(
                8495653923123431417604973247489272438418190587263600148770280649306958101930
            )
        ];

        uint256[4] memory gamma = beta; // Same points for simplicity
        uint256[4] memory delta = beta;

        // IC points: need at least 2 (IC[0] + 1 public input)
        uint256[][] memory ic = new uint256[][](2);
        ic[0] = new uint256[](2);
        ic[0][0] = G1_X;
        ic[0][1] = G1_Y;
        ic[1] = new uint256[](2);
        ic[1][0] = G1_X;
        ic[1][1] = G1_Y;

        verifier = new OptimizedGroth16Verifier(alpha, beta, gamma, delta, ic);
    }

    // ============= Constructor =============

    function test_Constructor_DeploysSuccessfully() public view {
        // Verifier deployed with valid VK
        assertTrue(address(verifier) != address(0));
        assertTrue(address(verifier).code.length > 0);
    }

    // ============= Proof Verification =============

    function test_VerifyProof_RevertInvalidProofLength() public {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 42;

        vm.expectRevert(OptimizedGroth16Verifier.InvalidProofLength.selector);
        verifier.verifyProof(hex"aabb", inputs);
    }

    function test_VerifyProof_RevertInvalidInputsLength() public {
        // 256 bytes proof but wrong number of inputs (need 1, provide 0)
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](0);

        vm.expectRevert(
            OptimizedGroth16Verifier.InvalidPublicInputsLength.selector
        );
        verifier.verifyProof(proof, inputs);
    }

    function test_VerifyProof_RevertInvalidInputsTooMany() public {
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](5);

        vm.expectRevert(
            OptimizedGroth16Verifier.InvalidPublicInputsLength.selector
        );
        verifier.verifyProof(proof, inputs);
    }

    function test_VerifyProof_RevertInvalidPublicInput() public {
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = R_MOD; // >= R_MOD, should be invalid

        vm.expectRevert(OptimizedGroth16Verifier.InvalidPublicInput.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_VerifyProof_InvalidProofReturnsFalseOrReverts() public {
        // Construct a 256-byte proof with zeros (invalid proof but valid length)
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 1;

        // An all-zero proof should either return false or revert with PrecompileFailed
        // since (0,0) as a point is the identity, pairing with it won't be valid
        try verifier.verifyProof(proof, inputs) returns (bool result) {
            // If it doesn't revert, it should return false
            assertFalse(result);
        } catch {
            // Revert is also acceptable (precompile failure)
            assertTrue(true);
        }
    }

    // ============= Batch Verification =============

    function test_BatchVerifyProofs_RevertLengthMismatch() public {
        bytes[] memory proofs = new bytes[](2);
        uint256[][] memory inputs = new uint256[][](1);

        vm.expectRevert(OptimizedGroth16Verifier.InvalidProofLength.selector);
        verifier.batchVerifyProofs(proofs, inputs);
    }

    function test_BatchVerifyProofs_RevertInvalidProofLength() public {
        bytes[] memory proofs = new bytes[](1);
        proofs[0] = hex"aabb"; // too short
        uint256[][] memory inputs = new uint256[][](1);
        inputs[0] = new uint256[](1);

        vm.expectRevert(OptimizedGroth16Verifier.InvalidProofLength.selector);
        verifier.batchVerifyProofs(proofs, inputs);
    }

    function test_BatchVerifyProofs_RevertInvalidInputsLength() public {
        bytes[] memory proofs = new bytes[](1);
        proofs[0] = new bytes(256);
        uint256[][] memory inputs = new uint256[][](1);
        inputs[0] = new uint256[](0); // wrong length

        vm.expectRevert(
            OptimizedGroth16Verifier.InvalidPublicInputsLength.selector
        );
        verifier.batchVerifyProofs(proofs, inputs);
    }

    // ============= Internal Functions via Assembly =============

    function test_EcAdd_Precompile() public view {
        // Use assembly to call ecAdd precompile to verify it works
        uint256[4] memory input = [G1_X, G1_Y, G1_X, G1_Y];
        uint256[2] memory result;

        assembly {
            let success := staticcall(gas(), 0x06, input, 128, result, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }

        // G1 + G1 = 2*G1
        assertTrue(result[0] != 0);
        assertTrue(result[1] != 0);
    }

    function test_EcMul_Precompile() public view {
        // G1 * 2 should give same as G1 + G1
        uint256[3] memory mulInput = [G1_X, G1_Y, uint256(2)];
        uint256[2] memory mulResult;

        assembly {
            let success := staticcall(gas(), 0x07, mulInput, 96, mulResult, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }

        uint256[4] memory addInput = [G1_X, G1_Y, G1_X, G1_Y];
        uint256[2] memory addResult;

        assembly {
            let success := staticcall(gas(), 0x06, addInput, 128, addResult, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }

        assertEq(mulResult[0], addResult[0]);
        assertEq(mulResult[1], addResult[1]);
    }

    function test_EcMul_ByZero_ReturnsIdentity() public view {
        uint256[3] memory input = [G1_X, G1_Y, uint256(0)];
        uint256[2] memory result;

        assembly {
            let success := staticcall(gas(), 0x07, input, 96, result, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }

        assertEq(result[0], 0);
        assertEq(result[1], 0);
    }

    function test_EcMul_ByOrder_ReturnsIdentity() public view {
        // G1 * R_MOD should give identity (for subgroup order)
        // Actually BN254 G1 subgroup order equals R_MOD
        uint256[3] memory input = [G1_X, G1_Y, R_MOD];
        uint256[2] memory result;

        assembly {
            let success := staticcall(gas(), 0x07, input, 96, result, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }

        assertEq(result[0], 0);
        assertEq(result[1], 0);
    }

    // ============= Fuzz Tests =============

    function testFuzz_VerifyProof_RevertInvalidInput(uint256 offset) public {
        // Bound offset to [0, type(uint256).max - R_MOD] so input = R_MOD + offset >= R_MOD always holds
        uint256 input = R_MOD + bound(offset, 0, type(uint256).max - R_MOD);
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = input;

        vm.expectRevert(OptimizedGroth16Verifier.InvalidPublicInput.selector);
        verifier.verifyProof(proof, inputs);
    }

    function testFuzz_EcMul_Identity(uint256 scalar) public view {
        // 0 * scalar = identity
        uint256[3] memory input = [uint256(0), uint256(0), scalar];
        uint256[2] memory result;

        assembly {
            let success := staticcall(gas(), 0x07, input, 96, result, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }

        assertEq(result[0], 0);
        assertEq(result[1], 0);
    }
}
