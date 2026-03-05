// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/internal/validators/ProofValidator.sol";

/// @dev Harness to expose internal ProofValidator library functions
contract ProofValidatorHarness {
    function validateGroth16BN254Format(
        bytes calldata proof
    ) external pure returns (bool isValid, bytes32 proofHash) {
        return ProofValidator.validateGroth16BN254Format(proof);
    }

    function validateGroth16BLSFormat(
        bytes calldata proof
    ) external pure returns (bool isValid, bytes32 proofHash) {
        return ProofValidator.validateGroth16BLSFormat(proof);
    }

    function extractPublicInputs(
        bytes calldata proofData,
        uint256 inputCount,
        uint256 proofSize
    ) external pure returns (bytes32[] memory inputs) {
        return
            ProofValidator.extractPublicInputs(
                proofData,
                inputCount,
                proofSize
            );
    }

    function validateCommitmentBinding(
        bytes32[] memory publicInputs,
        bytes32 expectedCommitment,
        uint256 commitmentIndex
    ) external pure returns (bool isValid) {
        return
            ProofValidator.validateCommitmentBinding(
                publicInputs,
                expectedCommitment,
                commitmentIndex
            );
    }

    function extractNullifier(
        bytes32[] memory publicInputs,
        uint256 nullifierIndex
    ) external pure returns (bytes32 nullifier) {
        return ProofValidator.extractNullifier(publicInputs, nullifierIndex);
    }

    function validateFull(
        bytes calldata proofData,
        bytes32 expectedCommitment,
        ProofValidator.ProofFormat memory format
    ) external pure returns (ProofValidator.ValidatedProof memory validated) {
        return
            ProofValidator.validateFull(proofData, expectedCommitment, format);
    }
}

contract ProofValidatorTest is Test {
    ProofValidatorHarness public harness;

    function setUp() public {
        harness = new ProofValidatorHarness();
    }

    /*//////////////////////////////////////////////////////////////
                    GROTH16 BN254 FORMAT VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_validateGroth16BN254Format_valid() public view {
        bytes memory proof = _makeBytes(256);
        (bool valid, bytes32 h) = harness.validateGroth16BN254Format(proof);
        assertTrue(valid);
        assertEq(h, keccak256(proof));
    }

    function test_validateGroth16BN254Format_maxLength() public view {
        bytes memory proof = _makeBytes(512);
        (bool valid, ) = harness.validateGroth16BN254Format(proof);
        assertTrue(valid);
    }

    function test_validateGroth16BN254Format_tooShort() public view {
        bytes memory proof = _makeBytes(255);
        (bool valid, bytes32 h) = harness.validateGroth16BN254Format(proof);
        assertFalse(valid);
        assertEq(h, bytes32(0));
    }

    function test_validateGroth16BN254Format_tooLong() public view {
        bytes memory proof = _makeBytes(513);
        (bool valid, bytes32 h) = harness.validateGroth16BN254Format(proof);
        assertFalse(valid);
        assertEq(h, bytes32(0));
    }

    function testFuzz_validateGroth16BN254Format(uint16 len) public view {
        bytes memory proof = _makeBytes(len);
        (bool valid, bytes32 h) = harness.validateGroth16BN254Format(proof);
        if (len >= 256 && len <= 512) {
            assertTrue(valid);
            assertEq(h, keccak256(proof));
        } else {
            assertFalse(valid);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    GROTH16 BLS FORMAT VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_validateGroth16BLSFormat_valid() public view {
        bytes memory proof = _makeBytes(384);
        (bool valid, bytes32 h) = harness.validateGroth16BLSFormat(proof);
        assertTrue(valid);
        assertEq(h, keccak256(proof));
    }

    function test_validateGroth16BLSFormat_tooShort() public view {
        bytes memory proof = _makeBytes(383);
        (bool valid, ) = harness.validateGroth16BLSFormat(proof);
        assertFalse(valid);
    }

    function test_validateGroth16BLSFormat_tooLong() public view {
        bytes memory proof = _makeBytes(769);
        (bool valid, ) = harness.validateGroth16BLSFormat(proof);
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                      EXTRACT PUBLIC INPUTS
    //////////////////////////////////////////////////////////////*/

    function test_extractPublicInputs_single() public view {
        // 256 bytes proof + 32 bytes public input
        bytes32 expectedInput = keccak256("input1");
        bytes memory proofData = abi.encodePacked(
            _makeBytes(256),
            expectedInput
        );
        bytes32[] memory inputs = harness.extractPublicInputs(
            proofData,
            1,
            256
        );
        assertEq(inputs.length, 1);
        assertEq(inputs[0], expectedInput);
    }

    function test_extractPublicInputs_multiple() public view {
        bytes32 input0 = keccak256("commitment");
        bytes32 input1 = keccak256("nullifier");
        bytes32 input2 = keccak256("newCommitment");
        bytes memory proofData = abi.encodePacked(
            _makeBytes(256),
            input0,
            input1,
            input2
        );
        bytes32[] memory inputs = harness.extractPublicInputs(
            proofData,
            3,
            256
        );
        assertEq(inputs.length, 3);
        assertEq(inputs[0], input0);
        assertEq(inputs[1], input1);
        assertEq(inputs[2], input2);
    }

    function test_extractPublicInputs_revertsOnTruncated() public {
        // Only 256 bytes, but asking for 1 input (needs 256+32=288)
        bytes memory proofData = _makeBytes(256);
        vm.expectRevert(ProofValidator.InvalidPublicInputs.selector);
        harness.extractPublicInputs(proofData, 1, 256);
    }

    /*//////////////////////////////////////////////////////////////
                    COMMITMENT BINDING VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_validateCommitmentBinding_matches() public view {
        bytes32 commitment = keccak256("state");
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = commitment;
        inputs[1] = keccak256("nullifier");
        assertTrue(harness.validateCommitmentBinding(inputs, commitment, 0));
    }

    function test_validateCommitmentBinding_mismatch() public view {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("actual");
        assertFalse(
            harness.validateCommitmentBinding(inputs, keccak256("expected"), 0)
        );
    }

    function test_validateCommitmentBinding_outOfBounds() public view {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("val");
        assertFalse(harness.validateCommitmentBinding(inputs, inputs[0], 5));
    }

    /*//////////////////////////////////////////////////////////////
                      EXTRACT NULLIFIER
    //////////////////////////////////////////////////////////////*/

    function test_extractNullifier() public view {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("commitment");
        inputs[1] = keccak256("nullifier");
        assertEq(harness.extractNullifier(inputs, 1), inputs[1]);
    }

    function test_extractNullifier_revertsOutOfBounds() public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("val");
        vm.expectRevert(ProofValidator.InvalidPublicInputs.selector);
        harness.extractNullifier(inputs, 2);
    }

    /*//////////////////////////////////////////////////////////////
                       FULL VALIDATION PIPELINE
    //////////////////////////////////////////////////////////////*/

    function test_validateFull_valid() public view {
        bytes32 commitment = keccak256("state");
        bytes32 nullifier = keccak256("nullifier");
        bytes32 newCommitment = keccak256("newState");

        // Build proof data: 256 bytes proof + 3 public inputs
        bytes memory proofData = abi.encodePacked(
            _makeBytes(256),
            commitment,
            nullifier,
            newCommitment
        );

        ProofValidator.ProofFormat memory fmt = ProofValidator.ProofFormat({
            minLength: 256 + 96, // 256 proof + 3*32 inputs
            maxLength: 1024,
            publicInputCount: 3,
            proofElementCount: 0
        });

        ProofValidator.ValidatedProof memory result = harness.validateFull(
            proofData,
            commitment,
            fmt
        );

        assertTrue(result.isValid);
        assertEq(result.nullifier, nullifier);
        assertEq(result.newCommitment, newCommitment);
        assertEq(result.proofHash, keccak256(proofData));
    }

    function test_validateFull_tooShort() public view {
        bytes memory proofData = _makeBytes(100);

        ProofValidator.ProofFormat memory fmt = ProofValidator.ProofFormat({
            minLength: 256,
            maxLength: 512,
            publicInputCount: 1,
            proofElementCount: 0
        });

        ProofValidator.ValidatedProof memory result = harness.validateFull(
            proofData,
            keccak256("state"),
            fmt
        );
        assertFalse(result.isValid);
    }

    function test_validateFull_commitmentMismatch() public view {
        bytes32 actualCommitment = keccak256("actual");
        bytes memory proofData = abi.encodePacked(
            _makeBytes(256),
            actualCommitment
        );

        ProofValidator.ProofFormat memory fmt = ProofValidator.ProofFormat({
            minLength: 288,
            maxLength: 1024,
            publicInputCount: 1,
            proofElementCount: 0
        });

        ProofValidator.ValidatedProof memory result = harness.validateFull(
            proofData,
            keccak256("expected"), // different from actual
            fmt
        );
        assertFalse(result.isValid);
    }

    /*//////////////////////////////////////////////////////////////
                             HELPERS
    //////////////////////////////////////////////////////////////*/

    function _makeBytes(
        uint256 size
    ) internal pure returns (bytes memory data) {
        data = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            data[i] = bytes1(uint8(i % 256));
        }
    }
}
