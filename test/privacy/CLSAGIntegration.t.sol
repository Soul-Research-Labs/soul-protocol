// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/experimental/verifiers/CLSAGVerifier.sol";
import "../../contracts/privacy/GasOptimizedPrivacy.sol";

/**
 * @title CLSAGIntegration
 * @notice Integration tests: CLSAGVerifier ↔ GasOptimizedRingCT wiring
 * @dev Constructs valid CLSAG signatures off-chain (in Solidity) and
 *      verifies full RingCT processing through GasOptimizedRingCT.processRingCT().
 */
contract CLSAGIntegrationTest is Test {
    CLSAGVerifier public clsag;
    GasOptimizedRingCT public ringCT;
    address public owner;

    // Mirror CLSAGVerifier domain separators
    bytes32 constant COMMITMENT_DOMAIN = keccak256("ZASEON_CLSAG_COMMITMENT_V1");
    bytes32 constant CHALLENGE_DOMAIN = keccak256("ZASEON_CLSAG_CHALLENGE_V1");
    bytes32 constant KEY_IMAGE_DOMAIN = keccak256("ZASEON_KEY_IMAGE_V1");

    // secp256k1 half-order for malleability check
    uint256 constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function setUp() public {
        owner = address(this);
        clsag = new CLSAGVerifier();
        ringCT = new GasOptimizedRingCT();
        ringCT.setRingSignatureVerifier(address(clsag));
    }

    // ───────────────────────────────────────────────────────────────
    // HELPERS
    // ───────────────────────────────────────────────────────────────

    /// @dev Computes the balanceCheck hash the same way processRingCT does (assembly keccak).
    function _computeBalanceCheck(
        bytes32[] memory inputs,
        bytes32[] memory outputs,
        bytes32 pseudo
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(inputs, outputs, pseudo));
    }

    /// @dev Builds a valid CLSAG signature for (ring, keyImages, message).
    ///      Steps:
    ///        1. Pick deterministic response scalars in (0, HALF_N].
    ///        2. Compute commitments.
    ///        3. Derive challenge via Fiat-Shamir.
    ///        4. Encode: challenge ++ responses.
    function _buildSignature(
        bytes32[] memory ring,
        bytes32[] memory keyImages,
        bytes32 message
    ) internal pure returns (bytes memory) {
        uint256 ringSize = ring.length;
        bytes32[] memory responses = new bytes32[](ringSize);
        bytes32[] memory commitments = new bytes32[](ringSize);

        for (uint256 i = 0; i < ringSize; i++) {
            // Deterministic scalar: 1 + i  (all < HALF_N, non-zero)
            responses[i] = bytes32(uint256(i + 1));
            commitments[i] = keccak256(
                abi.encodePacked(COMMITMENT_DOMAIN, responses[i], ring[i])
            );
        }

        bytes32 challenge = keccak256(
            abi.encodePacked(
                CHALLENGE_DOMAIN,
                message,
                ring,
                keyImages,
                commitments
            )
        );

        // Encode: challenge || responses
        bytes memory sig = new bytes(32 + ringSize * 32);
        assembly {
            mstore(add(sig, 32), challenge)
        }
        for (uint256 i = 0; i < ringSize; i++) {
            bytes32 r = responses[i];
            uint256 offset = 32 + 32 + i * 32; // skip length word + challenge
            assembly {
                mstore(add(sig, offset), r)
            }
        }
        return sig;
    }

    // ───────────────────────────────────────────────────────────────
    // WIRING TESTS
    // ───────────────────────────────────────────────────────────────

    function test_VerifierWiredCorrectly() public view {
        assertEq(ringCT.ringSignatureVerifier(), address(clsag));
    }

    function test_CLSAGVerify_Standalone() public view {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = keccak256("member0");
        ring[1] = keccak256("member1");

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("keyImage0");

        bytes32 message = keccak256("testMessage");

        bytes memory sig = _buildSignature(ring, keyImages, message);
        bool valid = clsag.verify(ring, keyImages, sig, message);
        assertTrue(valid, "standalone CLSAG verification failed");
    }

    // ───────────────────────────────────────────────────────────────
    // FULL INTEGRATION: processRingCT
    // ───────────────────────────────────────────────────────────────

    function test_ProcessRingCT_SuccessWithCLSAG() public {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("input0");
        inputs[1] = keccak256("input1");

        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("output0");

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("keyImage0");

        bytes32 pseudo = keccak256("pseudo0");

        // Compute the message (balance check) exactly as processRingCT does
        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);

        // Build a valid CLSAG signature for ring=inputs
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        // Should succeed—no revert
        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);

        // Key image should now be spent
        assertTrue(ringCT.usedKeyImages(keyImages[0]));
        // Output commitments should be in the set
        assertTrue(ringCT.commitmentSet(outputs[0]));
    }

    function test_ProcessRingCT_RevertDoubleSpend() public {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("input_ds_0");
        inputs[1] = keccak256("input_ds_1");

        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("output_ds_0");

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("keyImage_ds");

        bytes32 pseudo = keccak256("pseudo_ds");
        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        // First tx succeeds
        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);

        // Second tx with same key image must revert
        bytes32[] memory outputs2 = new bytes32[](1);
        outputs2[0] = keccak256("output_ds_1");
        bytes32 balanceCheck2 = _computeBalanceCheck(inputs, outputs2, pseudo);
        bytes memory sig2 = _buildSignature(inputs, keyImages, balanceCheck2);

        vm.expectRevert();
        ringCT.processRingCT(inputs, outputs2, keyImages, sig2, pseudo);
    }

    function test_ProcessRingCT_RevertWithoutVerifier() public {
        GasOptimizedRingCT bare = new GasOptimizedRingCT();
        // Don't set verifier — should revert with RingSignatureVerificationNotImplemented

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("in0");
        inputs[1] = keccak256("in1");
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("out0");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki0");
        bytes32 pseudo = keccak256("p0");

        vm.expectRevert();
        bare.processRingCT(inputs, outputs, keyImages, hex"", pseudo);
    }

    function test_ProcessRingCT_RevertInvalidSignature() public {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("inv_in0");
        inputs[1] = keccak256("inv_in1");
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("inv_out0");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("inv_ki");
        bytes32 pseudo = keccak256("inv_p");

        // Build signature for a DIFFERENT message — should fail verification
        bytes memory badSig = _buildSignature(
            inputs,
            keyImages,
            keccak256("wrong_message")
        );

        vm.expectRevert();
        ringCT.processRingCT(inputs, outputs, keyImages, badSig, pseudo);
    }

    function test_ProcessRingCT_RingSize4() public {
        bytes32[] memory inputs = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            inputs[i] = keccak256(abi.encodePacked("ring4_in", i));
        }
        bytes32[] memory outputs = new bytes32[](2);
        outputs[0] = keccak256("ring4_out0");
        outputs[1] = keccak256("ring4_out1");
        bytes32[] memory keyImages = new bytes32[](2);
        keyImages[0] = keccak256("ring4_ki0");
        keyImages[1] = keccak256("ring4_ki1");
        bytes32 pseudo = keccak256("ring4_pseudo");

        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);

        for (uint256 i = 0; i < 2; i++) {
            assertTrue(ringCT.usedKeyImages(keyImages[i]));
            assertTrue(ringCT.commitmentSet(outputs[i]));
        }
    }

    function test_ProcessRingCT_MaxRingSize16() public {
        bytes32[] memory inputs = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            inputs[i] = keccak256(abi.encodePacked("ring16_in", i));
        }
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("ring16_out0");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ring16_ki0");
        bytes32 pseudo = keccak256("ring16_pseudo");

        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);

        assertTrue(ringCT.usedKeyImages(keyImages[0]));
    }

    // ───────────────────────────────────────────────────────────────
    // CLSAG STANDALONE EDGE CASES
    // ───────────────────────────────────────────────────────────────

    function test_CLSAGVerify_RevertRingTooSmall() public {
        bytes32[] memory ring = new bytes32[](1);
        ring[0] = keccak256("solo");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki");

        vm.expectRevert(CLSAGVerifier.InvalidRingSize.selector);
        clsag.verify(ring, keyImages, hex"", keccak256("m"));
    }

    function test_CLSAGVerify_RevertRingTooLarge() public {
        bytes32[] memory ring = new bytes32[](17);
        for (uint256 i = 0; i < 17; i++) ring[i] = bytes32(uint256(i + 100));
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki");

        vm.expectRevert(CLSAGVerifier.InvalidRingSize.selector);
        clsag.verify(ring, keyImages, hex"", keccak256("m"));
    }

    function test_CLSAGVerify_RevertEmptyKeyImages() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = keccak256("a");
        ring[1] = keccak256("b");
        bytes32[] memory keyImages = new bytes32[](0);

        vm.expectRevert(CLSAGVerifier.InvalidKeyImageCount.selector);
        clsag.verify(ring, keyImages, hex"", keccak256("m"));
    }

    function test_CLSAGVerify_RevertBadSignatureLength() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = keccak256("a");
        ring[1] = keccak256("b");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki");

        // Expected: 32 + 2*32 = 96 bytes, provide 64
        vm.expectRevert(CLSAGVerifier.InvalidSignatureLength.selector);
        clsag.verify(ring, keyImages, new bytes(64), keccak256("m"));
    }

    function test_CLSAGVerify_InvalidResponseScalar() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = keccak256("a");
        ring[1] = keccak256("b");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki");

        // Build sig with response[0] = 0 (invalid)
        bytes memory sig = new bytes(96); // 32 + 2*32
        // challenge at offset 0 — doesn't matter, we'll fail on scalar check
        // response[0] = 0 (zero scalar)
        // response[1] = 1
        assembly {
            mstore(add(sig, 32), 0) // challenge placeholder
            mstore(add(sig, 64), 0) // response 0 = 0 (invalid!)
            mstore(add(sig, 96), 1) // response 1 = 1
        }

        bool valid = clsag.verify(ring, keyImages, sig, keccak256("m"));
        assertFalse(valid, "should fail for zero scalar");
    }

    function test_CLSAGVerify_WrongMessage() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = keccak256("a");
        ring[1] = keccak256("b");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki");

        bytes32 correctMsg = keccak256("correct");
        bytes memory sig = _buildSignature(ring, keyImages, correctMsg);

        // Verify against wrong message
        bool valid = clsag.verify(ring, keyImages, sig, keccak256("wrong"));
        assertFalse(valid, "should fail for wrong message");
    }

    // ───────────────────────────────────────────────────────────────
    // CLSAG HELPERS
    // ───────────────────────────────────────────────────────────────

    function test_ComputeKeyImage() public view {
        bytes32 secret = keccak256("secret");
        bytes32 pubkeyHash = keccak256("pubkey");
        bytes32 ki = clsag.computeKeyImage(secret, pubkeyHash);
        bytes32 expected = keccak256(
            abi.encodePacked(KEY_IMAGE_DOMAIN, secret, pubkeyHash)
        );
        assertEq(ki, expected);
    }

    function test_ComputeCommitment() public view {
        bytes32 response = bytes32(uint256(42));
        bytes32 ringMember = keccak256("member");
        bytes32 c = clsag.computeCommitment(response, ringMember);
        bytes32 expected = keccak256(
            abi.encodePacked(COMMITMENT_DOMAIN, response, ringMember)
        );
        assertEq(c, expected);
    }

    function test_ComputeChallenge() public view {
        bytes32 message = keccak256("msg");
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = keccak256("a");
        ring[1] = keccak256("b");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki");
        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = keccak256("c0");
        commitments[1] = keccak256("c1");

        bytes32 ch = clsag.computeChallenge(
            message,
            ring,
            keyImages,
            commitments
        );
        bytes32 expected = keccak256(
            abi.encodePacked(
                CHALLENGE_DOMAIN,
                message,
                ring,
                keyImages,
                commitments
            )
        );
        assertEq(ch, expected);
    }

    // ───────────────────────────────────────────────────────────────
    // BATCH VERIFICATION
    // ───────────────────────────────────────────────────────────────

    function test_BatchVerify() public view {
        // Build 3 valid signatures, 1 invalid
        uint256 count = 4;
        bytes32[][] memory rings = new bytes32[][](count);
        bytes32[][] memory allKeyImages = new bytes32[][](count);
        bytes[] memory sigs = new bytes[](count);
        bytes32[] memory messages = new bytes32[](count);

        for (uint256 i = 0; i < count; i++) {
            rings[i] = new bytes32[](2);
            rings[i][0] = keccak256(abi.encodePacked("batch_r0_", i));
            rings[i][1] = keccak256(abi.encodePacked("batch_r1_", i));
            allKeyImages[i] = new bytes32[](1);
            allKeyImages[i][0] = keccak256(abi.encodePacked("batch_ki_", i));
            messages[i] = keccak256(abi.encodePacked("batch_msg_", i));

            if (i < 3) {
                sigs[i] = _buildSignature(
                    rings[i],
                    allKeyImages[i],
                    messages[i]
                );
            } else {
                // Build signature for wrong message
                sigs[i] = _buildSignature(
                    rings[i],
                    allKeyImages[i],
                    keccak256("wrong")
                );
            }
        }

        uint256 results = clsag.batchVerify(
            rings,
            allKeyImages,
            sigs,
            messages
        );

        // First 3 valid → bits 0,1,2 set; 4th invalid → bit 3 unset
        assertEq(results & (1 << 0), 1 << 0, "sig 0 should be valid");
        assertEq(results & (1 << 1), 1 << 1, "sig 1 should be valid");
        assertEq(results & (1 << 2), 1 << 2, "sig 2 should be valid");
        assertEq(results & (1 << 3), 0, "sig 3 should be invalid");
    }

    // ───────────────────────────────────────────────────────────────
    // GAS BENCHMARKS
    // ───────────────────────────────────────────────────────────────

    function test_GasBenchmark_RingSize2() public {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = keccak256("gas2_in0");
        inputs[1] = keccak256("gas2_in1");
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("gas2_out0");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("gas2_ki0");
        bytes32 pseudo = keccak256("gas2_pseudo");
        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        uint256 gasBefore = gasleft();
        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("Gas (ring-2)", gasUsed);
    }

    function test_GasBenchmark_RingSize8() public {
        bytes32[] memory inputs = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) {
            inputs[i] = keccak256(abi.encodePacked("gas8_in", i));
        }
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("gas8_out0");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("gas8_ki0");
        bytes32 pseudo = keccak256("gas8_pseudo");
        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        uint256 gasBefore = gasleft();
        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("Gas (ring-8)", gasUsed);
    }

    // ───────────────────────────────────────────────────────────────
    // FUZZ
    // ───────────────────────────────────────────────────────────────

    function testFuzz_ProcessRingCT(uint256 seed) public {
        // Ring size 2-8 from seed
        uint256 ringSize = 2 + (seed % 7);
        bytes32[] memory inputs = new bytes32[](ringSize);
        for (uint256 i = 0; i < ringSize; i++) {
            inputs[i] = keccak256(abi.encodePacked("fuzz_in", seed, i));
        }
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256(abi.encodePacked("fuzz_out", seed));
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256(abi.encodePacked("fuzz_ki", seed));
        bytes32 pseudo = keccak256(abi.encodePacked("fuzz_pseudo", seed));

        bytes32 balanceCheck = _computeBalanceCheck(inputs, outputs, pseudo);
        bytes memory sig = _buildSignature(inputs, keyImages, balanceCheck);

        ringCT.processRingCT(inputs, outputs, keyImages, sig, pseudo);
        assertTrue(ringCT.usedKeyImages(keyImages[0]));
    }
}
