// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/libraries/ProofEnvelope.sol";
import "../../contracts/libraries/FixedSizeMessageWrapper.sol";

contract ProofEnvelopeTest is Test {
    using ProofEnvelope for bytes;

    ProofEnvelopeWrapper internal wrapper;

    function setUp() public {
        wrapper = new ProofEnvelopeWrapper();
    }

    // ════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ════════════════════════════════════════════════════════════════

    function test_envelopeSize() public pure {
        assertEq(ProofEnvelope.ENVELOPE_SIZE, 2048);
    }

    function test_maxProofSize() public pure {
        assertEq(ProofEnvelope.MAX_PROOF_SIZE, 2046); // 2048 - 2 prefix
    }

    // ════════════════════════════════════════════════════════════════
    // WRAP / UNWRAP ROUNDTRIP
    // ════════════════════════════════════════════════════════════════

    function test_wrapUnwrap_emptyProof() public pure {
        bytes memory proof = "";
        bytes memory envelope = ProofEnvelope.wrap(proof);

        assertEq(envelope.length, ProofEnvelope.ENVELOPE_SIZE);

        bytes memory unwrapped = ProofEnvelope.unwrap(envelope);
        assertEq(unwrapped.length, 0);
    }

    function test_wrapUnwrap_smallProof() public pure {
        // Groth16-sized proof (~256 bytes)
        bytes memory proof = new bytes(256);
        for (uint256 i; i < 256; i++) {
            proof[i] = bytes1(uint8(i % 256));
        }

        bytes memory envelope = ProofEnvelope.wrap(proof);
        assertEq(envelope.length, ProofEnvelope.ENVELOPE_SIZE);

        bytes memory unwrapped = ProofEnvelope.unwrap(envelope);
        assertEq(unwrapped.length, 256);
        assertEq(keccak256(unwrapped), keccak256(proof));
    }

    function test_wrapUnwrap_largeProof() public pure {
        // PLONK-sized proof (~1500 bytes)
        bytes memory proof = new bytes(1500);
        for (uint256 i; i < 1500; i++) {
            proof[i] = bytes1(uint8(i % 256));
        }

        bytes memory envelope = ProofEnvelope.wrap(proof);
        assertEq(envelope.length, ProofEnvelope.ENVELOPE_SIZE);

        bytes memory unwrapped = ProofEnvelope.unwrap(envelope);
        assertEq(unwrapped.length, 1500);
        assertEq(keccak256(unwrapped), keccak256(proof));
    }

    function test_wrapUnwrap_maxSizeProof() public pure {
        bytes memory proof = new bytes(ProofEnvelope.MAX_PROOF_SIZE);
        for (uint256 i; i < proof.length; i++) {
            proof[i] = bytes1(uint8(i % 256));
        }

        bytes memory envelope = ProofEnvelope.wrap(proof);
        assertEq(envelope.length, ProofEnvelope.ENVELOPE_SIZE);

        bytes memory unwrapped = ProofEnvelope.unwrap(envelope);
        assertEq(unwrapped.length, ProofEnvelope.MAX_PROOF_SIZE);
        assertEq(keccak256(unwrapped), keccak256(proof));
    }

    // ════════════════════════════════════════════════════════════════
    // UNIFORM SIZE — ALL PROOF TYPES PRODUCE SAME ENVELOPE SIZE
    // ════════════════════════════════════════════════════════════════

    function test_uniformSize_differentProofSystems() public pure {
        // Simulate different proof system sizes
        bytes memory groth16 = new bytes(256);
        bytes memory bulletproof = new bytes(700);
        bytes memory plonk = new bytes(1500);
        bytes memory small = new bytes(32);

        bytes memory env1 = ProofEnvelope.wrap(groth16);
        bytes memory env2 = ProofEnvelope.wrap(bulletproof);
        bytes memory env3 = ProofEnvelope.wrap(plonk);
        bytes memory env4 = ProofEnvelope.wrap(small);

        // ALL envelopes must be exactly the same size
        assertEq(env1.length, env2.length);
        assertEq(env2.length, env3.length);
        assertEq(env3.length, env4.length);
        assertEq(env4.length, ProofEnvelope.ENVELOPE_SIZE);
    }

    // ════════════════════════════════════════════════════════════════
    // ERROR CASES
    // ════════════════════════════════════════════════════════════════

    function test_wrap_revertsTooLarge() public {
        bytes memory tooLarge = new bytes(ProofEnvelope.MAX_PROOF_SIZE + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofEnvelope.ProofTooLarge.selector,
                ProofEnvelope.MAX_PROOF_SIZE + 1,
                ProofEnvelope.MAX_PROOF_SIZE
            )
        );
        wrapper.wrap(tooLarge);
    }

    function test_unwrap_revertsWrongSize() public {
        bytes memory wrongSize = new bytes(1024);
        vm.expectRevert(
            abi.encodeWithSelector(ProofEnvelope.InvalidEnvelope.selector, 1024)
        );
        wrapper.unwrap(wrongSize);
    }

    // ════════════════════════════════════════════════════════════════
    // VALIDATE
    // ════════════════════════════════════════════════════════════════

    function test_validate_validEnvelope() public pure {
        bytes memory proof = new bytes(256);
        bytes memory envelope = ProofEnvelope.wrap(proof);

        (bool valid, uint256 proofLen) = ProofEnvelope.validate(envelope);
        assertTrue(valid);
        assertEq(proofLen, 256);
    }

    function test_validate_invalidSize() public pure {
        bytes memory bad = new bytes(100);
        (bool valid, ) = ProofEnvelope.validate(bad);
        assertFalse(valid);
    }

    // ════════════════════════════════════════════════════════════════
    // PADDING VERIFICATION — TRAILING BYTES ARE ZERO
    // ════════════════════════════════════════════════════════════════

    function test_wrap_trailingBytesAreZero() public pure {
        bytes memory proof = new bytes(100);
        for (uint256 i; i < 100; i++) {
            proof[i] = bytes1(0xFF);
        }

        bytes memory envelope = ProofEnvelope.wrap(proof);

        // Check that bytes after the proof are zero
        for (uint256 i = 102; i < ProofEnvelope.ENVELOPE_SIZE; i++) {
            assertEq(uint8(envelope[i]), 0);
        }
    }

    // ════════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ════════════════════════════════════════════════════════════════

    function testFuzz_wrapUnwrap_roundtrip(bytes calldata proof) public pure {
        vm.assume(proof.length <= ProofEnvelope.MAX_PROOF_SIZE);

        bytes memory envelope = ProofEnvelope.wrapCalldata(proof);
        assertEq(envelope.length, ProofEnvelope.ENVELOPE_SIZE);

        bytes memory unwrapped = ProofEnvelope.unwrap(envelope);
        assertEq(unwrapped.length, proof.length);
        assertEq(keccak256(unwrapped), keccak256(proof));
    }

    function testFuzz_validate_alwaysConsistentWithWrap(
        bytes calldata proof
    ) public pure {
        vm.assume(proof.length <= ProofEnvelope.MAX_PROOF_SIZE);

        bytes memory envelope = ProofEnvelope.wrapCalldata(proof);
        (bool valid, uint256 len) = ProofEnvelope.validate(envelope);
        assertTrue(valid);
        assertEq(len, proof.length);
    }
}

// ═════════════════════════════════════════════════════════════════════
// FIXED SIZE MESSAGE WRAPPER TESTS
// ═════════════════════════════════════════════════════════════════════

contract FixedSizeMessageWrapperTest is Test {
    FixedSizeMessageWrapperHelper internal msgWrapper;

    function setUp() public {
        msgWrapper = new FixedSizeMessageWrapperHelper();
    }

    // ════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ════════════════════════════════════════════════════════════════

    function test_messageEnvelopeSize() public pure {
        assertEq(FixedSizeMessageWrapper.MESSAGE_ENVELOPE_SIZE, 4096);
    }

    function test_maxPayloadSize() public pure {
        assertEq(FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE, 4092); // 4096 - 4
    }

    // ════════════════════════════════════════════════════════════════
    // WRAP / UNWRAP
    // ════════════════════════════════════════════════════════════════

    function test_wrapUnwrap_emptyPayload() public pure {
        bytes memory payload = "";
        bytes memory envelope = FixedSizeMessageWrapper.wrap(payload);
        assertEq(
            envelope.length,
            FixedSizeMessageWrapper.MESSAGE_ENVELOPE_SIZE
        );

        bytes memory unwrapped = FixedSizeMessageWrapper.unwrap(envelope);
        assertEq(unwrapped.length, 0);
    }

    function test_wrapUnwrap_typicalMessage() public pure {
        // Typical cross-chain transfer message (~300 bytes)
        bytes memory payload = new bytes(300);
        for (uint256 i; i < 300; i++) {
            payload[i] = bytes1(uint8(i % 256));
        }

        bytes memory envelope = FixedSizeMessageWrapper.wrap(payload);
        assertEq(
            envelope.length,
            FixedSizeMessageWrapper.MESSAGE_ENVELOPE_SIZE
        );

        bytes memory unwrapped = FixedSizeMessageWrapper.unwrap(envelope);
        assertEq(keccak256(unwrapped), keccak256(payload));
    }

    // ════════════════════════════════════════════════════════════════
    // UNIFORM SIZE — ALL MESSAGE TYPES PRODUCE SAME SIZE
    // ════════════════════════════════════════════════════════════════

    function test_uniformSize_differentMessageTypes() public pure {
        bytes memory simpleTransfer = new bytes(200);
        bytes memory multiSig = new bytes(600);
        bytes memory conditional = new bytes(2000);
        bytes memory proofBearing = new bytes(3500);

        bytes memory env1 = FixedSizeMessageWrapper.wrap(simpleTransfer);
        bytes memory env2 = FixedSizeMessageWrapper.wrap(multiSig);
        bytes memory env3 = FixedSizeMessageWrapper.wrap(conditional);
        bytes memory env4 = FixedSizeMessageWrapper.wrap(proofBearing);

        assertEq(env1.length, env2.length);
        assertEq(env2.length, env3.length);
        assertEq(env3.length, env4.length);
        assertEq(env4.length, FixedSizeMessageWrapper.MESSAGE_ENVELOPE_SIZE);
    }

    // ════════════════════════════════════════════════════════════════
    // ERROR CASES
    // ════════════════════════════════════════════════════════════════

    function test_wrap_revertsTooLarge() public {
        bytes memory tooLarge = new bytes(
            FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE + 1
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                FixedSizeMessageWrapper.PayloadTooLarge.selector,
                FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE + 1,
                FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE
            )
        );
        msgWrapper.wrap(tooLarge);
    }

    function test_unwrap_revertsWrongSize() public {
        bytes memory bad = new bytes(2048);
        vm.expectRevert(
            abi.encodeWithSelector(
                FixedSizeMessageWrapper.InvalidMessageEnvelope.selector,
                2048
            )
        );
        msgWrapper.unwrap(bad);
    }

    // ════════════════════════════════════════════════════════════════
    // VALIDATE
    // ════════════════════════════════════════════════════════════════

    function test_validate_valid() public pure {
        bytes memory payload = new bytes(500);
        bytes memory envelope = FixedSizeMessageWrapper.wrap(payload);

        (bool valid, uint256 payloadLen) = FixedSizeMessageWrapper.validate(
            envelope
        );
        assertTrue(valid);
        assertEq(payloadLen, 500);
    }

    function test_validate_invalidSize() public pure {
        bytes memory bad = new bytes(100);
        (bool valid, ) = FixedSizeMessageWrapper.validate(bad);
        assertFalse(valid);
    }

    // ════════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ════════════════════════════════════════════════════════════════

    function testFuzz_wrapUnwrap_roundtrip(bytes calldata payload) public pure {
        vm.assume(payload.length <= FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE);

        bytes memory envelope = FixedSizeMessageWrapper.wrapCalldata(payload);
        assertEq(
            envelope.length,
            FixedSizeMessageWrapper.MESSAGE_ENVELOPE_SIZE
        );

        bytes memory unwrapped = FixedSizeMessageWrapper.unwrap(envelope);
        assertEq(unwrapped.length, payload.length);
        assertEq(keccak256(unwrapped), keccak256(payload));
    }

    function testFuzz_uniformEnvelopeSize(
        uint256 size1,
        uint256 size2
    ) public pure {
        size1 = bound(size1, 0, FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE);
        size2 = bound(size2, 0, FixedSizeMessageWrapper.MAX_PAYLOAD_SIZE);

        bytes memory p1 = new bytes(size1);
        bytes memory p2 = new bytes(size2);

        bytes memory e1 = FixedSizeMessageWrapper.wrap(p1);
        bytes memory e2 = FixedSizeMessageWrapper.wrap(p2);

        // Regardless of input size, envelope size must be identical
        assertEq(e1.length, e2.length);
    }
}

// ═════════════════════════════════════════════════════════════════════
// HELPER CONTRACTS (for vm.expectRevert on library calls)
// ═════════════════════════════════════════════════════════════════════

contract ProofEnvelopeWrapper {
    function wrap(bytes memory proof) external pure returns (bytes memory) {
        return ProofEnvelope.wrap(proof);
    }

    function unwrap(
        bytes memory envelope
    ) external pure returns (bytes memory) {
        return ProofEnvelope.unwrap(envelope);
    }
}

contract FixedSizeMessageWrapperHelper {
    function wrap(bytes memory payload) external pure returns (bytes memory) {
        return FixedSizeMessageWrapper.wrap(payload);
    }

    function unwrap(
        bytes memory envelope
    ) external pure returns (bytes memory) {
        return FixedSizeMessageWrapper.unwrap(envelope);
    }
}
