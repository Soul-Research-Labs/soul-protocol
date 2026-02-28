// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {RingSignatureVerifier} from "../../contracts/verifiers/RingSignatureVerifier.sol";
// IRingSignatureVerifier unused — types referenced via RingSignatureVerifier directly
import {BN254} from "../../contracts/libraries/BN254.sol";

/**
 * @title RingSignatureVerifierTest
 * @notice Comprehensive tests for the production CLSAG ring signature verifier
 * @dev Generates valid CLSAG signatures on-chain in test helpers and verifies them.
 *
 * Test categories:
 *   1. Valid signatures (ring sizes 2, 4, 8)
 *   2. Invalid signatures (wrong message, corrupted challenge, wrong key image)
 *   3. Input validation (revert cases)
 *   4. Gas benchmarks
 */
contract RingSignatureVerifierTest is Test {
    RingSignatureVerifier public verifier;

    // Domain separator — must match the verifier contract
    bytes13 constant DOMAIN = "Zaseon_CLSAG_v1";

    function setUp() public {
        verifier = new RingSignatureVerifier();
    }

    /*//////////////////////////////////////////////////////////////
                         KEY GENERATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Compute public key from secret key: P = sk * G
    function _pubkey(uint256 sk) internal view returns (uint256 x, uint256 y) {
        return BN254.mul(BN254.G_X, BN254.G_Y, sk);
    }

    /// @dev Compute compressed public key from secret key
    function _compressedPubkey(uint256 sk) internal view returns (bytes32) {
        (uint256 x, uint256 y) = _pubkey(sk);
        return BN254.compress(x, y);
    }

    /// @dev Generate a ring of compressed public keys from secret keys
    function _makeRing(
        uint256[] memory secretKeys
    ) internal view returns (bytes32[] memory ring) {
        ring = new bytes32[](secretKeys.length);
        for (uint256 i; i < secretKeys.length; i++) {
            ring[i] = _compressedPubkey(secretKeys[i]);
        }
    }

    /// @dev Compute key image: I = sk * H_p(pk)
    function _keyImage(
        uint256 sk,
        bytes32 compressedPk
    ) internal view returns (uint256 x, uint256 y) {
        (uint256 hpX, uint256 hpY) = BN254.hashToPoint(compressedPk);
        return BN254.mul(hpX, hpY, sk);
    }

    /// @dev Compute compressed key image
    function _compressedKeyImage(
        uint256 sk,
        bytes32 compressedPk
    ) internal view returns (bytes32) {
        (uint256 x, uint256 y) = _keyImage(sk, compressedPk);
        return BN254.compress(x, y);
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNING HELPER
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Generate a valid CLSAG ring signature (for testing only)
     * @param signerSk Secret key of the signer
     * @param signerIdx Position of the signer in the ring
     * @param ring Array of compressed public keys
     * @param message Message to sign
     * @return sig The packed signature bytes (c0, s_0, ..., s_{n-1})
     * @return keyImageComp The compressed key image
     */
    function _sign(
        uint256 signerSk,
        uint256 signerIdx,
        bytes32[] memory ring,
        bytes32 message
    ) internal view returns (bytes memory sig, bytes32 keyImageComp) {
        uint256 ringSize = ring.length;

        // Compute key image
        (uint256 kIx, uint256 kIy) = _keyImage(signerSk, ring[signerIdx]);
        keyImageComp = BN254.compress(kIx, kIy);

        // Deterministic nonce (safe for testing; production should use secure randomness)
        uint256 alpha = uint256(
            keccak256(abi.encodePacked(signerSk, message, uint256(0xCAFE)))
        ) % BN254.N;

        // Compute initial commitment: L = alpha*G, R = alpha*H_p(pk)
        (uint256 aGx, uint256 aGy) = BN254.mul(BN254.G_X, BN254.G_Y, alpha);
        (uint256 hpX, uint256 hpY) = BN254.hashToPoint(ring[signerIdx]);
        (uint256 aHx, uint256 aHy) = BN254.mul(hpX, hpY, alpha);

        // Challenges and responses arrays
        uint256[] memory challenges = new uint256[](ringSize + 1);
        uint256[] memory responses = new uint256[](ringSize);

        // c_{signerIdx+1} from the signer's commitment
        uint256 nextIdx = (signerIdx + 1) % ringSize;
        challenges[nextIdx] =
            uint256(
                keccak256(abi.encodePacked(DOMAIN, message, aGx, aGy, aHx, aHy))
            ) %
            BN254.N;

        // Propagate challenge chain for non-signer positions
        for (uint256 k = 1; k < ringSize; k++) {
            uint256 i = (signerIdx + k) % ringSize;
            uint256 ni = (i + 1) % ringSize;

            // Deterministic random response for non-signer i
            responses[i] =
                uint256(
                    keccak256(
                        abi.encodePacked(signerSk, i, message, uint256(0xBEEF))
                    )
                ) %
                BN254.N;

            uint256 Lx;
            uint256 Ly;
            uint256 Rx;
            uint256 Ry;
            {
                // L_i = s_i * G + c_i * P_i
                (uint256 pkX, uint256 pkY) = BN254.decompress(ring[i]);
                (uint256 sGx, uint256 sGy) = BN254.mul(
                    BN254.G_X,
                    BN254.G_Y,
                    responses[i]
                );
                (uint256 cPx, uint256 cPy) = BN254.mul(pkX, pkY, challenges[i]);
                (Lx, Ly) = BN254.add(sGx, sGy, cPx, cPy);
            }
            {
                // R_i = s_i * H_p(P_i) + c_i * I
                (uint256 hX, uint256 hY) = BN254.hashToPoint(ring[i]);
                (uint256 sHx, uint256 sHy) = BN254.mul(hX, hY, responses[i]);
                (uint256 cIx, uint256 cIy) = BN254.mul(kIx, kIy, challenges[i]);
                (Rx, Ry) = BN254.add(sHx, sHy, cIx, cIy);
            }

            challenges[ni] =
                uint256(
                    keccak256(abi.encodePacked(DOMAIN, message, Lx, Ly, Rx, Ry))
                ) %
                BN254.N;
        }

        // Solve for signer's response: s_j = alpha - c_j * sk (mod N)
        uint256 csk = mulmod(challenges[signerIdx], signerSk, BN254.N);
        responses[signerIdx] = addmod(alpha, BN254.N - csk, BN254.N);

        // Pack signature: challenges[0] || responses[0] || ... || responses[n-1]
        sig = new bytes(32 * (1 + ringSize));
        bytes32 c0Bytes = bytes32(challenges[0]);
        assembly ("memory-safe") {
            mstore(add(sig, 32), c0Bytes)
        }
        for (uint256 i; i < ringSize; i++) {
            bytes32 si = bytes32(responses[i]);
            uint256 offset = 64 + i * 32; // skip length (32) + c0 (32)
            assembly ("memory-safe") {
                mstore(add(sig, offset), si)
            }
        }
    }

    /// @dev Build keyImages array (all identical entries for CLSAG)
    function _fillKeyImages(
        bytes32 ki,
        uint256 size
    ) internal pure returns (bytes32[] memory arr) {
        arr = new bytes32[](size);
        for (uint256 i; i < size; i++) {
            arr[i] = ki;
        }
    }

    /*//////////////////////////////////////////////////////////////
                      VALID SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_validSignature_ring2() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("test_message_ring2");

        // Sign as member 0
        (bytes memory sig, bytes32 ki) = _sign(42, 0, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 2);

        bool valid = verifier.verify(ring, keyImages, sig, message);
        assertTrue(valid, "Valid ring-2 signature should verify");
    }

    function test_validSignature_ring2_signerAt1() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 100;
        sks[1] = 200;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("test_signer_position_1");

        // Sign as member 1
        (bytes memory sig, bytes32 ki) = _sign(200, 1, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 2);

        bool valid = verifier.verify(ring, keyImages, sig, message);
        assertTrue(valid, "Valid ring-2 signature (signer=1) should verify");
    }

    function test_validSignature_ring4() public view {
        uint256[] memory sks = new uint256[](4);
        sks[0] = 10;
        sks[1] = 20;
        sks[2] = 30;
        sks[3] = 40;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("ring4_test");

        // Sign as member 2
        (bytes memory sig, bytes32 ki) = _sign(30, 2, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 4);

        assertTrue(
            verifier.verify(ring, keyImages, sig, message),
            "Valid ring-4 signature should verify"
        );
    }

    function test_validSignature_ring8() public view {
        uint256[] memory sks = new uint256[](8);
        for (uint256 i; i < 8; i++) {
            sks[i] = 100 + i;
        }

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("ring8_large_anonymity_set");

        // Sign as member 5
        (bytes memory sig, bytes32 ki) = _sign(105, 5, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 8);

        assertTrue(
            verifier.verify(ring, keyImages, sig, message),
            "Valid ring-8 signature should verify"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    INVALID SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_invalidSignature_wrongMessage() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("original_message");

        (bytes memory sig, bytes32 ki) = _sign(42, 0, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 2);

        // Verify with DIFFERENT message
        bytes32 wrongMessage = keccak256("tampered_message");
        bool valid = verifier.verify(ring, keyImages, sig, wrongMessage);
        assertFalse(valid, "Wrong message should fail verification");
    }

    function test_invalidSignature_corruptedChallenge() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("test_corruption");

        (bytes memory sig, bytes32 ki) = _sign(42, 0, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 2);

        // Corrupt c_0 (first 32 bytes of signature)
        sig[0] = bytes1(uint8(sig[0]) ^ 0x01);

        bool valid = verifier.verify(ring, keyImages, sig, message);
        assertFalse(valid, "Corrupted challenge should fail verification");
    }

    function test_invalidSignature_corruptedResponse() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("test_response_corruption");

        (bytes memory sig, bytes32 ki) = _sign(42, 0, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 2);

        // Corrupt s_0 (byte 32 of signature)
        sig[32] = bytes1(uint8(sig[32]) ^ 0xFF);

        bool valid = verifier.verify(ring, keyImages, sig, message);
        assertFalse(valid, "Corrupted response should fail verification");
    }

    function test_invalidSignature_wrongKeyImage() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;

        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("wrong_key_image");

        (bytes memory sig, ) = _sign(42, 0, ring, message);

        // Use key image from a DIFFERENT secret key
        bytes32 wrongKi = _compressedKeyImage(99, _compressedPubkey(99));
        bytes32[] memory keyImages = _fillKeyImages(wrongKi, 2);

        bool valid = verifier.verify(ring, keyImages, sig, message);
        assertFalse(valid, "Wrong key image should fail verification");
    }

    /*//////////////////////////////////////////////////////////////
                      REVERT CASES
    //////////////////////////////////////////////////////////////*/

    function test_revert_ringSizeTooSmall() public {
        bytes32[] memory ring = new bytes32[](1);
        ring[0] = _compressedPubkey(42);
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = _compressedKeyImage(42, ring[0]);

        vm.expectRevert(
            abi.encodeWithSelector(
                RingSignatureVerifier.RingSizeTooSmall.selector,
                1,
                2
            )
        );
        verifier.verify(ring, keyImages, new bytes(64), keccak256("m"));
    }

    function test_revert_zeroMessage() public {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;
        bytes32[] memory ring = _makeRing(sks);
        bytes32[] memory keyImages = _fillKeyImages(
            _compressedKeyImage(42, ring[0]),
            2
        );

        vm.expectRevert(RingSignatureVerifier.ZeroMessage.selector);
        verifier.verify(ring, keyImages, new bytes(96), bytes32(0));
    }

    function test_revert_signatureLengthMismatch() public {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;
        bytes32[] memory ring = _makeRing(sks);
        bytes32[] memory keyImages = _fillKeyImages(
            _compressedKeyImage(42, ring[0]),
            2
        );

        // Ring size 2 expects 32*(1+2)=96 bytes, provide 64
        vm.expectRevert(
            abi.encodeWithSelector(
                RingSignatureVerifier.InvalidSignatureLength.selector,
                64,
                96
            )
        );
        verifier.verify(ring, keyImages, new bytes(64), keccak256("m"));
    }

    function test_revert_keyImageMismatch() public {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;
        bytes32[] memory ring = _makeRing(sks);

        bytes32[] memory keyImages = new bytes32[](2);
        keyImages[0] = _compressedKeyImage(42, ring[0]);
        keyImages[1] = _compressedKeyImage(43, ring[1]); // Different!

        vm.expectRevert(RingSignatureVerifier.KeyImageMismatch.selector);
        verifier.verify(ring, keyImages, new bytes(96), keccak256("m"));
    }

    function test_revert_zeroRingMember() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = _compressedPubkey(42);
        ring[1] = bytes32(0); // Zero!

        bytes32[] memory keyImages = _fillKeyImages(
            _compressedKeyImage(42, ring[0]),
            2
        );

        vm.expectRevert(RingSignatureVerifier.ZeroRingMember.selector);
        verifier.verify(ring, keyImages, new bytes(96), keccak256("m"));
    }

    /*//////////////////////////////////////////////////////////////
                       CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getMinRingSize() public view {
        assertEq(verifier.getMinRingSize(), 2);
    }

    function test_getMaxRingSize() public view {
        assertEq(verifier.getMaxRingSize(), 64);
    }

    /*//////////////////////////////////////////////////////////////
                       GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function test_gas_ring2() public view {
        uint256[] memory sks = new uint256[](2);
        sks[0] = 42;
        sks[1] = 43;
        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("gas_ring2");
        (bytes memory sig, bytes32 ki) = _sign(42, 0, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 2);

        uint256 gasBefore = gasleft();
        verifier.verify(ring, keyImages, sig, message);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas for ring size 2:", gasUsed);
    }

    function test_gas_ring8() public view {
        uint256[] memory sks = new uint256[](8);
        for (uint256 i; i < 8; i++) sks[i] = 100 + i;
        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("gas_ring8");
        (bytes memory sig, bytes32 ki) = _sign(105, 5, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 8);

        uint256 gasBefore = gasleft();
        verifier.verify(ring, keyImages, sig, message);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas for ring size 8:", gasUsed);
    }

    function test_gas_ring16() public view {
        uint256[] memory sks = new uint256[](16);
        for (uint256 i; i < 16; i++) sks[i] = 500 + i;
        bytes32[] memory ring = _makeRing(sks);
        bytes32 message = keccak256("gas_ring16");
        (bytes memory sig, bytes32 ki) = _sign(507, 7, ring, message);
        bytes32[] memory keyImages = _fillKeyImages(ki, 16);

        uint256 gasBefore = gasleft();
        verifier.verify(ring, keyImages, sig, message);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas for ring size 16:", gasUsed);
    }

    /*//////////////////////////////////////////////////////////////
                     KEY IMAGE LINKABILITY
    //////////////////////////////////////////////////////////////*/

    /// @dev Same secret key must produce the same key image regardless of ring composition
    function test_keyImageDeterminism() public view {
        bytes32 pk = _compressedPubkey(42);
        bytes32 ki1 = _compressedKeyImage(42, pk);
        bytes32 ki2 = _compressedKeyImage(42, pk);
        assertEq(
            ki1,
            ki2,
            "Key image must be deterministic for same secret key"
        );
    }

    /// @dev Different secret keys must produce different key images
    function test_keyImageUniqueness() public view {
        bytes32 pk1 = _compressedPubkey(42);
        bytes32 pk2 = _compressedPubkey(43);
        bytes32 ki1 = _compressedKeyImage(42, pk1);
        bytes32 ki2 = _compressedKeyImage(43, pk2);
        assertTrue(ki1 != ki2, "Different keys must have different key images");
    }
}
