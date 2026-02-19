// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRingSignatureVerifier} from "../interfaces/IRingSignatureVerifier.sol";
import {BN254} from "../libraries/BN254.sol";

/**
 * @title RingSignatureVerifier
 * @author Soul Protocol
 * @notice Production CLSAG ring signature verifier for GasOptimizedRingCT
 * @dev Implements hash-based CLSAG (Concise Linkable Spontaneous Anonymous Group)
 *      verification using BN254 (alt_bn128) elliptic curve operations via EVM precompiles.
 *
 * Verification algorithm:
 *   1. Decode signature into (c_0, s_0, ..., s_{n-1})
 *   2. Decompress key image I and validate all keyImages entries are identical (CLSAG)
 *   3. For each ring member i:
 *      a. L_i = s_i · G + c_i · P_i              (using ecMul + ecAdd precompiles)
 *      b. H_p(P_i) = hashToPoint(ring[i])         (try-and-increment hash-to-curve)
 *      c. R_i = s_i · H_p(P_i) + c_i · I
 *      d. c_{i+1} = H("Soul_CLSAG_v1", message, L_i, R_i) mod n
 *   4. Verify ring closure: c_n == c_0
 *
 * Security properties:
 *   - Unforgeability: Cannot create valid signature without private key (DLOG assumption on BN254)
 *   - Anonymity: Verifier learns nothing about which ring member signed
 *   - Linkability: Key image I = sk · H_p(pk) is deterministic — enables double-spend detection
 *
 * Signature format (packed bytes, length = 32 + 32 × ringSize):
 *   [0..31]:   c_0 (initial challenge, uint256 < n)
 *   [32..63]:  s_0 (response scalar for ring[0], uint256 < n)
 *   [64..95]:  s_1
 *   ...
 *   [32+32×(n-1)..32+32×n-1]: s_{n-1}
 *
 * Compressed point format:
 *   bytes32 = x-coordinate | (y_parity << 255)
 *
 * Gas cost: ~26,000 per ring member (4 ecMul + 2 ecAdd + 1 hashToPoint + 1 decompress + 1 keccak)
 *   Ring size 2:  ~55k gas
 *   Ring size 8:  ~215k gas
 *   Ring size 64: ~1,700k gas
 *
 * @custom:security Production CLSAG verifier using BN254 precompiles.
 *                  See docs/THREAT_MODEL.md §8.4 "Ring Signature Verifier".
 */
contract RingSignatureVerifier is IRingSignatureVerifier {
    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error RingSizeTooSmall(uint256 actual, uint256 minimum);
    error RingSizeTooLarge(uint256 actual, uint256 maximum);
    error KeyImageCountMismatch(uint256 keyImages, uint256 ringSize);
    error InvalidSignatureLength(uint256 actual, uint256 expected);
    error ZeroKeyImage();
    error ZeroRingMember();
    error ZeroMessage();
    /// @dev All keyImages entries must be identical for CLSAG (single key image)
    error KeyImageMismatch();

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum ring size (anonymity set must contain at least 2 members)
    uint256 public constant MIN_RING_SIZE = 2;

    /// @notice Maximum ring size (bounded to prevent DoS via gas exhaustion)
    uint256 public constant MAX_RING_SIZE = 64;

    /// @dev Domain separator for challenge computation
    bytes13 internal constant DOMAIN = "Soul_CLSAG_v1";

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a CLSAG ring signature over BN254
     * @param ring Compressed BN254 public keys forming the ring (anonymity set)
     * @param keyImages Compressed BN254 key image (all entries must be identical)
     * @param signature Packed (c_0, s_0, ..., s_{n-1}) — see format in contract docs
     * @param message The message hash that was signed
     * @return valid True if the ring signature is cryptographically valid
     */
    function verify(
        bytes32[] calldata ring,
        bytes32[] calldata keyImages,
        bytes calldata signature,
        bytes32 message
    ) external view override returns (bool valid) {
        // ═══════════════════════════════════════════════════════════════
        // INPUT VALIDATION (reverts on malformed inputs)
        // ═══════════════════════════════════════════════════════════════

        uint256 ringSize = ring.length;
        if (ringSize < MIN_RING_SIZE)
            revert RingSizeTooSmall(ringSize, MIN_RING_SIZE);
        if (ringSize > MAX_RING_SIZE)
            revert RingSizeTooLarge(ringSize, MAX_RING_SIZE);

        if (keyImages.length != ringSize)
            revert KeyImageCountMismatch(keyImages.length, ringSize);

        // Signature = c_0 (32 bytes) + ringSize responses (32 bytes each)
        uint256 expectedLen = 32 * (1 + ringSize);
        if (signature.length != expectedLen)
            revert InvalidSignatureLength(signature.length, expectedLen);

        if (message == bytes32(0)) revert ZeroMessage();

        // Validate ring members are non-zero
        for (uint256 i; i < ringSize; ) {
            if (ring[i] == bytes32(0)) revert ZeroRingMember();
            unchecked {
                ++i;
            }
        }

        // CLSAG: single key image — all entries must be identical and non-zero
        bytes32 keyImageCompressed = keyImages[0];
        if (keyImageCompressed == bytes32(0)) revert ZeroKeyImage();
        for (uint256 i = 1; i < ringSize; ) {
            if (keyImages[i] != keyImageCompressed) revert KeyImageMismatch();
            unchecked {
                ++i;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // DECODE SIGNATURE
        // ═══════════════════════════════════════════════════════════════

        uint256 c0;
        assembly ("memory-safe") {
            c0 := calldataload(signature.offset)
        }
        // c_0 must be a valid scalar (< group order)
        if (c0 >= BN254.N) return false;

        // ═══════════════════════════════════════════════════════════════
        // DECOMPRESS KEY IMAGE
        // ═══════════════════════════════════════════════════════════════

        (uint256 keyImgX, uint256 keyImgY) = BN254.decompress(
            keyImageCompressed
        );

        // ═══════════════════════════════════════════════════════════════
        // CLSAG VERIFICATION — CHALLENGE CHAIN
        // ═══════════════════════════════════════════════════════════════

        uint256 challenge = c0;

        for (uint256 i; i < ringSize; ) {
            // Read response scalar s_i from signature
            uint256 s_i;
            assembly ("memory-safe") {
                s_i := calldataload(add(signature.offset, add(32, mul(i, 32))))
            }
            // Response must be a valid scalar
            if (s_i >= BN254.N) return false;

            // Scope block to limit stack pressure during EC operations
            uint256 Lx;
            uint256 Ly;
            uint256 Rx;
            uint256 Ry;
            {
                // Decompress ring member public key P_i
                (uint256 pkX, uint256 pkY) = BN254.decompress(ring[i]);

                // L_i = s_i · G + c_i · P_i
                (uint256 sGx, uint256 sGy) = BN254.mul(
                    BN254.G_X,
                    BN254.G_Y,
                    s_i
                );
                (uint256 cPx, uint256 cPy) = BN254.mul(pkX, pkY, challenge);
                (Lx, Ly) = BN254.add(sGx, sGy, cPx, cPy);
            }
            {
                // H_p(P_i) — hash ring member to curve point
                (uint256 hpX, uint256 hpY) = BN254.hashToPoint(ring[i]);

                // R_i = s_i · H_p(P_i) + c_i · I
                (uint256 sHx, uint256 sHy) = BN254.mul(hpX, hpY, s_i);
                (uint256 cIx, uint256 cIy) = BN254.mul(
                    keyImgX,
                    keyImgY,
                    challenge
                );
                (Rx, Ry) = BN254.add(sHx, sHy, cIx, cIy);
            }

            // c_{i+1} = H(domain, message, L_i, R_i) mod n
            challenge =
                uint256(
                    keccak256(abi.encodePacked(DOMAIN, message, Lx, Ly, Rx, Ry))
                ) %
                BN254.N;

            unchecked {
                ++i;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // VERIFY RING CLOSURE
        // ═══════════════════════════════════════════════════════════════

        return challenge == c0;
    }

    /// @inheritdoc IRingSignatureVerifier
    function getMinRingSize() external pure override returns (uint256) {
        return MIN_RING_SIZE;
    }

    /// @inheritdoc IRingSignatureVerifier
    function getMaxRingSize() external pure override returns (uint256) {
        return MAX_RING_SIZE;
    }
}
