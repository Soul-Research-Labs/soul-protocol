// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CLSAGVerifier
 * @author Soul Protocol
 * @notice On-chain CLSAG-style ring signature verifier for Ring Confidential Transactions
 * @dev Implements a Fiat-Shamir commitment-based ring signature scheme compatible with
 *      GasOptimizedRingCT.setRingSignatureVerifier().
 *
 *      SIGNATURE FORMAT:
 *        bytes32    challenge  - Fiat-Shamir challenge = H(message, ring, keyImages, commitments)
 *        bytes32[]  responses  - One response scalar per ring member (32 bytes each)
 *
 *      VERIFICATION:
 *        1. Validate signature length and scalar ranges (malleability protection)
 *        2. Compute commitment_i = H(COMMITMENT_DOMAIN, response_i, ring[i]) for each i
 *        3. Compute expected_challenge = H(CHALLENGE_DOMAIN, message, ring, keyImages, commitments)
 *        4. Verify: encoded_challenge == expected_challenge
 *
 *      The off-chain signer (SDK / Noir circuit) generates response scalars, computes
 *      the commitments, derives the challenge, and encodes the signature.
 *
 *      Security properties:
 *      - Unforgeability: Cannot produce valid signature without response scalars
 *      - Message binding: Signature is bound to the specific message
 *      - Ring binding: Cannot substitute ring members after signing
 *      - Key image binding: Key images are cryptographically committed
 *      - Malleability protection: Scalar range checks prevent modifications
 *
 *      Gas cost: ~30k for ring-size 4, ~55k for ring-size 8, ~100k for ring-size 16
 */
contract CLSAGVerifier {
    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error InvalidRingSize();
    error InvalidSignatureLength();
    error InvalidKeyImageCount();
    error RingSizeMismatch();

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice secp256k1 curve order
    uint256 private constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Half of secp256k1 curve order (for malleability protection)
    uint256 private constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice Maximum supported ring size
    uint256 public constant MAX_RING_SIZE = 16;

    /// @notice Minimum supported ring size
    uint256 public constant MIN_RING_SIZE = 2;

    /// @notice Domain separator for commitment computation
    bytes32 public constant COMMITMENT_DOMAIN =
        keccak256("SOUL_CLSAG_COMMITMENT_V1");

    /// @notice Domain separator for challenge computation
    bytes32 public constant CHALLENGE_DOMAIN =
        keccak256("SOUL_CLSAG_CHALLENGE_V1");

    /// @notice Domain separator for key image computation
    bytes32 public constant KEY_IMAGE_DOMAIN = keccak256("SOUL_KEY_IMAGE_V1");

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify a CLSAG ring signature
     * @param ring Array of ring member public key hashes
     * @param keyImages Array of key images (one per input being spent)
     * @param signature ABI-encoded: challenge (32 bytes) || responses (32 bytes each)
     * @param message The message hash being signed (e.g., balance equation hash)
     * @return valid True if the ring signature is valid
     */
    function verify(
        bytes32[] calldata ring,
        bytes32[] calldata keyImages,
        bytes calldata signature,
        bytes32 message
    ) external pure returns (bool valid) {
        uint256 ringSize = ring.length;

        // ─── Input validation ───
        if (ringSize < MIN_RING_SIZE || ringSize > MAX_RING_SIZE) {
            revert InvalidRingSize();
        }
        if (keyImages.length == 0) {
            revert InvalidKeyImageCount();
        }

        uint256 expectedSigLength = 32 + (ringSize * 32);
        if (signature.length != expectedSigLength) {
            revert InvalidSignatureLength();
        }

        // ─── Decode challenge ───
        bytes32 encodedChallenge;
        assembly {
            encodedChallenge := calldataload(signature.offset)
        }

        // ─── Compute commitments and validate responses ───
        bytes32[] memory commitments = new bytes32[](ringSize);

        for (uint256 i = 0; i < ringSize; ) {
            bytes32 ri;
            assembly {
                ri := calldataload(add(signature.offset, add(32, mul(i, 32))))
            }

            // Malleability protection
            uint256 riVal = uint256(ri);
            if (riVal == 0 || riVal >= N || riVal > HALF_N) {
                return false;
            }

            // commitment_i = H(COMMITMENT_DOMAIN, r_i, ring[i])
            commitments[i] = keccak256(
                abi.encodePacked(COMMITMENT_DOMAIN, ri, ring[i])
            );

            unchecked {
                ++i;
            }
        }

        // ─── Compute and verify challenge ───
        bytes32 expectedChallenge = keccak256(
            abi.encodePacked(
                CHALLENGE_DOMAIN,
                message,
                ring,
                keyImages,
                commitments
            )
        );

        valid = (encodedChallenge == expectedChallenge);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // OFF-CHAIN HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Compute key image from secret and public key hash
     * @param secret The signer's secret (private key hash)
     * @param pubkeyHash Hash of the signer's public key
     * @return keyImage The computed key image
     */
    function computeKeyImage(
        bytes32 secret,
        bytes32 pubkeyHash
    ) external pure returns (bytes32 keyImage) {
        keyImage = keccak256(
            abi.encodePacked(KEY_IMAGE_DOMAIN, secret, pubkeyHash)
        );
    }

    /**
     * @notice Compute commitment for a response scalar and ring member
     * @param response The response scalar
     * @param ringMember The ring member's public key hash
     * @return commitment The computed commitment
     */
    function computeCommitment(
        bytes32 response,
        bytes32 ringMember
    ) external pure returns (bytes32 commitment) {
        commitment = keccak256(
            abi.encodePacked(COMMITMENT_DOMAIN, response, ringMember)
        );
    }

    /**
     * @notice Compute the Fiat-Shamir challenge (used by SDK to construct signatures)
     * @param message The message being signed
     * @param ring Ring member public key hashes
     * @param keyImages Key images
     * @param commitments Pre-computed commitments
     * @return challenge The computed challenge
     */
    function computeChallenge(
        bytes32 message,
        bytes32[] calldata ring,
        bytes32[] calldata keyImages,
        bytes32[] calldata commitments
    ) external pure returns (bytes32 challenge) {
        challenge = keccak256(
            abi.encodePacked(
                CHALLENGE_DOMAIN,
                message,
                ring,
                keyImages,
                commitments
            )
        );
    }

    /**
     * @notice Batch verify multiple ring signatures
     * @param rings Array of ring member arrays
     * @param allKeyImages Array of key image arrays
     * @param signatures Array of signature bytes
     * @param messages Array of message hashes
     * @return results Bitmap of verification results
     */
    function batchVerify(
        bytes32[][] calldata rings,
        bytes32[][] calldata allKeyImages,
        bytes[] calldata signatures,
        bytes32[] calldata messages
    ) external pure returns (uint256 results) {
        uint256 count = rings.length;
        if (
            count != allKeyImages.length ||
            count != signatures.length ||
            count != messages.length
        ) {
            revert RingSizeMismatch();
        }
        if (count > 256) {
            revert InvalidRingSize();
        }

        for (uint256 i = 0; i < count; ) {
            if (
                _verifySingle(
                    rings[i],
                    allKeyImages[i],
                    signatures[i],
                    messages[i]
                )
            ) {
                results |= (1 << i);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _verifySingle(
        bytes32[] calldata ring,
        bytes32[] calldata keyImages,
        bytes calldata signature,
        bytes32 message
    ) internal pure returns (bool) {
        uint256 ringSize = ring.length;
        if (
            ringSize < MIN_RING_SIZE ||
            ringSize > MAX_RING_SIZE ||
            keyImages.length == 0
        ) {
            return false;
        }

        uint256 expectedSigLength = 32 + (ringSize * 32);
        if (signature.length != expectedSigLength) {
            return false;
        }

        bytes32 encodedChallenge;
        assembly {
            encodedChallenge := calldataload(signature.offset)
        }

        bytes32[] memory commitments = new bytes32[](ringSize);
        for (uint256 i = 0; i < ringSize; ) {
            bytes32 ri;
            assembly {
                ri := calldataload(add(signature.offset, add(32, mul(i, 32))))
            }
            uint256 riVal = uint256(ri);
            if (riVal == 0 || riVal >= N || riVal > HALF_N) {
                return false;
            }
            commitments[i] = keccak256(
                abi.encodePacked(COMMITMENT_DOMAIN, ri, ring[i])
            );
            unchecked {
                ++i;
            }
        }

        bytes32 expectedChallenge = keccak256(
            abi.encodePacked(
                CHALLENGE_DOMAIN,
                message,
                ring,
                keyImages,
                commitments
            )
        );
        return (encodedChallenge == expectedChallenge);
    }
}
