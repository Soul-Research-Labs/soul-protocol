// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IUltraHonkVerifier
 * @notice Interface for bb-generated UltraHonk Solidity verifiers
 */
interface IUltraHonkRingSigVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool);
}

/**
 * @title RingSignatureHonkBridge
 * @author ZASEON
 * @notice Bridges the legacy CLSAG/MLSAG ring signature interface expected by
 *         GasOptimizedRingCT to the Noir-generated UltraHonk verifier (RingSignatureHonkVerifier).
 *
 * @dev GasOptimizedRingCT calls:
 *          verify(bytes32[] ring, bytes32[] keyImages, bytes signature, bytes32 message)
 *
 *      But the bb-generated RingSignatureHonkVerifier expects:
 *          verify(bytes proof, bytes32[36] publicInputs)
 *
 *      Public inputs layout (36 elements):
 *        [0]              = message hash
 *        [1]              = ring_size (zero-padded to 16)
 *        [2]              = key_image_count
 *        [3..18]          = ring members (padded to MAX_RING_SIZE=16)
 *        [19..34]         = key images  (padded to MAX_KEY_IMAGES=16)
 *        [35]             = commitment root (Poseidon hash of ring+message+keyImages)
 *
 *      The `signature` parameter encodes:
 *        abi.encode(bytes proof, bytes32 commitmentRoot)
 *      where `proof` is the UltraHonk proof bytes from the Noir prover.
 *
 * @custom:security This adapter performs no ZK computation itself —
 *                  all verification is delegated to the Honk verifier.
 */
contract RingSignatureHonkBridge {
    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Maximum ring size supported by the Noir circuit
    uint256 public constant MAX_RING_SIZE = 16;

    /// @notice Maximum key images supported
    uint256 public constant MAX_KEY_IMAGES = 16;

    /// @notice Total public inputs expected by the Honk verifier
    uint256 public constant PUBLIC_INPUT_COUNT = 36;

    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice The bb-generated RingSignatureHonkVerifier
    IUltraHonkRingSigVerifier public immutable honkVerifier;

    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error RingSizeTooLarge(uint256 provided, uint256 max);
    error KeyImageCountTooLarge(uint256 provided, uint256 max);
    error EmptyRing();
    error EmptyKeyImages();
    error ZeroVerifierAddress();
    error InvalidSignatureEncoding();

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    /// @param _honkVerifier Address of the deployed RingSignatureHonkVerifier
    constructor(address _honkVerifier) {
        if (_honkVerifier == address(0)) revert ZeroVerifierAddress();
        honkVerifier = IUltraHonkRingSigVerifier(_honkVerifier);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXTERNAL — CLSAG-compatible verify interface
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify a ring signature via the Noir UltraHonk circuit
     * @dev This matches the interface GasOptimizedRingCT expects:
     *          verify(bytes32[],bytes32[],bytes,bytes32) → bool
     *
     * @param ring           Array of ring member public key hashes
     * @param keyImages      Array of key images (spent tags)
     * @param signature      ABI-encoded (bytes proof, bytes32 commitmentRoot)
     * @param message        Transaction message hash being signed
     * @return valid         True if the Honk proof verifies
     */
    function verify(
        bytes32[] calldata ring,
        bytes32[] calldata keyImages,
        bytes calldata signature,
        bytes32 message
    ) external view returns (bool valid) {
        // ── Input validation ──────────────────────────────────────────────
        if (ring.length == 0) revert EmptyRing();
        if (ring.length > MAX_RING_SIZE) {
            revert RingSizeTooLarge(ring.length, MAX_RING_SIZE);
        }
        if (keyImages.length == 0) revert EmptyKeyImages();
        if (keyImages.length > MAX_KEY_IMAGES) {
            revert KeyImageCountTooLarge(keyImages.length, MAX_KEY_IMAGES);
        }

        // ── Decode the ZK proof and commitment root from `signature` ─────
        if (signature.length < 64) revert InvalidSignatureEncoding();
        (bytes memory proof, bytes32 commitmentRoot) = abi.decode(
            signature,
            (bytes, bytes32)
        );

        // ── Build public inputs array for the Honk verifier ──────────────
        bytes32[] memory publicInputs = new bytes32[](PUBLIC_INPUT_COUNT);

        // [0] = message hash
        publicInputs[0] = message;

        // [1] = ring_size
        publicInputs[1] = bytes32(ring.length);

        // [2] = key_image_count
        publicInputs[2] = bytes32(keyImages.length);

        // [3..18] = ring members (zero-padded)
        for (uint256 i = 0; i < ring.length; ) {
            publicInputs[3 + i] = ring[i];
            unchecked {
                ++i;
            }
        }
        // Remaining slots [3 + ring.length .. 18] stay bytes32(0)

        // [19..34] = key images (zero-padded)
        for (uint256 i = 0; i < keyImages.length; ) {
            publicInputs[19 + i] = keyImages[i];
            unchecked {
                ++i;
            }
        }
        // Remaining slots [19 + keyImages.length .. 34] stay bytes32(0)

        // [35] = commitment root
        publicInputs[35] = commitmentRoot;

        // ── Delegate to the Honk verifier ────────────────────────────────
        return honkVerifier.verify(proof, publicInputs);
    }
}
