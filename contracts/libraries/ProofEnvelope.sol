// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ProofEnvelope
 * @author ZASEON
 * @notice Pads ZK proofs to a uniform size to prevent proof-system inference attacks
 * @dev Different proof systems produce different-sized proofs:
 *      - Groth16: ~256 bytes (8 × 32-byte field elements)
 *      - UltraHonk/PLONK: ~1500+ bytes
 *      - STARKs: variable, often 10KB+
 *      - Bulletproofs: ~700 bytes
 *
 *      An observer can infer which proof system is used from the proof size alone,
 *      which leaks metadata about the operation type or chain being used.
 *
 *      ProofEnvelope wraps all proofs in a fixed-size envelope:
 *      ┌──────────────────────────────────────────────────────┐
 *      │ [2 bytes] actual proof length (big-endian uint16)    │
 *      │ [N bytes] actual proof data                          │
 *      │ [P bytes] zero padding to reach ENVELOPE_SIZE        │
 *      └──────────────────────────────────────────────────────┘
 *
 *      All envelopes are exactly ENVELOPE_SIZE bytes, regardless of proof system.
 */
library ProofEnvelope {
    /// @notice Standard envelope size — accommodates all proof systems
    /// @dev 2048 bytes matches BatchAccumulator.FIXED_PAYLOAD_SIZE convention.
    ///      Groth16 (256B), Bulletproofs (700B), PLONK (1500B) all fit.
    ///      STARKs exceeding 2046B (2048 - 2 length prefix) should use
    ///      recursive proof compression before enveloping.
    uint256 internal constant ENVELOPE_SIZE = 2048;

    /// @notice Length prefix size (uint16 big-endian)
    uint256 internal constant LENGTH_PREFIX = 2;

    /// @notice Maximum proof size that fits in the envelope
    uint256 internal constant MAX_PROOF_SIZE = ENVELOPE_SIZE - LENGTH_PREFIX;

    /// @notice Error when proof exceeds maximum envelope capacity
    error ProofTooLarge(uint256 proofSize, uint256 maxSize);

    /// @notice Error when envelope is malformed (too small or corrupt length)
    error InvalidEnvelope(uint256 envelopeSize);

    /**
     * @notice Wrap a proof in a fixed-size envelope
     * @param proof The raw proof bytes
     * @return envelope Fixed-size envelope of exactly ENVELOPE_SIZE bytes
     */
    function wrap(
        bytes memory proof
    ) internal pure returns (bytes memory envelope) {
        uint256 proofLen = proof.length;
        if (proofLen > MAX_PROOF_SIZE) {
            revert ProofTooLarge(proofLen, MAX_PROOF_SIZE);
        }

        envelope = new bytes(ENVELOPE_SIZE);

        // Write length prefix (big-endian uint16)
        envelope[0] = bytes1(uint8(proofLen >> 8));
        envelope[1] = bytes1(uint8(proofLen));

        // Copy proof data
        for (uint256 i; i < proofLen; ) {
            envelope[i + LENGTH_PREFIX] = proof[i];
            unchecked {
                ++i;
            }
        }

        // Remaining bytes are already zero (Solidity default)
    }

    /**
     * @notice Unwrap a proof from its fixed-size envelope
     * @param envelope The fixed-size envelope
     * @return proof The original proof bytes
     */
    function unwrap(
        bytes memory envelope
    ) internal pure returns (bytes memory proof) {
        if (envelope.length != ENVELOPE_SIZE) {
            revert InvalidEnvelope(envelope.length);
        }

        // Read length prefix (big-endian uint16)
        uint256 proofLen = (uint256(uint8(envelope[0])) << 8) |
            uint256(uint8(envelope[1]));

        if (proofLen > MAX_PROOF_SIZE) {
            revert InvalidEnvelope(proofLen);
        }

        proof = new bytes(proofLen);
        for (uint256 i; i < proofLen; ) {
            proof[i] = envelope[i + LENGTH_PREFIX];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Wrap a proof provided as calldata (gas-efficient for external calls)
     * @param proof The raw proof bytes from calldata
     * @return envelope Fixed-size envelope
     */
    function wrapCalldata(
        bytes calldata proof
    ) internal pure returns (bytes memory envelope) {
        uint256 proofLen = proof.length;
        if (proofLen > MAX_PROOF_SIZE) {
            revert ProofTooLarge(proofLen, MAX_PROOF_SIZE);
        }

        envelope = new bytes(ENVELOPE_SIZE);

        // Write length prefix
        envelope[0] = bytes1(uint8(proofLen >> 8));
        envelope[1] = bytes1(uint8(proofLen));

        // Copy from calldata
        for (uint256 i; i < proofLen; ) {
            envelope[i + LENGTH_PREFIX] = proof[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Check if an envelope is well-formed without unwrapping
     * @param envelope The envelope to validate
     * @return valid Whether the envelope is valid
     * @return proofLength The embedded proof length
     */
    function validate(
        bytes memory envelope
    ) internal pure returns (bool valid, uint256 proofLength) {
        if (envelope.length != ENVELOPE_SIZE) return (false, 0);

        proofLength =
            (uint256(uint8(envelope[0])) << 8) |
            uint256(uint8(envelope[1]));
        valid = proofLength <= MAX_PROOF_SIZE;
    }
}
