// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title FixedSizeMessageWrapper
 * @author ZASEON
 * @notice Wraps cross-chain messages in fixed-size envelopes to prevent size-based inference
 * @dev Cross-chain messages vary in size by operation type:
 *      - Simple transfers: ~200 bytes
 *      - Multi-sig operations: ~600 bytes
 *      - Conditional logic with proofs: ~2000 bytes
 *
 *      An observer monitoring bridge adapter calls can infer operation type from
 *      message size. This library wraps all messages in a uniform-size envelope
 *      before passing them to IBridgeAdapter.bridgeMessage().
 *
 *      Envelope format:
 *      ┌──────────────────────────────────────────────────────┐
 *      │ [4 bytes] actual payload length (big-endian uint32)  │
 *      │ [N bytes] actual payload data                        │
 *      │ [P bytes] zero padding to reach MESSAGE_ENVELOPE_SIZE│
 *      └──────────────────────────────────────────────────────┘
 *
 *      Integrates with IBridgeAdapter — callers wrap before calling bridgeMessage
 *      and unwrap on the receiving end.
 */
library FixedSizeMessageWrapper {
    /// @notice Standard envelope size for all cross-chain messages
    /// @dev 4096 bytes accommodates all current message types with headroom.
    ///      Larger than ProofEnvelope (2048) because messages include proof +
    ///      metadata + routing info + encrypted state.
    uint256 internal constant MESSAGE_ENVELOPE_SIZE = 4096;

    /// @notice Length prefix size (uint32 big-endian)
    uint256 internal constant LENGTH_PREFIX = 4;

    /// @notice Maximum payload size
    uint256 internal constant MAX_PAYLOAD_SIZE =
        MESSAGE_ENVELOPE_SIZE - LENGTH_PREFIX;

    error PayloadTooLarge(uint256 payloadSize, uint256 maxSize);
    error InvalidMessageEnvelope(uint256 envelopeSize);
    error CorruptLengthPrefix(uint256 declaredLength, uint256 maxAllowed);

    /**
     * @notice Wrap a cross-chain message payload in a fixed-size envelope
     * @param payload The original message payload
     * @return envelope Fixed-size envelope of exactly MESSAGE_ENVELOPE_SIZE bytes
     */
    function wrap(
        bytes memory payload
    ) internal pure returns (bytes memory envelope) {
        uint256 payloadLen = payload.length;
        if (payloadLen > MAX_PAYLOAD_SIZE) {
            revert PayloadTooLarge(payloadLen, MAX_PAYLOAD_SIZE);
        }

        envelope = new bytes(MESSAGE_ENVELOPE_SIZE);

        // Write length prefix (big-endian uint32)
        envelope[0] = bytes1(uint8(payloadLen >> 24));
        envelope[1] = bytes1(uint8(payloadLen >> 16));
        envelope[2] = bytes1(uint8(payloadLen >> 8));
        envelope[3] = bytes1(uint8(payloadLen));

        // Copy payload
        for (uint256 i; i < payloadLen; ) {
            envelope[i + LENGTH_PREFIX] = payload[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Wrap a calldata payload (gas-efficient for bridge adapter calls)
     * @param payload The original message payload from calldata
     * @return envelope Fixed-size envelope
     */
    function wrapCalldata(
        bytes calldata payload
    ) internal pure returns (bytes memory envelope) {
        uint256 payloadLen = payload.length;
        if (payloadLen > MAX_PAYLOAD_SIZE) {
            revert PayloadTooLarge(payloadLen, MAX_PAYLOAD_SIZE);
        }

        envelope = new bytes(MESSAGE_ENVELOPE_SIZE);

        // Write length prefix
        envelope[0] = bytes1(uint8(payloadLen >> 24));
        envelope[1] = bytes1(uint8(payloadLen >> 16));
        envelope[2] = bytes1(uint8(payloadLen >> 8));
        envelope[3] = bytes1(uint8(payloadLen));

        // Copy from calldata
        for (uint256 i; i < payloadLen; ) {
            envelope[i + LENGTH_PREFIX] = payload[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Unwrap a message from its fixed-size envelope
     * @param envelope The fixed-size envelope
     * @return payload The original message payload
     */
    function unwrap(
        bytes memory envelope
    ) internal pure returns (bytes memory payload) {
        if (envelope.length != MESSAGE_ENVELOPE_SIZE) {
            revert InvalidMessageEnvelope(envelope.length);
        }

        // Read length prefix (big-endian uint32)
        uint256 payloadLen = (uint256(uint8(envelope[0])) << 24) |
            (uint256(uint8(envelope[1])) << 16) |
            (uint256(uint8(envelope[2])) << 8) |
            uint256(uint8(envelope[3]));

        if (payloadLen > MAX_PAYLOAD_SIZE) {
            revert CorruptLengthPrefix(payloadLen, MAX_PAYLOAD_SIZE);
        }

        payload = new bytes(payloadLen);
        for (uint256 i; i < payloadLen; ) {
            payload[i] = envelope[i + LENGTH_PREFIX];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Validate an envelope without fully unwrapping it
     * @param envelope The envelope to validate
     * @return valid Whether the envelope is well-formed
     * @return payloadLength The declared payload length
     */
    function validate(
        bytes memory envelope
    ) internal pure returns (bool valid, uint256 payloadLength) {
        if (envelope.length != MESSAGE_ENVELOPE_SIZE) return (false, 0);

        payloadLength =
            (uint256(uint8(envelope[0])) << 24) |
            (uint256(uint8(envelope[1])) << 16) |
            (uint256(uint8(envelope[2])) << 8) |
            uint256(uint8(envelope[3]));

        valid = payloadLength <= MAX_PAYLOAD_SIZE;
    }
}
