// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CrossChainMessageCodec
 * @author ZASEON
 * @notice Standardized cross-chain message encoding/decoding library.
 * @dev Addresses the inconsistency where bridge adapters use mixed `abi.encode`
 *      and `abi.encodePacked` for message ID generation. This library provides:
 *
 *      1. **Collision-safe encoding**: All message IDs use `abi.encode` (not
 *         `abi.encodePacked`) to prevent hash collisions with variable-length types.
 *      2. **Canonical field ordering**: (sourceChainId, destChainId, sender,
 *         recipient, nonce, payloadHash, timestamp) — deterministic across all adapters.
 *      3. **Domain separation**: Type-prefixed hashing prevents cross-protocol replays.
 *      4. **Proof-carrying wrapping**: Standard envelope for bridged proof payloads.
 *
 * @custom:security Uses abi.encode exclusively. Never use abi.encodePacked
 *   with variable-length types (bytes, string, arrays) — see Solidity docs
 *   on non-standard packing and hash collision risk.
 */
library CrossChainMessageCodec {
    /*//////////////////////////////////////////////////////////////
                           TYPE HASHES
    //////////////////////////////////////////////////////////////*/

    /// @dev Domain separator for standard bridge messages
    bytes32 internal constant MESSAGE_TYPEHASH =
        keccak256(
            "ZaseonMessage(uint256 sourceChainId,uint256 destChainId,address sender,address recipient,uint256 nonce,bytes32 payloadHash,uint256 timestamp)"
        );

    /// @dev Domain separator for proof-carrying messages
    bytes32 internal constant PROOF_MESSAGE_TYPEHASH =
        keccak256(
            "ZaseonProofMessage(uint256 sourceChainId,uint256 destChainId,address sender,address recipient,uint256 nonce,bytes32 proofHash,bytes32 publicInputsHash,uint256 timestamp)"
        );

    /// @dev Domain separator for deposit messages
    bytes32 internal constant DEPOSIT_TYPEHASH =
        keccak256(
            "ZaseonDeposit(uint256 sourceChainId,address depositor,address recipient,address token,uint256 amount,uint256 nonce,uint256 timestamp)"
        );

    /// @dev Domain separator for withdrawal messages
    bytes32 internal constant WITHDRAWAL_TYPEHASH =
        keccak256(
            "ZaseonWithdrawal(uint256 sourceChainId,address requester,address recipient,address token,uint256 amount,uint256 nonce,uint256 timestamp)"
        );

    /// @dev Domain separator for emergency relay messages
    bytes32 internal constant EMERGENCY_TYPEHASH =
        keccak256(
            "ZaseonEmergency(uint256 sourceChainId,uint256 destChainId,uint8 severity,address broadcaster,uint256 nonce,uint256 timestamp)"
        );

    /// @dev Protocol version for forward compatibility
    uint8 internal constant CODEC_VERSION = 1;

    /*//////////////////////////////////////////////////////////////
                         CANONICAL MESSAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Canonical cross-chain message struct.
     * @dev All bridge adapters should convert their internal formats to/from this struct.
     */
    struct CanonicalMessage {
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address recipient;
        uint256 nonce;
        bytes payload;
        uint256 timestamp;
    }

    /**
     * @notice Compute a collision-safe message ID using abi.encode.
     * @param msg_ The canonical message
     * @return messageId Deterministic unique identifier
     * @dev Uses abi.encode (NOT abi.encodePacked) to prevent hash collisions
     *      when payload is variable-length. Includes MESSAGE_TYPEHASH for
     *      domain separation from other hash uses in the protocol.
     */
    function computeMessageId(
        CanonicalMessage memory msg_
    ) internal pure returns (bytes32 messageId) {
        messageId = keccak256(
            abi.encode(
                MESSAGE_TYPEHASH,
                msg_.sourceChainId,
                msg_.destChainId,
                msg_.sender,
                msg_.recipient,
                msg_.nonce,
                keccak256(msg_.payload),
                msg_.timestamp
            )
        );
    }

    /**
     * @notice Compute a message ID from individual parameters (no struct allocation).
     * @param sourceChainId Origin chain ID
     * @param destChainId Destination chain ID
     * @param sender Message sender
     * @param recipient Message recipient
     * @param nonce Monotonic nonce
     * @param payload Raw payload bytes
     * @param timestamp Block timestamp
     * @return messageId Deterministic unique identifier
     */
    function computeMessageId(
        uint256 sourceChainId,
        uint256 destChainId,
        address sender,
        address recipient,
        uint256 nonce,
        bytes memory payload,
        uint256 timestamp
    ) internal pure returns (bytes32 messageId) {
        messageId = keccak256(
            abi.encode(
                MESSAGE_TYPEHASH,
                sourceChainId,
                destChainId,
                sender,
                recipient,
                nonce,
                keccak256(payload),
                timestamp
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                      PROOF-CARRYING MESSAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute a message ID for proof-carrying cross-chain messages.
     * @param sourceChainId Origin chain ID
     * @param destChainId Destination chain ID
     * @param sender Proof submitter
     * @param recipient Proof verifier/consumer
     * @param nonce Monotonic nonce
     * @param proofHash Hash of the ZK proof bytes
     * @param publicInputsHash Hash of the public inputs
     * @param timestamp Block timestamp
     * @return messageId Deterministic unique identifier
     */
    function computeProofMessageId(
        uint256 sourceChainId,
        uint256 destChainId,
        address sender,
        address recipient,
        uint256 nonce,
        bytes32 proofHash,
        bytes32 publicInputsHash,
        uint256 timestamp
    ) internal pure returns (bytes32 messageId) {
        messageId = keccak256(
            abi.encode(
                PROOF_MESSAGE_TYPEHASH,
                sourceChainId,
                destChainId,
                sender,
                recipient,
                nonce,
                proofHash,
                publicInputsHash,
                timestamp
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSIT / WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute a deposit ID using canonical encoding.
     * @param sourceChainId Origin chain ID
     * @param depositor The depositor address
     * @param recipient The recipient on destination chain
     * @param token Token address (address(0) for native)
     * @param amount Deposit amount
     * @param nonce Deposit counter
     * @param timestamp Block timestamp
     * @return depositId Deterministic unique identifier
     */
    function computeDepositId(
        uint256 sourceChainId,
        address depositor,
        address recipient,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 timestamp
    ) internal pure returns (bytes32 depositId) {
        depositId = keccak256(
            abi.encode(
                DEPOSIT_TYPEHASH,
                sourceChainId,
                depositor,
                recipient,
                token,
                amount,
                nonce,
                timestamp
            )
        );
    }

    /**
     * @notice Compute a withdrawal ID using canonical encoding.
     * @param sourceChainId Origin chain ID
     * @param requester The requester address
     * @param recipient The recipient on destination chain
     * @param token Token address (address(0) for native)
     * @param amount Withdrawal amount
     * @param nonce Withdrawal counter
     * @param timestamp Block timestamp
     * @return withdrawalId Deterministic unique identifier
     */
    function computeWithdrawalId(
        uint256 sourceChainId,
        address requester,
        address recipient,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 timestamp
    ) internal pure returns (bytes32 withdrawalId) {
        withdrawalId = keccak256(
            abi.encode(
                WITHDRAWAL_TYPEHASH,
                sourceChainId,
                requester,
                recipient,
                token,
                amount,
                nonce,
                timestamp
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                       EMERGENCY MESSAGES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute an emergency relay message ID.
     * @param sourceChainId Origin chain ID
     * @param destChainId Destination chain ID
     * @param severity Emergency severity level (1-5)
     * @param broadcaster Emergency broadcaster address
     * @param nonce Emergency nonce
     * @param timestamp Block timestamp
     * @return emergencyId Deterministic unique identifier
     */
    function computeEmergencyId(
        uint256 sourceChainId,
        uint256 destChainId,
        uint8 severity,
        address broadcaster,
        uint256 nonce,
        uint256 timestamp
    ) internal pure returns (bytes32 emergencyId) {
        emergencyId = keccak256(
            abi.encode(
                EMERGENCY_TYPEHASH,
                sourceChainId,
                destChainId,
                severity,
                broadcaster,
                nonce,
                timestamp
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                      ENVELOPE ENCODING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Encode a canonical message into a standardized envelope for bridging.
     * @param msg_ The canonical message
     * @return envelope ABI-encoded envelope with version prefix
     * @dev Envelope layout: [version (uint8)][messageId (bytes32)][sourceChainId][sender][payload]
     */
    function encodeEnvelope(
        CanonicalMessage memory msg_
    ) internal pure returns (bytes memory envelope) {
        bytes32 messageId = computeMessageId(msg_);
        envelope = abi.encode(
            CODEC_VERSION,
            messageId,
            msg_.sourceChainId,
            msg_.destChainId,
            msg_.sender,
            msg_.recipient,
            msg_.nonce,
            msg_.payload,
            msg_.timestamp
        );
    }

    /**
     * @notice Decode a standardized envelope back into a canonical message.
     * @param envelope The encoded envelope bytes
     * @return msg_ The decoded canonical message
     * @return messageId The message ID embedded in the envelope
     */
    function decodeEnvelope(
        bytes memory envelope
    ) internal pure returns (CanonicalMessage memory msg_, bytes32 messageId) {
        uint8 version;
        (
            version,
            messageId,
            msg_.sourceChainId,
            msg_.destChainId,
            msg_.sender,
            msg_.recipient,
            msg_.nonce,
            msg_.payload,
            msg_.timestamp
        ) = abi.decode(
            envelope,
            (
                uint8,
                bytes32,
                uint256,
                uint256,
                address,
                address,
                uint256,
                bytes,
                uint256
            )
        );

        // Verify version compatibility
        require(
            version == CODEC_VERSION,
            "CrossChainMessageCodec: unsupported version"
        );

        // Verify message ID integrity
        bytes32 recomputed = computeMessageId(msg_);
        require(
            messageId == recomputed,
            "CrossChainMessageCodec: message ID mismatch"
        );
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate a canonical message has all required fields populated.
     * @param msg_ The canonical message to validate
     * @return valid Whether all fields are non-zero/non-empty
     */
    function validateMessage(
        CanonicalMessage memory msg_
    ) internal pure returns (bool valid) {
        valid =
            msg_.sourceChainId != 0 &&
            msg_.destChainId != 0 &&
            msg_.sender != address(0) &&
            msg_.recipient != address(0) &&
            msg_.payload.length > 0 &&
            msg_.sourceChainId != msg_.destChainId;
    }
}
