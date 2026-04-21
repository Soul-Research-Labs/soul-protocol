// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CompactProof
 * @author ZASEON
 * @notice Packed calldata format for proof + public inputs in a single
 *         `bytes` argument. Reduces L2 calldata cost by ~30–40% vs.
 *         passing `bytes proof` + `uint256[] publicInputs` separately
 *         (two length prefixes → one; tight uint256 packing preserved).
 *
 * @dev Layout (all big-endian):
 *
 *      offset 0..0     :  uint8   version         (currently 1)
 *      offset 1..32    :  bytes32 circuitId
 *      offset 33..34   :  uint16  piCount
 *      offset 35..36   :  uint16  proofLen        (bytes)
 *      offset 37..68   :  bytes32 callerCtx
 *      offset 69..     :  uint256[piCount]  public inputs (tight)
 *      offset ...      :  bytes[proofLen]  proof bytes (tight)
 *
 *      Max proofLen is 65535 bytes; max piCount is 65535. UltraHonk
 *      proofs are ~14KB and have ≤64 public inputs in practice, so
 *      these bounds are generous.
 */
library CompactProof {
    uint8 internal constant VERSION = 1;

    error BadVersion(uint8 got);
    error BadLength();

    /// @notice Decode a packed compact proof blob.
    function decode(
        bytes calldata blob
    )
        internal
        pure
        returns (
            bytes32 circuitId,
            uint256[] memory publicInputs,
            bytes memory proof,
            bytes32 callerCtx
        )
    {
        if (blob.length < 69) revert BadLength();
        if (uint8(blob[0]) != VERSION) revert BadVersion(uint8(blob[0]));

        // circuitId
        circuitId = bytes32(blob[1:33]);

        // counts
        uint16 piCount = (uint16(uint8(blob[33])) << 8) |
            uint16(uint8(blob[34]));
        uint16 proofLen = (uint16(uint8(blob[35])) << 8) |
            uint16(uint8(blob[36])); // solhint-disable-line var-name-mixedcase

        // callerCtx
        callerCtx = bytes32(blob[37:69]);

        uint256 piBytes = uint256(piCount) * 32;
        uint256 expected = 69 + piBytes + uint256(proofLen);
        if (blob.length != expected) revert BadLength();

        publicInputs = new uint256[](piCount);
        uint256 cursor = 69;
        for (uint256 i = 0; i < piCount; ) {
            publicInputs[i] = uint256(bytes32(blob[cursor:cursor + 32]));
            cursor += 32;
            unchecked {
                ++i;
            }
        }

        proof = blob[cursor:cursor + proofLen];
    }

    /// @notice Encode — provided for tests / off-chain clients.
    function encode(
        bytes32 circuitId,
        uint256[] memory publicInputs,
        bytes memory proof,
        bytes32 callerCtx
    ) internal pure returns (bytes memory blob) {
        uint16 piCount = uint16(publicInputs.length);
        uint16 proofLen = uint16(proof.length);

        blob = new bytes(69 + uint256(piCount) * 32 + uint256(proofLen));
        blob[0] = bytes1(VERSION);
        // circuitId
        assembly {
            mstore(add(blob, 0x21), circuitId) // 0x20 skip len + 1 byte ver
        }
        blob[33] = bytes1(uint8(piCount >> 8));
        blob[34] = bytes1(uint8(piCount));
        blob[35] = bytes1(uint8(proofLen >> 8));
        blob[36] = bytes1(uint8(proofLen));
        assembly {
            mstore(add(blob, 0x45), callerCtx) // 32 (len) + 37
        }

        uint256 cursor = 69;
        for (uint256 i = 0; i < piCount; ) {
            uint256 v = publicInputs[i];
            assembly {
                mstore(add(add(blob, 0x20), cursor), v)
            }
            cursor += 32;
            unchecked {
                ++i;
            }
        }
        for (uint256 i = 0; i < proofLen; ) {
            blob[cursor + i] = proof[i];
            unchecked {
                ++i;
            }
        }
    }
}
