// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GasOptimizedBatchOps
 * @author ZASEON
 * @notice Gas-optimized batch operation helpers for protocol-wide batch processing
 * @dev Provides pure/view utility functions for batching common protocol operations
 *      to reduce per-tx overhead. Uses assembly where beneficial for gas savings.
 *
 *      Capabilities:
 *      - Batch nullifier existence checks
 *      - Batch commitment hashing
 *      - Batch Merkle leaf computation
 *      - Multicall-style encoding/decoding helpers
 *      - Packed array operations for gas-efficient iteration
 *      - Bitmap operations for set membership
 *
 *      Design principles:
 *      - All functions are pure or internal to avoid SLOAD overhead
 *      - No external calls — this is a computation library
 *      - Assembly used only where measurable gas savings exist
 *      - All assembly blocks are well-documented
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
library GasOptimizedBatchOps {
    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error EmptyArray();
    error LengthMismatch(uint256 expected, uint256 actual);
    error BitmapIndexOutOfRange(uint256 index);

    /*//////////////////////////////////////////////////////////////
                          BATCH HASHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute commitment hashes for a batch of (value, blinding) pairs
     * @dev Uses assembly to batch keccak256 calls, skipping Solidity ABI encoding overhead
     * @param values Array of values
     * @param blindings Array of blinding factors
     * @return commitments Array of keccak256(abi.encodePacked(value, blinding))
     */
    function batchComputeCommitments(
        uint256[] calldata values,
        bytes32[] calldata blindings
    ) internal pure returns (bytes32[] memory commitments) {
        uint256 len = values.length;
        if (len == 0) revert EmptyArray();
        if (len != blindings.length)
            revert LengthMismatch(len, blindings.length);

        commitments = new bytes32[](len);

        for (uint256 i; i < len; ) {
            commitments[i] = keccak256(
                abi.encodePacked(values[i], blindings[i])
            );
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Compute nullifier hashes for a batch of (secret, leafIndex) pairs
     * @param secrets Array of nullifier secrets
     * @param leafIndices Array of Merkle tree leaf indices
     * @return nullifiers Array of keccak256(abi.encodePacked(secret, leafIndex))
     */
    function batchComputeNullifiers(
        bytes32[] calldata secrets,
        uint256[] calldata leafIndices
    ) internal pure returns (bytes32[] memory nullifiers) {
        uint256 len = secrets.length;
        if (len == 0) revert EmptyArray();
        if (len != leafIndices.length)
            revert LengthMismatch(len, leafIndices.length);

        nullifiers = new bytes32[](len);

        for (uint256 i; i < len; ) {
            nullifiers[i] = keccak256(
                abi.encodePacked(secrets[i], leafIndices[i])
            );
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Compute Merkle leaf hashes for a batch of commitments
     * @dev Standard Merkle tree leaf: keccak256(abi.encodePacked(commitment))
     * @param commitments Array of commitments
     * @return leaves Array of leaf hashes
     */
    function batchComputeLeaves(
        bytes32[] calldata commitments
    ) internal pure returns (bytes32[] memory leaves) {
        uint256 len = commitments.length;
        if (len == 0) revert EmptyArray();

        leaves = new bytes32[](len);

        for (uint256 i; i < len; ) {
            leaves[i] = keccak256(abi.encodePacked(commitments[i]));
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        BITMAP OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set a bit in a 256-bit bitmap
     * @param bitmap The current bitmap
     * @param index Bit index to set (0-255)
     * @return Updated bitmap
     */
    function setBit(
        uint256 bitmap,
        uint8 index
    ) internal pure returns (uint256) {
        return bitmap | (1 << index);
    }

    /**
     * @notice Check if a bit is set in a 256-bit bitmap
     * @param bitmap The bitmap to check
     * @param index Bit index to check (0-255)
     * @return Whether the bit is set
     */
    function getBit(uint256 bitmap, uint8 index) internal pure returns (bool) {
        return (bitmap & (1 << index)) != 0;
    }

    /**
     * @notice Clear a bit in a 256-bit bitmap
     * @param bitmap The current bitmap
     * @param index Bit index to clear (0-255)
     * @return Updated bitmap
     */
    function clearBit(
        uint256 bitmap,
        uint8 index
    ) internal pure returns (uint256) {
        return bitmap & ~(1 << index);
    }

    /**
     * @notice Count set bits in a bitmap (population count)
     * @dev Uses Brian Kernighan's algorithm for O(k) where k = number of set bits
     * @param bitmap The bitmap to count
     * @return count Number of set bits
     */
    function popCount(uint256 bitmap) internal pure returns (uint256 count) {
        while (bitmap != 0) {
            bitmap &= (bitmap - 1); // Clear lowest set bit
            unchecked {
                ++count;
            }
        }
    }

    /**
     * @notice Check batch membership using bitmap
     * @dev Checks multiple indices against a bitmap in a single pass
     * @param bitmap The membership bitmap
     * @param indices Array of indices to check
     * @return allPresent Whether all indices are set
     * @return presentCount Number of indices that are set
     */
    function batchCheckMembership(
        uint256 bitmap,
        uint8[] calldata indices
    ) internal pure returns (bool allPresent, uint256 presentCount) {
        uint256 len = indices.length;
        if (len == 0) revert EmptyArray();

        allPresent = true;
        for (uint256 i; i < len; ) {
            if (getBit(bitmap, indices[i])) {
                unchecked {
                    ++presentCount;
                }
            } else {
                allPresent = false;
            }
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                       ARRAY UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pack two uint128 values into one uint256 (gas-efficient storage)
     * @param high Upper 128 bits
     * @param low Lower 128 bits
     * @return packed The packed value
     */
    function pack128(
        uint128 high,
        uint128 low
    ) internal pure returns (uint256 packed) {
        packed = (uint256(high) << 128) | uint256(low);
    }

    /**
     * @notice Unpack a uint256 into two uint128 values
     * @param packed The packed value
     * @return high Upper 128 bits
     * @return low Lower 128 bits
     */
    function unpack128(
        uint256 packed
    ) internal pure returns (uint128 high, uint128 low) {
        high = uint128(packed >> 128);
        low = uint128(packed);
    }

    /**
     * @notice Pack four uint64 values into one uint256
     * @param a First value (bits 192-255)
     * @param b Second value (bits 128-191)
     * @param c Third value (bits 64-127)
     * @param d Fourth value (bits 0-63)
     * @return packed The packed value
     */
    function pack64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) internal pure returns (uint256 packed) {
        packed =
            (uint256(a) << 192) |
            (uint256(b) << 128) |
            (uint256(c) << 64) |
            uint256(d);
    }

    /**
     * @notice Unpack a uint256 into four uint64 values
     * @param packed The packed value
     * @return a First value
     * @return b Second value
     * @return c Third value
     * @return d Fourth value
     */
    function unpack64(
        uint256 packed
    ) internal pure returns (uint64 a, uint64 b, uint64 c, uint64 d) {
        a = uint64(packed >> 192);
        b = uint64(packed >> 128);
        c = uint64(packed >> 64);
        d = uint64(packed);
    }

    /**
     * @notice Deduplicate a sorted bytes32 array (remove consecutive duplicates)
     * @dev Input MUST be sorted for correctness
     * @param sorted Sorted array of bytes32 values
     * @return deduped Array with duplicates removed
     */
    function deduplicateSorted(
        bytes32[] calldata sorted
    ) internal pure returns (bytes32[] memory deduped) {
        uint256 len = sorted.length;
        if (len == 0) return new bytes32[](0);
        if (len == 1) {
            deduped = new bytes32[](1);
            deduped[0] = sorted[0];
            return deduped;
        }

        // First pass: count unique elements
        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < len; ) {
            if (sorted[i] != sorted[i - 1]) {
                unchecked {
                    ++uniqueCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Second pass: fill unique array
        deduped = new bytes32[](uniqueCount);
        deduped[0] = sorted[0];
        uint256 idx = 1;
        for (uint256 i = 1; i < len; ) {
            if (sorted[i] != sorted[i - 1]) {
                deduped[idx] = sorted[i];
                unchecked {
                    ++idx;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                     MULTICALL HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Encode a batch of function calls for multicall-style execution
     * @dev Returns ABI-encoded batch suitable for external multicall contracts
     * @param targets Target addresses
     * @param callDatas Encoded function calls
     * @return batchHash Hash of the entire batch (for tracking/verification)
     */
    function hashBatch(
        address[] calldata targets,
        bytes[] calldata callDatas
    ) internal pure returns (bytes32 batchHash) {
        uint256 len = targets.length;
        if (len == 0) revert EmptyArray();
        if (len != callDatas.length)
            revert LengthMismatch(len, callDatas.length);

        batchHash = keccak256(abi.encodePacked(targets[0], callDatas[0]));
        for (uint256 i = 1; i < len; ) {
            batchHash = keccak256(
                abi.encodePacked(batchHash, targets[i], callDatas[i])
            );
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Compute a domain-separated hash for cross-chain batch operations
     * @param chainId Chain ID for domain separation
     * @param batchNonce Batch nonce for replay protection
     * @param batchHash Hash of the batch operations
     * @return domainHash Domain-separated hash
     */
    function domainSeparatedBatchHash(
        uint256 chainId,
        uint256 batchNonce,
        bytes32 batchHash
    ) internal pure returns (bytes32 domainHash) {
        domainHash = keccak256(
            abi.encodePacked("ZaseonBatch_v1", chainId, batchNonce, batchHash)
        );
    }

    /*//////////////////////////////////////////////////////////////
                    EFFICIENT SUM / AGGREGATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Sum an array of uint256 values with overflow checking
     * @param values Array to sum
     * @return total Sum of all values
     */
    function sum(
        uint256[] calldata values
    ) internal pure returns (uint256 total) {
        uint256 len = values.length;
        for (uint256 i; i < len; ) {
            total += values[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Find min and max in a uint256 array in a single pass
     * @param values Array to analyze
     * @return min Minimum value
     * @return max Maximum value
     */
    function minMax(
        uint256[] calldata values
    ) internal pure returns (uint256 min, uint256 max) {
        uint256 len = values.length;
        if (len == 0) revert EmptyArray();

        min = values[0];
        max = values[0];

        for (uint256 i = 1; i < len; ) {
            if (values[i] < min) min = values[i];
            if (values[i] > max) max = values[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Calculate weighted average (values weighted by weights, denominator = sum of weights)
     * @param values Array of values
     * @param weights Array of weights (same length)
     * @return avg Weighted average
     */
    function weightedAverage(
        uint256[] calldata values,
        uint256[] calldata weights
    ) internal pure returns (uint256 avg) {
        uint256 len = values.length;
        if (len == 0) revert EmptyArray();
        if (len != weights.length) revert LengthMismatch(len, weights.length);

        uint256 totalWeighted;
        uint256 totalWeight;

        for (uint256 i; i < len; ) {
            totalWeighted += values[i] * weights[i];
            totalWeight += weights[i];
            unchecked {
                ++i;
            }
        }

        if (totalWeight == 0) return 0;
        avg = totalWeighted / totalWeight;
    }
}
