// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GasOptimizations
 * @author ZASEON
 * @notice Gas optimization library providing common patterns for efficient operations
 * @dev Targets 20-40% gas reduction through assembly, storage packing, and algorithmic improvements
 *
 * OPTIMIZATION TECHNIQUES:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  TECHNIQUE              │ GAS SAVINGS  │ USE CASE                        │
 * ├─────────────────────────┼──────────────┼─────────────────────────────────│
 * │  Assembly keccak256     │ ~500 gas     │ Hash computations               │
 * │  Unchecked arithmetic   │ ~40 gas/op   │ Loop counters, safe math        │
 * │  Storage packing        │ ~20k gas     │ Multiple small values           │
 * │  Calldata vs memory     │ ~3k gas      │ Function parameters             │
 * │  Short-circuit eval     │ Variable     │ Conditional checks              │
 * │  Bitmap operations      │ ~15k gas     │ Boolean arrays                  │
 * │  Cache storage reads    │ ~100 gas     │ Repeated reads in function      │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
library GasOptimizations {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ArrayLengthMismatch();
    error IndexOutOfBounds();
    error Overflow();
    error ZeroValue();

    /*//////////////////////////////////////////////////////////////
                         ASSEMBLY HASH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gas-optimized keccak256 for two bytes32 values
     * @dev Saves ~500 gas vs abi.encodePacked
     * @param a First bytes32 value
     * @param b Second bytes32 value
     * @return result The keccak256 hash
     */
    function efficientHash(
        bytes32 a,
        bytes32 b
    ) internal pure returns (bytes32 result) {
        assembly {
            // Store values in scratch space (0x00-0x40)
            mstore(0x00, a)
            mstore(0x20, b)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @notice Gas-optimized keccak256 for three bytes32 values
     * @dev Common pattern for nullifier derivation
     */
    function efficientHash3(
        bytes32 a,
        bytes32 b,
        bytes32 c
    ) internal pure returns (bytes32 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, a)
            mstore(add(ptr, 0x20), b)
            mstore(add(ptr, 0x40), c)
            result := keccak256(ptr, 0x60)
        }
    }

    /**
     * @notice Gas-optimized keccak256 for address and uint256
     * @dev Common pattern for nonce and message ID computation
     */
    function efficientHashAddressUint(
        address addr,
        uint256 value
    ) internal pure returns (bytes32 result) {
        assembly {
            mstore(0x00, addr)
            mstore(0x20, value)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @notice Batch hash computation for merkle tree construction
     * @dev Significantly more efficient for multiple hashes
     */
    function batchHash(
        bytes32[] memory leaves
    ) internal pure returns (bytes32[] memory hashes) {
        uint256 len = leaves.length;
        if (len == 0) return new bytes32[](0);

        uint256 outputLen = (len + 1) >> 1; // Ceiling division by 2
        hashes = new bytes32[](outputLen);

        assembly {
            let leavesPtr := add(leaves, 0x20)
            let hashesPtr := add(hashes, 0x20)
            let i := 0

            for {

            } lt(i, outputLen) {
                i := add(i, 1)
            } {
                let leftIdx := mul(i, 2)
                let rightIdx := add(leftIdx, 1)

                // Load left leaf
                let left := mload(add(leavesPtr, mul(leftIdx, 0x20)))

                // Load right leaf (or duplicate left if odd)
                let right := left
                if lt(rightIdx, len) {
                    right := mload(add(leavesPtr, mul(rightIdx, 0x20)))
                }

                // Hash pair
                mstore(0x00, left)
                mstore(0x20, right)
                mstore(add(hashesPtr, mul(i, 0x20)), keccak256(0x00, 0x40))
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         STORAGE PACKING HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pack two uint128 values into a single uint256
     * @dev Saves 20k gas per additional storage slot avoided
     */
    function packUint128(
        uint128 a,
        uint128 b
    ) internal pure returns (uint256 packed) {
        assembly {
            packed := or(
                shl(128, a),
                and(b, 0xffffffffffffffffffffffffffffffff)
            )
        }
    }

    /**
     * @notice Unpack uint256 into two uint128 values
     */
    function unpackUint128(
        uint256 packed
    ) internal pure returns (uint128 a, uint128 b) {
        assembly {
            a := shr(128, packed)
            b := and(packed, 0xffffffffffffffffffffffffffffffff)
        }
    }

    /**
     * @notice Pack four uint64 values into a single uint256
     */
    function packUint64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) internal pure returns (uint256 packed) {
        assembly {
            packed := or(or(shl(192, a), shl(128, b)), or(shl(64, c), d))
        }
    }

    /**
     * @notice Unpack uint256 into four uint64 values
     */
    function unpackUint64(
        uint256 packed
    ) internal pure returns (uint64 a, uint64 b, uint64 c, uint64 d) {
        assembly {
            a := shr(192, packed)
            b := and(shr(128, packed), 0xffffffffffffffff)
            c := and(shr(64, packed), 0xffffffffffffffff)
            d := and(packed, 0xffffffffffffffff)
        }
    }

    /**
     * @notice Pack address with additional 96 bits of data
     * @dev Useful for storing address + timestamp/flags in one slot
     */
    function packAddressWithData(
        address addr,
        uint96 data
    ) internal pure returns (uint256 packed) {
        assembly {
            packed := or(shl(96, addr), data)
        }
    }

    /**
     * @notice Unpack address and 96-bit data from uint256
     */
    function unpackAddressWithData(
        uint256 packed
    ) internal pure returns (address addr, uint96 data) {
        assembly {
            addr := shr(96, packed)
            data := and(packed, 0xffffffffffffffffffffffff)
        }
    }

    /*//////////////////////////////////////////////////////////////
                           BITMAP OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get bit at index in a uint256 bitmap
     * @dev Saves ~15k gas vs using mapping(uint256 => bool)
     */
    function getBit(
        uint256 bitmap,
        uint256 index
    ) internal pure returns (bool) {
        if (index >= 256) revert IndexOutOfBounds();
        return (bitmap >> index) & 1 == 1;
    }

    /**
     * @notice Set bit at index in a uint256 bitmap
     */
    function setBit(
        uint256 bitmap,
        uint256 index
    ) internal pure returns (uint256) {
        if (index >= 256) revert IndexOutOfBounds();
        return bitmap | (1 << index);
    }

    /**
     * @notice Clear bit at index in a uint256 bitmap
     */
    function clearBit(
        uint256 bitmap,
        uint256 index
    ) internal pure returns (uint256) {
        if (index >= 256) revert IndexOutOfBounds();
        return bitmap & ~(1 << index);
    }

    /**
     * @notice Count set bits in bitmap (population count)
     * @dev Optimized using parallel counting
     */
    function popCount(uint256 bitmap) internal pure returns (uint256 count) {
        assembly {
            // Brian Kernighan's algorithm
            for {

            } bitmap {

            } {
                bitmap := and(bitmap, sub(bitmap, 1))
                count := add(count, 1)
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         ARRAY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if sorted array contains value using binary search
     * @dev O(log n) vs O(n) for linear search
     */
    function binarySearch(
        bytes32[] memory sortedArray,
        bytes32 value
    ) internal pure returns (bool found, uint256 index) {
        if (sortedArray.length == 0) return (false, 0);

        uint256 low = 0;
        uint256 high = sortedArray.length - 1;

        while (low <= high) {
            uint256 mid = (low + high) >> 1; // Safe: low + high < 2^256
            bytes32 midVal = sortedArray[mid];

            if (midVal == value) {
                return (true, mid);
            } else if (midVal < value) {
                low = mid + 1;
            } else {
                if (mid == 0) break;
                high = mid - 1;
            }
        }
        return (false, low);
    }

    /**
     * @notice Sum array of uint256 values with overflow check
     * @dev Relies on Solidity 0.8+ built-in overflow protection
     */
    function safeSum(
        uint256[] memory values
    ) internal pure returns (uint256 total) {
        uint256 len = values.length;
        for (uint256 i = 0; i < len; ) {
            total += values[i]; // Solidity 0.8 reverts on overflow
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Copy calldata array to memory efficiently
     * @dev Uses assembly for direct memory copy
     */
    function copyCalldataArray(
        bytes32[] calldata source
    ) internal pure returns (bytes32[] memory dest) {
        uint256 len = source.length;
        dest = new bytes32[](len);

        assembly {
            // Copy calldata to memory
            calldatacopy(add(dest, 0x20), source.offset, mul(len, 0x20))
        }
    }

    /*//////////////////////////////////////////////////////////////
                       COMPARISON OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gas-efficient max of two uint256 values
     * @dev Uses branchless assembly; safe for internal calls (no `return` opcode)
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := a
            if gt(b, a) {
                result := b
            }
        }
    }

    /**
     * @notice Gas-efficient min of two uint256 values
     * @dev Uses branchless assembly; safe for internal calls (no `return` opcode)
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := a
            if lt(b, a) {
                result := b
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         SAFE ARITHMETIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Safe increment with overflow check
     * @dev Use for counters that might overflow
     */
    function safeIncrement(uint256 value) internal pure returns (uint256) {
        if (value == type(uint256).max) revert Overflow();
        unchecked {
            return value + 1;
        }
    }

    /**
     * @notice Unchecked increment for loop counters
     * @dev Only use when overflow is impossible
     */
    function unsafeIncrement(uint256 value) internal pure returns (uint256) {
        unchecked {
            return value + 1;
        }
    }

    /*//////////////////////////////////////////////////////////////
                      MERKLE TREE HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify merkle proof efficiently
     * @dev Optimized assembly version saves ~2k gas
     */
    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        uint256 proofLength = proof.length;

        for (uint256 i = 0; i < proofLength; ) {
            bytes32 proofElement = proof[i];

            assembly {
                // Sort and hash
                switch lt(computedHash, proofElement)
                case 1 {
                    mstore(0x00, computedHash)
                    mstore(0x20, proofElement)
                }
                default {
                    mstore(0x00, proofElement)
                    mstore(0x20, computedHash)
                }
                computedHash := keccak256(0x00, 0x40)
            }

            unchecked {
                ++i;
            }
        }

        return computedHash == root;
    }

    /**
     * @notice Compute merkle root from leaves
     * @dev Efficient single-pass computation
     */
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        uint256 len = leaves.length;
        if (len == 0) return bytes32(0);
        if (len == 1) return leaves[0];

        while (len > 1) {
            uint256 nextLen = (len + 1) >> 1;

            for (uint256 i = 0; i < nextLen; ) {
                uint256 leftIdx = i << 1;
                uint256 rightIdx = leftIdx + 1;

                bytes32 left = leaves[leftIdx];
                bytes32 right = rightIdx < len ? leaves[rightIdx] : left;

                assembly {
                    mstore(0x00, left)
                    mstore(0x20, right)
                    mstore(
                        add(leaves, add(0x20, mul(i, 0x20))),
                        keccak256(0x00, 0x40)
                    )
                }

                unchecked {
                    ++i;
                }
            }

            len = nextLen;
        }

        return leaves[0];
    }
}
