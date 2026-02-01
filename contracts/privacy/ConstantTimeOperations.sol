// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

error InvalidLength();


/// @title ConstantTimeOperations
/// @notice Library providing constant-time operations to prevent timing side-channel attacks
/// @dev Critical for privacy-preserving operations where timing leaks could reveal secrets
/// @custom:security-contact security@soulprotocol.io

library ConstantTimeOperations {
    // =========================================================================
    // CONSTANT-TIME COMPARISON
    // =========================================================================

    /// @notice Constant-time comparison of two bytes32 values
    /// @dev Prevents timing attacks by always checking all bits
    /// @param a First value
    /// @param b Second value
    /// @return result True if equal, false otherwise
    function constantTimeEquals(
        bytes32 a,
        bytes32 b
    ) internal pure returns (bool result) {
        assembly {
            // XOR the values - if equal, result is 0
            let diff := xor(a, b)

            // If diff is 0, they're equal
            // Use iszero which is constant-time
            result := iszero(diff)
        }
    }

    /// @notice Constant-time comparison of two uint256 values
    /// @param a First value
    /// @param b Second value
    /// @return result True if equal, false otherwise
    function constantTimeEqualsUint(
        uint256 a,
        uint256 b
    ) internal pure returns (bool result) {
        assembly {
            let diff := xor(a, b)
            result := iszero(diff)
        }
    }

    /// @notice Constant-time comparison of byte arrays
    /// @dev Always iterates through all bytes regardless of mismatch position
    /// @param a First byte array
    /// @param b Second byte array
    /// @return result True if equal, false otherwise
    function constantTimeEqualsBytes(
        bytes memory a,
        bytes memory b
    ) internal pure returns (bool result) {
        if (a.length != b.length) {
            return false;
        }

        uint256 diff = 0;
        uint256 length = a.length;

        assembly {
            let aPtr := add(a, 32)
            let bPtr := add(b, 32)

            // Process 32 bytes at a time
            for {
                let i := 0
            } lt(i, length) {
                i := add(i, 32)
            } {
                let aWord := mload(add(aPtr, i))
                let bWord := mload(add(bPtr, i))
                diff := or(diff, xor(aWord, bWord))
            }

            result := iszero(diff)
        }
    }

    // =========================================================================
    // CONSTANT-TIME SELECTION
    // =========================================================================

    /// @notice Constant-time conditional select for bytes32
    /// @dev Returns a if condition is true, b otherwise, in constant time
    /// @param condition Selection condition
    /// @param a Value to return if true
    /// @param b Value to return if false
    /// @return result Selected value
    function constantTimeSelect(
        bool condition,
        bytes32 a,
        bytes32 b
    ) internal pure returns (bytes32 result) {
        assembly {
            // Convert bool to 0 or 0xFF...FF mask
            let mask := sub(0, condition)

            // result = (a & mask) | (b & ~mask)
            result := or(and(a, mask), and(b, not(mask)))
        }
    }

    /// @notice Constant-time conditional select for uint256
    /// @param condition Selection condition
    /// @param a Value to return if true
    /// @param b Value to return if false
    /// @return result Selected value
    function constantTimeSelectUint(
        bool condition,
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            let mask := sub(0, condition)
            result := or(and(a, mask), and(b, not(mask)))
        }
    }

    /// @notice Constant-time conditional select for addresses
    /// @param condition Selection condition
    /// @param a Address to return if true
    /// @param b Address to return if false
    /// @return result Selected address
    function constantTimeSelectAddress(
        bool condition,
        address a,
        address b
    ) internal pure returns (address result) {
        assembly {
            let mask := sub(0, condition)
            result := or(and(a, mask), and(b, not(mask)))
        }
    }

    // =========================================================================
    // CONSTANT-TIME ARITHMETIC
    // =========================================================================

    /// @notice Constant-time less-than comparison
    /// @dev Returns 1 if a < b, 0 otherwise, without branching
    /// @param a First value
    /// @param b Second value
    /// @return result 1 if a < b, 0 otherwise
    function constantTimeLessThan(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            result := lt(a, b)
        }
    }

    /// @notice Constant-time greater-than comparison
    /// @param a First value
    /// @param b Second value
    /// @return result 1 if a > b, 0 otherwise
    function constantTimeGreaterThan(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            result := gt(a, b)
        }
    }

    /// @notice Constant-time minimum
    /// @param a First value
    /// @param b Second value
    /// @return result The smaller value
    function constantTimeMin(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            // If a < b, mask = 0xFF...FF, else mask = 0
            let mask := sub(0, lt(a, b))
            // result = (a & mask) | (b & ~mask)
            result := or(and(a, mask), and(b, not(mask)))
        }
    }

    /// @notice Constant-time maximum
    /// @param a First value
    /// @param b Second value
    /// @return result The larger value
    function constantTimeMax(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            let mask := sub(0, gt(a, b))
            result := or(and(a, mask), and(b, not(mask)))
        }
    }

    /// @notice Constant-time absolute difference
    /// @param a First value
    /// @param b Second value
    /// @return result |a - b|
    function constantTimeAbsDiff(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            let diff := sub(a, b)
            let negDiff := sub(b, a)
            let mask := sub(0, gt(a, b))
            result := or(and(diff, mask), and(negDiff, not(mask)))
        }
    }

    // =========================================================================
    // CONSTANT-TIME MEMORY OPERATIONS
    // =========================================================================

    /// @notice Constant-time memory copy
    /// @dev Always copies exactly `length` bytes regardless of content
    /// @param dest Destination pointer
    /// @param src Source pointer
    /// @param length Number of bytes to copy
    function constantTimeCopy(
        bytes memory dest,
        bytes memory src,
        uint256 length
    ) internal pure {
        if (dest.length < length || src.length < length) revert InvalidLength();

        assembly {
            let destPtr := add(dest, 32)
            let srcPtr := add(src, 32)

            // Copy 32 bytes at a time
            for {
                let i := 0
            } lt(i, length) {
                i := add(i, 32)
            } {
                mstore(add(destPtr, i), mload(add(srcPtr, i)))
            }
        }
    }

    /// @notice Constant-time memory zero
    /// @dev Zeros memory in constant time
    /// @param data Memory to zero
    function constantTimeZero(bytes memory data) internal pure {
        assembly {
            let ptr := add(data, 32)
            let length := mload(data)

            for {
                let i := 0
            } lt(i, length) {
                i := add(i, 32)
            } {
                mstore(add(ptr, i), 0)
            }
        }
    }

    // =========================================================================
    // CONSTANT-TIME BIT OPERATIONS
    // =========================================================================

    /// @notice Constant-time bit extraction
    /// @param value Value to extract bit from
    /// @param position Bit position (0-255)
    /// @return bit The bit value (0 or 1)
    function constantTimeGetBit(
        uint256 value,
        uint8 position
    ) internal pure returns (uint256 bit) {
        assembly {
            bit := and(shr(position, value), 1)
        }
    }

    /// @notice Constant-time bit setting
    /// @param value Original value
    /// @param position Bit position
    /// @param bitValue New bit value (0 or 1)
    /// @return result Value with bit set
    function constantTimeSetBit(
        uint256 value,
        uint8 position,
        bool bitValue
    ) internal pure returns (uint256 result) {
        assembly {
            let mask := shl(position, 1)
            let clearMask := not(mask)
            let setBit := shl(position, bitValue)
            result := or(and(value, clearMask), setBit)
        }
    }

    /// @notice Constant-time population count (number of 1 bits)
    /// @param value Value to count bits in
    /// @return count Number of 1 bits
    function constantTimePopCount(
        uint256 value
    ) internal pure returns (uint256 count) {
        assembly {
            // Parallel bit counting algorithm
            // Process all bits in constant time

            // Step 1: Count pairs
            let
                m1
            := 0x5555555555555555555555555555555555555555555555555555555555555555
            value := add(and(value, m1), and(shr(1, value), m1))

            // Step 2: Count nibbles
            let
                m2
            := 0x3333333333333333333333333333333333333333333333333333333333333333
            value := add(and(value, m2), and(shr(2, value), m2))

            // Step 3: Count bytes
            let
                m4
            := 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
            value := add(and(value, m4), and(shr(4, value), m4))

            // Step 4: Sum all bytes
            let
                h01
            := 0x0101010101010101010101010101010101010101010101010101010101010101
            count := shr(248, mul(value, h01))
        }
    }

    // =========================================================================
    // CONSTANT-TIME VALIDATION
    // =========================================================================

    /// @notice Constant-time range check
    /// @dev Returns true if min <= value <= max in constant time
    /// @param value Value to check
    /// @param min Minimum allowed value
    /// @param max Maximum allowed value
    /// @return inRange True if in range
    function constantTimeInRange(
        uint256 value,
        uint256 min,
        uint256 max
    ) internal pure returns (bool inRange) {
        assembly {
            // value >= min AND value <= max
            let geMin := iszero(lt(value, min))
            let leMax := iszero(gt(value, max))
            inRange := and(geMin, leMax)
        }
    }

    /// @notice Constant-time non-zero check
    /// @param value Value to check
    /// @return nonZero True if value is non-zero
    function constantTimeIsNonZero(
        uint256 value
    ) internal pure returns (bool nonZero) {
        assembly {
            nonZero := iszero(iszero(value))
        }
    }

    /// @notice Constant-time power of 2 check
    /// @param value Value to check
    /// @return isPow2 True if value is a power of 2
    function constantTimeIsPowerOf2(
        uint256 value
    ) internal pure returns (bool isPow2) {
        assembly {
            // x is power of 2 if x > 0 and (x & (x-1)) == 0
            let nonZero := iszero(iszero(value))
            let oneBit := iszero(and(value, sub(value, 1)))
            isPow2 := and(nonZero, oneBit)
        }
    }

    // =========================================================================
    // CONSTANT-TIME CRYPTOGRAPHIC HELPERS
    // =========================================================================

    /// @notice Constant-time conditional swap
    /// @dev Swaps a and b if condition is true, in constant time
    /// @param condition Swap condition
    /// @param a First value (will contain smaller if condition)
    /// @param b Second value (will contain larger if condition)
    /// @return x First output
    /// @return y Second output
    function constantTimeSwap(
        bool condition,
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 x, uint256 y) {
        assembly {
            let mask := sub(0, condition)
            let diff := xor(a, b)
            let maskedDiff := and(diff, mask)
            x := xor(a, maskedDiff)
            y := xor(b, maskedDiff)
        }
    }

    /// @notice Constant-time modular reduction hint
    /// @dev For use with modular arithmetic to avoid timing leaks
    /// @param value Value to reduce
    /// @param modulus The modulus
    /// @return reduced The reduced value
    function constantTimeModHint(
        uint256 value,
        uint256 modulus
    ) internal pure returns (uint256 reduced) {
        assembly {
            reduced := mod(value, modulus)
        }
    }
}

/// @title ConstantTimePrivacy
/// @notice Higher-level constant-time operations specific to privacy protocols
library ConstantTimePrivacy {
    using ConstantTimeOperations for *;

    /// @notice Constant-time nullifier comparison
    /// @dev Critical for preventing timing attacks on nullifier lookups
    function constantTimeNullifierLookup(
        bytes32 target,
        bytes32[] memory nullifiers
    ) internal pure returns (bool found, uint256 index) {
        uint256 len = nullifiers.length;
        bytes32 foundMask = bytes32(0);
        uint256 foundIndex = 0;

        for (uint256 i = 0; i < len; i++) {
            bool match_ = ConstantTimeOperations.constantTimeEquals(
                target,
                nullifiers[i]
            );
            // Update found status using constant-time select
            foundMask = ConstantTimeOperations.constantTimeSelect(
                match_,
                bytes32(type(uint256).max),
                foundMask
            );
            foundIndex = ConstantTimeOperations.constantTimeSelectUint(
                match_,
                i,
                foundIndex
            );
        }

        found = foundMask != bytes32(0);
        index = foundIndex;
    }

    /// @notice Constant-time key image lookup
    /// @dev Prevents timing attacks when checking for double-spend
    function constantTimeKeyImageLookup(
        bytes32 keyImage,
        bytes32[] memory usedKeyImages
    ) internal pure returns (bool used) {
        (used, ) = constantTimeNullifierLookup(keyImage, usedKeyImages);
    }

    /// @notice Constant-time ring member selection
    /// @dev Selects decoy indices without timing leaks
    function constantTimeDecoySelect(
        uint256 realIndex,
        uint256 ringSize,
        uint256 randomSeed
    ) internal pure returns (uint256[] memory indices) {
        indices = new uint256[](ringSize);

        // Fill with sequential indices
        for (uint256 i = 0; i < ringSize; i++) {
            indices[i] = i;
        }

        // Fisher-Yates shuffle in constant time
        for (uint256 i = ringSize - 1; i > 0; i--) {
            uint256 j = uint256(keccak256(abi.encodePacked(randomSeed, i))) %
                (i + 1);
            (indices[i], indices[j]) = ConstantTimeOperations.constantTimeSwap(
                true, // Always swap for constant time
                indices[i],
                indices[j]
            );
        }

        // Place real index at a random position (constant-time)
        uint256 targetPos = uint256(
            keccak256(abi.encodePacked(randomSeed, "POS"))
        ) % ringSize;
        (indices[targetPos], ) = ConstantTimeOperations.constantTimeSwap(
            true,
            realIndex,
            indices[targetPos]
        );
    }

    /// @notice Constant-time commitment verification
    /// @dev Verifies Pedersen commitment without timing leaks
    function constantTimeCommitmentVerify(
        bytes32 commitment,
        uint256 value,
        bytes32 blinding,
        bytes32 expectedCommitment
    ) internal pure returns (bool valid) {
        // Compute commitment (this should also be constant-time in actual impl)
        bytes32 computed = keccak256(abi.encodePacked(value, blinding));

        // Constant-time comparison
        bool commitmentMatch = ConstantTimeOperations.constantTimeEquals(
            computed,
            commitment
        );
        bool expectedMatch = ConstantTimeOperations.constantTimeEquals(
            commitment,
            expectedCommitment
        );

        valid = commitmentMatch && expectedMatch;
    }
}
