// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title StackOptimizedHelper
 * @author ZASEON
 * @notice Gas and stack-optimized helper functions for complex operations
 * @dev Extracts common logic from main contracts to reduce stack depth.
 *      These functions are designed to be called internally and help
 *      complex contracts like ZKBoundStateLocks pass coverage instrumentation.
 *
 * USAGE:
 * Import and use as a library or inherit for internal access.
 *
 * STACK OPTIMIZATION TECHNIQUES:
 * - Function extraction: Large functions split into smaller units
 * - Variable consolidation: Related data packed into structs
 * - Early returns: Validation checks fail fast
 * - Memory vs storage: Strategic use to reduce stack pressure
 */
library StackOptimizedHelper {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidInput();
    error OverflowDetected();
    error UnderflowDetected();

    /*//////////////////////////////////////////////////////////////
                            HASHING UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes a domain-separated hash
     * @dev Uses EIP-712 style domain separation for uniqueness
     * @param domainSeparator The domain separator (chain + app + epoch)
     * @param structHash Hash of the struct being signed
     * @return digest The final domain-separated digest
     */
    function computeDomainHash(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32 digest) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }

    /**
     * @notice Computes lock ID from components
     * @dev Deterministic hash ensuring global uniqueness
     * @param stateCommitment The state being locked
     * @param predicateHash Hash of transition predicate
     * @param domainSeparator Domain separator
     * @param creator Lock creator address
     * @param nonce Unique nonce
     * @return lockId Unique lock identifier
     */
    function computeLockId(
        bytes32 stateCommitment,
        bytes32 predicateHash,
        bytes32 domainSeparator,
        address creator,
        uint256 nonce
    ) internal pure returns (bytes32 lockId) {
        return
            keccak256(
                abi.encodePacked(
                    stateCommitment,
                    predicateHash,
                    domainSeparator,
                    creator,
                    nonce
                )
            );
    }

    /**
     * @notice Computes cross-domain nullifier
     * @dev CDNA: Nullifier = H(secret || domain || transitionId)
     * @param secret User's secret
     * @param domainSeparator Domain context
     * @param transitionId Transition identifier
     * @return nullifier The computed nullifier
     */
    function computeNullifier(
        bytes32 secret,
        bytes32 domainSeparator,
        bytes32 transitionId
    ) internal pure returns (bytes32 nullifier) {
        return
            keccak256(abi.encodePacked(secret, domainSeparator, transitionId));
    }

    /*//////////////////////////////////////////////////////////////
                          VALIDATION UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates proof structure before detailed verification
     * @dev Quick checks to fail fast and save gas
     * @param proofData Raw proof bytes
     * @param minLength Minimum expected length
     * @param maxLength Maximum expected length
     * @return valid True if basic structure is valid
     */
    function validateProofStructure(
        bytes memory proofData,
        uint256 minLength,
        uint256 maxLength
    ) internal pure returns (bool valid) {
        uint256 len = proofData.length;
        return len >= minLength && len <= maxLength;
    }

    /**
     * @notice Checks if timestamp is within valid range
     * @param timestamp Timestamp to check
     * @param minTime Minimum allowed time
     * @param maxTime Maximum allowed time
     * @return valid True if within range
     */
    function isTimestampValid(
        uint256 timestamp,
        uint256 minTime,
        uint256 maxTime
    ) internal pure returns (bool valid) {
        return timestamp >= minTime && timestamp <= maxTime;
    }

    /**
     * @notice Safe deadline check with buffer
     * @param deadline The deadline timestamp
     * @param buffer Time buffer for miner manipulation
     * @return expired True if deadline has passed
     */
    function isDeadlineExpired(
        uint256 deadline,
        uint256 buffer
    ) internal view returns (bool expired) {
        return block.timestamp > deadline + buffer;
    }

    /*//////////////////////////////////////////////////////////////
                          PACKING UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Packs two uint128 values into one uint256
     * @param high High 128 bits
     * @param low Low 128 bits
     * @return packed The packed uint256
     */
    function packUint128(
        uint128 high,
        uint128 low
    ) internal pure returns (uint256 packed) {
        return (uint256(high) << 128) | uint256(low);
    }

    /**
     * @notice Unpacks uint256 into two uint128 values
     * @param packed The packed value
     * @return high High 128 bits
     * @return low Low 128 bits
     */
    function unpackUint128(
        uint256 packed
    ) internal pure returns (uint128 high, uint128 low) {
        high = uint128(packed >> 128);
        low = uint128(packed);
    }

    /**
     * @notice Packs address and uint96 into uint256
     * @param addr 20-byte address
     * @param value 12-byte value
     * @return packed The packed uint256
     */
    function packAddressUint96(
        address addr,
        uint96 value
    ) internal pure returns (uint256 packed) {
        return (uint256(uint160(addr)) << 96) | uint256(value);
    }

    /*//////////////////////////////////////////////////////////////
                          ARRAY UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes Merkle root from leaf and path
     * @dev Reduces stack depth by handling path verification in library
     * @param leaf The leaf hash
     * @param path Array of sibling hashes
     * @param indices Bit flags indicating left/right
     * @return root Computed Merkle root
     */
    function computeMerkleRoot(
        bytes32 leaf,
        bytes32[] memory path,
        uint256 indices
    ) internal pure returns (bytes32 root) {
        root = leaf;
        for (uint256 i = 0; i < path.length; ) {
            bytes32 sibling = path[i];
            bool isLeft = (indices >> i) & 1 == 0;

            if (isLeft) {
                root = keccak256(abi.encodePacked(root, sibling));
            } else {
                root = keccak256(abi.encodePacked(sibling, root));
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Safely gets element from bytes32 array
     * @param arr The array
     * @param index Index to access
     * @return element The element at index (or zero if out of bounds)
     */
    function safeGet(
        bytes32[] memory arr,
        uint256 index
    ) internal pure returns (bytes32 element) {
        if (index < arr.length) {
            return arr[index];
        }
        return bytes32(0);
    }
}
