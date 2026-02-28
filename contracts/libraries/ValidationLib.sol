// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ValidationLib
 * @author ZASEON
 * @notice Gas-optimized validation library for common checks across ZASEON
 * @dev Reduces code duplication and provides consistent error handling
 *
 * GAS SAVINGS:
 * - Assembly-based zero checks: ~20 gas per call
 * - Consolidated validation: ~100-500 gas by reducing redundant checks
 * - Custom errors vs require strings: ~200+ gas savings
 */
library ValidationLib {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a zero address is provided where it's not allowed
    error ZeroAddress();

    /// @notice Thrown when a zero value is provided where it's not allowed
    error ZeroValue();

    /// @notice Thrown when an array is empty
    error EmptyArray();

    /// @notice Thrown when array lengths don't match
    error ArrayLengthMismatch(uint256 expected, uint256 actual);

    /// @notice Thrown when a batch exceeds maximum size
    error BatchTooLarge(uint256 size, uint256 maxSize);

    /// @notice Thrown when an amount exceeds a threshold
    error AmountExceedsThreshold(uint256 amount, uint256 threshold);

    /// @notice Thrown when an operation has expired
    error Expired(uint256 deadline, uint256 currentTime);

    /// @notice Thrown when an invalid chain ID is provided
    error InvalidChainId(uint256 chainId);

    /// @notice Thrown when a value is out of bounds
    error OutOfBounds(uint256 value, uint256 min, uint256 max);

    /*//////////////////////////////////////////////////////////////
                          ADDRESS VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that an address is not zero
     * @dev Uses assembly for gas optimization (~20 gas cheaper than Solidity)
     * @param addr The address to validate
     */
    function requireNonZeroAddress(address addr) internal pure {
        assembly {
            if iszero(addr) {
                // ZeroAddress() selector = 0xd92e233d
                mstore(
                    0x00,
                    0xd92e233d00000000000000000000000000000000000000000000000000000000
                )
                revert(0x00, 0x04)
            }
        }
    }

    /**
     * @notice Validates multiple addresses are not zero
     * @dev Batch validation for constructor/initializer patterns
     * @param addresses Array of addresses to validate
     */
    function requireNonZeroAddresses(address[] memory addresses) internal pure {
        uint256 len = addresses.length;
        for (uint256 i = 0; i < len; ) {
            requireNonZeroAddress(addresses[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Validates two addresses are not zero (common pattern)
     * @param addr1 First address
     * @param addr2 Second address
     */
    function requireNonZeroAddresses(
        address addr1,
        address addr2
    ) internal pure {
        requireNonZeroAddress(addr1);
        requireNonZeroAddress(addr2);
    }

    /*//////////////////////////////////////////////////////////////
                          VALUE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that a uint256 value is not zero
     * @param value The value to validate
     */
    function requireNonZeroValue(uint256 value) internal pure {
        assembly {
            if iszero(value) {
                // ZeroValue() selector = 0x7c946ed7
                mstore(
                    0x00,
                    0x7c946ed700000000000000000000000000000000000000000000000000000000
                )
                revert(0x00, 0x04)
            }
        }
    }

    /**
     * @notice Validates value is within bounds [min, max]
     * @param value The value to validate
     * @param min Minimum allowed value
     * @param max Maximum allowed value
     */
    function requireInBounds(
        uint256 value,
        uint256 min,
        uint256 max
    ) internal pure {
        if (value < min || value > max) {
            revert OutOfBounds(value, min, max);
        }
    }

    /**
     * @notice Validates value does not exceed threshold
     * @param value The value to check
     * @param threshold The maximum allowed value
     */
    function requireBelowThreshold(
        uint256 value,
        uint256 threshold
    ) internal pure {
        if (value > threshold) {
            revert AmountExceedsThreshold(value, threshold);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ARRAY VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that an array is not empty
     * @param length The array length to validate
     */
    function requireNonEmptyArray(uint256 length) internal pure {
        assembly {
            if iszero(length) {
                // EmptyArray() selector
                mstore(
                    0x00,
                    0x0a72b8ce00000000000000000000000000000000000000000000000000000000
                )
                revert(0x00, 0x04)
            }
        }
    }

    /**
     * @notice Validates that two arrays have matching lengths
     * @param len1 First array length
     * @param len2 Second array length
     */
    function requireMatchingLengths(uint256 len1, uint256 len2) internal pure {
        if (len1 != len2) {
            revert ArrayLengthMismatch(len1, len2);
        }
    }

    /**
     * @notice Validates batch size is within limits
     * @param size Current batch size
     * @param maxSize Maximum allowed batch size
     */
    function requireValidBatchSize(
        uint256 size,
        uint256 maxSize
    ) internal pure {
        requireNonEmptyArray(size);
        if (size > maxSize) {
            revert BatchTooLarge(size, maxSize);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          TIME VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that a deadline has not passed
     * @param deadline The deadline timestamp
     */
    function requireNotExpired(uint256 deadline) internal view {
        if (block.timestamp > deadline) {
            revert Expired(deadline, block.timestamp);
        }
    }

    /**
     * @notice Validates that a deadline has passed
     * @param deadline The deadline timestamp
     */
    function requireExpired(uint256 deadline) internal view {
        if (block.timestamp <= deadline) {
            revert Expired(deadline, block.timestamp);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         CHAIN ID VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that a chain ID is valid (non-zero and not current chain)
     * @param chainId The chain ID to validate
     */
    function requireValidDestinationChain(uint256 chainId) internal view {
        if (chainId == 0 || chainId == block.chainid) {
            revert InvalidChainId(chainId);
        }
    }

    /**
     * @notice Validates that we're on the expected chain
     * @param expectedChainId The expected chain ID
     */
    function requireOnChain(uint256 expectedChainId) internal view {
        if (block.chainid != expectedChainId) {
            revert InvalidChainId(block.chainid);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        BYTES VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that bytes data is not empty
     * @param data The bytes data to validate
     */
    function requireNonEmptyBytes(bytes calldata data) internal pure {
        if (data.length == 0) {
            revert EmptyArray();
        }
    }

    /**
     * @notice Validates that bytes32 is not zero
     * @param value The bytes32 value to validate
     */
    function requireNonZeroBytes32(bytes32 value) internal pure {
        assembly {
            if iszero(value) {
                // ZeroValue() selector
                mstore(
                    0x00,
                    0x7c946ed700000000000000000000000000000000000000000000000000000000
                )
                revert(0x00, 0x04)
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                      COMPOUND VALIDATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates a standard transfer: non-zero recipient, non-zero amount
     * @param recipient The transfer recipient
     * @param amount The transfer amount
     */
    function validateTransfer(address recipient, uint256 amount) internal pure {
        requireNonZeroAddress(recipient);
        requireNonZeroValue(amount);
    }

    /**
     * @notice Validates proof submission parameters
     * @param proof The proof data
     * @param publicInputs The public inputs
     * @param sourceChainId Source chain ID
     * @param destChainId Destination chain ID
     */
    function validateProofParams(
        bytes calldata proof,
        bytes calldata publicInputs,
        uint64 sourceChainId,
        uint64 destChainId
    ) internal view {
        requireNonEmptyBytes(proof);
        requireNonEmptyBytes(publicInputs);
        requireNonZeroValue(sourceChainId);
        requireValidDestinationChain(destChainId);
    }
}
