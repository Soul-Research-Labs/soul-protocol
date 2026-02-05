// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FHETypes
 * @author Soul Protocol
 * @notice Type definitions and utilities for FHE encrypted values
 * @dev Provides type-safe wrappers for encrypted handles compatible with fhEVM
 *
 * Type System:
 * - ebool:    Encrypted boolean (1 bit)
 * - euint4:   Encrypted 4-bit unsigned integer
 * - euint8:   Encrypted 8-bit unsigned integer
 * - euint16:  Encrypted 16-bit unsigned integer
 * - euint32:  Encrypted 32-bit unsigned integer
 * - euint64:  Encrypted 64-bit unsigned integer
 * - euint128: Encrypted 128-bit unsigned integer
 * - euint256: Encrypted 256-bit unsigned integer
 * - eaddress: Encrypted address (160 bits)
 * - ebytes64: Encrypted 64-byte value
 * - ebytes128: Encrypted 128-byte value
 * - ebytes256: Encrypted 256-byte value
 */
library FHETypes {
    // ============================================
    // TYPE CODES
    // ============================================

    uint8 internal constant TYPE_EBOOL = 0;
    uint8 internal constant TYPE_EUINT4 = 1;
    uint8 internal constant TYPE_EUINT8 = 2;
    uint8 internal constant TYPE_EUINT16 = 3;
    uint8 internal constant TYPE_EUINT32 = 4;
    uint8 internal constant TYPE_EUINT64 = 5;
    uint8 internal constant TYPE_EUINT128 = 6;
    uint8 internal constant TYPE_EUINT256 = 7;
    uint8 internal constant TYPE_EADDRESS = 8;
    uint8 internal constant TYPE_EBYTES64 = 9;
    uint8 internal constant TYPE_EBYTES128 = 10;
    uint8 internal constant TYPE_EBYTES256 = 11;
    uint8 internal constant TYPE_EPACKED64X4 = 12; // 4x 64-bit values for SIMD

    // ============================================
    // TYPE BOUNDS
    // ============================================

    uint256 internal constant MAX_EUINT4 = 15;
    uint256 internal constant MAX_EUINT8 = 255;
    uint256 internal constant MAX_EUINT16 = 65535;
    uint256 internal constant MAX_EUINT32 = 4294967295;
    uint256 internal constant MAX_EUINT64 = 18446744073709551615;
    uint256 internal constant MAX_EUINT128 = (2 ** 128) - 1;
    uint256 internal constant MAX_EUINT256 = type(uint256).max;

    // ============================================
    // ERRORS
    // ============================================

    error InvalidTypeCode(uint8 code);
    error TypeOverflow(uint8 typeCode, uint256 value);
    error TypeMismatch(uint8 expected, uint8 actual);
    error InvalidHandle();
    error NullHandle();
    error DataIntegrityCheckFailed();

    // ============================================
    // TYPE VALIDATION
    // ============================================

    /**
     * @notice Check if type code is valid
     * @param typeCode The type code to check
     * @return valid Whether the type code is valid
     */
    function isValidType(uint8 typeCode) internal pure returns (bool valid) {
        return typeCode <= TYPE_EPACKED64X4;
    }

    /**
     * @notice Get the bit width for a type
     * @param typeCode The type code
     * @return bits The bit width
     */
    function getBitWidth(uint8 typeCode) internal pure returns (uint16 bits) {
        if (typeCode == TYPE_EBOOL) return 1;
        if (typeCode == TYPE_EUINT4) return 4;
        if (typeCode == TYPE_EUINT8) return 8;
        if (typeCode == TYPE_EUINT16) return 16;
        if (typeCode == TYPE_EUINT32) return 32;
        if (typeCode == TYPE_EUINT64) return 64;
        if (typeCode == TYPE_EUINT128) return 128;
        if (typeCode == TYPE_EUINT256) return 256;
        if (typeCode == TYPE_EADDRESS) return 160;
        if (typeCode == TYPE_EBYTES64) return 512;
        if (typeCode == TYPE_EBYTES128) return 1024;
        if (typeCode == TYPE_EBYTES256) return 2048;
        if (typeCode == TYPE_EPACKED64X4) return 256;
        revert InvalidTypeCode(typeCode);
    }

    /**
     * @notice Get maximum value for a type
     * @param typeCode The type code
     * @return maxValue The maximum value
     */
    function getMaxValue(
        uint8 typeCode
    ) internal pure returns (uint256 maxValue) {
        if (typeCode == TYPE_EBOOL) return 1;
        if (typeCode == TYPE_EUINT4) return MAX_EUINT4;
        if (typeCode == TYPE_EUINT8) return MAX_EUINT8;
        if (typeCode == TYPE_EUINT16) return MAX_EUINT16;
        if (typeCode == TYPE_EUINT32) return MAX_EUINT32;
        if (typeCode == TYPE_EUINT64) return MAX_EUINT64;
        if (typeCode == TYPE_EUINT128) return MAX_EUINT128;
        if (typeCode == TYPE_EUINT256) return MAX_EUINT256;
        if (typeCode == TYPE_EADDRESS) return type(uint160).max;
        // For bytes types, max value is the full range
        if (typeCode >= TYPE_EBYTES64) return MAX_EUINT256;
        revert InvalidTypeCode(typeCode);
    }

    /**
     * @notice Validate that a value fits within a type
     * @param value The value to check
     * @param typeCode The target type
     */
    function validateValue(uint256 value, uint8 typeCode) internal pure {
        uint256 maxVal = getMaxValue(typeCode);
        if (value > maxVal) {
            revert TypeOverflow(typeCode, value);
        }
    }

    /**
     * @notice Get type name as string
     * @param typeCode The type code
     * @return name The type name
     */
    function getTypeName(
        uint8 typeCode
    ) internal pure returns (string memory name) {
        if (typeCode == TYPE_EBOOL) return "ebool";
        if (typeCode == TYPE_EUINT4) return "euint4";
        if (typeCode == TYPE_EUINT8) return "euint8";
        if (typeCode == TYPE_EUINT16) return "euint16";
        if (typeCode == TYPE_EUINT32) return "euint32";
        if (typeCode == TYPE_EUINT64) return "euint64";
        if (typeCode == TYPE_EUINT128) return "euint128";
        if (typeCode == TYPE_EUINT256) return "euint256";
        if (typeCode == TYPE_EADDRESS) return "eaddress";
        if (typeCode == TYPE_EBYTES64) return "ebytes64";
        if (typeCode == TYPE_EBYTES128) return "ebytes128";
        if (typeCode == TYPE_EBYTES256) return "ebytes256";
        if (typeCode == TYPE_EPACKED64X4) return "epacked64x4";
        revert InvalidTypeCode(typeCode);
    }

    /**
     * @notice Check if type is a numeric type (can do arithmetic)
     */
    function isNumericType(uint8 typeCode) internal pure returns (bool) {
        return typeCode >= TYPE_EUINT4 && typeCode <= TYPE_EUINT256;
    }

    /**
     * @notice Check if type is a bytes type
     */
    function isBytesType(uint8 typeCode) internal pure returns (bool) {
        return typeCode >= TYPE_EBYTES64;
    }

    /**
     * @notice Get the common type for two types (for binary operations)
     * @dev Returns the larger type, or reverts if incompatible
     */
    function commonType(
        uint8 typeA,
        uint8 typeB
    ) internal pure returns (uint8) {
        if (typeA == typeB) return typeA;

        // Both must be numeric for promotion
        if (!isNumericType(typeA) || !isNumericType(typeB)) {
            revert TypeMismatch(typeA, typeB);
        }

        // Return the larger type
        return typeA > typeB ? typeA : typeB;
    }

    // ============================================
    // HANDLE UTILITIES
    // ============================================

    /**
     * @notice Check if handle is null
     */
    function isNull(bytes32 handle) internal pure returns (bool) {
        return handle == bytes32(0);
    }

    /**
     * @notice Require handle is not null
     */
    function requireNonNull(bytes32 handle) internal pure {
        if (handle == bytes32(0)) {
            revert NullHandle();
        }
    }

    /**
     * @notice Extract type code from handle (embedded in last byte)
     * @dev Handle format: [254 bits data][8 bits type]
     */
    function extractType(bytes32 handle) internal pure returns (uint8) {
        return uint8(uint256(handle) & 0xFF);
    }

    /**
     * @notice Create handle with embedded type
     */
    function embedType(
        bytes32 baseHandle,
        uint8 typeCode
    ) internal pure returns (bytes32) {
        // Clear last byte and set type
        return
            bytes32((uint256(baseHandle) & ~uint256(0xFF)) | uint256(typeCode));
    }

    // ============================================
    // CIPHERTEXT METADATA
    // ============================================

    /**
     * @notice Ciphertext metadata structure
     */
    struct CiphertextMeta {
        bytes32 handle; // Handle reference
        uint8 typeCode; // Type of encrypted value
        uint64 createdAt; // Creation timestamp
        bytes32 ownerHash; // Hash of owner identity
        bytes32 securityZone; // Security domain
        bool isCompact; // Compact ciphertext format
        uint32 version; // Schema version
    }

    /**
     * @notice Encode ciphertext metadata
     */
    function encodeMeta(
        CiphertextMeta memory meta
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                meta.handle,
                meta.typeCode,
                meta.createdAt,
                meta.ownerHash,
                meta.securityZone,
                meta.isCompact,
                meta.version
            );
    }

    /**
     * @notice Decode ciphertext metadata
     */
    function decodeMeta(
        bytes memory data
    ) internal pure returns (CiphertextMeta memory meta) {
        (
            meta.handle,
            meta.typeCode,
            meta.createdAt,
            meta.ownerHash,
            meta.securityZone,
            meta.isCompact,
            meta.version
        ) = abi.decode(
            data,
            (bytes32, uint8, uint64, bytes32, bytes32, bool, uint32)
        );
    }

    // ============================================
    // SERIALIZATION
    // ============================================

    /**
     * @notice Serialize encrypted value for cross-chain transfer
     */
    function serializeForTransfer(
        bytes32 handle,
        uint8 typeCode,
        bytes memory ciphertextData,
        bytes32 sourceChain,
        bytes32 destChain
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                handle,
                typeCode,
                ciphertextData,
                sourceChain,
                destChain,
                keccak256(abi.encode(handle, typeCode, ciphertextData))
            );
    }

    /**
     * @notice Deserialize encrypted value from cross-chain transfer
     */
    function deserializeFromTransfer(
        bytes memory data
    )
        internal
        pure
        returns (
            bytes32 handle,
            uint8 typeCode,
            bytes memory ciphertextData,
            bytes32 sourceChain,
            bytes32 destChain,
            bytes32 dataHash
        )
    {
        (
            handle,
            typeCode,
            ciphertextData,
            sourceChain,
            destChain,
            dataHash
        ) = abi.decode(
            data,
            (bytes32, uint8, bytes, bytes32, bytes32, bytes32)
        );

        // Verify data integrity
        if (
            dataHash != keccak256(abi.encode(handle, typeCode, ciphertextData))
        ) {
            revert DataIntegrityCheckFailed();
        }
    }
}

/**
 * @title Encrypted type wrappers
 * @notice User-defined types for encrypted values
 */

// Encrypted boolean
type ebool is bytes32;

// Encrypted unsigned integers
type euint4 is bytes32;
type euint8 is bytes32;
type euint16 is bytes32;
type euint32 is bytes32;
type euint64 is bytes32;
type euint128 is bytes32;
type euint256 is bytes32;

// Encrypted address
type eaddress is bytes32;

// Encrypted bytes
type ebytes64 is bytes32;
type ebytes128 is bytes32;
type ebytes256 is bytes32;
type epacked64x4 is bytes32;

/**
 * @title FHETypeCast
 * @notice Type casting utilities for encrypted values
 */
library FHETypeCast {
    using FHETypes for uint8;
    using FHETypes for bytes32;

    // ============================================
    // WRAP/UNWRAP
    // ============================================

    function asEbool(bytes32 handle) internal pure returns (ebool) {
        return ebool.wrap(handle);
    }

    function asEuint4(bytes32 handle) internal pure returns (euint4) {
        return euint4.wrap(handle);
    }

    function asEuint8(bytes32 handle) internal pure returns (euint8) {
        return euint8.wrap(handle);
    }

    function asEuint16(bytes32 handle) internal pure returns (euint16) {
        return euint16.wrap(handle);
    }

    function asEuint32(bytes32 handle) internal pure returns (euint32) {
        return euint32.wrap(handle);
    }

    function asEuint64(bytes32 handle) internal pure returns (euint64) {
        return euint64.wrap(handle);
    }

    function asEuint128(bytes32 handle) internal pure returns (euint128) {
        return euint128.wrap(handle);
    }

    function asEuint256(bytes32 handle) internal pure returns (euint256) {
        return euint256.wrap(handle);
    }

    function asEaddress(bytes32 handle) internal pure returns (eaddress) {
        return eaddress.wrap(handle);
    }

    function asEbytes64(bytes32 handle) internal pure returns (ebytes64) {
        return ebytes64.wrap(handle);
    }

    function asEbytes128(bytes32 handle) internal pure returns (ebytes128) {
        return ebytes128.wrap(handle);
    }

    function asEbytes256(bytes32 handle) internal pure returns (ebytes256) {
        return ebytes256.wrap(handle);
    }

    // Unwrap functions
    function unwrap(ebool v) internal pure returns (bytes32) {
        return ebool.unwrap(v);
    }

    function unwrap(euint4 v) internal pure returns (bytes32) {
        return euint4.unwrap(v);
    }

    function unwrap(euint8 v) internal pure returns (bytes32) {
        return euint8.unwrap(v);
    }

    function unwrap(euint16 v) internal pure returns (bytes32) {
        return euint16.unwrap(v);
    }

    function unwrap(euint32 v) internal pure returns (bytes32) {
        return euint32.unwrap(v);
    }

    function unwrap(euint64 v) internal pure returns (bytes32) {
        return euint64.unwrap(v);
    }

    function unwrap(euint128 v) internal pure returns (bytes32) {
        return euint128.unwrap(v);
    }

    function unwrap(euint256 v) internal pure returns (bytes32) {
        return euint256.unwrap(v);
    }

    function unwrap(eaddress v) internal pure returns (bytes32) {
        return eaddress.unwrap(v);
    }

    function unwrap(ebytes64 v) internal pure returns (bytes32) {
        return ebytes64.unwrap(v);
    }

    function unwrap(ebytes128 v) internal pure returns (bytes32) {
        return ebytes128.unwrap(v);
    }

    function unwrap(ebytes256 v) internal pure returns (bytes32) {
        return ebytes256.unwrap(v);
    }

    // ============================================
    // NULL CHECKS
    // ============================================

    function isNull(ebool v) internal pure returns (bool) {
        return ebool.unwrap(v) == bytes32(0);
    }

    function isNull(euint4 v) internal pure returns (bool) {
        return euint4.unwrap(v) == bytes32(0);
    }

    function isNull(euint8 v) internal pure returns (bool) {
        return euint8.unwrap(v) == bytes32(0);
    }

    function isNull(euint16 v) internal pure returns (bool) {
        return euint16.unwrap(v) == bytes32(0);
    }

    function isNull(euint32 v) internal pure returns (bool) {
        return euint32.unwrap(v) == bytes32(0);
    }

    function isNull(euint64 v) internal pure returns (bool) {
        return euint64.unwrap(v) == bytes32(0);
    }

    function isNull(euint128 v) internal pure returns (bool) {
        return euint128.unwrap(v) == bytes32(0);
    }

    function isNull(euint256 v) internal pure returns (bool) {
        return euint256.unwrap(v) == bytes32(0);
    }

    function isNull(eaddress v) internal pure returns (bool) {
        return eaddress.unwrap(v) == bytes32(0);
    }
}

/**
 * @title FHEInputValidator
 * @notice Validates encrypted inputs before operations
 */
library FHEInputValidator {
    using FHETypes for uint8;
    using FHETypeCast for bytes32;

    error NullHandle();
    error InputCountMismatch(uint256 expected, uint256 actual);
    error InputTypeMismatch(uint8 expected, uint8 actual);

    /**
     * @notice Validate input list for computation
     */
    function validateInputs(
        bytes32[] memory inputs,
        uint8[] memory expectedTypes
    ) internal pure {
        if (inputs.length != expectedTypes.length) {
            revert InputCountMismatch(expectedTypes.length, inputs.length);
        }

        for (uint256 i = 0; i < inputs.length; i++) {
            if (inputs[i] == bytes32(0)) {
                revert NullHandle();
            }

            uint8 actualType = FHETypes.extractType(inputs[i]);
            if (actualType != expectedTypes[i]) {
                revert InputTypeMismatch(expectedTypes[i], actualType);
            }
        }
    }

    /**
     * @notice Validate binary operation inputs
     */
    function validateBinaryOp(
        bytes32 lhs,
        bytes32 rhs
    ) internal pure returns (uint8 resultType) {
        FHETypes.requireNonNull(lhs);
        FHETypes.requireNonNull(rhs);

        uint8 typeA = FHETypes.extractType(lhs);
        uint8 typeB = FHETypes.extractType(rhs);

        return FHETypes.commonType(typeA, typeB);
    }

    /**
     * @notice Validate comparison operation inputs
     */
    function validateComparisonOp(bytes32 lhs, bytes32 rhs) internal pure {
        FHETypes.requireNonNull(lhs);
        FHETypes.requireNonNull(rhs);

        uint8 typeA = FHETypes.extractType(lhs);
        uint8 typeB = FHETypes.extractType(rhs);

        // Must be same type or both numeric
        if (typeA != typeB) {
            if (
                !FHETypes.isNumericType(typeA) || !FHETypes.isNumericType(typeB)
            ) {
                revert InputTypeMismatch(typeA, typeB);
            }
        }
    }

    /**
     * @notice Validate select operation inputs
     */
    function validateSelectOp(
        bytes32 condition,
        bytes32 ifTrue,
        bytes32 ifFalse
    ) internal pure returns (uint8 resultType) {
        FHETypes.requireNonNull(condition);
        FHETypes.requireNonNull(ifTrue);
        FHETypes.requireNonNull(ifFalse);

        // Condition must be ebool
        uint8 condType = FHETypes.extractType(condition);
        if (condType != FHETypes.TYPE_EBOOL) {
            revert InputTypeMismatch(FHETypes.TYPE_EBOOL, condType);
        }

        // True and false branches must match
        uint8 trueType = FHETypes.extractType(ifTrue);
        uint8 falseType = FHETypes.extractType(ifFalse);

        if (trueType != falseType) {
            revert InputTypeMismatch(trueType, falseType);
        }

        return trueType;
    }
}
