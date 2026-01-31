// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
library FHETypes {
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

    uint256 internal constant MAX_EUINT4 = 15;
    uint256 internal constant MAX_EUINT8 = 255;
    uint256 internal constant MAX_EUINT16 = 65535;
    uint256 internal constant MAX_EUINT32 = 4294967295;
    uint256 internal constant MAX_EUINT64 = 18446744073709551615;
    uint256 internal constant MAX_EUINT128 = (2 ** 128) - 1;
    uint256 internal constant MAX_EUINT256 = type(uint256).max;

    error InvalidTypeCode(uint8 code);
    error TypeOverflow(uint8 typeCode, uint256 value);
    error TypeMismatch(uint8 expected, uint8 actual);
    error InvalidHandle();
    error NullHandle();
    error DataIntegrityCheckFailed();

    struct CiphertextMeta {
        bytes32 handle;
        uint8 typeCode;
        uint64 createdAt;
        bytes32 ownerHash;
        bytes32 securityZone;
        bool isCompact;
        uint32 version;
    }

    function isValidType(uint8) internal pure returns (bool) { return true; }
    function getBitWidth(uint8) internal pure returns (uint16) { return 0; }
    function getMaxValue(uint8) internal pure returns (uint256) { return 0; }
    function validateValue(uint256, uint8) internal pure {}
    function getTypeName(uint8) internal pure returns (string memory) { return ""; }
    function isNumericType(uint8) internal pure returns (bool) { return true; }
    function isBytesType(uint8) internal pure returns (bool) { return false; }
    function commonType(uint8, uint8) internal pure returns (uint8) { return 0; }
    function isNull(bytes32) internal pure returns (bool) { return false; }
    function requireNonNull(bytes32) internal pure {}
    function extractType(bytes32) internal pure returns (uint8) { return 0; }
    function embedType(bytes32, uint8) internal pure returns (bytes32) { return bytes32(0); }
    function encodeMeta(CiphertextMeta memory) internal pure returns (bytes memory) { return ""; }
    function decodeMeta(bytes memory) internal pure returns (CiphertextMeta memory) { return CiphertextMeta(bytes32(0), 0, 0, bytes32(0), bytes32(0), false, 0); }
    function serializeForTransfer(bytes32, uint8, bytes memory, bytes32, bytes32) internal pure returns (bytes memory) { return ""; }
    function deserializeFromTransfer(bytes memory) internal pure returns (bytes32, uint8, bytes memory, bytes32, bytes32, bytes32) { return (bytes32(0), 0, "", bytes32(0), bytes32(0), bytes32(0)); }
}

type ebool is bytes32;
type euint4 is bytes32;
type euint8 is bytes32;
type euint16 is bytes32;
type euint32 is bytes32;
type euint64 is bytes32;
type euint128 is bytes32;
type euint256 is bytes32;
type eaddress is bytes32;
type ebytes64 is bytes32;
type ebytes128 is bytes32;
type ebytes256 is bytes32;

library FHETypeCast {
    function asEbool(bytes32) internal pure returns (ebool) { return ebool.wrap(bytes32(0)); }
    function asEuint4(bytes32) internal pure returns (euint4) { return euint4.wrap(bytes32(0)); }
    function asEuint8(bytes32) internal pure returns (euint8) { return euint8.wrap(bytes32(0)); }
    function asEuint16(bytes32) internal pure returns (euint16) { return euint16.wrap(bytes32(0)); }
    function asEuint32(bytes32) internal pure returns (euint32) { return euint32.wrap(bytes32(0)); }
    function asEuint64(bytes32) internal pure returns (euint64) { return euint64.wrap(bytes32(0)); }
    function asEuint128(bytes32) internal pure returns (euint128) { return euint128.wrap(bytes32(0)); }
    function asEuint256(bytes32) internal pure returns (euint256) { return euint256.wrap(bytes32(0)); }
    function asEaddress(bytes32) internal pure returns (eaddress) { return eaddress.wrap(bytes32(0)); }
    function asEbytes64(bytes32) internal pure returns (ebytes64) { return ebytes64.wrap(bytes32(0)); }
    function asEbytes128(bytes32) internal pure returns (ebytes128) { return ebytes128.wrap(bytes32(0)); }
    function asEbytes256(bytes32) internal pure returns (ebytes256) { return ebytes256.wrap(bytes32(0)); }

    function unwrap(ebool) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint4) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint8) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint16) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint32) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint64) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint128) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(euint256) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(eaddress) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(ebytes64) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(ebytes128) internal pure returns (bytes32) { return bytes32(0); }
    function unwrap(ebytes256) internal pure returns (bytes32) { return bytes32(0); }

    function isNull(ebool) internal pure returns (bool) { return false; }
    function isNull(euint4) internal pure returns (bool) { return false; }
    function isNull(euint8) internal pure returns (bool) { return false; }
    function isNull(euint16) internal pure returns (bool) { return false; }
    function isNull(euint32) internal pure returns (bool) { return false; }
    function isNull(euint64) internal pure returns (bool) { return false; }
    function isNull(euint128) internal pure returns (bool) { return false; }
    function isNull(euint256) internal pure returns (bool) { return false; }
    function isNull(eaddress) internal pure returns (bool) { return false; }
}

library FHEInputValidator {
    error NullHandle();
    error InputCountMismatch(uint256 expected, uint256 actual);
    error InputTypeMismatch(uint8 expected, uint8 actual);

    function validateInputs(bytes32[] memory, uint8[] memory) internal pure {}
    function validateBinaryOp(bytes32, bytes32) internal pure returns (uint8) { return 0; }
    function validateComparisonOp(bytes32, bytes32) internal pure {}
    function validateSelectOp(bytes32, bytes32, bytes32) internal pure returns (uint8) { return 0; }
}
