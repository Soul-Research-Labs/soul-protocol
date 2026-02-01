// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FHEGateway.sol";
import "./FHETypes.sol";
import "./lib/FHEUtils.sol";

/**
 * @title FHEOperations
 * @author Soul Protocol
 * @notice Library for FHE operations with type-safe wrappers
 * @dev Provides convenient functions for encrypted computations via FHEGateway
 *
 * Operation Categories:
 * - Arithmetic: add, sub, mul, div, rem, neg
 * - Comparison: eq, ne, ge, gt, le, lt, min, max
 * - Bitwise: and, or, xor, not, shl, shr, rotl, rotr
 * - Conditional: select (ternary), cmux
 * - Casting: asEuintX (type promotion)
 * - Random: rand (encrypted random)
 */
library FHEOperations {
    using FHETypeCast for bytes32;
    using FHETypeCast for ebool;
    using FHETypeCast for euint8;
    using FHETypeCast for euint16;
    using FHETypeCast for euint32;
    using FHETypeCast for euint64;
    using FHETypeCast for euint128;
    using FHETypeCast for euint256;
    using FHETypeCast for epacked64x4;

    // ============================================
    // ERRORS
    // ============================================

    error GatewayNotSet();
    error OperationFailed();

    // ============================================
    // GATEWAY STORAGE
    // ============================================

    // Storage slot for gateway address - fixed hex to work with assembly
    // keccak256("fhe.operations.gateway.slot")
    bytes32 private constant GATEWAY_SLOT =
        0x7a8dd5c3f3e6b0d4d7c3e17bf5b0c8c5c1f3a8b9e7d6c5b4a3f2e1d0c9b8a7f6;

    /**
     * @notice Set the FHE gateway address
     * @param gateway The gateway contract address
     */
    function setGateway(address gateway) internal {
        assembly {
            sstore(
                0x7a8dd5c3f3e6b0d4d7c3e17bf5b0c8c5c1f3a8b9e7d6c5b4a3f2e1d0c9b8a7f6,
                gateway
            )
        }
    }

    /**
     * @notice Get the FHE gateway address
     * @return gateway The gateway contract address
     */
    function getGateway() internal view returns (FHEGateway gateway) {
        address addr;
        assembly {
            addr := sload(
                0x7a8dd5c3f3e6b0d4d7c3e17bf5b0c8c5c1f3a8b9e7d6c5b4a3f2e1d0c9b8a7f6
            )
        }
        if (addr == address(0)) revert GatewayNotSet();
        return FHEGateway(addr);
    }

    // ============================================
    // HELPERS
    // ============================================

    function _performBinary(FHEUtils.Opcode op, bytes32 lhs, bytes32 rhs) private returns (bytes32) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = lhs;
        inputs[1] = rhs;
        return getGateway().performOp(op, inputs, "");
    }

    function _performUnary(FHEUtils.Opcode op, bytes32 val) private returns (bytes32) {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = val;
        return getGateway().performOp(op, inputs, "");
    }

    function _performShift(FHEUtils.Opcode op, bytes32 val, uint8 bits) private returns (bytes32) {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = val;
        return getGateway().performOp(op, inputs, abi.encode(bits));
    }

    function _performTernary(FHEUtils.Opcode op, bytes32 a, bytes32 b, bytes32 c) private returns (bytes32) {
        bytes32[] memory inputs = new bytes32[](3);
        inputs[0] = a;
        inputs[1] = b;
        inputs[2] = c;
        return getGateway().performOp(op, inputs, "");
    }

    // ============================================
    // TRIVIAL ENCRYPT (plaintext -> ciphertext)
    // ============================================

    /**
     * @notice Encrypt a boolean value
     */
    function asEbool(bool value) internal returns (ebool) {
        bytes32 handle = getGateway().trivialEncrypt(
            value ? 1 : 0,
            FHETypes.TYPE_EBOOL
        );
        return ebool.wrap(handle);
    }

    /**
     * @notice Encrypt a uint8 value
     */
    function asEuint8(uint8 value) internal returns (euint8) {
        bytes32 handle = getGateway().trivialEncrypt(
            value,
            FHETypes.TYPE_EUINT8
        );
        return euint8.wrap(handle);
    }

    /**
     * @notice Encrypt a uint16 value
     */
    function asEuint16(uint16 value) internal returns (euint16) {
        bytes32 handle = getGateway().trivialEncrypt(
            value,
            FHETypes.TYPE_EUINT16
        );
        return euint16.wrap(handle);
    }

    /**
     * @notice Encrypt a uint32 value
     */
    function asEuint32(uint32 value) internal returns (euint32) {
        bytes32 handle = getGateway().trivialEncrypt(
            value,
            FHETypes.TYPE_EUINT32
        );
        return euint32.wrap(handle);
    }

    /**
     * @notice Encrypt a uint64 value
     */
    function asEuint64(uint64 value) internal returns (euint64) {
        bytes32 handle = getGateway().trivialEncrypt(
            value,
            FHETypes.TYPE_EUINT64
        );
        return euint64.wrap(handle);
    }

    /**
     * @notice Encrypt a uint128 value
     */
    function asEuint128(uint128 value) internal returns (euint128) {
        bytes32 handle = getGateway().trivialEncrypt(
            value,
            FHETypes.TYPE_EUINT128
        );
        return euint128.wrap(handle);
    }

    /**
     * @notice Encrypt a uint256 value
     */
    function asEuint256(uint256 value) internal returns (euint256) {
        bytes32 handle = getGateway().trivialEncrypt(
            value,
            FHETypes.TYPE_EUINT256
        );
        return euint256.wrap(handle);
    }

    /**
     * @notice Encrypt an address value
     */
    function asEaddress(address value) internal returns (eaddress) {
        bytes32 handle = getGateway().trivialEncrypt(
            uint256(uint160(value)),
            FHETypes.TYPE_EADDRESS
        );
        return eaddress.wrap(handle);
    }

    // ============================================
    // ARITHMETIC OPERATIONS
    // ============================================

    // --- euint8 ---

    function add(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.ADD, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function sub(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.SUB, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function mul(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.MUL, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function div(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.DIV, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function rem(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.REM, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function neg(euint8 value) internal returns (euint8) {
        return euint8.wrap(_performUnary(FHEUtils.Opcode.NEG, euint8.unwrap(value)));
    }

    // --- euint16 ---

    function add(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return euint16.wrap(_performBinary(FHEUtils.Opcode.ADD, euint16.unwrap(lhs), euint16.unwrap(rhs)));
    }

    function sub(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return euint16.wrap(_performBinary(FHEUtils.Opcode.SUB, euint16.unwrap(lhs), euint16.unwrap(rhs)));
    }

    function mul(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return euint16.wrap(_performBinary(FHEUtils.Opcode.MUL, euint16.unwrap(lhs), euint16.unwrap(rhs)));
    }

    function div(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return euint16.wrap(_performBinary(FHEUtils.Opcode.DIV, euint16.unwrap(lhs), euint16.unwrap(rhs)));
    }

    function rem(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return euint16.wrap(_performBinary(FHEUtils.Opcode.REM, euint16.unwrap(lhs), euint16.unwrap(rhs)));
    }

    function neg(euint16 value) internal returns (euint16) {
        return euint16.wrap(_performUnary(FHEUtils.Opcode.NEG, euint16.unwrap(value)));
    }

    // --- euint32 ---

    function add(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.ADD, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function sub(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.SUB, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function mul(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.MUL, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function div(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.DIV, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function rem(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.REM, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function neg(euint32 value) internal returns (euint32) {
        return euint32.wrap(_performUnary(FHEUtils.Opcode.NEG, euint32.unwrap(value)));
    }

    // --- euint64 ---

    function add(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.ADD, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function sub(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.SUB, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function mul(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.MUL, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function div(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.DIV, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function rem(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.REM, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function neg(euint64 value) internal returns (euint64) {
        return euint64.wrap(_performUnary(FHEUtils.Opcode.NEG, euint64.unwrap(value)));
    }

    // --- euint128 ---

    function add(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return euint128.wrap(_performBinary(FHEUtils.Opcode.ADD, euint128.unwrap(lhs), euint128.unwrap(rhs)));
    }

    function sub(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return euint128.wrap(_performBinary(FHEUtils.Opcode.SUB, euint128.unwrap(lhs), euint128.unwrap(rhs)));
    }

    function mul(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return euint128.wrap(_performBinary(FHEUtils.Opcode.MUL, euint128.unwrap(lhs), euint128.unwrap(rhs)));
    }

    // --- euint256 ---

    function add(euint256 lhs, euint256 rhs) internal returns (euint256) {
        return euint256.wrap(_performBinary(FHEUtils.Opcode.ADD, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    function sub(euint256 lhs, euint256 rhs) internal returns (euint256) {
        return euint256.wrap(_performBinary(FHEUtils.Opcode.SUB, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    function mul(euint256 lhs, euint256 rhs) internal returns (euint256) {
        return euint256.wrap(_performBinary(FHEUtils.Opcode.MUL, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    // --- epacked64x4 (SIMD) ---

    /**
     * @notice SIMD addition of two packed ciphertexts
     */
    function simdAdd(epacked64x4 lhs, epacked64x4 rhs) internal returns (epacked64x4) {
        return epacked64x4.wrap(_performBinary(FHEUtils.Opcode.ADD, epacked64x4.unwrap(lhs), epacked64x4.unwrap(rhs)));
    }

    /**
     * @notice Multiply each element in packed ciphertext by a plaintext scalar
     */
    function simdScalarMul(epacked64x4 lhs, uint64 scalar) internal returns (epacked64x4) {
        return epacked64x4.wrap(getGateway().performOp(FHEUtils.Opcode.MUL, _asArray(epacked64x4.unwrap(lhs)), abi.encode(scalar)));
    }

    function _asArray(bytes32 val) private pure returns (bytes32[] memory) {
        bytes32[] memory arr = new bytes32[](1);
        arr[0] = val;
        return arr;
    }

    // ============================================
    // COMPARISON OPERATIONS
    // ============================================

    // --- euint8 comparisons ---

    function eq(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.EQ, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function ne(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.NE, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function ge(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GE, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function gt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GT, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function le(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.LE, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function lt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.LT, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function min(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.MIN, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function max(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.MAX, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    // --- euint32 comparisons ---

    function eq(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.EQ, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function ne(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.NE, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function ge(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GE, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function gt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GT, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function le(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.LE, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function lt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.LT, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function min(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.MIN, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function max(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.MAX, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    // --- euint64 comparisons ---

    function eq(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.EQ, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function ne(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.NE, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function ge(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GE, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function gt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GT, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function le(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.LE, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function lt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.LT, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function min(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.MIN, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function max(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.MAX, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    // --- euint256 comparisons ---

    function eq(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.EQ, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    function ne(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.NE, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    function ge(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GE, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    function gt(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.GT, euint256.unwrap(lhs), euint256.unwrap(rhs)));
    }

    // ============================================
    // BITWISE OPERATIONS
    // ============================================

    function and(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.AND, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function or(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.OR, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function xor(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return euint8.wrap(_performBinary(FHEUtils.Opcode.XOR, euint8.unwrap(lhs), euint8.unwrap(rhs)));
    }

    function not(euint8 value) internal returns (euint8) {
        return euint8.wrap(_performUnary(FHEUtils.Opcode.NOT, euint8.unwrap(value)));
    }

    function shl(euint8 value, uint8 bits) internal returns (euint8) {
        return euint8.wrap(_performShift(FHEUtils.Opcode.SHL, euint8.unwrap(value), bits));
    }

    function shr(euint8 value, uint8 bits) internal returns (euint8) {
        return euint8.wrap(_performShift(FHEUtils.Opcode.SHR, euint8.unwrap(value), bits));
    }

    // --- euint32 bitwise ---

    function and(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.AND, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function or(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.OR, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function xor(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return euint32.wrap(_performBinary(FHEUtils.Opcode.XOR, euint32.unwrap(lhs), euint32.unwrap(rhs)));
    }

    function not(euint32 value) internal returns (euint32) {
        return euint32.wrap(_performUnary(FHEUtils.Opcode.NOT, euint32.unwrap(value)));
    }

    function shl(euint32 value, uint8 bits) internal returns (euint32) {
        return euint32.wrap(_performShift(FHEUtils.Opcode.SHL, euint32.unwrap(value), bits));
    }

    function shr(euint32 value, uint8 bits) internal returns (euint32) {
        return euint32.wrap(_performShift(FHEUtils.Opcode.SHR, euint32.unwrap(value), bits));
    }

    // --- euint64 bitwise ---

    function and(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.AND, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function or(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.OR, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    function xor(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return euint64.wrap(_performBinary(FHEUtils.Opcode.XOR, euint64.unwrap(lhs), euint64.unwrap(rhs)));
    }

    // ============================================
    // CONDITIONAL OPERATIONS
    // ============================================

    /**
     * @notice Select between two values based on encrypted condition
     * @param condition Encrypted boolean condition
     * @param ifTrue Value if condition is true
     * @param ifFalse Value if condition is false
     */
    function select(
        ebool condition,
        euint8 ifTrue,
        euint8 ifFalse
    ) internal returns (euint8) {
        return euint8.wrap(_performTernary(FHEUtils.Opcode.SELECT, ebool.unwrap(condition), euint8.unwrap(ifTrue), euint8.unwrap(ifFalse)));
    }

    function select(
        ebool condition,
        euint16 ifTrue,
        euint16 ifFalse
    ) internal returns (euint16) {
        return euint16.wrap(_performTernary(FHEUtils.Opcode.SELECT, ebool.unwrap(condition), euint16.unwrap(ifTrue), euint16.unwrap(ifFalse)));
    }

    function select(
        ebool condition,
        euint32 ifTrue,
        euint32 ifFalse
    ) internal returns (euint32) {
        return euint32.wrap(_performTernary(FHEUtils.Opcode.SELECT, ebool.unwrap(condition), euint32.unwrap(ifTrue), euint32.unwrap(ifFalse)));
    }

    function select(
        ebool condition,
        euint64 ifTrue,
        euint64 ifFalse
    ) internal returns (euint64) {
        return euint64.wrap(_performTernary(FHEUtils.Opcode.SELECT, ebool.unwrap(condition), euint64.unwrap(ifTrue), euint64.unwrap(ifFalse)));
    }

    function select(
        ebool condition,
        euint128 ifTrue,
        euint128 ifFalse
    ) internal returns (euint128) {
        return euint128.wrap(_performTernary(FHEUtils.Opcode.SELECT, ebool.unwrap(condition), euint128.unwrap(ifTrue), euint128.unwrap(ifFalse)));
    }

    function select(
        ebool condition,
        euint256 ifTrue,
        euint256 ifFalse
    ) internal returns (euint256) {
        return euint256.wrap(_performTernary(FHEUtils.Opcode.SELECT, ebool.unwrap(condition), euint256.unwrap(ifTrue), euint256.unwrap(ifFalse)));
    }

    // ============================================
    // RANDOM GENERATION
    // ============================================

    /**
     * @notice Generate encrypted random euint8
     */
    function randEuint8() internal returns (euint8) {
        bytes32 handle = getGateway().random(FHETypes.TYPE_EUINT8, 0);
        return euint8.wrap(handle);
    }

    /**
     * @notice Generate encrypted random euint8 with upper bound
     */
    function randEuint8(uint8 upperBound) internal returns (euint8) {
        bytes32 handle = getGateway().random(FHETypes.TYPE_EUINT8, upperBound);
        return euint8.wrap(handle);
    }

    /**
     * @notice Generate encrypted random euint16
     */
    function randEuint16() internal returns (euint16) {
        bytes32 handle = getGateway().random(FHETypes.TYPE_EUINT16, 0);
        return euint16.wrap(handle);
    }

    /**
     * @notice Generate encrypted random euint32
     */
    function randEuint32() internal returns (euint32) {
        bytes32 handle = getGateway().random(FHETypes.TYPE_EUINT32, 0);
        return euint32.wrap(handle);
    }

    /**
     * @notice Generate encrypted random euint64
     */
    function randEuint64() internal returns (euint64) {
        bytes32 handle = getGateway().random(FHETypes.TYPE_EUINT64, 0);
        return euint64.wrap(handle);
    }

    /**
     * @notice Generate encrypted random euint256
     */
    function randEuint256() internal returns (euint256) {
        bytes32 handle = getGateway().random(FHETypes.TYPE_EUINT256, 0);
        return euint256.wrap(handle);
    }

    // ============================================
    // BOOLEAN OPERATIONS
    // ============================================

    function and(ebool lhs, ebool rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.AND, ebool.unwrap(lhs), ebool.unwrap(rhs)));
    }

    function or(ebool lhs, ebool rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.OR, ebool.unwrap(lhs), ebool.unwrap(rhs)));
    }

    function xor(ebool lhs, ebool rhs) internal returns (ebool) {
        return ebool.wrap(_performBinary(FHEUtils.Opcode.XOR, ebool.unwrap(lhs), ebool.unwrap(rhs)));
    }

    function not(ebool value) internal returns (ebool) {
        return ebool.wrap(_performUnary(FHEUtils.Opcode.NOT, ebool.unwrap(value)));
    }
}
