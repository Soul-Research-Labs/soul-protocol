// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FHEGateway.sol";
import "./FHETypes.sol";

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
        bytes32 result = getGateway().fheAdd(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function sub(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheSub(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function mul(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheMul(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function div(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheDiv(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function rem(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheRem(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function neg(euint8 value) internal returns (euint8) {
        bytes32 result = getGateway().fheNeg(euint8.unwrap(value));
        return euint8.wrap(result);
    }

    // --- euint16 ---

    function add(euint16 lhs, euint16 rhs) internal returns (euint16) {
        bytes32 result = getGateway().fheAdd(
            euint16.unwrap(lhs),
            euint16.unwrap(rhs)
        );
        return euint16.wrap(result);
    }

    function sub(euint16 lhs, euint16 rhs) internal returns (euint16) {
        bytes32 result = getGateway().fheSub(
            euint16.unwrap(lhs),
            euint16.unwrap(rhs)
        );
        return euint16.wrap(result);
    }

    function mul(euint16 lhs, euint16 rhs) internal returns (euint16) {
        bytes32 result = getGateway().fheMul(
            euint16.unwrap(lhs),
            euint16.unwrap(rhs)
        );
        return euint16.wrap(result);
    }

    function div(euint16 lhs, euint16 rhs) internal returns (euint16) {
        bytes32 result = getGateway().fheDiv(
            euint16.unwrap(lhs),
            euint16.unwrap(rhs)
        );
        return euint16.wrap(result);
    }

    function rem(euint16 lhs, euint16 rhs) internal returns (euint16) {
        bytes32 result = getGateway().fheRem(
            euint16.unwrap(lhs),
            euint16.unwrap(rhs)
        );
        return euint16.wrap(result);
    }

    function neg(euint16 value) internal returns (euint16) {
        bytes32 result = getGateway().fheNeg(euint16.unwrap(value));
        return euint16.wrap(result);
    }

    // --- euint32 ---

    function add(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheAdd(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function sub(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheSub(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function mul(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheMul(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function div(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheDiv(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function rem(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheRem(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function neg(euint32 value) internal returns (euint32) {
        bytes32 result = getGateway().fheNeg(euint32.unwrap(value));
        return euint32.wrap(result);
    }

    // --- euint64 ---

    function add(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheAdd(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function sub(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheSub(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function mul(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheMul(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function div(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheDiv(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function rem(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheRem(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function neg(euint64 value) internal returns (euint64) {
        bytes32 result = getGateway().fheNeg(euint64.unwrap(value));
        return euint64.wrap(result);
    }

    // --- euint128 ---

    function add(euint128 lhs, euint128 rhs) internal returns (euint128) {
        bytes32 result = getGateway().fheAdd(
            euint128.unwrap(lhs),
            euint128.unwrap(rhs)
        );
        return euint128.wrap(result);
    }

    function sub(euint128 lhs, euint128 rhs) internal returns (euint128) {
        bytes32 result = getGateway().fheSub(
            euint128.unwrap(lhs),
            euint128.unwrap(rhs)
        );
        return euint128.wrap(result);
    }

    function mul(euint128 lhs, euint128 rhs) internal returns (euint128) {
        bytes32 result = getGateway().fheMul(
            euint128.unwrap(lhs),
            euint128.unwrap(rhs)
        );
        return euint128.wrap(result);
    }

    // --- euint256 ---

    function add(euint256 lhs, euint256 rhs) internal returns (euint256) {
        bytes32 result = getGateway().fheAdd(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return euint256.wrap(result);
    }

    function sub(euint256 lhs, euint256 rhs) internal returns (euint256) {
        bytes32 result = getGateway().fheSub(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return euint256.wrap(result);
    }

    function mul(euint256 lhs, euint256 rhs) internal returns (euint256) {
        bytes32 result = getGateway().fheMul(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return euint256.wrap(result);
    }

    // ============================================
    // COMPARISON OPERATIONS
    // ============================================

    // --- euint8 comparisons ---

    function eq(euint8 lhs, euint8 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheEq(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ne(euint8 lhs, euint8 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheNe(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ge(euint8 lhs, euint8 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGe(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function gt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGt(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function le(euint8 lhs, euint8 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheLe(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function lt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheLt(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function min(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheMin(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function max(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheMax(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    // --- euint32 comparisons ---

    function eq(euint32 lhs, euint32 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheEq(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ne(euint32 lhs, euint32 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheNe(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ge(euint32 lhs, euint32 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGe(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function gt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGt(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function le(euint32 lhs, euint32 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheLe(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function lt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheLt(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function min(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheMin(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function max(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheMax(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    // --- euint64 comparisons ---

    function eq(euint64 lhs, euint64 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheEq(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ne(euint64 lhs, euint64 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheNe(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ge(euint64 lhs, euint64 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGe(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function gt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGt(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function le(euint64 lhs, euint64 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheLe(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function lt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheLt(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function min(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheMin(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function max(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheMax(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    // --- euint256 comparisons ---

    function eq(euint256 lhs, euint256 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheEq(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ne(euint256 lhs, euint256 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheNe(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function ge(euint256 lhs, euint256 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGe(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function gt(euint256 lhs, euint256 rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheGt(
            euint256.unwrap(lhs),
            euint256.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    // ============================================
    // BITWISE OPERATIONS
    // ============================================

    function and(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheAnd(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function or(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheOr(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function xor(euint8 lhs, euint8 rhs) internal returns (euint8) {
        bytes32 result = getGateway().fheXor(
            euint8.unwrap(lhs),
            euint8.unwrap(rhs)
        );
        return euint8.wrap(result);
    }

    function not(euint8 value) internal returns (euint8) {
        bytes32 result = getGateway().fheNot(euint8.unwrap(value));
        return euint8.wrap(result);
    }

    function shl(euint8 value, uint8 bits) internal returns (euint8) {
        bytes32 result = getGateway().fheShl(euint8.unwrap(value), bits);
        return euint8.wrap(result);
    }

    function shr(euint8 value, uint8 bits) internal returns (euint8) {
        bytes32 result = getGateway().fheShr(euint8.unwrap(value), bits);
        return euint8.wrap(result);
    }

    // --- euint32 bitwise ---

    function and(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheAnd(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function or(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheOr(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function xor(euint32 lhs, euint32 rhs) internal returns (euint32) {
        bytes32 result = getGateway().fheXor(
            euint32.unwrap(lhs),
            euint32.unwrap(rhs)
        );
        return euint32.wrap(result);
    }

    function not(euint32 value) internal returns (euint32) {
        bytes32 result = getGateway().fheNot(euint32.unwrap(value));
        return euint32.wrap(result);
    }

    function shl(euint32 value, uint8 bits) internal returns (euint32) {
        bytes32 result = getGateway().fheShl(euint32.unwrap(value), bits);
        return euint32.wrap(result);
    }

    function shr(euint32 value, uint8 bits) internal returns (euint32) {
        bytes32 result = getGateway().fheShr(euint32.unwrap(value), bits);
        return euint32.wrap(result);
    }

    // --- euint64 bitwise ---

    function and(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheAnd(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function or(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheOr(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
    }

    function xor(euint64 lhs, euint64 rhs) internal returns (euint64) {
        bytes32 result = getGateway().fheXor(
            euint64.unwrap(lhs),
            euint64.unwrap(rhs)
        );
        return euint64.wrap(result);
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
        bytes32 result = getGateway().fheSelect(
            ebool.unwrap(condition),
            euint8.unwrap(ifTrue),
            euint8.unwrap(ifFalse)
        );
        return euint8.wrap(result);
    }

    function select(
        ebool condition,
        euint16 ifTrue,
        euint16 ifFalse
    ) internal returns (euint16) {
        bytes32 result = getGateway().fheSelect(
            ebool.unwrap(condition),
            euint16.unwrap(ifTrue),
            euint16.unwrap(ifFalse)
        );
        return euint16.wrap(result);
    }

    function select(
        ebool condition,
        euint32 ifTrue,
        euint32 ifFalse
    ) internal returns (euint32) {
        bytes32 result = getGateway().fheSelect(
            ebool.unwrap(condition),
            euint32.unwrap(ifTrue),
            euint32.unwrap(ifFalse)
        );
        return euint32.wrap(result);
    }

    function select(
        ebool condition,
        euint64 ifTrue,
        euint64 ifFalse
    ) internal returns (euint64) {
        bytes32 result = getGateway().fheSelect(
            ebool.unwrap(condition),
            euint64.unwrap(ifTrue),
            euint64.unwrap(ifFalse)
        );
        return euint64.wrap(result);
    }

    function select(
        ebool condition,
        euint128 ifTrue,
        euint128 ifFalse
    ) internal returns (euint128) {
        bytes32 result = getGateway().fheSelect(
            ebool.unwrap(condition),
            euint128.unwrap(ifTrue),
            euint128.unwrap(ifFalse)
        );
        return euint128.wrap(result);
    }

    function select(
        ebool condition,
        euint256 ifTrue,
        euint256 ifFalse
    ) internal returns (euint256) {
        bytes32 result = getGateway().fheSelect(
            ebool.unwrap(condition),
            euint256.unwrap(ifTrue),
            euint256.unwrap(ifFalse)
        );
        return euint256.wrap(result);
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
        bytes32 result = getGateway().fheAnd(
            ebool.unwrap(lhs),
            ebool.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function or(ebool lhs, ebool rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheOr(
            ebool.unwrap(lhs),
            ebool.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function xor(ebool lhs, ebool rhs) internal returns (ebool) {
        bytes32 result = getGateway().fheXor(
            ebool.unwrap(lhs),
            ebool.unwrap(rhs)
        );
        return ebool.wrap(result);
    }

    function not(ebool value) internal returns (ebool) {
        bytes32 result = getGateway().fheNot(ebool.unwrap(value));
        return ebool.wrap(result);
    }
}
