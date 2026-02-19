// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title BN254
 * @author Soul Protocol
 * @notice Gas-efficient BN254 (alt_bn128) elliptic curve operations
 * @dev Uses EVM precompiles: ecAdd (0x06), ecMul (0x07), modExp (0x05).
 *      Curve equation: y² = x³ + 3 over F_p
 *
 * Constants:
 *   p = 21888242871839275222246405745257275088696311157297823662689037894645226208583 (field modulus)
 *   n = 21888242871839275222246405745257275088548364400416034343698204186575808495617 (group order)
 *   G = (1, 2) (generator point)
 *
 * Compressed point format:
 *   bytes32 = x-coordinate | (y_parity << 255)
 *   Since p < 2^254, bits 254-255 of x are always 0, so bit 255 is free.
 *
 * @custom:security Production library — uses audited EVM precompiles only.
 */
library BN254 {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Field modulus p
    uint256 internal constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev Group order n (number of points on the curve)
    uint256 internal constant N =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Generator point G_x
    uint256 internal constant G_X = 1;

    /// @dev Generator point G_y
    uint256 internal constant G_Y = 2;

    /// @dev (P + 1) / 4, used for modular square root since P ≡ 3 (mod 4)
    uint256 internal constant SQRT_EXP =
        5472060717959818805561601436314318772174077789324455915672259473661306552146;

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Compressed point does not represent a valid BN254 curve point
    error InvalidPoint();

    /// @dev Precompile call (ecAdd, ecMul, or modExp) failed
    error PrecompileFailed();

    /*//////////////////////////////////////////////////////////////
                        POINT ARITHMETIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add two BN254 points using the ecAdd precompile (0x06)
     * @param x1 First point x-coordinate
     * @param y1 First point y-coordinate
     * @param x2 Second point x-coordinate
     * @param y2 Second point y-coordinate
     * @return x3 Result x-coordinate
     * @return y3 Result y-coordinate
     */
    function add(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256 x3, uint256 y3) {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory result;
        bool success;
        assembly ("memory-safe") {
            success := staticcall(gas(), 0x06, input, 128, result, 64)
        }
        if (!success) revert PrecompileFailed();
        return (result[0], result[1]);
    }

    /**
     * @notice Scalar multiply a BN254 point using the ecMul precompile (0x07)
     * @param x Point x-coordinate
     * @param y Point y-coordinate
     * @param s Scalar multiplier
     * @return rx Result x-coordinate
     * @return ry Result y-coordinate
     */
    function mul(
        uint256 x,
        uint256 y,
        uint256 s
    ) internal view returns (uint256 rx, uint256 ry) {
        uint256[3] memory input = [x, y, s];
        uint256[2] memory result;
        bool success;
        assembly ("memory-safe") {
            success := staticcall(gas(), 0x07, input, 96, result, 64)
        }
        if (!success) revert PrecompileFailed();
        return (result[0], result[1]);
    }

    /**
     * @notice Check if a point lies on the BN254 curve: y² = x³ + 3 (mod P)
     * @param x Point x-coordinate
     * @param y Point y-coordinate
     * @return True if (x, y) is on the curve or is the point at infinity
     */
    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x == 0 && y == 0) return true; // Point at infinity
        if (x >= P || y >= P) return false;
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 3, P);
        return lhs == rhs;
    }

    /**
     * @notice Compress a BN254 point into 32 bytes
     * @dev Encodes x-coordinate with y-parity in bit 255
     * @param x Point x-coordinate
     * @param y Point y-coordinate
     * @return Compressed point as bytes32
     */
    function compress(uint256 x, uint256 y) internal pure returns (bytes32) {
        return bytes32(x | ((y & 1) << 255));
    }

    /**
     * @notice Decompress a compressed BN254 point
     * @dev Recovers (x, y) from compressed form using modular square root
     * @param compressed The compressed point (x with y-parity in bit 255)
     * @return x The x-coordinate
     * @return y The y-coordinate
     */
    function decompress(
        bytes32 compressed
    ) internal view returns (uint256 x, uint256 y) {
        uint256 raw = uint256(compressed);
        uint256 parity = raw >> 255;
        x = raw & ((1 << 255) - 1);

        if (x == 0 && parity == 0) {
            // Point at infinity
            return (0, 0);
        }
        if (x >= P) revert InvalidPoint();

        // y² = x³ + 3 (mod P)
        uint256 ySq = addmod(mulmod(mulmod(x, x, P), x, P), 3, P);

        // y = ySq^((P+1)/4) mod P — valid since P ≡ 3 (mod 4)
        y = _modExp(ySq, SQRT_EXP);

        // Verify the square root is valid (ySq must be a quadratic residue)
        if (mulmod(y, y, P) != ySq) revert InvalidPoint();

        // Fix y-parity to match compressed encoding
        if ((y & 1) != parity) {
            y = P - y;
        }
    }

    /**
     * @notice Negate a BN254 point: -(x, y) = (x, P - y)
     * @param x Point x-coordinate
     * @param y Point y-coordinate
     * @return nx Negated x (same as x)
     * @return ny Negated y
     */
    function negate(
        uint256 x,
        uint256 y
    ) internal pure returns (uint256 nx, uint256 ny) {
        if (x == 0 && y == 0) return (0, 0);
        return (x, P - y);
    }

    /**
     * @notice Hash an input to a BN254 curve point (try-and-increment)
     * @dev Not constant-time, but on-chain computation is public so this is fine.
     *      Average ~2 iterations. Max 256 iterations (probability ≈ 2^-256 of failure).
     * @param input The input to hash
     * @return x The x-coordinate of the resulting point
     * @return y The y-coordinate of the resulting point
     */
    function hashToPoint(
        bytes32 input
    ) internal view returns (uint256 x, uint256 y) {
        for (uint256 ctr; ctr < 256; ) {
            x = uint256(keccak256(abi.encodePacked(input, ctr))) % P;

            // y² = x³ + 3 (mod P)
            uint256 ySq = addmod(mulmod(mulmod(x, x, P), x, P), 3, P);
            y = _modExp(ySq, SQRT_EXP);

            if (mulmod(y, y, P) == ySq) {
                // Normalize to even y for determinism
                if (y & 1 != 0) y = P - y;
                return (x, y);
            }

            unchecked {
                ++ctr;
            }
        }
        revert InvalidPoint(); // Statistically unreachable
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Modular exponentiation using the modExp precompile (0x05)
     * @dev Computes base^exp mod P
     * @param base The base
     * @param exp The exponent
     * @return result base^exp mod P
     */
    function _modExp(
        uint256 base,
        uint256 exp
    ) private view returns (uint256 result) {
        // Input format: [baseLen(32), expLen(32), modLen(32), base, exp, mod]
        bytes memory input = abi.encodePacked(
            uint256(32),
            uint256(32),
            uint256(32),
            base,
            exp,
            P
        );

        bytes memory output = new bytes(32);
        bool success;
        assembly ("memory-safe") {
            success := staticcall(
                gas(),
                0x05,
                add(input, 32), // skip bytes length prefix
                192, // 6 × 32 bytes
                add(output, 32), // skip bytes length prefix
                32
            )
        }
        if (!success) revert PrecompileFailed();
        result = abi.decode(output, (uint256));
    }
}
