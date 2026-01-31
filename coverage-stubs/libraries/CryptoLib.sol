// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
library CryptoLib {
    struct G1Point { uint256 x; uint256 y; }
    function g1Add(G1Point memory, G1Point memory) internal pure returns (G1Point memory) { return G1Point(0, 0); }
    function g1Mul(G1Point memory, uint256) internal pure returns (G1Point memory) { return G1Point(0, 0); }
    function g1Neg(G1Point memory) internal pure returns (G1Point memory) { return G1Point(0, 0); }
    function g1Eq(G1Point memory, G1Point memory) internal pure returns (bool) { return true; }
}
