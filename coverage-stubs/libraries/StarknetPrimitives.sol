// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
library StarknetPrimitives {
    uint256 public constant STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001;
    function poseidonHash2(uint256, uint256) internal pure returns (bytes32) { return bytes32(0); }
    function addressToFelt(address) internal pure returns (uint256) { return 0; }
}
