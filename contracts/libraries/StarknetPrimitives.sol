// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title StarknetPrimitives
 * @notice Helper library for Starknet specific cryptographic operations
 * @dev Simplified implementation for testing purposes
 */
library StarknetPrimitives {
    uint256 public constant STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001;

    function poseidonHash2(uint256 a, uint256 b) internal pure returns (bytes32) {
        // In production this would use the Poseidon circuit-friendly hash
        // Here we use keccak256 modulo prime for simulation
        uint256 hash = uint256(keccak256(abi.encodePacked(a, b)));
        return bytes32(hash % STARK_PRIME);
    }
    
    function addressToFelt(address addr) internal pure returns (uint256) {
        return uint256(uint160(addr));
    }
}
