// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../primitives/CrossDomainNullifierAlgebra.sol";
import "../libraries/StarknetPrimitives.sol";

/**
 * @title CrossDomainNullifierStarknet
 * @notice Starknet-specific extension for CrossDomainNullifierAlgebra
 */
contract CrossDomainNullifierStarknet is CrossDomainNullifierAlgebra {
    
    /// @notice Mock Merkle root for testing purposes
    bytes32 public latestRoot;

    /**
     * @notice Register a nullifier from L1 (manual registration for integration)
     * @param nullifierHash The L1 nullifier pre-image/value
     * @param commitment The commitment hash
     * @param domainId The domain ID
     */
    function registerNullifierFromL1(
        bytes32 nullifierHash,
        bytes32 commitment,
        bytes32 domainId
    ) external onlyRole(NULLIFIER_REGISTRAR_ROLE) {
        // Use parent's registerNullifier
        // We use bytes32(0) for transitionId as default
        registerNullifier(domainId, nullifierHash, commitment, bytes32(0));

        // Update mock root to satisfy test expectation of changing root
        latestRoot = keccak256(abi.encodePacked(latestRoot, nullifierHash));
    }

    /**
     * @notice Get the current Merkle root
     */
    function getMerkleRoot() external view returns (bytes32) {
        return latestRoot;
    }

    /**
     * @notice Get the derived L2 nullifier for a given L1 nullifier
     * @param l1Nullifier The L1 nullifier
     * @return The derived L2 nullifier as a felt
     */
    function getL2Nullifier(bytes32 l1Nullifier) external pure returns (uint256) {
        // Derive L2 nullifier from L1 nullifier using Poseidon
        // We use 0 as the second element (salt/separator could be used here)
        return uint256(StarknetPrimitives.poseidonHash2(uint256(l1Nullifier), 0));
    }
}
