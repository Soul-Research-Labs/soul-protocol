// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FHETypes.sol";
import "../infrastructure/ConfidentialDataAvailability.sol";

/**
 * @title ConfidentialStateRegistry
 * @author Soul Protocol
 * @notice Registry for managing off-chain FHE state commitments
 * @dev Connects FHE operations with the CDA (Confidential Data Availability) layer
 */
contract ConfidentialStateRegistry is AccessControl {
    ConfidentialDataAvailability public cda;

    /// @notice Maps a state slot to its latest DA commitment
    mapping(bytes32 => bytes32) public stateCommitments;

    event StateUpdated(bytes32 indexed slot, bytes32 indexed commitment, bytes32 blobId);

    constructor(address _cda) {
        cda = ConfidentialDataAvailability(_cda);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Register a new state commitment for a storage slot
     * @param slot The storage slot (e.g., keccak256(owner, token))
     * @param blobId The ID of the blob in CDA containing the ciphertext
     */
    function updateState(bytes32 slot, bytes32 blobId) external {
        // In production: verify that blobId exists in CDA and is available
        (,,,,,,,,,,,, AvailabilityStatus status,,,,,) = cda.blobs(blobId);
        require(status == AvailabilityStatus.Available, "Blob not available");

        bytes32 commitment = computeStateCommitment(slot, blobId);
        stateCommitments[slot] = commitment;

        emit StateUpdated(slot, commitment, blobId);
    }

    /**
     * @notice Compute a deterministic commitment for a state slot
     */
    function computeStateCommitment(bytes32 slot, bytes32 blobId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(slot, blobId));
    }
}
