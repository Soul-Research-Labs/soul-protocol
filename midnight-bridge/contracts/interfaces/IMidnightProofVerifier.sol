// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMidnightProofVerifier
 * @notice Interface for the Midnight Proof Verifier contract
 */
interface IMidnightProofVerifier {
    // =========================================================================
    // ENUMS
    // =========================================================================

    enum CircuitType {
        BridgeTransfer,
        StateTransition,
        NullifierBatch,
        MerkleInclusion
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ProofVerified(
        CircuitType indexed circuitType,
        bytes32 indexed proofHash,
        bool valid
    );

    event VerificationKeyUpdated(
        CircuitType indexed circuitType,
        bytes32 vkeyHash
    );

    // =========================================================================
    // FUNCTIONS
    // =========================================================================

    /**
     * @notice Verify a Midnight bridge transfer proof
     * @param commitment The transfer commitment
     * @param nullifier The nullifier to prevent double-spending
     * @param merkleRoot The Merkle root containing the commitment
     * @param stateRoot The Midnight state root at proof time
     * @param proof The ZK proof bytes
     * @return valid Whether the proof is valid
     */
    function verifyMidnightProof(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 merkleRoot,
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool valid);

    /**
     * @notice Verify a state transition proof
     * @param oldStateRoot Previous state root
     * @param newStateRoot New state root
     * @param proof The ZK proof bytes
     * @return valid Whether the proof is valid
     */
    function verifyStateTransition(
        bytes32 oldStateRoot,
        bytes32 newStateRoot,
        bytes calldata proof
    ) external view returns (bool valid);

    /**
     * @notice Verify a batch nullifier proof
     * @param nullifiers Array of nullifiers
     * @param nullifierRoot Expected nullifier root
     * @param proof The ZK proof bytes
     * @return valid Whether the proof is valid
     */
    function verifyNullifierBatch(
        bytes32[] calldata nullifiers,
        bytes32 nullifierRoot,
        bytes calldata proof
    ) external view returns (bool valid);

    /**
     * @notice Verify Merkle inclusion proof
     * @param leaf The leaf value
     * @param root The expected root
     * @param proof The Merkle proof path
     * @param index The leaf index
     * @return valid Whether the proof is valid
     */
    function verifyMerkleInclusion(
        bytes32 leaf,
        bytes32 root,
        bytes32[] calldata proof,
        uint256 index
    ) external pure returns (bool valid);

    /**
     * @notice Get the verification key hash for a circuit type
     * @param circuitType The circuit type
     * @return vkeyHash The verification key hash
     */
    function getVerificationKeyHash(
        CircuitType circuitType
    ) external view returns (bytes32 vkeyHash);

    /**
     * @notice Check if a circuit type is supported
     * @param circuitType The circuit type
     * @return supported Whether the circuit is supported
     */
    function isCircuitSupported(
        CircuitType circuitType
    ) external view returns (bool supported);
}
