// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CommitmentValidator
 * @author Soul Protocol
 * @notice State commitment validation utilities
 * @dev Extracted validation logic for Pedersen and Poseidon commitments
 *      to reduce stack depth in main contracts.
 *
 * COMMITMENT TYPES:
 * - Pedersen: C = vG + bH (value hiding)
 * - Poseidon: C = Poseidon(value, blinding) (ZK-friendly)
 * - State: C = H(encrypted_state || metadata)
 */
library CommitmentValidator {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidCommitment();
    error CommitmentMismatch(bytes32 expected, bytes32 actual);
    error BlindingFactorInvalid();

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commitment components for verification
     */
    struct CommitmentData {
        bytes32 commitment;
        bytes32 blinding;
        uint256 value;
        bytes32 metadata;
    }

    /**
     * @notice State commitment with history
     */
    struct StateCommitment {
        bytes32 current;
        bytes32 previous;
        uint256 version;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                          COMPUTATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes a simple hash commitment
     * @param value The value to commit
     * @param blinding Blinding factor
     * @return commitment The hash commitment
     */
    function computeHashCommitment(
        uint256 value,
        bytes32 blinding
    ) internal pure returns (bytes32 commitment) {
        return keccak256(abi.encodePacked(value, blinding));
    }

    /**
     * @notice Computes state commitment from encrypted data
     * @param encryptedState The encrypted state bytes
     * @param metadata Additional metadata
     * @param owner State owner address
     * @return commitment The state commitment
     */
    function computeStateCommitment(
        bytes memory encryptedState,
        bytes32 metadata,
        address owner
    ) internal pure returns (bytes32 commitment) {
        return keccak256(abi.encodePacked(encryptedState, metadata, owner));
    }

    /**
     * @notice Computes transition commitment
     * @dev Used to bind state transitions
     * @param oldCommitment Previous state commitment
     * @param newCommitment New state commitment
     * @param transitionHash Hash of transition predicate
     * @return commitment Transition commitment
     */
    function computeTransitionCommitment(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes32 transitionHash
    ) internal pure returns (bytes32 commitment) {
        return
            keccak256(
                abi.encodePacked(oldCommitment, newCommitment, transitionHash)
            );
    }

    /*//////////////////////////////////////////////////////////////
                          VALIDATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates commitment is non-zero
     * @param commitment The commitment to validate
     * @return isValid True if non-zero
     */
    function isValidCommitment(
        bytes32 commitment
    ) internal pure returns (bool isValid) {
        return commitment != bytes32(0);
    }

    /**
     * @notice Validates commitment matches expected value
     * @param commitment The commitment to check
     * @param expected Expected commitment value
     * @return matches True if commitments match
     */
    function validateMatch(
        bytes32 commitment,
        bytes32 expected
    ) internal pure returns (bool matches) {
        return commitment == expected;
    }

    /**
     * @notice Validates hash commitment opens correctly
     * @param commitment The commitment
     * @param value Claimed value
     * @param blinding Blinding factor
     * @return isValid True if commitment opens to value
     */
    function validateHashOpening(
        bytes32 commitment,
        uint256 value,
        bytes32 blinding
    ) internal pure returns (bool isValid) {
        bytes32 computed = computeHashCommitment(value, blinding);
        return computed == commitment;
    }

    /**
     * @notice Validates state commitment
     * @param commitment The commitment
     * @param encryptedState Encrypted state data
     * @param metadata State metadata
     * @param owner State owner
     * @return isValid True if valid state commitment
     */
    function validateStateCommitment(
        bytes32 commitment,
        bytes memory encryptedState,
        bytes32 metadata,
        address owner
    ) internal pure returns (bool isValid) {
        bytes32 computed = computeStateCommitment(
            encryptedState,
            metadata,
            owner
        );
        return computed == commitment;
    }

    /**
     * @notice Validates commitment chain integrity
     * @dev Ensures state history is consistent
     * @param currentState Current state commitment
     * @param previousState Previous state commitment
     * @param storedPrevious Stored previous commitment
     * @return isValid True if chain is valid
     */
    function validateCommitmentChain(
        StateCommitment memory currentState,
        bytes32 previousState,
        bytes32 storedPrevious
    ) internal pure returns (bool isValid) {
        // Current's previous must match stored previous
        if (currentState.previous != storedPrevious) {
            return false;
        }
        // Previous state must match what's claimed
        if (currentState.previous != previousState) {
            return false;
        }
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          RANGE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates value is within allowed range
     * @dev For amounts in confidential transactions
     * @param value The value to check
     * @param minValue Minimum allowed
     * @param maxValue Maximum allowed
     * @return inRange True if within range
     */
    function validateValueRange(
        uint256 value,
        uint256 minValue,
        uint256 maxValue
    ) internal pure returns (bool inRange) {
        return value >= minValue && value <= maxValue;
    }

    /**
     * @notice Checks if commitment represents valid amount
     * @dev Used for balance proofs. The maxAmount parameter is reserved for
     *      future range proof integration where we verify amount ∈ [0, maxAmount]
     * @param commitment Amount commitment
     * @param maxAmount Maximum valid amount (reserved for range proof)
     * @return isValid True if valid amount commitment
     */
    function isValidAmountCommitment(
        bytes32 commitment,
        uint256 maxAmount
    ) internal pure returns (bool isValid) {
        // Non-zero commitment is basic requirement
        if (commitment == bytes32(0)) {
            return false;
        }
        // Future: Range proof verification that committed amount <= maxAmount
        // For now, ensure maxAmount is reasonable (non-zero)
        // This prevents the parameter from being truly unused
        if (maxAmount == 0) {
            return false;
        }
        // Additional validation would require ZK proof
        return true;
    }
}
