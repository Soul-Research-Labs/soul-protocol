// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./OptimisticRelayVerifier.sol";

/**
 * @title RelayFraudProof
 * @notice Verifies fraud proofs and resolves challenges on OptimisticRelayVerifier
 */
contract RelayFraudProof is AccessControl {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    OptimisticRelayVerifier public immutable optimisticVerifier;

    event FraudProofSubmitted(bytes32 indexed transferId, address submitter);
    event FraudVerified(bytes32 indexed transferId);

    error TransferNotChallenged(bytes32 transferId);
    error ProofMismatch(bytes32 transferId);
    error FraudNotProven(bytes32 transferId);

    constructor(address _optimisticVerifier, address _admin) {
        optimisticVerifier = OptimisticRelayVerifier(_optimisticVerifier);
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    /**
     * @notice Submit a fraud proof to resolve a challenge
     * @param transferId The transfer ID being challenged
     * @param originalProof The original proof submitted with the transfer
     * @param fraudEvidence Evidence of fraud (e.g. conflicting state, invalid signature)
     */
    function submitFraudProof(
        bytes32 transferId,
        bytes calldata originalProof,
        bytes calldata fraudEvidence
    ) external onlyRole(VERIFIER_ROLE) {
        // 1. Verify that the original proof matches the pending transfer
        OptimisticRelayVerifier.PendingTransfer
            memory transfer = optimisticVerifier.getVerification(transferId);
        if (
            transfer.status != OptimisticRelayVerifier.TransferStatus.CHALLENGED
        ) revert TransferNotChallenged(transferId);
        if (keccak256(originalProof) != transfer.proofHash) {
            revert ProofMismatch(transferId);
        }

        // 2. Mock verification of fraud evidence
        // In production, this would verify the ZK proof or state transition logic.
        // For this implementation, we assume if evidence is non-empty and starts with "FRAUD", it's valid.
        bool isFraudulent = _verifyEvidence(originalProof, fraudEvidence);

        if (!isFraudulent) revert FraudNotProven(transferId);

        emit FraudProofSubmitted(transferId, msg.sender);
        emit FraudVerified(transferId);

        // 3. Resolve the challenge via the Verifier
        // This contract must have RESOLVER_ROLE on the OptimisticRelayVerifier
        optimisticVerifier.resolveChallenge(transferId, originalProof, true);
    }

    /**
     * @dev Mock verification logic
     */
    function _verifyEvidence(
        bytes calldata /*originalProof*/,
        bytes calldata evidence
    ) internal pure returns (bool) {
        if (evidence.length < 5) return false;
        // Check if evidence starts with "FRAUD"
        return (bytes5(evidence) == bytes5("FRAUD"));
    }
}
