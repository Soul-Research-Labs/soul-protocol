// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./OptimisticBridgeVerifier.sol";

/**
 * @title BridgeFraudProof
 * @notice Verifies fraud proofs and resolves challenges on OptimisticBridgeVerifier
 */
contract BridgeFraudProof is AccessControl {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    OptimisticBridgeVerifier public immutable optimisticVerifier;

    event FraudProofSubmitted(bytes32 indexed transferId, address submitter);
    event FraudVerified(bytes32 indexed transferId);

    constructor(address _optimisticVerifier, address _admin) {
        optimisticVerifier = OptimisticBridgeVerifier(_optimisticVerifier);
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
    ) external {
        // 1. Verify that the original proof matches the pending transfer
        OptimisticBridgeVerifier.PendingTransfer
            memory transfer = optimisticVerifier.getVerification(transferId);
        require(
            transfer.status ==
                OptimisticBridgeVerifier.TransferStatus.CHALLENGED,
            "Not challenged"
        );
        require(
            keccak256(originalProof) == transfer.proofHash,
            "Original proof mismatch"
        );

        // 2. Mock verification of fraud evidence
        // In production, this would verify the ZK proof or state transition logic.
        // For this implementation, we assume if evidence is non-empty and starts with "FRAUD", it's valid.
        bool isFraudulent = _verifyEvidence(originalProof, fraudEvidence);

        require(isFraudulent, "Fraud not proven");

        emit FraudProofSubmitted(transferId, msg.sender);
        emit FraudVerified(transferId);

        // 3. Resolve the challenge via the Verifier
        // This contract must have RESOLVER_ROLE on the OptimisticBridgeVerifier
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
