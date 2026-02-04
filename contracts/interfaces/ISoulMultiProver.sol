// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulMultiProver
/// @notice Interface for multi-prover verification with 2-of-3 consensus
interface ISoulMultiProver {
    enum ProverSystem {
        NOIR,
        SP1,
        JOLT,
        PLONKY3,
        BINIUS,
        HALO2,
        GROTH16,
        RISC_ZERO
    }

    struct ProverConfig {
        ProverSystem system;
        address verifier;
        bool isActive;
        uint256 weight;
        uint256 successCount;
        uint256 failureCount;
    }

    struct ProofSubmission {
        ProverSystem prover;
        bytes proof;
        bool isValid;
        uint64 submittedAt;
        address submitter;
    }

    struct VerificationResult {
        bytes32 proofId;
        bool consensusReached;
        uint256 validCount;
        uint256 totalCount;
        ProverSystem[] validProvers;
    }

    event ProverRegistered(ProverSystem indexed system, address verifier);

    event ProofSubmitted(
        bytes32 indexed proofId,
        ProverSystem indexed prover,
        address submitter
    );

    event ConsensusReached(
        bytes32 indexed proofId,
        uint256 validCount,
        uint256 totalCount
    );

    event MultiProofVerified(
        bytes32 indexed proofId,
        bytes32 publicInputsHash,
        ProverSystem[] validProvers
    );

    function registerProver(
        ProverSystem system,
        address verifier,
        uint256 weight
    ) external;

    function submitProof(
        bytes32 proofId,
        bytes32 publicInputsHash,
        ProverSystem prover,
        bytes calldata proof
    ) external;

    function submitMultipleProofs(
        bytes32 proofId,
        bytes32 publicInputsHash,
        ProverSystem[] calldata proverList,
        bytes[] calldata proofs
    ) external;

    function finalizeProof(bytes32 proofId) external;

    function getVerificationResult(
        bytes32 proofId
    ) external view returns (VerificationResult memory result);

    function isProofVerified(bytes32 proofId) external view returns (bool);

    function getActiveProverCount() external view returns (uint256);

    function getActiveProvers() external view returns (ProverSystem[] memory);
}
