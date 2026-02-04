// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulPreconfirmationHandler
/// @notice Interface for preconfirmation handling aligned with SSF
interface ISoulPreconfirmationHandler {
    enum PreconfStatus {
        PENDING,
        PRECONFIRMED,
        INCLUDED,
        EXPIRED,
        SLASHED
    }

    struct PreconfRequest {
        bytes32 txHash;
        bytes32 commitmentHash;
        bytes32 nullifier;
        address submitter;
        uint64 requestedSlot;
        uint64 submittedAt;
        uint256 tip;
        PreconfStatus status;
    }

    struct ProposerCommitment {
        bytes32 preconfId;
        address proposer;
        uint64 slot;
        bytes signature;
        uint64 committedAt;
        bool honored;
    }

    struct OrbitAttestation {
        bytes32 stateRoot;
        uint256[] committee;
        bytes aggregatedSig;
        uint64 slot;
        uint256 participationBits;
    }

    event PreconfRequested(
        bytes32 indexed preconfId,
        bytes32 indexed txHash,
        address indexed submitter,
        uint64 requestedSlot,
        uint256 tip
    );

    event PreconfAccepted(
        bytes32 indexed preconfId,
        address indexed proposer,
        uint64 slot
    );

    event PreconfIncluded(
        bytes32 indexed preconfId,
        bytes32 indexed txHash,
        uint64 slot
    );

    event ProposerSlashed(
        address indexed proposer,
        bytes32 indexed preconfId,
        uint256 slashAmount
    );

    function requestPreconfirmation(
        bytes32 txHash,
        bytes32 commitmentHash,
        bytes32 nullifier,
        uint64 requestedSlot
    ) external payable returns (bytes32 preconfId);

    function acceptPreconfirmation(
        bytes32 preconfId,
        uint64 slot,
        bytes calldata signature
    ) external;

    function confirmInclusion(
        bytes32 preconfId,
        bytes calldata inclusionProof
    ) external;

    function slashProposer(bytes32 preconfId) external;

    function verifyOrbitCommittee(
        OrbitAttestation calldata attestation
    ) external view returns (bool valid);

    function getEffectiveChallengePeriod()
        external
        view
        returns (uint64 period);
}
