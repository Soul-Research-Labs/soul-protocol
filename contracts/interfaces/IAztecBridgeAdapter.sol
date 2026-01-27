// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IAztecBridgeAdapter
 * @notice Interface for Aztec Network bridge adapter
 */
interface IAztecBridgeAdapter {
    /// @notice Aztec note types
    enum NoteType {
        VALUE_NOTE,
        DEFI_NOTE,
        ACCOUNT_NOTE,
        CUSTOM_NOTE
    }

    /// @notice Cross-domain proof types
    enum ProofType {
        Soul_TO_AZTEC,
        AZTEC_TO_Soul,
        BIDIRECTIONAL
    }

    /// @notice Soul to Aztec bridge request
    struct SoulToAztecRequest {
        bytes32 requestId;
        bytes32 pilCommitment;
        bytes32 pilNullifier;
        bytes32 aztecRecipient;
        uint256 amount;
        NoteType noteType;
        bytes32 appDataHash;
        uint256 timestamp;
        bool processed;
        bytes32 resultingNoteHash;
    }

    /// @notice Aztec to Soul bridge request
    struct AztecToSoulRequest {
        bytes32 requestId;
        bytes32 aztecNoteHash;
        bytes32 aztecNullifier;
        address pilRecipient;
        uint256 amount;
        bytes32 pilCommitment;
        uint256 timestamp;
        bool processed;
    }

    /// @notice Cross-domain proof
    struct CrossDomainProof {
        bytes32 proofId;
        ProofType proofType;
        bytes32 sourceCommitment;
        bytes32 targetCommitment;
        bytes32 nullifier;
        bytes proof;
        bytes32 publicInputsHash;
        bool verified;
        uint256 verifiedAt;
    }

    /// @notice Aztec state sync
    struct AztecStateSync {
        uint256 rollupId;
        bytes32 dataTreeRoot;
        bytes32 nullifierTreeRoot;
        bytes32 contractTreeRoot;
        bytes32 l1ToL2MessageTreeRoot;
        uint256 blockNumber;
        uint256 timestamp;
        bool finalized;
    }

    // Events
    event SoulToAztecInitiated(
        bytes32 indexed requestId,
        bytes32 indexed pilCommitment,
        bytes32 aztecRecipient,
        uint256 amount
    );

    event SoulToAztecCompleted(
        bytes32 indexed requestId,
        bytes32 indexed resultingNoteHash
    );

    event AztecToSoulInitiated(
        bytes32 indexed requestId,
        bytes32 indexed aztecNoteHash,
        address pilRecipient,
        uint256 amount
    );

    event AztecToSoulCompleted(
        bytes32 indexed requestId,
        bytes32 indexed pilCommitment
    );

    event CrossDomainProofVerified(
        bytes32 indexed proofId,
        ProofType proofType,
        bytes32 sourceCommitment,
        bytes32 targetCommitment
    );

    event AztecStateSynced(
        uint256 indexed rollupId,
        bytes32 dataTreeRoot,
        bytes32 nullifierTreeRoot
    );

    // Functions
    function configureAztecContracts(
        address _rollup,
        address _inbox,
        address _outbox
    ) external;

    function bridgeSoulToAztec(
        bytes32 pilCommitment,
        bytes32 pilNullifier,
        bytes32 aztecRecipient,
        uint256 amount,
        NoteType noteType,
        bytes32 appDataHash,
        bytes calldata proof
    ) external payable;

    function completeSoulToAztec(
        bytes32 requestId,
        bytes32 resultingNoteHash,
        bytes calldata proof
    ) external;

    function bridgeAztecToSoul(
        bytes32 aztecNoteHash,
        bytes32 aztecNullifier,
        address pilRecipient,
        uint256 amount,
        bytes calldata proof
    ) external;

    function syncAztecState(
        uint256 rollupId,
        bytes32 dataTreeRoot,
        bytes32 nullifierTreeRoot,
        bytes32 contractTreeRoot,
        bytes32 l1ToL2MessageTreeRoot,
        uint256 blockNumber
    ) external;

    function verifyCrossDomainProof(
        ProofType proofType,
        bytes32 sourceCommitment,
        bytes32 targetCommitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 publicInputsHash
    ) external returns (bytes32 proofId);

    function getSoulToAztecRequest(
        bytes32 requestId
    ) external view returns (SoulToAztecRequest memory);

    function getAztecToSoulRequest(
        bytes32 requestId
    ) external view returns (AztecToSoulRequest memory);

    function getCrossDomainProof(
        bytes32 proofId
    ) external view returns (CrossDomainProof memory);

    function getAztecStateSync(
        uint256 rollupId
    ) external view returns (AztecStateSync memory);

    function isNullifierUsed(bytes32 nullifier) external view returns (bool);

    function isNoteMirrored(bytes32 noteHash) external view returns (bool);

    function isSoulCommitmentRegistered(
        bytes32 commitment
    ) external view returns (bool);

    function getBridgeStats()
        external
        view
        returns (
            uint256 pendingRequests,
            uint256 totalBridgedToAztec,
            uint256 totalBridgedFromAztec,
            uint256 accumulatedFees,
            uint256 latestRollupId
        );
}
