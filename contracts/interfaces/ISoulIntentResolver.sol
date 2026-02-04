// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulIntentResolver
/// @notice Interface for ERC-7683 compatible private intent resolution
interface ISoulIntentResolver {
    enum IntentStatus {
        PENDING,
        FILLED,
        SETTLED,
        CANCELLED,
        EXPIRED
    }

    struct PrivateIntent {
        bytes32 intentId;
        bytes32 intentHash;
        bytes32 nullifier;
        bytes32 commitment;
        bytes encryptedPayload;
        uint256[] destinationChains;
        address initiator;
        uint64 deadline;
        uint256 minOutput;
        IntentStatus status;
    }

    struct FillProof {
        bytes32 intentId;
        uint256 filledChainId;
        bytes32 fillTxHash;
        bytes32 outputCommitment;
        bytes zkProof;
        address filler;
        uint64 filledAt;
    }

    struct CrossChainOrder {
        address settlementContract;
        address swapper;
        uint256 nonce;
        uint32 originChainId;
        uint32 initiateDeadline;
        uint32 fillDeadline;
        bytes orderData;
    }

    struct ResolvedCrossChainOrder {
        address settlementContract;
        address swapper;
        uint256 nonce;
        uint32 originChainId;
        uint32 initiateDeadline;
        uint32 fillDeadline;
        bytes32[] swapperInputs;
        bytes32[] swapperOutputs;
        bytes32[] fillerOutputs;
    }

    event PrivateIntentCreated(
        bytes32 indexed intentId,
        address indexed initiator,
        uint256[] destinationChains,
        uint64 deadline
    );

    event IntentFilled(
        bytes32 indexed intentId,
        address indexed filler,
        uint256 indexed chainId,
        bytes32 fillTxHash
    );

    event IntentSettled(
        bytes32 indexed intentId,
        bytes32 indexed nullifier,
        address indexed filler
    );

    function submitPrivateIntent(
        bytes32 intentHash,
        bytes32 nullifier,
        bytes32 commitment,
        bytes calldata encryptedPayload,
        uint256[] calldata destinationChains,
        uint64 deadline
    ) external returns (bytes32 intentId);

    function open(
        CrossChainOrder calldata order
    ) external returns (ResolvedCrossChainOrder memory resolvedOrder);

    function submitFillProof(
        bytes32 intentId,
        uint256 filledChainId,
        bytes32 fillTxHash,
        bytes32 outputCommitment,
        bytes calldata zkProof
    ) external;

    function settle(bytes32 intentId) external;

    function cancelIntent(bytes32 intentId) external;

    function getIntent(
        bytes32 intentId
    ) external view returns (PrivateIntent memory);

    function isNullifierUsed(bytes32 nullifier) external view returns (bool);
}
