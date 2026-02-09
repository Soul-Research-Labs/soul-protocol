// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IConfidentialStateContainerV3
 * @notice Interface for the ConfidentialStateContainerV3 encrypted state management
 * @dev Manages encrypted on-chain state with ZK proof verification for state transitions
 */
interface IConfidentialStateContainerV3 {
    /*//////////////////////////////////////////////////////////////
                               ENUMS
    //////////////////////////////////////////////////////////////*/

    enum StateStatus {
        Active,
        Locked,
        Frozen,
        Retired
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct EncryptedState {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 metadata;
        address owner;
        uint48 createdAt;
        uint48 updatedAt;
        uint32 version;
        StateStatus status;
        bytes encryptedState;
    }

    struct StateTransition {
        bytes32 fromCommitment;
        bytes32 toCommitment;
        address fromOwner;
        address toOwner;
        uint256 timestamp;
        bytes32 transactionHash;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateRegistered(
        bytes32 indexed commitment,
        address indexed owner,
        bytes32 nullifier,
        uint256 timestamp
    );
    event StateTransferred(
        bytes32 indexed fromCommitment,
        bytes32 indexed toCommitment,
        address indexed newOwner,
        uint256 version
    );
    event StateStatusChanged(
        bytes32 indexed commitment,
        StateStatus oldStatus,
        StateStatus newStatus
    );
    event StateBatchRegistered(
        bytes32[] commitments,
        address indexed owner,
        uint256 count
    );
    event ProofValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);
    event MaxStateSizeUpdated(uint256 oldSize, uint256 newSize);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error NotStateOwner(address caller, address owner);
    error ZeroAddress();
    error EmptyEncryptedState();
    error CommitmentAlreadyExists(bytes32 commitment);
    error CommitmentNotFound(bytes32 commitment);
    error StateSizeTooLarge(uint256 size, uint256 maxSize);
    error StateNotActive(bytes32 commitment, StateStatus status);
    error InvalidSignature();
    error SignatureExpired();
    error InvalidNonce();
    error BatchTooLarge(uint256 size, uint256 maxSize);

    /*//////////////////////////////////////////////////////////////
                         CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 metadata
    ) external;

    function registerStateWithSignature(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 metadata,
        address owner,
        uint256 deadline,
        bytes calldata signature
    ) external;

    function batchRegisterStates(
        BatchStateInput[] calldata stateInputs
    ) external;

    function transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes32 spendingNullifier,
        bytes calldata proof,
        address newOwner
    ) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isStateActive(bytes32 commitment) external view returns (bool);

    function getState(
        bytes32 commitment
    ) external view returns (EncryptedState memory);

    function getOwnerCommitments(
        address owner
    ) external view returns (bytes32[] memory);

    function getOwnerCommitmentsPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory commitments, uint256 total);

    function getStateHistory(
        bytes32 commitment
    ) external view returns (StateTransition[] memory);

    function getNonce(address account) external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setProofValidityWindow(uint256 _window) external;

    function setMaxStateSize(uint256 _maxSize) external;

    function lockState(bytes32 commitment) external;

    function unlockState(bytes32 commitment) external;

    function freezeState(bytes32 commitment) external;

    function pause() external;

    function unpause() external;
}

/**
 * @title BatchStateInput
 * @notice Input struct for batch state registration
 */
struct BatchStateInput {
    bytes encryptedState;
    bytes32 commitment;
    bytes32 nullifier;
    bytes proof;
    bytes32 metadata;
}
