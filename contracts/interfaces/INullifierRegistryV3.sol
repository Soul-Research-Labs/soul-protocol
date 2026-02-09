// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title INullifierRegistryV3
 * @notice Interface for the NullifierRegistryV3 cross-domain nullifier tracking
 * @dev Manages nullifier registration with Merkle tree accumulation and cross-chain sync
 */
interface INullifierRegistryV3 {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct NullifierData {
        uint64 timestamp;
        uint64 blockNumber;
        uint64 sourceChainId;
        address registrar;
        bytes32 commitment;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed commitment,
        uint256 indexed index,
        address registrar,
        uint64 chainId
    );
    event NullifierBatchRegistered(
        bytes32[] nullifiers,
        uint256 startIndex,
        uint256 count
    );
    event MerkleRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 nullifierCount
    );
    event CrossChainNullifiersReceived(
        uint256 indexed sourceChainId,
        bytes32 indexed merkleRoot,
        uint256 count
    );
    event RegistrarAdded(address indexed registrar);
    event RegistrarRemoved(address indexed registrar);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NullifierAlreadyExists(bytes32 nullifier);
    error NullifierNotFound(bytes32 nullifier);
    error InvalidMerkleProof();
    error BatchTooLarge(uint256 size, uint256 maxSize);
    error EmptyBatch();
    error ZeroNullifier();
    error RootNotInHistory(bytes32 root);
    error InvalidChainId();

    /*//////////////////////////////////////////////////////////////
                         CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment
    ) external returns (uint256 index);

    function batchRegisterNullifiers(
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments
    ) external returns (uint256 startIndex);

    function receiveCrossChainNullifiers(
        uint256 sourceChainId,
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments,
        bytes32 sourceMerkleRoot
    ) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function exists(bytes32 nullifier) external view returns (bool);

    function batchExists(
        bytes32[] calldata _nullifiers
    ) external view returns (bool[] memory);

    function getNullifierData(
        bytes32 nullifier
    ) external view returns (NullifierData memory);

    function isValidRoot(bytes32 root) external view returns (bool);

    function verifyMerkleProof(
        bytes32 nullifier,
        uint256 index,
        bytes32[] calldata siblings,
        bytes32 root
    ) external view returns (bool);

    function getTreeStats()
        external
        view
        returns (
            uint256 _totalNullifiers,
            bytes32 _merkleRoot,
            uint256 _rootHistorySize
        );

    function getNullifierCountByChain(
        uint256 chainId
    ) external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function addRegistrar(address registrar) external;

    function removeRegistrar(address registrar) external;

    function pause() external;

    function unpause() external;
}
