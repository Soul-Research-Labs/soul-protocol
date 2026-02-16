// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title NullifierRegistryV3Upgradeable
/// @author Soul Protocol
/// @notice UUPS-upgradeable version of NullifierRegistryV3 with merkle tree support
/// @dev Replaces immutable CHAIN_ID with storage variable for proxy compatibility.
///      Preserves all gas optimizations: assembly hashing, pre-computed role hashes,
///      unchecked arithmetic, packed NullifierData struct.
///
/// @custom:security-contact security@soul.network
/// @custom:oz-upgrades-from NullifierRegistryV3
contract NullifierRegistryV3Upgradeable is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeCast for uint256;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for authorized registrars (other contracts, relayers)
    /// @dev Pre-computed: keccak256("REGISTRAR_ROLE")
    bytes32 public constant REGISTRAR_ROLE =
        0xedcc084d3dcd65a1f7f23c65c46722faca6953d28e43150a467cf43e5c309238;

    /// @notice Role for cross-chain bridge operations
    /// @dev Pre-computed: keccak256("BRIDGE_ROLE")
    bytes32 public constant BRIDGE_ROLE =
        0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;

    /// @notice Role for emergency operations
    /// @dev Pre-computed: keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @notice Role for contract upgrades
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Nullifier metadata structure
    /// @param timestamp Block timestamp when registered
    /// @param blockNumber Block number when registered
    /// @param sourceChainId Origin chain ID
    /// @param registrar Address that registered the nullifier
    /// @param commitment Associated commitment (if any)
    /// @param index Position in the merkle tree
    struct NullifierData {
        uint64 timestamp;
        uint64 blockNumber;
        uint64 sourceChainId;
        address registrar;
        bytes32 commitment;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                          MERKLE TREE CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Merkle tree depth (supports 2^32 = ~4 billion nullifiers)
    uint256 public constant TREE_DEPTH = 32;

    /// @notice Zero values for each level of the tree (precomputed)
    bytes32[33] public zeros;

    /// @notice Current merkle tree branches
    bytes32[32] public branches;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of nullifier to its data
    mapping(bytes32 => NullifierData) public nullifiers;

    /// @notice Mapping for quick existence check
    mapping(bytes32 => bool) public isNullifierUsed;

    /// @notice Current merkle root
    bytes32 public merkleRoot;

    /// @notice Historical merkle roots (for delayed verification)
    mapping(bytes32 => bool) public historicalRoots;

    /// @notice Number of historical roots to keep
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    /// @notice Array of historical roots for iteration
    bytes32[100] public rootHistory;

    /// @notice Current root history index
    uint256 public rootHistoryIndex;

    /// @notice Total nullifiers registered
    uint256 public totalNullifiers;

    /// @notice Nullifiers per chain
    mapping(uint256 => uint256) public chainNullifierCount;

    /// @dev DEPRECATED: Storage slot preserved for upgrade compatibility
    mapping(bytes32 => bytes32[])
        private __deprecated_pendingCrossChainNullifiers;

    /// @notice Chain ID for this deployment (storage instead of immutable for proxy)
    uint256 public chainId;

    /// @notice Maximum batch size
    uint256 public constant MAX_BATCH_SIZE = 20;

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

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
    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

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
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract (replaces constructor)
    /// @param admin The initial admin address
    function initialize(address admin) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        chainId = block.chainid;
        require(block.chainid <= type(uint64).max, "Chain ID exceeds uint64");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
        _grantRole(BRIDGE_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Initialize zero values for merkle tree
        bytes32 currentZero = bytes32(0);
        zeros[0] = currentZero;

        for (uint256 i = 1; i <= TREE_DEPTH; ) {
            currentZero = _hashPair(currentZero, currentZero);
            zeros[i] = currentZero;
            unchecked {
                ++i;
            }
        }

        // Initialize root as empty tree root
        merkleRoot = zeros[TREE_DEPTH];
        _addRootToHistory(merkleRoot);

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          UPGRADE AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Authorize upgrade - only UPGRADER_ROLE can upgrade
    function _authorizeUpgrade(
        address /* newImplementation */
    ) internal override onlyRole(UPGRADER_ROLE) {
        uint256 oldVersion = contractVersion;
        contractVersion++;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registers a single nullifier
    /// @param nullifier The nullifier hash to register
    /// @param commitment Associated commitment (optional)
    /// @return index The index in the merkle tree
    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused returns (uint256 index) {
        return _registerNullifier(nullifier, commitment, msg.sender);
    }

    /// @notice Registers multiple nullifiers in a batch
    /// @param _nullifiers Array of nullifiers to register
    /// @param _commitments Array of associated commitments
    /// @return startIndex The starting index in the merkle tree
    function batchRegisterNullifiers(
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments
    )
        external
        onlyRole(REGISTRAR_ROLE)
        whenNotPaused
        returns (uint256 startIndex)
    {
        uint256 len = _nullifiers.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (_commitments.length != 0 && _commitments.length != len)
            revert BatchTooLarge(_commitments.length, len);

        startIndex = totalNullifiers;

        for (uint256 i = 0; i < len; ) {
            bytes32 commitment = _commitments.length > 0
                ? _commitments[i]
                : bytes32(0);
            _registerNullifier(_nullifiers[i], commitment, msg.sender);
            unchecked {
                ++i;
            }
        }

        emit NullifierBatchRegistered(_nullifiers, startIndex, len);
    }

    /// @notice Receives nullifiers from another chain
    /// @param sourceChainId_ The source chain ID
    /// @param _nullifiers Array of nullifiers
    /// @param _commitments Array of commitments
    /// @param sourceMerkleRoot The merkle root from source chain
    function receiveCrossChainNullifiers(
        uint256 sourceChainId_,
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments,
        bytes32 sourceMerkleRoot
    ) external onlyRole(BRIDGE_ROLE) whenNotPaused {
        if (sourceChainId_ == chainId) revert InvalidChainId();

        uint256 len = _nullifiers.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        for (uint256 i = 0; i < len; ) {
            bytes32 nullifier = _nullifiers[i];

            if (!isNullifierUsed[nullifier]) {
                _registerCrossChainNullifier(
                    nullifier,
                    _commitments.length > i ? _commitments[i] : bytes32(0),
                    sourceChainId_
                );
            }
            unchecked {
                ++i;
            }
        }

        emit CrossChainNullifiersReceived(
            sourceChainId_,
            sourceMerkleRoot,
            len
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Internal helper to register cross-chain nullifier (reduces stack depth)
    function _registerCrossChainNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 sourceChainId_
    ) internal {
        if (nullifier == bytes32(0)) revert ZeroNullifier();

        uint256 index = totalNullifiers;

        nullifiers[nullifier] = NullifierData({
            timestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number),
            sourceChainId: sourceChainId_.toUint64(),
            registrar: msg.sender,
            commitment: commitment,
            index: index
        });

        isNullifierUsed[nullifier] = true;
        _insertIntoTree(nullifier);

        unchecked {
            ++totalNullifiers;
            ++chainNullifierCount[sourceChainId_];
        }

        emit NullifierRegistered(
            nullifier,
            commitment,
            index,
            msg.sender,
            sourceChainId_.toUint64()
        );
    }

    function _registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        address registrar
    ) internal returns (uint256 index) {
        if (nullifier == bytes32(0)) revert ZeroNullifier();
        if (isNullifierUsed[nullifier])
            revert NullifierAlreadyExists(nullifier);

        index = totalNullifiers;

        nullifiers[nullifier] = NullifierData({
            timestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number),
            sourceChainId: chainId.toUint64(),
            registrar: registrar,
            commitment: commitment,
            index: index
        });

        isNullifierUsed[nullifier] = true;
        _insertIntoTree(nullifier);

        unchecked {
            ++totalNullifiers;
            ++chainNullifierCount[chainId];
        }

        emit NullifierRegistered(
            nullifier,
            commitment,
            index,
            registrar,
            chainId.toUint64()
        );
    }

    /// @notice Inserts a leaf into the incremental merkle tree
    /// @param leaf The leaf to insert
    function _insertIntoTree(bytes32 leaf) internal {
        bytes32 oldRoot = merkleRoot;
        uint256 index = totalNullifiers;
        bytes32 currentHash = leaf;

        for (uint256 i = 0; i < TREE_DEPTH; ) {
            if (index & 1 == 0) {
                branches[i] = currentHash;
                currentHash = _hashPair(currentHash, zeros[i]);
            } else {
                currentHash = _hashPair(branches[i], currentHash);
            }
            index >>= 1;
            unchecked {
                ++i;
            }
        }

        merkleRoot = currentHash;
        _addRootToHistory(currentHash);

        emit MerkleRootUpdated(oldRoot, currentHash, totalNullifiers);
    }

    /// @notice Adds a root to the history ring buffer
    /// @param root The root to add
    function _addRootToHistory(bytes32 root) internal {
        bytes32 evictedRoot = rootHistory[rootHistoryIndex];
        if (evictedRoot != bytes32(0) && evictedRoot != root) {
            historicalRoots[evictedRoot] = false;
        }

        rootHistory[rootHistoryIndex] = root;
        historicalRoots[root] = true;

        unchecked {
            rootHistoryIndex = (rootHistoryIndex + 1) % ROOT_HISTORY_SIZE;
        }
    }

    /// @notice Hashes two nodes together using assembly for gas efficiency
    /// @dev Saves ~500 gas vs abi.encodePacked approach
    /// @param left Left node
    /// @param right Right node
    /// @return hash The resulting hash
    function _hashPair(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32 hash) {
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)
            hash := keccak256(0x00, 0x40)
        }
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a nullifier exists
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier exists
    function exists(bytes32 nullifier) external view returns (bool) {
        return isNullifierUsed[nullifier];
    }

    /// @notice Batch checks if nullifiers exist
    /// @param _nullifiers Array of nullifiers to check
    /// @return results Array of existence results
    function batchExists(
        bytes32[] calldata _nullifiers
    ) external view returns (bool[] memory results) {
        uint256 len = _nullifiers.length;
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        results = new bool[](len);

        for (uint256 i = 0; i < len; ) {
            results[i] = isNullifierUsed[_nullifiers[i]];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Gets nullifier data
    /// @param nullifier The nullifier to query
    /// @return data The nullifier metadata
    function getNullifierData(
        bytes32 nullifier
    ) external view returns (NullifierData memory data) {
        if (!isNullifierUsed[nullifier]) revert NullifierNotFound(nullifier);
        return nullifiers[nullifier];
    }

    /// @notice Checks if a merkle root is valid (current or historical)
    /// @param root The root to check
    /// @return valid True if the root is valid
    function isValidRoot(bytes32 root) external view returns (bool valid) {
        return root == merkleRoot || historicalRoots[root];
    }

    /// @notice Verifies a merkle proof for nullifier inclusion
    /// @param nullifier The nullifier to verify
    /// @param index The index of the nullifier
    /// @param siblings The merkle proof siblings
    /// @param root The merkle root to verify against
    /// @return valid True if the proof is valid
    function verifyMerkleProof(
        bytes32 nullifier,
        uint256 index,
        bytes32[] calldata siblings,
        bytes32 root
    ) external view returns (bool valid) {
        if (root != merkleRoot && !historicalRoots[root]) {
            revert RootNotInHistory(root);
        }

        if (siblings.length != TREE_DEPTH) return false;

        bytes32 currentHash = nullifier;
        uint256 currentIndex = index;

        for (uint256 i = 0; i < TREE_DEPTH; ) {
            if (currentIndex & 1 == 0) {
                currentHash = _hashPair(currentHash, siblings[i]);
            } else {
                currentHash = _hashPair(siblings[i], currentHash);
            }
            currentIndex >>= 1;
            unchecked {
                ++i;
            }
        }

        return currentHash == root;
    }

    /// @notice Gets current tree statistics
    /// @return _totalNullifiers Total registered nullifiers
    /// @return _merkleRoot Current merkle root
    /// @return _rootHistorySize Number of valid historical roots
    function getTreeStats()
        external
        view
        returns (
            uint256 _totalNullifiers,
            bytes32 _merkleRoot,
            uint256 _rootHistorySize
        )
    {
        return (totalNullifiers, merkleRoot, ROOT_HISTORY_SIZE);
    }

    /// @notice Gets nullifier count for a specific chain
    /// @param chainId_ The chain ID to query
    /// @return count The number of nullifiers from that chain
    function getNullifierCountByChain(
        uint256 chainId_
    ) external view returns (uint256 count) {
        return chainNullifierCount[chainId_];
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Adds a registrar
    /// @param registrar The address to add
    function addRegistrar(
        address registrar
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(REGISTRAR_ROLE, registrar);
        emit RegistrarAdded(registrar);
    }

    /// @notice Removes a registrar
    /// @param registrar The address to remove
    function removeRegistrar(
        address registrar
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(REGISTRAR_ROLE, registrar);
        emit RegistrarRemoved(registrar);
    }

    /// @notice Pauses the contract
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
