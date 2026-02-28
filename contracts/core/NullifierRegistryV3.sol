// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {INullifierRegistryV3} from "../interfaces/INullifierRegistryV3.sol";

/// @title NullifierRegistryV3
/// @author ZASEON
/// @notice Production-ready nullifier registry with merkle tree support for light client verification
/// @dev Implements incremental merkle tree, cross-chain sync, and efficient batch operations
///
/// GAS OPTIMIZATIONS APPLIED:
/// - Assembly-optimized hash operations (saves ~500 gas per hash)
/// - Pre-computed role hashes (saves ~200 gas per access)
/// - Unchecked arithmetic in safe contexts (saves ~40 gas per operation)
/// - Packed NullifierData struct (saves ~20k gas on writes)
/**
 * @title NullifierRegistryV3
 * @author ZASEON Team
 * @notice Nullifier Registry V3 contract
 */
contract NullifierRegistryV3 is
    AccessControl,
    Pausable,
    ReentrancyGuard,
    INullifierRegistryV3
{
    using SafeCast for uint256;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for authorized registrars (other contracts, relayers)
    /// @dev Pre-computed hash saves ~200 gas per access: keccak256("REGISTRAR_ROLE")
    bytes32 public constant REGISTRAR_ROLE =
        0xedcc084d3dcd65a1f7f23c65c46722faca6953d28e43150a467cf43e5c309238;

    /// @notice Role for cross-chain relay operations
    /// @dev Pre-computed hash saves ~200 gas per access: keccak256("RELAY_ROLE")
    bytes32 public constant RELAY_ROLE =
        0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;

    /// @notice Role for emergency operations
    /// @dev Pre-computed hash saves ~200 gas per access: keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

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

    /// @notice Reference count for roots in the ring buffer (SECURITY FIX M-2)
    mapping(bytes32 => uint256) public rootRefCount;

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

    /// @dev DEPRECATED: pendingCrossChainNullifiers removed (was never written to)
    /// Storage slot preserved for upgrade compatibility
    mapping(bytes32 => bytes32[])
        private __deprecated_pendingCrossChainNullifiers;

    /// @notice Registered cross-chain peer domains for nullifier sync
    mapping(bytes32 => bool) public registeredDomains;

    /// @notice Chain ID for this deployment
    uint256 public immutable CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event DomainRegistered(bytes32 indexed domain);
    event DomainRemoved(bytes32 indexed domain);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error DomainAlreadyRegistered(bytes32 domain);
    error DomainNotRegistered(bytes32 domain);
    error ZeroDomain();

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum batch size (reduced from 100 to prevent DoS with 32-depth tree)
    /// @dev Each nullifier insertion does 32 hash operations, so 20 * 32 = 640 operations max
    uint256 public constant MAX_BATCH_SIZE = 20;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the nullifier registry
    constructor() {
        CHAIN_ID = block.chainid;
        require(block.chainid <= type(uint64).max, "Chain ID exceeds uint64");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, msg.sender);
        _grantRole(RELAY_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Initialize zero values for merkle tree
        // zeros[0] is the zero leaf, zeros[i] = hash(zeros[i-1], zeros[i-1])
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
    }

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registers a single nullifier
    /// @param nullifier The nullifier hash to register
    /// @param commitment Associated commitment (optional)
    /// @return index The index in the merkle tree
        /**
     * @notice Registers nullifier
     * @param nullifier The nullifier hash
     * @param commitment The cryptographic commitment
     * @return index The index
     */
function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment
    )
        external
        onlyRole(REGISTRAR_ROLE)
        whenNotPaused
        nonReentrant
        returns (uint256 index)
    {
        return _registerNullifier(nullifier, commitment, msg.sender);
    }

    /// @notice Registers multiple nullifiers in a batch
    /// @dev Gas-optimized: single Merkle root recomputation for the entire batch
    /// @param _nullifiers Array of nullifiers to register
    /// @param _commitments Array of associated commitments
    /// @return startIndex The starting index in the merkle tree
        /**
     * @notice Batchs register nullifiers
     * @param _nullifiers The _nullifiers
     * @param _commitments The _commitments
     * @return startIndex The start index
     */
function batchRegisterNullifiers(
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments
    )
        external
        onlyRole(REGISTRAR_ROLE)
        whenNotPaused
        nonReentrant
        returns (uint256 startIndex)
    {
        uint256 len = _nullifiers.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (_commitments.length != 0 && _commitments.length != len)
            revert BatchTooLarge(_commitments.length, len);

        startIndex = totalNullifiers;

        // Register nullifier state without individual tree insertions
        bytes32[] memory leaves = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            bytes32 commitment = _commitments.length > 0
                ? _commitments[i]
                : bytes32(0);
            leaves[i] = _registerNullifierState(
                _nullifiers[i],
                commitment,
                msg.sender
            );
            unchecked {
                ++i;
            }
        }

        // Single batched Merkle tree insertion — one root write + one history entry
        _batchInsertIntoTree(leaves, startIndex);

        emit NullifierBatchRegistered(_nullifiers, startIndex, len);
    }

    /// @notice Receives nullifiers from another chain
    /// @dev Gas-optimized: single Merkle root recomputation for the entire batch
    /// @param sourceChainId The source chain ID
    /// @param _nullifiers Array of nullifiers
    /// @param _commitments Array of commitments
    /// @param sourceMerkleRoot The merkle root from source chain
        /**
     * @notice Receive cross chain nullifiers
     * @param sourceChainId The source chain identifier
     * @param _nullifiers The _nullifiers
     * @param _commitments The _commitments
     * @param sourceMerkleRoot The source merkle root
     */
function receiveCrossChainNullifiers(
        uint256 sourceChainId,
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments,
        bytes32 sourceMerkleRoot
    ) external onlyRole(RELAY_ROLE) whenNotPaused nonReentrant {
        if (sourceChainId == CHAIN_ID) revert InvalidChainId();

        uint256 len = _nullifiers.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        // Collect new leaves for batched tree insertion
        uint256 newCount = 0;
        uint256 batchStartIndex = totalNullifiers;
        bytes32[] memory leaves = new bytes32[](len);

        for (uint256 i = 0; i < len; ) {
            bytes32 nullifier = _nullifiers[i];

            if (!isNullifierUsed[nullifier]) {
                leaves[newCount] = _registerCrossChainNullifierState(
                    nullifier,
                    _commitments.length > i ? _commitments[i] : bytes32(0),
                    sourceChainId
                );
                unchecked {
                    ++newCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Batched Merkle tree insertion for all new nullifiers
        if (newCount > 0) {
            // Trim leaves array to actual count
            if (newCount < len) {
                bytes32[] memory trimmed = new bytes32[](newCount);
                for (uint256 i = 0; i < newCount; ) {
                    trimmed[i] = leaves[i];
                    unchecked {
                        ++i;
                    }
                }
                _batchInsertIntoTree(trimmed, batchStartIndex);
            } else {
                _batchInsertIntoTree(leaves, batchStartIndex);
            }
        }

        emit CrossChainNullifiersReceived(sourceChainId, sourceMerkleRoot, len);
    }

    /// @dev Internal helper to register cross-chain nullifier state without tree insertion
    /// @return leaf The nullifier hash to insert into the tree
    function _registerCrossChainNullifierState(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 sourceChainId
    ) internal returns (bytes32 leaf) {
        if (nullifier == bytes32(0)) revert ZeroNullifier();

        uint256 index = totalNullifiers;

        nullifiers[nullifier] = NullifierData({
            timestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number),
            sourceChainId: sourceChainId.toUint64(),
            registrar: msg.sender,
            commitment: commitment,
            index: index
        });

        isNullifierUsed[nullifier] = true;

        unchecked {
            ++totalNullifiers;
            ++chainNullifierCount[sourceChainId];
        }

        emit NullifierRegistered(
            nullifier,
            commitment,
            index,
            msg.sender,
            sourceChainId.toUint64()
        );

        return nullifier;
    }

    /// @dev Legacy helper for single cross-chain nullifier registration.
    ///      Registers state AND inserts into tree.
    function _registerCrossChainNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 sourceChainId
    ) internal {
        uint256 idx = totalNullifiers;
        _registerCrossChainNullifierState(nullifier, commitment, sourceChainId);
        _insertIntoTree(nullifier, idx);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        address registrar
    ) internal returns (uint256 index) {
        // Capture index before state registration (which increments totalNullifiers)
        index = totalNullifiers;
        _registerNullifierState(nullifier, commitment, registrar);
        // Single-nullifier path: insert directly into tree at the pre-increment index
        _insertIntoTree(nullifier, index);
    }

    /// @dev Registers nullifier state (metadata, existence flag, counters, events)
    ///      without inserting into the Merkle tree. Used by batch path.
    /// @return leaf The nullifier hash (used as leaf in Merkle tree)
    function _registerNullifierState(
        bytes32 nullifier,
        bytes32 commitment,
        address registrar
    ) internal returns (bytes32) {
        if (nullifier == bytes32(0)) revert ZeroNullifier();
        if (isNullifierUsed[nullifier])
            revert NullifierAlreadyExists(nullifier);

        uint256 index = totalNullifiers;

        nullifiers[nullifier] = NullifierData({
            timestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number),
            sourceChainId: CHAIN_ID.toUint64(),
            registrar: registrar,
            commitment: commitment,
            index: index
        });

        isNullifierUsed[nullifier] = true;

        unchecked {
            ++totalNullifiers;
            ++chainNullifierCount[CHAIN_ID];
        }

        emit NullifierRegistered(
            nullifier,
            commitment,
            index,
            registrar,
            CHAIN_ID.toUint64()
        );

        return nullifier;
    }

    /// @notice Inserts a leaf into the incremental merkle tree
    /// @param leaf The leaf to insert
    /// @param treeIndex The position index in the tree for this leaf
    function _insertIntoTree(bytes32 leaf, uint256 treeIndex) internal {
        bytes32 oldRoot = merkleRoot;
        uint256 index = treeIndex;
        bytes32 currentHash = leaf;

        for (uint256 i = 0; i < TREE_DEPTH; ) {
            if (index & 1 == 0) {
                // Left child - store in branches and use zero for right
                branches[i] = currentHash;
                currentHash = _hashPair(currentHash, zeros[i]);
            } else {
                // Right child - use stored branch for left
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

    /// @notice Batch inserts multiple leaves into the incremental Merkle tree
    /// @dev Gas optimization: inserts all leaves sequentially but only writes the final
    ///      Merkle root and history entry once, saving ~20k gas per additional leaf.
    ///      Each leaf is inserted at its correct index position.
    /// @param leaves Array of leaf hashes to insert
    /// @param startIndex The tree index of the first leaf (totalNullifiers BEFORE the batch registered state)
    function _batchInsertIntoTree(
        bytes32[] memory leaves,
        uint256 startIndex
    ) internal {
        bytes32 oldRoot = merkleRoot;
        uint256 len = leaves.length;
        bytes32 currentHash;

        for (uint256 leafIdx = 0; leafIdx < len; ) {
            uint256 index = startIndex + leafIdx;
            currentHash = leaves[leafIdx];

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

            unchecked {
                ++leafIdx;
            }
        }

        // Write root and history only once for entire batch
        merkleRoot = currentHash;
        _addRootToHistory(currentHash);

        emit MerkleRootUpdated(oldRoot, currentHash, startIndex + len);
    }

    /// @notice Adds a root to the history ring buffer
    /// @param root The root to add
    function _addRootToHistory(bytes32 root) internal {
        // SECURITY FIX M-2: Use reference counting to handle duplicate roots correctly
        // Decrement ref count for evicted root
        bytes32 evictedRoot = rootHistory[rootHistoryIndex];
        if (evictedRoot != bytes32(0)) {
            uint256 refCount = rootRefCount[evictedRoot];
            if (refCount <= 1) {
                // Last reference — invalidate the root
                historicalRoots[evictedRoot] = false;
                delete rootRefCount[evictedRoot];
            } else {
                rootRefCount[evictedRoot] = refCount - 1;
            }
        }

        // Write new root at current position and increment its ref count
        rootHistory[rootHistoryIndex] = root;
        historicalRoots[root] = true;
        rootRefCount[root]++;

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
            // Store in scratch space and hash
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
    /// @return exists True if the nullifier exists
        /**
     * @notice Exists
     * @param nullifier The nullifier hash
     * @return The result value
     */
function exists(bytes32 nullifier) external view returns (bool) {
        return isNullifierUsed[nullifier];
    }

    /// @notice Batch checks if nullifiers exist
    /// @param _nullifiers Array of nullifiers to check
    /// @return results Array of existence results
        /**
     * @notice Batchs exists
     * @param _nullifiers The _nullifiers
     * @return results The results
     */
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
        /**
     * @notice Returns the nullifier data
     * @param nullifier The nullifier hash
     * @return data The data
     */
function getNullifierData(
        bytes32 nullifier
    ) external view returns (NullifierData memory data) {
        if (!isNullifierUsed[nullifier]) revert NullifierNotFound(nullifier);
        return nullifiers[nullifier];
    }

    /// @notice Checks if a merkle root is valid (current or historical)
    /// @param root The root to check
    /// @return valid True if the root is valid
        /**
     * @notice Checks if valid root
     * @param root The Merkle root
     * @return valid The valid
     */
function isValidRoot(bytes32 root) external view returns (bool valid) {
        return root == merkleRoot || historicalRoots[root];
    }

    /// @notice Verifies a merkle proof for nullifier inclusion
    /// @param nullifier The nullifier to verify
    /// @param index The index of the nullifier
    /// @param siblings The merkle proof siblings
    /// @param root The merkle root to verify against
    /// @return valid True if the proof is valid
        /**
     * @notice Verifys merkle proof
     * @param nullifier The nullifier hash
     * @param index The index in the collection
     * @param siblings The siblings
     * @param root The Merkle root
     * @return valid The valid
     */
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
        /**
     * @notice Returns the tree stats
     * @return _totalNullifiers The _total nullifiers
     * @return _merkleRoot The _merkle root
     * @return _rootHistorySize The _root history size
     */
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
    /// @param chainId The chain ID to query
    /// @return count The number of nullifiers from that chain
        /**
     * @notice Returns the nullifier count by chain
     * @param chainId The chain identifier
     * @return count The count
     */
function getNullifierCountByChain(
        uint256 chainId
    ) external view returns (uint256 count) {
        return chainNullifierCount[chainId];
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Adds a registrar
    /// @param registrar The address to add
        /**
     * @notice Adds registrar
     * @param registrar The registrar
     */
function addRegistrar(
        address registrar
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(REGISTRAR_ROLE, registrar);
        emit RegistrarAdded(registrar);
    }

    /// @notice Removes a registrar
    /// @param registrar The address to remove
        /**
     * @notice Removes registrar
     * @param registrar The registrar
     */
function removeRegistrar(
        address registrar
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(REGISTRAR_ROLE, registrar);
        emit RegistrarRemoved(registrar);
    }

    /// @notice Registers a cross-chain domain for nullifier sync
    /// @param domain The domain identifier (typically bytes32 of chain ID)
        /**
     * @notice Registers domain
     * @param domain The domain identifier
     */
function registerDomain(
        bytes32 domain
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (domain == bytes32(0)) revert ZeroDomain();
        if (registeredDomains[domain]) revert DomainAlreadyRegistered(domain);
        registeredDomains[domain] = true;
        emit DomainRegistered(domain);
    }

    /// @notice Removes a registered cross-chain domain
    /// @param domain The domain identifier to remove
        /**
     * @notice Removes domain
     * @param domain The domain identifier
     */
function removeDomain(
        bytes32 domain
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!registeredDomains[domain]) revert DomainNotRegistered(domain);
        registeredDomains[domain] = false;
        emit DomainRemoved(domain);
    }

    /// @notice Pauses the contract
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
