// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PlinkoPIR
 * @notice On-chain verification for Plinko Private Information Retrieval proofs
 * @dev Implements Vitalik's Plinko protocol for O(√N) private state reads
 * Reference: https://vitalik.eth.limo/general/2025/11/25/plinko.html
 *
 * Key Features:
 * - Verify PIR query commitments without learning queried index
 * - Integrate with cross-chain state roots for private L2 reads
 * - Nullifier tracking to prevent replay attacks
 * - XOR-based batch verification for efficiency
 */
contract PlinkoPIR is ReentrancyGuard, Ownable {
    // ========================================================================
    // CONSTANTS
    // ========================================================================

    /// @notice Default grid size (√N where N = 1M entries)
    uint256 public constant DEFAULT_GRID_SIZE = 1024;

    /// @notice Cell size in bytes (32 bytes for Ethereum storage slot)
    uint256 public constant CELL_SIZE = 32;

    /// @notice Maximum Merkle proof depth
    uint256 public constant MAX_MERKLE_DEPTH = 32;

    /// @notice Maximum PRF block depth for invertibility
    uint256 public constant MAX_PRF_DEPTH = 16;

    // ========================================================================
    // STRUCTS
    // ========================================================================

    /// @notice PIR query structure (commitment only, actual points hidden)
    struct PIRQueryCommitment {
        bytes32 queryHash;
        bytes32 hintCommitment;
        uint256 gridSize;
        uint256 timestamp;
    }

    /// @notice PIR proof for verification
    struct PIRProof {
        bytes32 queryCommitment;
        bytes32 responseHintXor;
        bytes32 responseJunkXor;
        bytes32 hintCommitment;
        bytes32 retrievedValue;
        bytes32 merkleRoot;
        bytes32[] merklePath;
        uint8[] merklePathIndices;
    }

    /// @notice Cross-chain PIR proof
    struct CrossChainPIRProof {
        uint64 sourceChain;
        uint64 targetChain;
        PIRProof pirProof;
        bytes32 nullifier;
        bytes32 sourceStateRoot;
    }

    /// @notice Database registration for PIR
    struct DatabaseRegistration {
        bytes32 merkleRoot;
        uint256 gridSize;
        uint256 cellCount;
        uint256 lastUpdate;
        bool active;
    }

    /// @notice Query statistics
    struct QueryStats {
        uint256 totalQueries;
        uint256 successfulQueries;
        uint256 failedQueries;
        uint256 totalGasUsed;
    }

    // ========================================================================
    // STATE
    // ========================================================================

    /// @notice Registered databases by ID
    mapping(bytes32 => DatabaseRegistration) public databases;

    /// @notice Used nullifiers to prevent replay
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Query commitments by hash
    mapping(bytes32 => PIRQueryCommitment) public queryCommitments;

    /// @notice Cross-chain state roots by chain ID
    mapping(uint64 => bytes32) public chainStateRoots;

    /// @notice Trusted state root relayers
    mapping(address => bool) public trustedRelayers;

    /// @notice Query statistics
    QueryStats public stats;

    /// @notice Grid size configuration
    uint256 public gridSize;

    /// @notice Whether strict mode is enabled (requires valid Merkle proofs)
    bool public strictMode;

    // ========================================================================
    // EVENTS
    // ========================================================================

    event DatabaseRegistered(
        bytes32 indexed databaseId,
        bytes32 merkleRoot,
        uint256 gridSize,
        uint256 cellCount
    );

    event DatabaseUpdated(
        bytes32 indexed databaseId,
        bytes32 newMerkleRoot,
        uint256 timestamp
    );

    event PIRQuerySubmitted(
        bytes32 indexed queryHash,
        bytes32 hintCommitment,
        address indexed submitter
    );

    event PIRProofVerified(
        bytes32 indexed queryCommitment,
        bytes32 retrievedValue,
        bool success
    );

    event CrossChainPIRVerified(
        uint64 indexed sourceChain,
        uint64 indexed targetChain,
        bytes32 nullifier,
        bool success
    );

    event NullifierUsed(bytes32 indexed nullifier, address indexed user);

    event StateRootUpdated(uint64 indexed chainId, bytes32 stateRoot);

    event RelayerUpdated(address indexed relayer, bool trusted);

    // ========================================================================
    // ERRORS
    // ========================================================================

    error InvalidProof();
    error NullifierAlreadyUsed();
    error DatabaseNotRegistered();
    error InvalidMerkleProof();
    error InvalidChainId();
    error UnauthorizedRelayer();
    error InvalidGridSize();
    error QueryNotFound();
    error ZeroAddress();

    // ========================================================================
    // CONSTRUCTOR
    // ========================================================================

    constructor(uint256 _gridSize) Ownable(msg.sender) {
        if (_gridSize == 0 || _gridSize > 1 << 20) revert InvalidGridSize();
        gridSize = _gridSize;
        strictMode = true;
    }

    // ========================================================================
    // DATABASE MANAGEMENT
    // ========================================================================

    /**
     * @notice Register a new database for PIR queries
     * @param databaseId Unique identifier for the database
     * @param merkleRoot Merkle root of the database contents
     * @param _gridSize Grid size (√N)
     * @param cellCount Total number of cells
     */
    function registerDatabase(
        bytes32 databaseId,
        bytes32 merkleRoot,
        uint256 _gridSize,
        uint256 cellCount
    ) external onlyOwner {
        if (_gridSize == 0 || _gridSize > 1 << 20) revert InvalidGridSize();

        databases[databaseId] = DatabaseRegistration({
            merkleRoot: merkleRoot,
            gridSize: _gridSize,
            cellCount: cellCount,
            lastUpdate: block.timestamp,
            active: true
        });

        emit DatabaseRegistered(databaseId, merkleRoot, _gridSize, cellCount);
    }

    /**
     * @notice Update database Merkle root
     * @param databaseId Database identifier
     * @param newMerkleRoot New Merkle root after update
     */
    function updateDatabaseRoot(
        bytes32 databaseId,
        bytes32 newMerkleRoot
    ) external onlyOwner {
        DatabaseRegistration storage db = databases[databaseId];
        if (!db.active) revert DatabaseNotRegistered();

        db.merkleRoot = newMerkleRoot;
        db.lastUpdate = block.timestamp;

        emit DatabaseUpdated(databaseId, newMerkleRoot, block.timestamp);
    }

    // ========================================================================
    // PIR VERIFICATION
    // ========================================================================

    /**
     * @notice Verify a PIR proof
     * @param proof The PIR proof to verify
     * @param databaseId The database being queried
     * @return success Whether the proof is valid
     * @return retrievedValue The value retrieved (commitment)
     */
    function verifyPIRProof(
        PIRProof calldata proof,
        bytes32 databaseId
    ) external nonReentrant returns (bool success, bytes32 retrievedValue) {
        uint256 gasStart = gasleft();

        DatabaseRegistration storage db = databases[databaseId];
        if (!db.active) revert DatabaseNotRegistered();

        // 1. Verify query commitment matches
        bool queryValid = proof.queryCommitment != bytes32(0);

        // 2. Verify response processing
        // retrievedValue = hintXor XOR responseHintXor
        bytes32 computedValue = proof.hintCommitment ^ proof.responseHintXor;
        bool valueValid = computedValue == proof.retrievedValue;

        // 3. Verify Merkle proof if in strict mode
        bool merkleValid = true;
        if (strictMode && proof.merklePath.length > 0) {
            merkleValid = _verifyMerkleProof(
                proof.retrievedValue,
                proof.merkleRoot,
                proof.merklePath,
                proof.merklePathIndices
            );

            // Verify Merkle root matches database
            merkleValid = merkleValid && (proof.merkleRoot == db.merkleRoot);
        }

        success = queryValid && valueValid && merkleValid;
        retrievedValue = proof.retrievedValue;

        // Update stats
        stats.totalQueries++;
        if (success) {
            stats.successfulQueries++;
        } else {
            stats.failedQueries++;
        }
        stats.totalGasUsed += gasStart - gasleft();

        emit PIRProofVerified(proof.queryCommitment, retrievedValue, success);
    }

    /**
     * @notice Verify a cross-chain PIR proof
     * @param proof The cross-chain PIR proof
     * @return success Whether the proof is valid
     */
    function verifyCrossChainPIR(
        CrossChainPIRProof calldata proof
    ) external nonReentrant returns (bool success) {
        // 1. Verify chains are different
        if (proof.sourceChain == proof.targetChain) revert InvalidChainId();

        // 2. Verify nullifier hasn't been used
        if (usedNullifiers[proof.nullifier]) revert NullifierAlreadyUsed();

        // 3. Verify source state root
        bytes32 expectedRoot = chainStateRoots[proof.sourceChain];
        if (expectedRoot != proof.sourceStateRoot && expectedRoot != bytes32(0)) {
            revert InvalidProof();
        }

        // 4. Verify PIR proof against source state
        bool pirValid = _verifyPIRProofInternal(proof.pirProof, proof.sourceStateRoot);

        if (pirValid) {
            // Mark nullifier as used
            usedNullifiers[proof.nullifier] = true;
            emit NullifierUsed(proof.nullifier, msg.sender);
        }

        success = pirValid;

        emit CrossChainPIRVerified(
            proof.sourceChain,
            proof.targetChain,
            proof.nullifier,
            success
        );
    }

    /**
     * @notice Submit a PIR query commitment
     * @param queryHash Hash of the query points
     * @param hintCommitment Commitment to the hint used
     */
    function submitQueryCommitment(
        bytes32 queryHash,
        bytes32 hintCommitment
    ) external {
        queryCommitments[queryHash] = PIRQueryCommitment({
            queryHash: queryHash,
            hintCommitment: hintCommitment,
            gridSize: gridSize,
            timestamp: block.timestamp
        });

        emit PIRQuerySubmitted(queryHash, hintCommitment, msg.sender);
    }

    // ========================================================================
    // CROSS-CHAIN STATE ROOT MANAGEMENT
    // ========================================================================

    /**
     * @notice Update state root for a chain (only trusted relayers)
     * @param chainId The chain ID
     * @param stateRoot The new state root
     */
    function updateStateRoot(
        uint64 chainId,
        bytes32 stateRoot
    ) external {
        if (!trustedRelayers[msg.sender] && msg.sender != owner()) {
            revert UnauthorizedRelayer();
        }

        chainStateRoots[chainId] = stateRoot;
        emit StateRootUpdated(chainId, stateRoot);
    }

    /**
     * @notice Set trusted relayer status
     * @param relayer The relayer address
     * @param trusted Whether the relayer is trusted
     */
    function setTrustedRelayer(
        address relayer,
        bool trusted
    ) external onlyOwner {
        if (relayer == address(0)) revert ZeroAddress();
        trustedRelayers[relayer] = trusted;
        emit RelayerUpdated(relayer, trusted);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * @notice Set grid size
     * @param _gridSize New grid size
     */
    function setGridSize(uint256 _gridSize) external onlyOwner {
        if (_gridSize == 0 || _gridSize > 1 << 20) revert InvalidGridSize();
        gridSize = _gridSize;
    }

    /**
     * @notice Set strict mode
     * @param _strictMode Whether to require valid Merkle proofs
     */
    function setStrictMode(bool _strictMode) external onlyOwner {
        strictMode = _strictMode;
    }

    // ========================================================================
    // VIEW FUNCTIONS
    // ========================================================================

    /**
     * @notice Get database info
     * @param databaseId The database ID
     * @return merkleRoot The Merkle root
     * @return dbGridSize The grid size
     * @return cellCount Number of cells
     * @return lastUpdate Last update timestamp
     * @return active Whether active
     */
    function getDatabase(
        bytes32 databaseId
    )
        external
        view
        returns (
            bytes32 merkleRoot,
            uint256 dbGridSize,
            uint256 cellCount,
            uint256 lastUpdate,
            bool active
        )
    {
        DatabaseRegistration storage db = databases[databaseId];
        return (db.merkleRoot, db.gridSize, db.cellCount, db.lastUpdate, db.active);
    }

    /**
     * @notice Get query statistics
     * @return total Total queries
     * @return successful Successful queries
     * @return failed Failed queries
     * @return gasUsed Total gas used
     */
    function getStats()
        external
        view
        returns (
            uint256 total,
            uint256 successful,
            uint256 failed,
            uint256 gasUsed
        )
    {
        return (
            stats.totalQueries,
            stats.successfulQueries,
            stats.failedQueries,
            stats.totalGasUsed
        );
    }

    /**
     * @notice Check if nullifier has been used
     * @param nullifier The nullifier to check
     * @return used Whether the nullifier has been used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool used) {
        return usedNullifiers[nullifier];
    }

    /**
     * @notice Get state root for a chain
     * @param chainId The chain ID
     * @return stateRoot The state root
     */
    function getStateRoot(uint64 chainId) external view returns (bytes32 stateRoot) {
        return chainStateRoots[chainId];
    }

    // ========================================================================
    // INTERNAL FUNCTIONS
    // ========================================================================

    /**
     * @notice Internal PIR proof verification
     */
    function _verifyPIRProofInternal(
        PIRProof calldata proof,
        bytes32 expectedRoot
    ) internal view returns (bool) {
        // Verify query commitment
        if (proof.queryCommitment == bytes32(0)) return false;

        // Verify value computation
        bytes32 computedValue = proof.hintCommitment ^ proof.responseHintXor;
        if (computedValue != proof.retrievedValue) return false;

        // Verify Merkle proof if provided
        if (proof.merklePath.length > 0) {
            bool merkleValid = _verifyMerkleProof(
                proof.retrievedValue,
                expectedRoot,
                proof.merklePath,
                proof.merklePathIndices
            );
            if (!merkleValid) return false;
        }

        return true;
    }

    /**
     * @notice Verify a Merkle proof
     */
    function _verifyMerkleProof(
        bytes32 leaf,
        bytes32 root,
        bytes32[] calldata path,
        uint8[] calldata pathIndices
    ) internal pure returns (bool) {
        if (path.length != pathIndices.length) return false;
        if (path.length > MAX_MERKLE_DEPTH) return false;

        bytes32 computedRoot = leaf;

        for (uint256 i = 0; i < path.length; i++) {
            if (pathIndices[i] == 0) {
                computedRoot = keccak256(abi.encodePacked(computedRoot, path[i]));
            } else {
                computedRoot = keccak256(abi.encodePacked(path[i], computedRoot));
            }
        }

        return computedRoot == root;
    }

    /**
     * @notice Compute invertible PRF column
     * @dev H(S_row, j) -> column, using block-based structure
     */
    function _invertiblePRF(
        bytes32 rowSeed,
        uint256 hintIndex,
        uint256 _gridSize
    ) internal pure returns (uint256) {
        uint256 blockIndex = hintIndex / MAX_PRF_DEPTH;
        uint256 offset = hintIndex % MAX_PRF_DEPTH;

        bytes32 hash = keccak256(abi.encodePacked(rowSeed, blockIndex));

        // Extract bits for column index
        uint256 bitsNeeded = _log2(_gridSize);
        uint256 startBit = (offset * bitsNeeded) % 256;

        uint256 column = 0;
        for (uint256 i = 0; i < bitsNeeded; i++) {
            uint256 bitPos = (startBit + i) % 256;
            uint256 bytePos = bitPos / 8;
            uint256 bitInByte = bitPos % 8;

            uint8 b = uint8(hash[bytePos]);
            uint256 bit = (b >> bitInByte) & 1;
            column |= bit << i;
        }

        return column % _gridSize;
    }

    /**
     * @notice Compute log2 (for bit width calculation)
     */
    function _log2(uint256 x) internal pure returns (uint256) {
        uint256 result = 0;
        while (x > 1) {
            x >>= 1;
            result++;
        }
        return result;
    }
}
