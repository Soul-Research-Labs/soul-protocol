// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title ProofAggregator
/// @author Soul Protocol
/// @notice Aggregates multiple ZK proofs into a single proof for gas-efficient batch verification
/// @dev Supports recursive proof aggregation and merkle-based batch verification
contract ProofAggregator is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Individual proof data for aggregation
    struct ProofData {
        bytes32 proofHash;
        bytes32 publicInputsHash;
        uint64 chainId;
        uint64 timestamp;
        bool verified;
    }

    /// @notice Aggregated batch structure
    struct AggregatedBatch {
        bytes32 batchId;
        bytes32 merkleRoot;
        bytes32 aggregatedProofHash;
        bytes32[] proofHashes;
        uint256 proofCount;
        uint64 createdAt;
        uint64 verifiedAt;
        bool isVerified;
        AggregationType aggregationType;
    }

    /// @notice Type of aggregation used
    enum AggregationType {
        MERKLE, // Merkle tree aggregation
        RECURSIVE, // Recursive SNARK
        ACCUMULATOR // Proof accumulator
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of proof hash to proof data
    mapping(bytes32 => ProofData) public proofData;

    /// @notice Mapping of batch ID to aggregated batch
    mapping(bytes32 => AggregatedBatch) public aggregatedBatches;

    /// @notice Mapping of proof hash to batch ID
    mapping(bytes32 => bytes32) public proofToBatch;

    /// @notice Verifier contract for aggregated proofs
    address public aggregatedProofVerifier;

    /// @notice Maximum proofs per batch
    uint256 public constant MAX_BATCH_SIZE = 256;

    /// @notice Minimum proofs to aggregate
    uint256 public constant MIN_BATCH_SIZE = 2;

    /// @notice Total batches created
    uint256 public totalBatches;

    /// @notice Total proofs aggregated
    uint256 public totalProofsAggregated;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofAdded(
        bytes32 indexed proofHash,
        bytes32 publicInputsHash,
        uint64 chainId
    );

    event BatchCreated(
        bytes32 indexed batchId,
        bytes32 merkleRoot,
        uint256 proofCount,
        AggregationType aggregationType
    );

    event BatchVerified(
        bytes32 indexed batchId,
        bytes32 aggregatedProofHash,
        uint256 gasUsed
    );

    event AggregatedProofVerified(bytes32 indexed batchId, bool valid);

    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error BatchTooLarge(uint256 size, uint256 max);
    error BatchTooSmall(uint256 size, uint256 min);
    error BatchNotFound(bytes32 batchId);
    error BatchAlreadyVerified(bytes32 batchId);
    error ProofAlreadyAdded(bytes32 proofHash);
    error ProofNotFound(bytes32 proofHash);
    error InvalidMerkleProof();
    error VerifierNotSet();
    error InvalidAggregatedProof();
    error EmptyProofArray();
    error LengthMismatch();
    error MerkleRootMismatch();


    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _aggregatedProofVerifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AGGREGATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);

        aggregatedProofVerifier = _aggregatedProofVerifier;
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Registers a proof for future aggregation
    /// @param proofHash Hash of the proof
    /// @param publicInputsHash Hash of public inputs
    /// @param chainId Source chain ID
    function registerProof(
        bytes32 proofHash,
        bytes32 publicInputsHash,
        uint64 chainId
    ) external onlyRole(AGGREGATOR_ROLE) {
        if (proofData[proofHash].proofHash != bytes32(0)) {
            revert ProofAlreadyAdded(proofHash);
        }

        proofData[proofHash] = ProofData({
            proofHash: proofHash,
            publicInputsHash: publicInputsHash,
            chainId: chainId,
            timestamp: uint64(block.timestamp),
            verified: false
        });

        emit ProofAdded(proofHash, publicInputsHash, chainId);
    }

    /// @notice Batch registers multiple proofs
    /// @param proofHashes Array of proof hashes
    /// @param publicInputsHashes Array of public input hashes
    /// @param chainIds Array of chain IDs
    function registerProofsBatch(
        bytes32[] calldata proofHashes,
        bytes32[] calldata publicInputsHashes,
        uint64[] calldata chainIds
    ) external onlyRole(AGGREGATOR_ROLE) {
        uint256 len = proofHashes.length;
        if (len != publicInputsHashes.length || len != chainIds.length)
            revert LengthMismatch();


        for (uint256 i = 0; i < len; ) {
            if (proofData[proofHashes[i]].proofHash == bytes32(0)) {
                proofData[proofHashes[i]] = ProofData({
                    proofHash: proofHashes[i],
                    publicInputsHash: publicInputsHashes[i],
                    chainId: chainIds[i],
                    timestamp: uint64(block.timestamp),
                    verified: false
                });
                emit ProofAdded(
                    proofHashes[i],
                    publicInputsHashes[i],
                    chainIds[i]
                );
            }
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        MERKLE AGGREGATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a merkle-aggregated batch from registered proofs
    /// @param proofHashes Array of proof hashes to aggregate
    /// @return batchId The created batch ID
    function createMerkleBatch(
        bytes32[] calldata proofHashes
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 batchId) {
        uint256 len = proofHashes.length;
        if (len == 0) revert EmptyProofArray();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (len < MIN_BATCH_SIZE) revert BatchTooSmall(len, MIN_BATCH_SIZE);

        // Verify all proofs are registered
        for (uint256 i = 0; i < len; ) {
            if (proofData[proofHashes[i]].proofHash == bytes32(0)) {
                revert ProofNotFound(proofHashes[i]);
            }
            unchecked {
                ++i;
            }
        }

        // Compute merkle root
        bytes32 merkleRoot = _computeMerkleRoot(proofHashes);

        // Generate batch ID
        batchId = keccak256(
            abi.encodePacked(
                merkleRoot,
                msg.sender,
                block.timestamp,
                totalBatches
            )
        );

        // Store batch
        aggregatedBatches[batchId] = AggregatedBatch({
            batchId: batchId,
            merkleRoot: merkleRoot,
            aggregatedProofHash: bytes32(0),
            proofHashes: proofHashes,
            proofCount: len,
            createdAt: uint64(block.timestamp),
            verifiedAt: 0,
            isVerified: false,
            aggregationType: AggregationType.MERKLE
        });

        // Link proofs to batch
        for (uint256 i = 0; i < len; ) {
            proofToBatch[proofHashes[i]] = batchId;
            unchecked {
                ++i;
            }
        }

        totalBatches++;
        totalProofsAggregated += len;

        emit BatchCreated(batchId, merkleRoot, len, AggregationType.MERKLE);
    }

    /// @notice Verifies a merkle batch using a single aggregated proof
    /// @param batchId The batch to verify
    /// @param aggregatedProof The aggregated proof for the entire batch
    /// @param publicInputs Public inputs for the aggregated proof
    function verifyMerkleBatch(
        bytes32 batchId,
        bytes calldata aggregatedProof,
        bytes calldata publicInputs
    ) external onlyRole(AGGREGATOR_ROLE) returns (bool) {
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        if (batch.batchId == bytes32(0)) revert BatchNotFound(batchId);
        if (batch.isVerified) revert BatchAlreadyVerified(batchId);
        if (aggregatedProofVerifier == address(0)) revert VerifierNotSet();

        uint256 gasStart = gasleft();

        // Verify the aggregated proof includes the merkle root
        bytes32 expectedRoot = batch.merkleRoot;
        bytes32 providedRoot;
        assembly {
            // Assuming merkle root is first 32 bytes of public inputs
            providedRoot := calldataload(add(publicInputs.offset, 0))
        }
        if (providedRoot != expectedRoot) revert MerkleRootMismatch();


        // Call the verifier
        bool valid = _verifyAggregatedProof(aggregatedProof, publicInputs);
        if (!valid) revert InvalidAggregatedProof();

        // Update batch status
        batch.isVerified = true;
        batch.verifiedAt = uint64(block.timestamp);
        batch.aggregatedProofHash = keccak256(aggregatedProof);

        // Mark individual proofs as verified
        for (uint256 i = 0; i < batch.proofCount; ) {
            proofData[batch.proofHashes[i]].verified = true;
            unchecked {
                ++i;
            }
        }

        uint256 gasUsed = gasStart - gasleft();
        emit BatchVerified(batchId, batch.aggregatedProofHash, gasUsed);
        emit AggregatedProofVerified(batchId, true);

        return true;
    }

    /// @notice Verifies membership of a proof in a verified batch
    /// @param proofHash The proof hash to verify
    /// @param merkleProof Merkle proof of inclusion
    /// @param proofIndex Index in the batch
    /// @return valid Whether the proof is in the verified batch
    function verifyProofInBatch(
        bytes32 proofHash,
        bytes32[] calldata merkleProof,
        uint256 proofIndex
    ) external view returns (bool valid) {
        bytes32 batchId = proofToBatch[proofHash];
        if (batchId == bytes32(0)) return false;

        AggregatedBatch storage batch = aggregatedBatches[batchId];
        if (!batch.isVerified) return false;

        // Verify merkle proof
        bytes32 computedRoot = _computeMerkleProof(
            proofHash,
            proofIndex,
            merkleProof
        );
        return computedRoot == batch.merkleRoot;
    }

    /*//////////////////////////////////////////////////////////////
                      RECURSIVE AGGREGATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a recursively aggregated batch
    /// @dev Requires off-chain recursive proof generation
    /// @param proofHashes Array of proof hashes being aggregated
    /// @param aggregatedProofHash Hash of the pre-computed recursive proof
    /// @return batchId The created batch ID
    function createRecursiveBatch(
        bytes32[] calldata proofHashes,
        bytes32 aggregatedProofHash
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 batchId) {
        uint256 len = proofHashes.length;
        if (len == 0) revert EmptyProofArray();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        // Compute batch ID from aggregated proof
        batchId = keccak256(
            abi.encodePacked(
                aggregatedProofHash,
                msg.sender,
                block.timestamp,
                totalBatches
            )
        );

        // Compute merkle root for reference
        bytes32 merkleRoot = _computeMerkleRoot(proofHashes);

        aggregatedBatches[batchId] = AggregatedBatch({
            batchId: batchId,
            merkleRoot: merkleRoot,
            aggregatedProofHash: aggregatedProofHash,
            proofHashes: proofHashes,
            proofCount: len,
            createdAt: uint64(block.timestamp),
            verifiedAt: 0,
            isVerified: false,
            aggregationType: AggregationType.RECURSIVE
        });

        for (uint256 i = 0; i < len; ) {
            proofToBatch[proofHashes[i]] = batchId;
            unchecked {
                ++i;
            }
        }

        totalBatches++;
        totalProofsAggregated += len;

        emit BatchCreated(batchId, merkleRoot, len, AggregationType.RECURSIVE);
    }

    /// @notice Verifies a recursive batch with a single aggregated proof
    /// @param batchId The batch to verify
    /// @param recursiveProof The recursive aggregated proof
    /// @param publicInputs Public inputs containing batch commitment
    function verifyRecursiveBatch(
        bytes32 batchId,
        bytes calldata recursiveProof,
        bytes calldata publicInputs
    ) external onlyRole(AGGREGATOR_ROLE) returns (bool) {
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        if (batch.batchId == bytes32(0)) revert BatchNotFound(batchId);
        if (batch.isVerified) revert BatchAlreadyVerified(batchId);
        if (aggregatedProofVerifier == address(0)) revert VerifierNotSet();

        // Verify proof hash matches
        bytes32 proofHash = keccak256(recursiveProof);
        if (proofHash != batch.aggregatedProofHash)
            revert InvalidAggregatedProof();


        uint256 gasStart = gasleft();

        // Verify the recursive proof
        bool valid = _verifyAggregatedProof(recursiveProof, publicInputs);
        if (!valid) revert InvalidAggregatedProof();

        // Update batch
        batch.isVerified = true;
        batch.verifiedAt = uint64(block.timestamp);

        // Mark proofs verified
        for (uint256 i = 0; i < batch.proofCount; ) {
            proofData[batch.proofHashes[i]].verified = true;
            unchecked {
                ++i;
            }
        }

        uint256 gasUsed = gasStart - gasleft();
        emit BatchVerified(batchId, proofHash, gasUsed);
        emit AggregatedProofVerified(batchId, true);

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        ACCUMULATOR AGGREGATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates an accumulator-based batch (for incremental aggregation)
    /// @param proofHashes Initial proof hashes
    /// @param initialAccumulator Initial accumulator value
    /// @return batchId The created batch ID
    function createAccumulatorBatch(
        bytes32[] calldata proofHashes,
        bytes32 initialAccumulator
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 batchId) {
        uint256 len = proofHashes.length;
        if (len == 0) revert EmptyProofArray();

        batchId = keccak256(
            abi.encodePacked(
                initialAccumulator,
                msg.sender,
                block.timestamp,
                totalBatches
            )
        );

        bytes32 merkleRoot = _computeMerkleRoot(proofHashes);

        aggregatedBatches[batchId] = AggregatedBatch({
            batchId: batchId,
            merkleRoot: merkleRoot,
            aggregatedProofHash: initialAccumulator,
            proofHashes: proofHashes,
            proofCount: len,
            createdAt: uint64(block.timestamp),
            verifiedAt: 0,
            isVerified: false,
            aggregationType: AggregationType.ACCUMULATOR
        });

        for (uint256 i = 0; i < len; ) {
            proofToBatch[proofHashes[i]] = batchId;
            unchecked {
                ++i;
            }
        }

        totalBatches++;
        totalProofsAggregated += len;

        emit BatchCreated(
            batchId,
            merkleRoot,
            len,
            AggregationType.ACCUMULATOR
        );
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets batch details
    function getBatch(
        bytes32 batchId
    )
        external
        view
        returns (
            bytes32 merkleRoot,
            bytes32 aggregatedProofHash,
            uint256 proofCount,
            uint64 createdAt,
            uint64 verifiedAt,
            bool isVerified,
            AggregationType aggregationType
        )
    {
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        return (
            batch.merkleRoot,
            batch.aggregatedProofHash,
            batch.proofCount,
            batch.createdAt,
            batch.verifiedAt,
            batch.isVerified,
            batch.aggregationType
        );
    }

    /// @notice Gets proof hashes in a batch
    function getBatchProofs(
        bytes32 batchId
    ) external view returns (bytes32[] memory) {
        return aggregatedBatches[batchId].proofHashes;
    }

    /// @notice Checks if a proof has been verified
    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return proofData[proofHash].verified;
    }

    /// @notice Gets gas savings estimate for batching
    function estimateGasSavings(
        uint256 numProofs
    )
        external
        pure
        returns (
            uint256 individualGas,
            uint256 batchedGas,
            uint256 savings,
            uint256 savingsPercent
        )
    {
        // Estimated gas per individual proof verification
        uint256 gasPerProof = 280_000;

        // Estimated base gas for batch verification
        uint256 baseBatchGas = 300_000;

        // Additional gas per proof in batch (mainly storage)
        uint256 gasPerProofInBatch = 25_000;

        individualGas = numProofs * gasPerProof;
        batchedGas = baseBatchGas + (numProofs * gasPerProofInBatch);

        if (individualGas > batchedGas) {
            savings = individualGas - batchedGas;
            savingsPercent = (savings * 100) / individualGas;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates the aggregated proof verifier
    function setAggregatedProofVerifier(
        address _verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        address old = aggregatedProofVerifier;
        aggregatedProofVerifier = _verifier;
        emit VerifierUpdated(old, _verifier);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes merkle root from leaf hashes
    function _computeMerkleRoot(
        bytes32[] calldata leaves
    ) internal pure returns (bytes32) {
        uint256 len = leaves.length;
        if (len == 0) return bytes32(0);
        if (len == 1) return leaves[0];

        // Copy to memory for processing
        bytes32[] memory nodes = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            nodes[i] = leaves[i];
            unchecked {
                ++i;
            }
        }

        // Build tree bottom-up
        while (len > 1) {
            uint256 newLen = (len + 1) / 2;
            for (uint256 i = 0; i < newLen; ) {
                uint256 left = i * 2;
                uint256 right = left + 1;
                if (right < len) {
                    nodes[i] = _hashPair(nodes[left], nodes[right]);
                } else {
                    nodes[i] = nodes[left];
                }
                unchecked {
                    ++i;
                }
            }
            len = newLen;
        }

        return nodes[0];
    }

    /// @notice Verifies merkle proof and returns root
    function _computeMerkleProof(
        bytes32 leaf,
        uint256 index,
        bytes32[] calldata proof
    ) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; ) {
            bytes32 proofElement = proof[i];

            if (index % 2 == 0) {
                computedHash = _hashPair(computedHash, proofElement);
            } else {
                computedHash = _hashPair(proofElement, computedHash);
            }

            index = index / 2;
            unchecked {
                ++i;
            }
        }

        return computedHash;
    }

    /// @notice Hash pair of nodes
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return
            a < b
                ? keccak256(abi.encodePacked(a, b))
                : keccak256(abi.encodePacked(b, a));
    }

    /// @notice Calls the verifier contract
    function _verifyAggregatedProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal view returns (bool) {
        (bool success, bytes memory result) = aggregatedProofVerifier
            .staticcall(
                abi.encodeWithSignature(
                    "verifyProof(bytes,bytes)",
                    proof,
                    publicInputs
                )
            );

        if (!success) {
            // Try alternative signature
            (success, result) = aggregatedProofVerifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes,bytes)",
                    proof,
                    publicInputs
                )
            );
        }

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }
}

/// @notice Batch proof input structure
struct BatchProofInput {
    bytes32 proofHash;
    bytes32 publicInputsHash;
    bytes32 commitment;
    uint64 sourceChainId;
    uint64 destChainId;
}

/// @notice Interface for proof verifiers
interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);
}
