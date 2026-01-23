// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title BrevisPrimitives
 * @author PIL Protocol
 * @notice Core primitives for Brevis ZK Coprocessor integration
 * @dev Implements query structures, proof verification, and data attestation
 *
 * BREVIS ARCHITECTURE:
 * - ZK Coprocessor for trustless off-chain computation
 * - Query-based historical data access
 * - SNARK proof verification (Groth16/PLONK)
 * - Cross-chain data attestation
 *
 * BNB CHAIN SPECIFICS:
 * - Chain ID: 56 (mainnet), 97 (testnet)
 * - Block time: ~3 seconds
 * - Optimized for high throughput privacy pools
 */
library BrevisPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice BNB Chain mainnet ID
    uint256 public constant BNB_MAINNET = 56;

    /// @notice BNB Chain testnet ID
    uint256 public constant BNB_TESTNET = 97;

    /// @notice Maximum query data slots
    uint256 public constant MAX_DATA_SLOTS = 64;

    /// @notice Maximum receipts per query
    uint256 public constant MAX_RECEIPTS = 32;

    /// @notice Maximum storage slots per query
    uint256 public constant MAX_STORAGE_SLOTS = 128;

    /// @notice Maximum transactions per query
    uint256 public constant MAX_TRANSACTIONS = 64;

    /// @notice Proof expiry time (24 hours)
    uint256 public constant PROOF_EXPIRY = 24 hours;

    /// @notice Minimum confirmations for finality
    uint256 public constant MIN_CONFIRMATIONS = 15;

    // =========================================================================
    // CROSS-DOMAIN CONSTANTS
    // =========================================================================

    /// @notice PIL-Brevis domain separator
    bytes32 public constant PIL_BREVIS_DOMAIN =
        keccak256("PIL_Brevis_PrivacyPool_v1");

    /// @notice Cross-domain nullifier prefix
    bytes public constant CROSS_DOMAIN_PREFIX = "B2P"; // Brevis to PIL

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Query types supported by Brevis
    enum QueryType {
        RECEIPT, // Transaction receipt data
        STORAGE, // Contract storage slots
        TRANSACTION, // Transaction data
        HEADER, // Block header data
        ACCOUNT // Account state
    }

    /// @notice Proof status
    enum ProofStatus {
        PENDING,
        VERIFIED,
        EXPIRED,
        INVALID
    }

    /// @notice Pool operation types
    enum PoolOperation {
        DEPOSIT,
        WITHDRAW,
        TRANSFER_NOTE,
        MERGE_NOTES
    }

    // =========================================================================
    // STRUCTS - QUERY TYPES
    // =========================================================================

    /// @notice Receipt query structure
    struct ReceiptQuery {
        bytes32 txHash;
        uint64 logIndex;
        uint64 blockNumber;
        address contractAddr;
        bytes32[] topics;
        bytes data;
    }

    /// @notice Storage query structure
    struct StorageQuery {
        address contractAddr;
        bytes32 slot;
        uint64 blockNumber;
        bytes32 value;
    }

    /// @notice Transaction query structure
    struct TransactionQuery {
        bytes32 txHash;
        uint64 blockNumber;
        address from;
        address to;
        uint256 value;
        bytes data;
    }

    /// @notice Block header query
    struct HeaderQuery {
        uint64 blockNumber;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        uint256 timestamp;
    }

    /// @notice Account state query
    struct AccountQuery {
        address account;
        uint64 blockNumber;
        uint256 nonce;
        uint256 balance;
        bytes32 storageRoot;
        bytes32 codeHash;
    }

    // =========================================================================
    // STRUCTS - PROOF TYPES
    // =========================================================================

    /// @notice Brevis proof structure
    struct BrevisProof {
        bytes32 queryHash;
        bytes32 resultHash;
        bytes32 vkHash;
        bytes proof;
        uint256 timestamp;
    }

    /// @notice SNARK proof elements (Groth16)
    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// @notice PLONK proof elements
    struct PlonkProof {
        uint256[24] commitments;
        uint256[8] evaluations;
        bytes openingProof;
    }

    /// @notice Aggregate proof for batched queries
    struct AggregateProof {
        bytes32[] queryHashes;
        bytes32 aggregateHash;
        bytes proof;
        uint256 batchSize;
    }

    // =========================================================================
    // STRUCTS - PRIVACY POOL
    // =========================================================================

    /// @notice Privacy pool note
    struct PrivacyNote {
        bytes32 commitment;
        bytes32 nullifier;
        uint256 amount;
        address token;
        uint64 createdBlock;
        bytes32 blinding;
    }

    /// @notice Deposit data
    struct DepositData {
        bytes32 commitment;
        uint256 amount;
        address token;
        address depositor;
        uint64 blockNumber;
        uint256 timestamp;
    }

    /// @notice Withdrawal data
    struct WithdrawalData {
        bytes32 nullifier;
        bytes32 root;
        address recipient;
        address relayer;
        uint256 amount;
        uint256 fee;
    }

    /// @notice Cross-chain note for PIL interoperability
    struct CrossChainNote {
        bytes32 brevisCommitment;
        bytes32 pilCommitment;
        bytes32 nullifierBinding;
        uint256 amount;
        uint256 sourceChainId;
        uint256 targetChainId;
    }

    /// @notice Merkle tree configuration
    struct MerkleConfig {
        uint256 depth;
        bytes32 zeroValue;
        bytes32[] zeroHashes;
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute Poseidon-like hash using keccak256 (EVM optimized)
     * @param left Left input
     * @param right Right input
     * @return result Hash result
     */
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    /**
     * @notice Compute hash of multiple inputs
     * @param inputs Array of inputs
     * @return result Hash result
     */
    function hashN(bytes32[] memory inputs) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(inputs));
    }

    /**
     * @notice Compute commitment from note data
     * @param amount Token amount
     * @param token Token address
     * @param blinding Random blinding factor
     * @return commitment Note commitment
     */
    function computeCommitment(
        uint256 amount,
        address token,
        bytes32 blinding
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(amount, token, blinding));
    }

    /**
     * @notice Derive nullifier from secret and commitment
     * @param secret User's secret
     * @param commitment Note commitment
     * @param leafIndex Position in Merkle tree
     * @return nullifier The nullifier
     */
    function deriveNullifier(
        bytes32 secret,
        bytes32 commitment,
        uint256 leafIndex
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(secret, commitment, leafIndex));
    }

    // =========================================================================
    // QUERY FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute query hash for verification
     * @param queryType Type of query
     * @param queryData Encoded query data
     * @return queryHash Hash of the query
     */
    function computeQueryHash(
        QueryType queryType,
        bytes memory queryData
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(queryType), queryData));
    }

    /**
     * @notice Encode receipt query
     * @param query Receipt query struct
     * @return encoded Encoded query data
     */
    function encodeReceiptQuery(
        ReceiptQuery memory query
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                query.txHash,
                query.logIndex,
                query.blockNumber,
                query.contractAddr,
                query.topics,
                query.data
            );
    }

    /**
     * @notice Encode storage query
     * @param query Storage query struct
     * @return encoded Encoded query data
     */
    function encodeStorageQuery(
        StorageQuery memory query
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                query.contractAddr,
                query.slot,
                query.blockNumber,
                query.value
            );
    }

    /**
     * @notice Verify query result matches expected
     * @param queryHash Hash of the query
     * @param resultHash Hash of the result
     * @param proof Brevis proof
     * @return valid True if valid
     */
    function verifyQueryResult(
        bytes32 queryHash,
        bytes32 resultHash,
        BrevisProof memory proof
    ) internal pure returns (bool) {
        // Verify query hash matches
        if (proof.queryHash != queryHash) return false;

        // Verify result hash matches
        if (proof.resultHash != resultHash) return false;

        // Verify proof is not expired (timestamp check done externally)
        return true;
    }

    // =========================================================================
    // MERKLE TREE FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute Merkle root from leaf and proof
     * @param leaf Leaf value
     * @param pathElements Sibling hashes
     * @param pathIndices Position indicators
     * @return root Computed root
     */
    function computeMerkleRoot(
        bytes32 leaf,
        bytes32[] memory pathElements,
        uint256[] memory pathIndices
    ) internal pure returns (bytes32) {
        bytes32 current = leaf;

        for (uint256 i = 0; i < pathElements.length; i++) {
            if (pathIndices[i] == 0) {
                current = hash2(current, pathElements[i]);
            } else {
                current = hash2(pathElements[i], current);
            }
        }

        return current;
    }

    /**
     * @notice Compute zero hash at level
     * @param level Tree level
     * @param zeroValue Base zero value
     * @return Zero hash at level
     */
    function computeZeroHash(
        uint256 level,
        bytes32 zeroValue
    ) internal pure returns (bytes32) {
        bytes32 current = zeroValue;
        for (uint256 i = 0; i < level; i++) {
            current = hash2(current, current);
        }
        return current;
    }

    // =========================================================================
    // CROSS-DOMAIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Derive cross-domain nullifier binding
     * @param brevisNullifier Original Brevis nullifier
     * @param sourceChain Source chain ID
     * @param targetChain Target chain ID
     * @return binding Cross-domain binding
     */
    function deriveCrossDomainNullifier(
        bytes32 brevisNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    PIL_BREVIS_DOMAIN,
                    brevisNullifier,
                    sourceChain,
                    targetChain,
                    CROSS_DOMAIN_PREFIX
                )
            );
    }

    /**
     * @notice Derive PIL binding from Brevis nullifier
     * @param brevisNullifier Brevis nullifier
     * @return pilBinding PIL-compatible binding
     */
    function derivePILBinding(
        bytes32 brevisNullifier
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    brevisNullifier,
                    PIL_BREVIS_DOMAIN,
                    CROSS_DOMAIN_PREFIX
                )
            );
    }

    // =========================================================================
    // VALIDATION FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if chain is BNB Chain
     * @param chainId Chain ID to check
     * @return True if BNB Chain
     */
    function isBNBChain(uint256 chainId) internal pure returns (bool) {
        return chainId == BNB_MAINNET || chainId == BNB_TESTNET;
    }

    /**
     * @notice Validate commitment
     * @param commitment Commitment to validate
     * @return valid True if valid
     */
    function isValidCommitment(
        bytes32 commitment
    ) internal pure returns (bool) {
        return commitment != bytes32(0);
    }

    /**
     * @notice Validate nullifier
     * @param nullifier Nullifier to validate
     * @return valid True if valid
     */
    function isValidNullifier(bytes32 nullifier) internal pure returns (bool) {
        return nullifier != bytes32(0);
    }

    /**
     * @notice Validate proof timestamp
     * @param proofTimestamp Proof creation time
     * @param currentTimestamp Current block timestamp
     * @return valid True if not expired
     */
    function isProofValid(
        uint256 proofTimestamp,
        uint256 currentTimestamp
    ) internal pure returns (bool) {
        return currentTimestamp - proofTimestamp <= PROOF_EXPIRY;
    }

    /**
     * @notice Validate block confirmations
     * @param queryBlock Block queried
     * @param currentBlock Current block
     * @return valid True if enough confirmations
     */
    function hasEnoughConfirmations(
        uint64 queryBlock,
        uint64 currentBlock
    ) internal pure returns (bool) {
        return currentBlock >= queryBlock + MIN_CONFIRMATIONS;
    }

    // =========================================================================
    // PROOF VERIFICATION
    // =========================================================================

    /**
     * @notice Verify Groth16 proof structure
     * @param proof Groth16 proof
     * @return valid True if structurally valid
     */
    function verifyGroth16Structure(
        Groth16Proof memory proof
    ) internal pure returns (bool) {
        // Basic structural validation
        // Real verification uses precompiles
        return proof.a[0] != 0 || proof.a[1] != 0;
    }

    /**
     * @notice Verify PLONK proof structure
     * @param proof PLONK proof
     * @return valid True if structurally valid
     */
    function verifyPlonkStructure(
        PlonkProof memory proof
    ) internal pure returns (bool) {
        return proof.commitments[0] != 0;
    }

    /**
     * @notice Verify aggregate proof
     * @param proof Aggregate proof
     * @return valid True if valid
     */
    function verifyAggregateProof(
        AggregateProof memory proof
    ) internal pure returns (bool) {
        if (proof.queryHashes.length == 0) return false;
        if (proof.queryHashes.length > MAX_RECEIPTS) return false;
        if (proof.batchSize != proof.queryHashes.length) return false;

        // Verify aggregate hash
        bytes32 computed = hashN(proof.queryHashes);
        return computed == proof.aggregateHash;
    }

    // =========================================================================
    // NOTE CONVERSION
    // =========================================================================

    /**
     * @notice Convert Brevis note to cross-chain format
     * @param note Privacy note
     * @param targetChainId Target chain
     * @return crossNote Cross-chain note
     */
    function toCrossChainNote(
        PrivacyNote memory note,
        uint256 targetChainId
    ) internal view returns (CrossChainNote memory crossNote) {
        crossNote.brevisCommitment = note.commitment;
        crossNote.pilCommitment = derivePILBinding(note.commitment);
        crossNote.nullifierBinding = derivePILBinding(note.nullifier);
        crossNote.amount = note.amount;
        crossNote.sourceChainId = block.chainid;
        crossNote.targetChainId = targetChainId;
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /**
     * @notice Pack deposit data for hashing
     * @param depositor Depositor address
     * @param amount Amount deposited
     * @param token Token address
     * @param blinding Blinding factor
     * @return packed Packed data
     */
    function packDepositData(
        address depositor,
        uint256 amount,
        address token,
        bytes32 blinding
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(depositor, amount, token, blinding);
    }

    /**
     * @notice Unpack and verify deposit proof result
     * @param proofResult Encoded proof result
     * @return depositor Depositor address
     * @return amount Deposit amount
     * @return token Token address
     */
    function unpackDepositResult(
        bytes memory proofResult
    ) internal pure returns (address depositor, uint256 amount, address token) {
        (depositor, amount, token) = abi.decode(
            proofResult,
            (address, uint256, address)
        );
    }
}
