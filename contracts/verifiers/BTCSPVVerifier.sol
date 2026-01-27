// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title BTCSPVVerifier
 * @author PIL Protocol
 * @notice Bitcoin SPV light client for transaction verification
 * @dev Stores Bitcoin block headers and verifies Merkle inclusion proofs
 *
 * SPV VERIFICATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                   Bitcoin SPV Verification                       │
 * ├─────────────────────────────────────────────────────────────────┤
 * │                                                                  │
 * │  ┌─────────────────────────────────────────────────────────┐    │
 * │  │                Bitcoin Block Header                      │    │
 * │  │  ┌─────────┬─────────┬─────────┬─────────┬─────────┐    │    │
 * │  │  │ Version │ Prev    │ Merkle  │ Time    │ Bits/   │    │    │
 * │  │  │ (4B)    │ Hash    │ Root    │ (4B)    │ Nonce   │    │    │
 * │  │  │         │ (32B)   │ (32B)   │         │ (8B)    │    │    │
 * │  │  └─────────┴─────────┴────┬────┴─────────┴─────────┘    │    │
 * │  └───────────────────────────┼──────────────────────────────┘    │
 * │                              │                                   │
 * │  ┌───────────────────────────▼──────────────────────────────┐    │
 * │  │                   Merkle Tree                            │    │
 * │  │            ┌───────────────────────┐                     │    │
 * │  │            │     Merkle Root       │                     │    │
 * │  │            └───────────┬───────────┘                     │    │
 * │  │                ┌───────┴───────┐                         │    │
 * │  │            ┌───┴───┐       ┌───┴───┐                     │    │
 * │  │            │  H12  │       │  H34  │                     │    │
 * │  │            └───┬───┘       └───┬───┘                     │    │
 * │  │          ┌─────┼─────┐   ┌─────┼─────┐                   │    │
 * │  │         H1    H2    H3    H4                             │    │
 * │  │         │           │                                    │    │
 * │  │        TX1   ...   TX_target                             │    │
 * │  └──────────────────────────────────────────────────────────┘    │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract BTCSPVVerifier is AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bitcoin block header size in bytes
    uint256 public constant BLOCK_HEADER_SIZE = 80;

    /// @notice Required confirmations for finality
    uint256 public constant REQUIRED_CONFIRMATIONS = 6;

    /// @notice Maximum retarget adjustment (4x)
    uint256 public constant MAX_RETARGET_FACTOR = 4;

    /// @notice Difficulty adjustment interval (2016 blocks)
    uint256 public constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

    /// @notice Target block time (10 minutes in seconds)
    uint256 public constant TARGET_BLOCK_TIME = 600;

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Stored block header
    struct BlockHeader {
        bytes32 blockHash;
        bytes32 prevBlockHash;
        bytes32 merkleRoot;
        uint32 timestamp;
        uint32 bits;
        uint32 nonce;
        uint256 height;
        uint256 chainWork;
        bool verified;
    }

    /// @notice Chain tip info
    struct ChainTip {
        bytes32 blockHash;
        uint256 height;
        uint256 totalWork;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Genesis block hash (Bitcoin mainnet)
    bytes32 public genesisBlockHash;

    /// @notice Current chain tip
    ChainTip public chainTip;

    /// @notice Minimum difficulty bits
    uint32 public minDifficultyBits;

    /// @notice Block headers by hash
    mapping(bytes32 => BlockHeader) public blockHeaders;

    /// @notice Block hash by height
    mapping(uint256 => bytes32) public blockHashByHeight;

    /// @notice Total verified blocks
    uint256 public totalVerifiedBlocks;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BlockHeaderVerified(bytes32 indexed blockHash, uint256 height);
    event ChainTipUpdated(bytes32 indexed blockHash, uint256 height, uint256 totalWork);
    event GenesisBlockSet(bytes32 indexed blockHash);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBlockHeaderSize();
    error InvalidPrevBlockHash();
    error BlockAlreadyVerified();
    error InsufficientProofOfWork();
    error InvalidMerkleProof();
    error InvalidMerkleRoot();
    error BlockNotFound();
    error InsufficientConfirmations();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, bytes32 _genesisBlockHash) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);

        genesisBlockHash = _genesisBlockHash;

        emit GenesisBlockSet(_genesisBlockHash);
    }

    /*//////////////////////////////////////////////////////////////
                       BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a Bitcoin block header
     * @param headerBytes Raw 80-byte block header
     * @param height Block height
     * @return blockHash The verified block hash
     */
    function submitBlockHeader(
        bytes calldata headerBytes,
        uint256 height
    ) external onlyRole(RELAYER_ROLE) returns (bytes32 blockHash) {
        if (headerBytes.length != BLOCK_HEADER_SIZE) {
            revert InvalidBlockHeaderSize();
        }

        // Parse header
        blockHash = _hashBlockHeader(headerBytes);
        bytes32 prevBlockHash = _extractPrevBlockHash(headerBytes);
        bytes32 merkleRoot = _extractMerkleRoot(headerBytes);
        uint32 timestamp = _extractTimestamp(headerBytes);
        uint32 bits = _extractBits(headerBytes);
        uint32 nonce = _extractNonce(headerBytes);

        // Check not already verified
        if (blockHeaders[blockHash].verified) {
            revert BlockAlreadyVerified();
        }

        // Verify proof of work
        if (!_verifyProofOfWork(blockHash, bits)) {
            revert InsufficientProofOfWork();
        }

        // Calculate chain work
        uint256 blockWork = _calculateWork(bits);
        uint256 totalWork = blockHeaders[prevBlockHash].chainWork + blockWork;

        // Store header
        blockHeaders[blockHash] = BlockHeader({
            blockHash: blockHash,
            prevBlockHash: prevBlockHash,
            merkleRoot: merkleRoot,
            timestamp: timestamp,
            bits: bits,
            nonce: nonce,
            height: height,
            chainWork: totalWork,
            verified: true
        });

        blockHashByHeight[height] = blockHash;
        totalVerifiedBlocks++;

        // Update chain tip if this has more work
        if (totalWork > chainTip.totalWork) {
            chainTip = ChainTip({
                blockHash: blockHash,
                height: height,
                totalWork: totalWork
            });
            emit ChainTipUpdated(blockHash, height, totalWork);
        }

        emit BlockHeaderVerified(blockHash, height);
    }

    /**
     * @notice Submit multiple block headers in batch
     * @param headers Array of raw 80-byte headers
     * @param startHeight Starting block height
     */
    function submitBlockHeaders(
        bytes[] calldata headers,
        uint256 startHeight
    ) external onlyRole(RELAYER_ROLE) {
        for (uint256 i = 0; i < headers.length; i++) {
            this.submitBlockHeader(headers[i], startHeight + i);
        }
    }

    /*//////////////////////////////////////////////////////////////
                      MERKLE PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify transaction inclusion via Merkle proof
     * @param txId Transaction hash (little-endian, as in Bitcoin)
     * @param merkleProof Array of sibling hashes
     * @param txIndex Transaction index in block
     * @param blockHash Block containing the transaction
     * @return valid Whether the proof is valid
     */
    function verifyTxInclusion(
        bytes32 txId,
        bytes32[] calldata merkleProof,
        uint256 txIndex,
        bytes32 blockHash
    ) external view returns (bool valid) {
        BlockHeader storage header = blockHeaders[blockHash];

        if (!header.verified) {
            revert BlockNotFound();
        }

        // Compute Merkle root from proof
        bytes32 computedRoot = _computeMerkleRoot(txId, merkleProof, txIndex);

        // Compare with stored Merkle root
        return computedRoot == header.merkleRoot;
    }

    /**
     * @notice Verify transaction with required confirmations
     * @param txId Transaction hash
     * @param merkleProof Merkle proof
     * @param txIndex Transaction index
     * @param blockHash Block hash
     * @param requiredConfirmations Minimum confirmations
     * @return valid Whether verified with enough confirmations
     */
    function verifyTxWithConfirmations(
        bytes32 txId,
        bytes32[] calldata merkleProof,
        uint256 txIndex,
        bytes32 blockHash,
        uint256 requiredConfirmations
    ) external view returns (bool valid) {
        BlockHeader storage header = blockHeaders[blockHash];

        if (!header.verified) {
            revert BlockNotFound();
        }

        // Check confirmations
        uint256 confirmations = chainTip.height - header.height + 1;
        if (confirmations < requiredConfirmations) {
            revert InsufficientConfirmations();
        }

        // Verify Merkle proof
        bytes32 computedRoot = _computeMerkleRoot(txId, merkleProof, txIndex);
        return computedRoot == header.merkleRoot;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getBlockHeader(bytes32 blockHash) external view returns (BlockHeader memory) {
        return blockHeaders[blockHash];
    }

    function getBlockHashAtHeight(uint256 height) external view returns (bytes32) {
        return blockHashByHeight[height];
    }

    function getChainTip() external view returns (ChainTip memory) {
        return chainTip;
    }

    function isBlockVerified(bytes32 blockHash) external view returns (bool) {
        return blockHeaders[blockHash].verified;
    }

    function getConfirmations(bytes32 blockHash) external view returns (uint256) {
        BlockHeader storage header = blockHeaders[blockHash];
        if (!header.verified) return 0;
        return chainTip.height - header.height + 1;
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Double SHA256 hash of block header (Bitcoin's hash function)
     */
    function _hashBlockHeader(bytes calldata headerBytes) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(headerBytes)));
    }

    /**
     * @dev Extract previous block hash from header (bytes 4-35)
     */
    function _extractPrevBlockHash(bytes calldata headerBytes) internal pure returns (bytes32) {
        bytes32 prevHash;
        assembly {
            prevHash := calldataload(add(headerBytes.offset, 4))
        }
        return _reverseBytes32(prevHash);
    }

    /**
     * @dev Extract Merkle root from header (bytes 36-67)
     */
    function _extractMerkleRoot(bytes calldata headerBytes) internal pure returns (bytes32) {
        bytes32 merkleRoot;
        assembly {
            merkleRoot := calldataload(add(headerBytes.offset, 36))
        }
        return _reverseBytes32(merkleRoot);
    }

    /**
     * @dev Extract timestamp from header (bytes 68-71)
     */
    function _extractTimestamp(bytes calldata headerBytes) internal pure returns (uint32) {
        uint32 blockTs;
        assembly {
            blockTs := shr(224, calldataload(add(headerBytes.offset, 68)))
        }
        return _reverseBytes4(blockTs);
    }

    /**
     * @dev Extract difficulty bits from header (bytes 72-75)
     */
    function _extractBits(bytes calldata headerBytes) internal pure returns (uint32) {
        uint32 bits;
        assembly {
            bits := shr(224, calldataload(add(headerBytes.offset, 72)))
        }
        return _reverseBytes4(bits);
    }

    /**
     * @dev Extract nonce from header (bytes 76-79)
     */
    function _extractNonce(bytes calldata headerBytes) internal pure returns (uint32) {
        uint32 nonce;
        assembly {
            nonce := shr(224, calldataload(add(headerBytes.offset, 76)))
        }
        return _reverseBytes4(nonce);
    }

    /**
     * @dev Verify proof of work meets difficulty target
     */
    function _verifyProofOfWork(bytes32 blockHash, uint32 bits) internal pure returns (bool) {
        // Convert compact bits to target
        uint256 target = _bitsToTarget(bits);

        // Block hash must be less than target
        return uint256(blockHash) < target;
    }

    /**
     * @dev Convert compact bits to full target
     */
    function _bitsToTarget(uint32 bits) internal pure returns (uint256) {
        uint256 exponent = bits >> 24;
        uint256 mantissa = bits & 0x007fffff;

        if (exponent <= 3) {
            return mantissa >> (8 * (3 - exponent));
        } else {
            return mantissa << (8 * (exponent - 3));
        }
    }

    /**
     * @dev Calculate chain work from difficulty bits
     */
    function _calculateWork(uint32 bits) internal pure returns (uint256) {
        uint256 target = _bitsToTarget(bits);
        if (target == 0) return 0;

        // Work = 2^256 / (target + 1)
        return type(uint256).max / (target + 1);
    }

    /**
     * @dev Compute Merkle root from transaction and proof
     */
    function _computeMerkleRoot(
        bytes32 txHash,
        bytes32[] calldata proof,
        uint256 index
    ) internal pure returns (bytes32) {
        bytes32 computedHash = txHash;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (index % 2 == 0) {
                // Current hash is left child
                computedHash = _hashPair(computedHash, proofElement);
            } else {
                // Current hash is right child
                computedHash = _hashPair(proofElement, computedHash);
            }

            index = index / 2;
        }

        return computedHash;
    }

    /**
     * @dev Hash two nodes in Merkle tree (Bitcoin uses double SHA256)
     */
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(a, b))));
    }

    /**
     * @dev Reverse bytes in bytes32 (Bitcoin uses little-endian)
     */
    function _reverseBytes32(bytes32 input) internal pure returns (bytes32) {
        bytes32 output;
        for (uint256 i = 0; i < 32; i++) {
            output |= bytes32(uint256(uint8(input[i])) << (8 * (31 - i)));
        }
        return output;
    }

    /**
     * @dev Reverse bytes in uint32 (little-endian to big-endian)
     */
    function _reverseBytes4(uint32 input) internal pure returns (uint32) {
        return ((input & 0xff) << 24) |
               ((input & 0xff00) << 8) |
               ((input & 0xff0000) >> 8) |
               ((input & 0xff000000) >> 24);
    }
}
