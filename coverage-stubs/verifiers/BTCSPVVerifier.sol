// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract BTCSPVVerifier is AccessControl {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    uint256 public constant BLOCK_HEADER_SIZE = 80;
    uint256 public constant REQUIRED_CONFIRMATIONS = 6;
    uint256 public constant MAX_RETARGET_FACTOR = 4;
    uint256 public constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
    uint256 public constant TARGET_BLOCK_TIME = 600;

    struct BlockHeader { bytes32 blockHash; bytes32 prevBlockHash; bytes32 merkleRoot; uint32 timestamp; uint32 bits; uint32 nonce; uint256 height; uint256 chainWork; bool verified; }
    struct ChainTip { bytes32 blockHash; uint256 height; uint256 totalWork; }

    bytes32 public genesisBlockHash;
    ChainTip public chainTip;
    uint32 public minDifficultyBits;
    mapping(bytes32 => BlockHeader) public blockHeaders;
    mapping(uint256 => bytes32) public blockHashByHeight;
    uint256 public totalVerifiedBlocks;

    event BlockHeaderVerified(bytes32 indexed blockHash, uint256 height);
    event ChainTipUpdated(bytes32 indexed blockHash, uint256 height, uint256 totalWork);
    event GenesisBlockSet(bytes32 indexed blockHash);

    error InvalidBlockHeaderSize();
    error InvalidPrevBlockHash();
    error BlockAlreadyVerified();
    error InsufficientProofOfWork();

    constructor(address _admin, bytes32 _genesisBlockHash) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        genesisBlockHash = _genesisBlockHash;
    }

    function submitBlockHeader(bytes calldata, uint256 h) external returns (bytes32) {
        bytes32 bh = keccak256(abi.encode(h));
        blockHeaders[bh] = BlockHeader(bh, bytes32(0), bytes32(0), 0, 0, 0, h, 0, true);
        blockHashByHeight[h] = bh;
        totalVerifiedBlocks++;
        emit BlockHeaderVerified(bh, h);
        return bh;
    }
    function submitBlockHeaders(bytes[] calldata, uint256) external {}
    function verifyTxInclusion(bytes32, bytes32[] calldata, uint256, bytes32) external view returns (bool) { return true; }
    function verifyTxWithConfirmations(bytes32, bytes32[] calldata, uint256, bytes32, uint256) external view returns (bool) { return true; }
    function getBlockHeader(bytes32 h) external view returns (BlockHeader memory) { return blockHeaders[h]; }
    function getBlockHashAtHeight(uint256 h) external view returns (bytes32) { return blockHashByHeight[h]; }
    function getChainTip() external view returns (ChainTip memory) { return chainTip; }
    function isBlockVerified(bytes32 h) external view returns (bool) { return blockHeaders[h].verified; }
    function getConfirmations(bytes32) external pure returns (uint256) { return 10; }
}
