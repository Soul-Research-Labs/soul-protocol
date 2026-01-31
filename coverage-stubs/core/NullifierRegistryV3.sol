// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract NullifierRegistryV3 is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = 0xedcc084d3dcd65a1f7f23c65c46722faca6953d28e43150a467cf43e5c309238;
    bytes32 public constant BRIDGE_ROLE = 0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;
    bytes32 public constant EMERGENCY_ROLE = 0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    struct NullifierData { uint64 timestamp; uint64 blockNumber; uint64 sourceChainId; address registrar; bytes32 commitment; uint256 index; }
    
    mapping(bytes32 => NullifierData) public nullifiers;
    mapping(bytes32 => bool) public isNullifierUsed;
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public historicalRoots;
    uint256 public constant TREE_DEPTH = 32;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    uint256 public totalNullifiers;
    mapping(uint256 => uint256) public chainNullifierCount;
    uint256 public immutable CHAIN_ID;

    event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed commitment, uint256 indexed index, address registrar, uint64 chainId);
    event NullifierBatchRegistered(bytes32[] nullifiers, uint256 startIndex, uint256 count);
    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint256 nullifierCount);
    event CrossChainNullifiersReceived(uint256 indexed sourceChainId, bytes32 indexed merkleRoot, uint256 count);
    event RegistrarAdded(address indexed registrar);
    event RegistrarRemoved(address indexed registrar);

    error NullifierAlreadyExists(bytes32 nullifier);
    error NullifierNotFound(bytes32 nullifier);

    constructor() {
        CHAIN_ID = block.chainid;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerNullifier(bytes32 n, bytes32 c) external returns (uint256) {
        if (isNullifierUsed[n]) revert NullifierAlreadyExists(n);
        isNullifierUsed[n] = true;
        totalNullifiers++;
        emit NullifierRegistered(n, c, totalNullifiers, msg.sender, uint64(CHAIN_ID));
        return totalNullifiers;
    }
    function batchRegisterNullifiers(bytes32[] calldata n, bytes32[] calldata) external returns (uint256) { return totalNullifiers; }
    function receiveCrossChainNullifiers(uint256, bytes32[] calldata, bytes32[] calldata, bytes32) external {}
    function exists(bytes32 n) external view returns (bool) { return isNullifierUsed[n]; }
    function batchExists(bytes32[] calldata n) external view returns (bool[] memory r) { return new bool[](n.length); }
    function getNullifierData(bytes32 n) external view returns (NullifierData memory) { return nullifiers[n]; }
    function isValidRoot(bytes32) external pure returns (bool) { return true; }
    function verifyMerkleProof(bytes32, uint256, bytes32[] calldata, bytes32) external pure returns (bool) { return true; }
    function getTreeStats() external view returns (uint256, bytes32, uint256) { return (totalNullifiers, merkleRoot, ROOT_HISTORY_SIZE); }
    function getNullifierCountByChain(uint256) external pure returns (uint256) { return 0; }
    function addRegistrar(address) external {}
    function removeRegistrar(address) external {}
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
}
