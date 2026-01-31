// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// STUB for coverage only
contract L2ChainAdapter is AccessControl, ReentrancyGuard {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    struct ChainConfig {
        uint256 chainId;
        string name;
        address bridge;
        address messenger;
        uint256 confirmations;
        bool enabled;
        uint256 gasLimit;
    }

    enum MessageStatus { PENDING, RELAYED, CONFIRMED, FAILED }

    struct Message {
        bytes32 id;
        uint256 sourceChain;
        uint256 targetChain;
        bytes payload;
        uint256 timestamp;
        MessageStatus status;
    }

    mapping(uint256 => ChainConfig) public chainConfigs;
    uint256[] public supportedChains;
    mapping(bytes32 => Message) public messages;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function addChain(uint256, string memory, address, address, uint256, uint256) external {}
    function updateChain(uint256, address, address, uint256, uint256, bool) external {}
    function sendMessage(uint256, bytes calldata) external returns (bytes32) { return bytes32(0); }
    function receiveMessage(bytes32, uint256, bytes calldata, bytes calldata) external {}
    function confirmMessage(bytes32) external {}
    function getSupportedChains() external view returns (uint256[] memory) { return supportedChains; }
    function getChainConfig(uint256) external view returns (ChainConfig memory) { return chainConfigs[0]; }
    function isChainSupported(uint256) external view returns (bool) { return true; }
    function getMessageStatus(bytes32) external view returns (MessageStatus) { return MessageStatus.PENDING; }
}
