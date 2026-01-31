// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract DirectL2Messenger is AccessControl {
    enum MessagePath { SUPERCHAIN, SHARED_SEQUENCER, FAST_RELAYER, SLOW_L1 }
    enum MessageStatus { NONE, SENT, RELAYED, CHALLENGED, EXECUTED, FAILED, REFUNDED }
    
    error InsufficientBond();

    struct L2Message {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address recipient;
        bytes payload;
        uint256 value;
        uint256 nonce;
        uint256 timestamp;
        uint256 deadline;
        MessagePath path;
        MessageStatus status;
        bytes32 nullifierBinding;
    }

    struct Relayer {
        address addr;
        uint256 bond;
        uint256 successCount;
        uint256 failCount;
        uint256 slashedAmount;
        bool active;
        uint256 registeredAt;
    }

    struct RouteConfig {
        MessagePath preferredPath;
        address adapter;
        uint256 minConfirmations;
        uint256 challengeWindow;
        bool active;
    }

    mapping(address => Relayer) public relayers;
    mapping(uint256 => mapping(uint256 => RouteConfig)) public routes;

    mapping(bytes32 => L2Message) public messages;

    constructor(address, address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function configureRoute(uint256, uint256, MessagePath, address, uint256, uint256) external {}
    function registerRelayer() external payable {}

    function sendMessage(uint256, address, bytes calldata, MessagePath, bytes32) external payable returns (bytes32) { return bytes32(0); }
    function receiveMessage(bytes32, uint256, address, address, bytes calldata) external {}
    function getRelayer(address addr) external view returns (Relayer memory) { return relayers[addr]; }
    function getRoute(uint256 src, uint256 dst) external view returns (RouteConfig memory) { return routes[src][dst]; }
    function getMessage(bytes32 id) external view returns (L2Message memory) { return messages[id]; }
}
