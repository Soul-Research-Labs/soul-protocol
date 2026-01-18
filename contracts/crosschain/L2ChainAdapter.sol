// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title L2ChainAdapter
 * @notice Adapter for connecting PIL to Layer 2 networks
 * @dev Handles chain-specific messaging and proof verification
 */
contract L2ChainAdapter is AccessControl, ReentrancyGuard {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // Chain configuration
    struct ChainConfig {
        uint256 chainId;
        string name;
        address bridge;
        address messenger;
        uint256 confirmations;
        bool enabled;
        uint256 gasLimit;
    }

    // Supported L2 chains
    mapping(uint256 => ChainConfig) public chainConfigs;
    uint256[] public supportedChains;

    // Message tracking
    struct Message {
        bytes32 id;
        uint256 sourceChain;
        uint256 targetChain;
        bytes payload;
        uint256 timestamp;
        MessageStatus status;
    }

    enum MessageStatus {
        PENDING,
        RELAYED,
        CONFIRMED,
        FAILED
    }

    mapping(bytes32 => Message) public messages;

    // Events
    event ChainAdded(uint256 indexed chainId, string name, address bridge);
    event ChainUpdated(uint256 indexed chainId, bool enabled);
    event MessageSent(
        bytes32 indexed messageId,
        uint256 sourceChain,
        uint256 targetChain
    );
    event MessageReceived(bytes32 indexed messageId, uint256 sourceChain);
    event MessageConfirmed(bytes32 indexed messageId);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        // Initialize default L2 configurations
        _initializeDefaultChains();
    }

    function _initializeDefaultChains() internal {
        // Arbitrum One
        _addChain(
            ChainConfig({
                chainId: 42161,
                name: "Arbitrum One",
                bridge: address(0), // Set actual bridge address
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 1000000
            })
        );

        // Optimism
        _addChain(
            ChainConfig({
                chainId: 10,
                name: "Optimism",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 1000000
            })
        );

        // Base
        _addChain(
            ChainConfig({
                chainId: 8453,
                name: "Base",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 1000000
            })
        );

        // zkSync Era
        _addChain(
            ChainConfig({
                chainId: 324,
                name: "zkSync Era",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 2000000
            })
        );

        // Scroll
        _addChain(
            ChainConfig({
                chainId: 534352,
                name: "Scroll",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 1500000
            })
        );

        // Linea
        _addChain(
            ChainConfig({
                chainId: 59144,
                name: "Linea",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 1000000
            })
        );

        // Polygon zkEVM
        _addChain(
            ChainConfig({
                chainId: 1101,
                name: "Polygon zkEVM",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: true,
                gasLimit: 1500000
            })
        );
    }

    function _addChain(ChainConfig memory config) internal {
        chainConfigs[config.chainId] = config;
        supportedChains.push(config.chainId);
        emit ChainAdded(config.chainId, config.name, config.bridge);
    }

    /**
     * @notice Add a new L2 chain configuration
     */
    function addChain(
        uint256 chainId,
        string memory name,
        address bridge,
        address messenger,
        uint256 confirmations,
        uint256 gasLimit
    ) external onlyRole(ADMIN_ROLE) {
        require(chainConfigs[chainId].chainId == 0, "Chain already exists");

        _addChain(
            ChainConfig({
                chainId: chainId,
                name: name,
                bridge: bridge,
                messenger: messenger,
                confirmations: confirmations,
                enabled: true,
                gasLimit: gasLimit
            })
        );
    }

    /**
     * @notice Update chain configuration
     */
    function updateChain(
        uint256 chainId,
        address bridge,
        address messenger,
        uint256 confirmations,
        uint256 gasLimit,
        bool enabled
    ) external onlyRole(ADMIN_ROLE) {
        require(chainConfigs[chainId].chainId != 0, "Chain not found");

        ChainConfig storage config = chainConfigs[chainId];
        config.bridge = bridge;
        config.messenger = messenger;
        config.confirmations = confirmations;
        config.gasLimit = gasLimit;
        config.enabled = enabled;

        emit ChainUpdated(chainId, enabled);
    }

    /**
     * @notice Send a message to another chain
     */
    function sendMessage(
        uint256 targetChain,
        bytes calldata payload
    ) external nonReentrant returns (bytes32 messageId) {
        require(chainConfigs[targetChain].enabled, "Chain not enabled");

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                targetChain,
                msg.sender,
                payload,
                block.timestamp
            )
        );

        messages[messageId] = Message({
            id: messageId,
            sourceChain: block.chainid,
            targetChain: targetChain,
            payload: payload,
            timestamp: block.timestamp,
            status: MessageStatus.PENDING
        });

        // Chain-specific message sending would go here
        // This is a simplified version

        emit MessageSent(messageId, block.chainid, targetChain);

        return messageId;
    }

    /**
     * @notice Receive a message from another chain
     */
    function receiveMessage(
        bytes32 messageId,
        uint256 sourceChain,
        bytes calldata payload,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        require(chainConfigs[sourceChain].enabled, "Source chain not enabled");
        require(
            messages[messageId].status == MessageStatus.PENDING ||
                messages[messageId].id == bytes32(0),
            "Invalid message status"
        );

        // Verify the message proof (chain-specific)
        require(
            _verifyMessageProof(sourceChain, messageId, payload, proof),
            "Invalid proof"
        );

        messages[messageId] = Message({
            id: messageId,
            sourceChain: sourceChain,
            targetChain: block.chainid,
            payload: payload,
            timestamp: block.timestamp,
            status: MessageStatus.RELAYED
        });

        emit MessageReceived(messageId, sourceChain);
    }

    /**
     * @notice Confirm message delivery
     */
    function confirmMessage(bytes32 messageId) external onlyRole(RELAYER_ROLE) {
        require(
            messages[messageId].status == MessageStatus.RELAYED,
            "Message not relayed"
        );

        messages[messageId].status = MessageStatus.CONFIRMED;
        emit MessageConfirmed(messageId);
    }

    /**
     * @dev Verify message proof (chain-specific implementation)
     */
    function _verifyMessageProof(
        uint256 sourceChain,
        bytes32 messageId,
        bytes calldata payload,
        bytes calldata proof
    ) internal view returns (bool) {
        // This would contain chain-specific proof verification
        // For now, return true for testing
        sourceChain;
        messageId;
        payload;
        proof; // Silence unused warnings
        return true;
    }

    /**
     * @notice Get all supported chains
     */
    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    /**
     * @notice Get chain configuration
     */
    function getChainConfig(
        uint256 chainId
    ) external view returns (ChainConfig memory) {
        return chainConfigs[chainId];
    }

    /**
     * @notice Check if a chain is supported and enabled
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].enabled;
    }

    /**
     * @notice Get message status
     */
    function getMessageStatus(
        bytes32 messageId
    ) external view returns (MessageStatus) {
        return messages[messageId].status;
    }
}
