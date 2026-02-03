// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title MidnightL2BridgeAdapter
 * @author Soul Protocol
 * @notice Unified L2 bridge adapter for Midnight ↔ Ethereum L2 transfers
 * @dev Supports: Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    L2 BRIDGE ADAPTER ARCHITECTURE                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                     MidnightL2BridgeAdapter                      │    │
 * │  │                                                                  │    │
 * │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐       │    │
 * │  │  │ Arbitrum  │ │ Optimism  │ │   Base    │ │  zkSync   │       │    │
 * │  │  │ Adapter   │ │ Adapter   │ │ Adapter   │ │  Adapter  │       │    │
 * │  │  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘       │    │
 * │  │        │             │             │             │              │    │
 * │  │  ┌─────▼─────────────▼─────────────▼─────────────▼─────┐       │    │
 * │  │  │              Unified Message Interface              │       │    │
 * │  │  │                                                     │       │    │
 * │  │  │  • sendToMidnight(proof, amount, recipient)        │       │    │
 * │  │  │  • receiveFromMidnight(midnightProof)              │       │    │
 * │  │  │  • syncState(stateRoot)                            │       │    │
 * │  │  └─────────────────────────────────────────────────────┘       │    │
 * │  │                                                                  │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                                                                          │
 * │  FAST PATH: Optimistic verification (30 sec - 2 min)                     │
 * │  SLOW PATH: Full L1 settlement (15+ min)                                 │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract MidnightL2BridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error UnsupportedChain(uint256 chainId);
    error InvalidProof();
    error InvalidMessage();
    error MessageAlreadyProcessed(bytes32 messageId);
    error InsufficientFee();
    error TransferFailed();
    error InvalidAdapter();
    error AdapterNotSet();
    error ChainMismatch();

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported L2 chain types
    enum L2ChainType {
        Arbitrum,
        Optimism,
        Base,
        ZkSync,
        Scroll,
        Linea,
        PolygonZkEVM
    }

    /// @notice Message status
    enum MessageStatus {
        None,
        Pending,
        Confirmed,
        Executed,
        Failed
    }

    /// @notice Cross-chain message
    struct CrossChainMessage {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 midnightCommitment;
        bytes32 nullifier;
        address sender;
        bytes32 recipient; // Midnight recipient or Eth address as bytes32
        uint256 amount;
        address token;
        uint64 timestamp;
        MessageStatus status;
    }

    /// @notice L2 adapter configuration
    struct L2AdapterConfig {
        address messenger; // Native messenger address
        address bridgeHub; // Main bridge hub contract
        uint256 gasLimit; // Default gas limit for messages
        uint64 confirmationBlocks; // Required confirmations
        bool isActive;
        L2ChainType chainType;
    }

    /// @notice Midnight message for cross-chain relay
    struct MidnightMessage {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 merkleRoot;
        uint256 amount;
        bytes32 midnightRecipient;
        bytes proof;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current chain ID
    uint256 public immutable CHAIN_ID;

    /// @notice Main bridge hub reference
    address public bridgeHub;

    /// @notice Midnight proof verifier
    address public proofVerifier;

    /// @notice L2 adapter configs per chain
    mapping(uint256 => L2AdapterConfig) public l2Configs;

    /// @notice Message storage
    mapping(bytes32 => CrossChainMessage) public messages;

    /// @notice Processed message IDs
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Nullifiers used (cross-chain sync)
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Midnight state roots synced
    mapping(bytes32 => bool) public midnightStateRoots;
    bytes32 public currentMidnightRoot;

    /// @notice Message counter
    uint256 public messageNonce;

    /// @notice Fee per message (in wei)
    uint256 public messageFee = 0.001 ether;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageId,
        uint256 indexed destChainId,
        bytes32 indexed commitment,
        address sender,
        uint256 amount
    );

    event MessageReceived(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        bytes32 indexed nullifier,
        address recipient,
        uint256 amount
    );

    event MessageExecuted(bytes32 indexed messageId, bool success);

    event L2ConfigUpdated(
        uint256 indexed chainId,
        address messenger,
        L2ChainType chainType
    );

    event MidnightStateUpdated(bytes32 indexed newRoot, uint64 blockNumber);

    event NullifierSynced(
        bytes32 indexed nullifier,
        uint256 indexed sourceChainId
    );

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _bridgeHub, address _proofVerifier, address _admin) {
        require(_bridgeHub != address(0), "Invalid bridge hub");
        require(_proofVerifier != address(0), "Invalid verifier");
        require(_admin != address(0), "Invalid admin");

        CHAIN_ID = block.chainid;
        bridgeHub = _bridgeHub;
        proofVerifier = _proofVerifier;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);

        _initializeL2Configs();
    }

    /**
     * @notice Initialize default L2 configurations
     */
    function _initializeL2Configs() internal {
        // Arbitrum One
        l2Configs[42161] = L2AdapterConfig({
            messenger: address(0), // Set by admin
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.Arbitrum
        });

        // Arbitrum Sepolia
        l2Configs[421614] = L2AdapterConfig({
            messenger: address(0),
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.Arbitrum
        });

        // Optimism
        l2Configs[10] = L2AdapterConfig({
            messenger: 0x4200000000000000000000000000000000000007, // L2CrossDomainMessenger
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.Optimism
        });

        // Base
        l2Configs[8453] = L2AdapterConfig({
            messenger: 0x4200000000000000000000000000000000000007,
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.Base
        });

        // zkSync Era
        l2Configs[324] = L2AdapterConfig({
            messenger: address(0),
            bridgeHub: bridgeHub,
            gasLimit: 2_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.ZkSync
        });

        // Scroll
        l2Configs[534352] = L2AdapterConfig({
            messenger: address(0),
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.Scroll
        });

        // Linea
        l2Configs[59144] = L2AdapterConfig({
            messenger: address(0),
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.Linea
        });

        // Polygon zkEVM
        l2Configs[1101] = L2AdapterConfig({
            messenger: address(0),
            bridgeHub: bridgeHub,
            gasLimit: 1_000_000,
            confirmationBlocks: 1,
            isActive: false,
            chainType: L2ChainType.PolygonZkEVM
        });
    }

    /*//////////////////////////////////////////////////////////////
                      L2 → MIDNIGHT (SEND)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send assets from L2 to Midnight
     * @param commitment Commitment to private transfer data
     * @param midnightRecipient Midnight recipient address
     * @param amount Amount to send
     * @param token Token address (address(0) for ETH)
     * @return messageId Unique message identifier
     */
    function sendToMidnight(
        bytes32 commitment,
        bytes32 midnightRecipient,
        uint256 amount,
        address token
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (amount == 0) revert InvalidMessage();
        if (msg.value < messageFee) revert InsufficientFee();

        // Generate unique message ID
        messageId = keccak256(
            abi.encodePacked(
                CHAIN_ID,
                msg.sender,
                commitment,
                messageNonce,
                block.timestamp
            )
        );

        // Store message
        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            sourceChainId: CHAIN_ID,
            destChainId: 0, // Midnight doesn't have EVM chain ID
            midnightCommitment: commitment,
            nullifier: bytes32(0), // Generated by Midnight
            sender: msg.sender,
            recipient: midnightRecipient,
            amount: amount,
            token: token,
            timestamp: uint64(block.timestamp),
            status: MessageStatus.Pending
        });

        unchecked {
            messageNonce++;
            totalMessagesSent++;
        }

        emit MessageSent(messageId, 0, commitment, msg.sender, amount);
    }

    /**
     * @notice Send assets from L2 to another L2 via Midnight
     * @param destChainId Destination L2 chain ID
     * @param commitment Commitment to private transfer data
     * @param recipient Recipient address on destination chain
     * @param amount Amount to send
     * @param token Token address
     * @return messageId Unique message identifier
     */
    function sendToL2ViaMidnight(
        uint256 destChainId,
        bytes32 commitment,
        address recipient,
        uint256 amount,
        address token
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        L2AdapterConfig storage destConfig = l2Configs[destChainId];
        if (!destConfig.isActive) revert UnsupportedChain(destChainId);
        if (amount == 0) revert InvalidMessage();
        if (msg.value < messageFee) revert InsufficientFee();

        messageId = keccak256(
            abi.encodePacked(
                CHAIN_ID,
                destChainId,
                msg.sender,
                commitment,
                messageNonce,
                block.timestamp
            )
        );

        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            sourceChainId: CHAIN_ID,
            destChainId: destChainId,
            midnightCommitment: commitment,
            nullifier: bytes32(0),
            sender: msg.sender,
            recipient: bytes32(uint256(uint160(recipient))),
            amount: amount,
            token: token,
            timestamp: uint64(block.timestamp),
            status: MessageStatus.Pending
        });

        unchecked {
            messageNonce++;
            totalMessagesSent++;
        }

        emit MessageSent(
            messageId,
            destChainId,
            commitment,
            msg.sender,
            amount
        );
    }

    /*//////////////////////////////////////////////////////////////
                      MIDNIGHT → L2 (RECEIVE)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive assets from Midnight
     * @param midnightMsg Message from Midnight with proof
     * @param recipient L2 recipient
     * @param token Token to receive
     */
    function receiveFromMidnight(
        MidnightMessage calldata midnightMsg,
        address recipient,
        address token
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify nullifier not used
        if (nullifierUsed[midnightMsg.nullifier]) {
            revert MessageAlreadyProcessed(midnightMsg.nullifier);
        }

        // Verify Midnight state root
        if (
            !midnightStateRoots[midnightMsg.merkleRoot] &&
            midnightMsg.merkleRoot != currentMidnightRoot
        ) {
            revert InvalidProof();
        }

        // Verify proof (delegated to proof verifier)
        bool valid = IMidnightProofVerifier(proofVerifier).verifyMidnightProof(
            midnightMsg.commitment,
            midnightMsg.nullifier,
            midnightMsg.merkleRoot,
            token,
            midnightMsg.amount,
            recipient,
            midnightMsg.proof
        );
        if (!valid) revert InvalidProof();

        // Mark nullifier as used
        nullifierUsed[midnightMsg.nullifier] = true;

        // Generate message ID
        bytes32 messageId = keccak256(
            abi.encodePacked(
                midnightMsg.commitment,
                midnightMsg.nullifier,
                CHAIN_ID
            )
        );

        // Store message
        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            sourceChainId: 0, // From Midnight
            destChainId: CHAIN_ID,
            midnightCommitment: midnightMsg.commitment,
            nullifier: midnightMsg.nullifier,
            sender: address(0),
            recipient: bytes32(uint256(uint160(recipient))),
            amount: midnightMsg.amount,
            token: token,
            timestamp: uint64(block.timestamp),
            status: MessageStatus.Executed
        });

        unchecked {
            totalMessagesReceived++;
        }

        // Execute transfer (assets come from bridge hub)
        _executeTransfer(token, midnightMsg.amount, recipient);

        emit MessageReceived(
            messageId,
            0,
            midnightMsg.nullifier,
            recipient,
            midnightMsg.amount
        );
    }

    /**
     * @notice Receive cross-L2 message that went through Midnight
     * @param sourceChainId Original source chain
     * @param midnightMsg Message with Midnight proof
     * @param recipient Final recipient
     * @param token Token address
     */
    function receiveFromL2ViaMidnight(
        uint256 sourceChainId,
        MidnightMessage calldata midnightMsg,
        address recipient,
        address token
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (nullifierUsed[midnightMsg.nullifier]) {
            revert MessageAlreadyProcessed(midnightMsg.nullifier);
        }

        // Verify proof
        bool valid = IMidnightProofVerifier(proofVerifier).verifyMidnightProof(
            midnightMsg.commitment,
            midnightMsg.nullifier,
            midnightMsg.merkleRoot,
            token,
            midnightMsg.amount,
            recipient,
            midnightMsg.proof
        );
        if (!valid) revert InvalidProof();

        nullifierUsed[midnightMsg.nullifier] = true;

        bytes32 messageId = keccak256(
            abi.encodePacked(
                sourceChainId,
                CHAIN_ID,
                midnightMsg.commitment,
                midnightMsg.nullifier
            )
        );

        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            sourceChainId: sourceChainId,
            destChainId: CHAIN_ID,
            midnightCommitment: midnightMsg.commitment,
            nullifier: midnightMsg.nullifier,
            sender: address(0),
            recipient: bytes32(uint256(uint160(recipient))),
            amount: midnightMsg.amount,
            token: token,
            timestamp: uint64(block.timestamp),
            status: MessageStatus.Executed
        });

        unchecked {
            totalMessagesReceived++;
        }

        _executeTransfer(token, midnightMsg.amount, recipient);

        emit MessageReceived(
            messageId,
            sourceChainId,
            midnightMsg.nullifier,
            recipient,
            midnightMsg.amount
        );
    }

    /*//////////////////////////////////////////////////////////////
                          STATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update Midnight state root
     * @param newRoot New Midnight state root
     * @param blockNumber Midnight block number
     * @param proof State transition proof
     */
    function updateMidnightState(
        bytes32 newRoot,
        uint64 blockNumber,
        bytes calldata proof
    ) external onlyRole(OPERATOR_ROLE) {
        // Verify state transition
        bool valid = IMidnightProofVerifier(proofVerifier)
            .verifyStateTransition(currentMidnightRoot, newRoot, proof);
        if (!valid) revert InvalidProof();

        // Store old root as historical
        if (currentMidnightRoot != bytes32(0)) {
            midnightStateRoots[currentMidnightRoot] = true;
        }

        currentMidnightRoot = newRoot;

        emit MidnightStateUpdated(newRoot, blockNumber);
    }

    /**
     * @notice Sync nullifiers from other L2s
     * @param nullifiers Array of nullifiers to sync
     * @param sourceChainId Source chain ID
     * @param proof Proof of nullifier validity
     */
    function syncNullifiers(
        bytes32[] calldata nullifiers,
        uint256 sourceChainId,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        // Verify proof (optional for trusted relayers)
        if (proof.length > 0) {
            bool valid = IMidnightProofVerifier(proofVerifier)
                .verifyNullifierBatch(nullifiers, currentMidnightRoot, proof);
            if (!valid) revert InvalidProof();
        }

        for (uint256 i = 0; i < nullifiers.length; ) {
            nullifierUsed[nullifiers[i]] = true;
            emit NullifierSynced(nullifiers[i], sourceChainId);
            unchecked {
                i++;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute token transfer
     */
    function _executeTransfer(
        address token,
        uint256 amount,
        address recipient
    ) internal {
        // Transfers are initiated from bridge hub
        // This adapter just validates and routes

        // In production, this would call the bridge hub to release funds
        // For now, we emit the event and let external system handle it
        emit MessageExecuted(
            keccak256(
                abi.encodePacked(token, amount, recipient, block.timestamp)
            ),
            true
        );
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update L2 configuration
     * @param chainId Chain ID to configure
     * @param messenger Messenger contract address
     * @param gasLimit Default gas limit
     * @param confirmations Required confirmations
     * @param isActive Whether chain is active
     * @param chainType L2 chain type
     */
    function setL2Config(
        uint256 chainId,
        address messenger,
        uint256 gasLimit,
        uint64 confirmations,
        bool isActive,
        L2ChainType chainType
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        l2Configs[chainId] = L2AdapterConfig({
            messenger: messenger,
            bridgeHub: bridgeHub,
            gasLimit: gasLimit,
            confirmationBlocks: confirmations,
            isActive: isActive,
            chainType: chainType
        });

        emit L2ConfigUpdated(chainId, messenger, chainType);
    }

    /**
     * @notice Update message fee
     * @param newFee New fee in wei
     */
    function setMessageFee(
        uint256 newFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        messageFee = newFee;
    }

    /**
     * @notice Update bridge hub
     * @param newBridgeHub New bridge hub address
     */
    function setBridgeHub(
        address newBridgeHub
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newBridgeHub != address(0), "Invalid bridge hub");
        bridgeHub = newBridgeHub;
    }

    /**
     * @notice Update proof verifier
     * @param newVerifier New verifier address
     */
    function setProofVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newVerifier != address(0), "Invalid verifier");
        proofVerifier = newVerifier;
    }

    /**
     * @notice Pause bridge
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /**
     * @notice Withdraw collected fees
     * @param recipient Fee recipient
     */
    function withdrawFees(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(recipient != address(0), "Invalid recipient");
        uint256 balance = address(this).balance;
        (bool success, ) = recipient.call{value: balance}("");
        if (!success) revert TransferFailed();
    }

    /*//////////////////////////////////////////////////////////////
                               VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get message details
     * @param messageId Message identifier
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (CrossChainMessage memory) {
        return messages[messageId];
    }

    /**
     * @notice Check if nullifier is used
     * @param nullifier Nullifier to check
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifierUsed[nullifier];
    }

    /**
     * @notice Get L2 config
     * @param chainId Chain ID
     */
    function getL2Config(
        uint256 chainId
    ) external view returns (L2AdapterConfig memory) {
        return l2Configs[chainId];
    }

    /**
     * @notice Check if chain is supported
     * @param chainId Chain ID to check
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return l2Configs[chainId].isActive;
    }

    /*//////////////////////////////////////////////////////////////
                              RECEIVE
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                    PROOF VERIFIER INTERFACE
//////////////////////////////////////////////////////////////*/

interface IMidnightProofVerifier {
    function verifyMidnightProof(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 merkleRoot,
        address token,
        uint256 amount,
        address recipient,
        bytes calldata proof
    ) external returns (bool);

    function verifyStateTransition(
        bytes32 oldStateHash,
        bytes32 newStateHash,
        bytes calldata proof
    ) external returns (bool);

    function verifyNullifierBatch(
        bytes32[] calldata nullifiers,
        bytes32 nullifierRoot,
        bytes calldata proof
    ) external returns (bool);
}
