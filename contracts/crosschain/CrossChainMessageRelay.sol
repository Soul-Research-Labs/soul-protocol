// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title CrossChainMessageRelay
 * @author PIL Protocol
 * @notice Handles cross-chain message passing between Ethereum L1 and L2 networks
 * @dev Implements secure message relay with signature verification and replay protection
 *
 * MESSAGE FLOW:
 *
 * L1 → L2 (Outbound):
 * ┌──────────┐     ┌───────────────┐     ┌──────────────┐     ┌──────────┐
 * │ L1 DApp  │────▶│ MessageRelay  │────▶│ Canonical    │────▶│ L2 DApp  │
 * │          │     │ (encode msg)  │     │ Bridge       │     │          │
 * └──────────┘     └───────────────┘     └──────────────┘     └──────────┘
 *
 * L2 → L1 (Inbound):
 * ┌──────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────┐
 * │ L2 DApp  │────▶│ Canonical    │────▶│ MessageRelay  │────▶│ L1 DApp  │
 * │          │     │ Bridge       │     │ (verify+exec) │     │          │
 * └──────────┘     └──────────────┘     └───────────────┘     └──────────┘
 */
contract CrossChainMessageRelay is AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Cross-chain message
    struct CrossChainMessage {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 targetChainId;
        address sender;
        address target;
        uint256 value;
        uint256 gasLimit;
        bytes data;
        uint256 nonce;
        uint256 timestamp;
        uint256 deadline;
    }

    /// @notice Message status
    enum MessageStatus {
        UNKNOWN,
        PENDING,
        RELAYED,
        EXECUTED,
        FAILED,
        EXPIRED
    }

    /// @notice Message execution result
    struct ExecutionResult {
        bool success;
        bytes returnData;
        uint256 gasUsed;
        uint256 executedAt;
    }

    /// @notice Batch of messages
    struct MessageBatch {
        bytes32 batchId;
        bytes32[] messageIds;
        bytes32 merkleRoot;
        uint256 sourceChainId;
        uint256 timestamp;
        bool finalized;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Ethereum mainnet chain ID
    uint256 public constant ETHEREUM_CHAIN_ID = 1;

    /// @notice Outbound message nonces per destination chain
    mapping(uint256 => uint256) public outboundNonces;

    /// @notice Inbound message nonces per source chain
    mapping(uint256 => uint256) public inboundNonces;

    /// @notice Message status tracking
    mapping(bytes32 => MessageStatus) public messageStatus;

    /// @notice Message execution results
    mapping(bytes32 => ExecutionResult) public executionResults;

    /// @notice Stored messages (for retry)
    mapping(bytes32 => CrossChainMessage) public storedMessages;

    /// @notice Message batches
    mapping(bytes32 => MessageBatch) public messageBatches;

    /// @notice Trusted remote contracts per chain
    mapping(uint256 => address) public trustedRemotes;

    /// @notice Registered bridge adapters
    mapping(uint256 => address) public bridgeAdapters;

    /// @notice Maximum gas limit for message execution
    uint256 public maxGasLimit = 5000000;

    /// @notice Minimum gas limit
    uint256 public minGasLimit = 21000;

    /// @notice Message expiry duration (default: 7 days)
    uint256 public messageExpiry = 7 days;

    /// @notice Failed message retry delay
    uint256 public retryDelay = 1 hours;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total messages executed
    uint256 public totalMessagesExecuted;

    /// @notice Max batch size for message aggregation
    uint256 public constant MAX_BATCH_SIZE = 50;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageId,
        uint256 indexed targetChainId,
        address indexed sender,
        address target,
        uint256 value,
        bytes data
    );

    event MessageReceived(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        address indexed sender,
        address target
    );

    event MessageExecuted(
        bytes32 indexed messageId,
        bool success,
        bytes returnData,
        uint256 gasUsed
    );

    event MessageFailed(bytes32 indexed messageId, string reason);

    event MessageRetried(bytes32 indexed messageId, uint256 attempt);

    event TrustedRemoteSet(uint256 indexed chainId, address indexed remote);

    event BridgeAdapterSet(uint256 indexed chainId, address indexed adapter);

    event BatchCreated(
        bytes32 indexed batchId,
        uint256 indexed sourceChainId,
        uint256 messageCount
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidChainId(uint256 chainId);
    error UntrustedRemote(uint256 chainId, address sender);
    error MessageAlreadyProcessed(bytes32 messageId);
    error MessageExpired(bytes32 messageId);
    error MessageNotFound(bytes32 messageId);
    error InvalidMessageStatus(
        bytes32 messageId,
        MessageStatus current,
        MessageStatus expected
    );
    error GasLimitOutOfRange(uint256 gasLimit, uint256 min, uint256 max);
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 received);
    error ExecutionFailed(bytes32 messageId, bytes reason);
    error RetryTooSoon(bytes32 messageId, uint256 nextRetry);
    error BatchTooLarge(uint256 size, uint256 max);
    error ZeroAddress();
    error InvalidDeadline();
    error InsufficientValue();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                       OUTBOUND MESSAGES (L1 → L2)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to an L2 chain
     * @param targetChainId The target chain ID
     * @param target The target contract address on L2
     * @param data The calldata for the target
     * @param gasLimit Gas limit for execution on L2
     * @return messageId The unique message ID
     */
    function sendMessage(
        uint256 targetChainId,
        address target,
        bytes calldata data,
        uint256 gasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        return _sendMessage(targetChainId, target, msg.value, data, gasLimit);
    }

    /**
     * @notice Send a message with custom value
     * @param targetChainId The target chain ID
     * @param target The target contract address
     * @param value Value to send with message
     * @param data The calldata
     * @param gasLimit Gas limit for execution
     * @return messageId The unique message ID
     */
    function sendMessageWithValue(
        uint256 targetChainId,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 gasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (msg.value < value) revert InsufficientValue();
        return _sendMessage(targetChainId, target, value, data, gasLimit);
    }

    /**
     * @notice Internal send message implementation
     */
    function _sendMessage(
        uint256 targetChainId,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 gasLimit
    ) internal returns (bytes32 messageId) {
        if (targetChainId == 0 || targetChainId == block.chainid) {
            revert InvalidChainId(targetChainId);
        }
        if (target == address(0)) revert ZeroAddress();
        if (gasLimit < minGasLimit || gasLimit > maxGasLimit) {
            revert GasLimitOutOfRange(gasLimit, minGasLimit, maxGasLimit);
        }

        uint256 nonce = outboundNonces[targetChainId]++;

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                targetChainId,
                msg.sender,
                target,
                value,
                keccak256(data),
                nonce,
                block.timestamp
            )
        );

        CrossChainMessage memory message = CrossChainMessage({
            messageId: messageId,
            sourceChainId: block.chainid,
            targetChainId: targetChainId,
            sender: msg.sender,
            target: target,
            value: value,
            gasLimit: gasLimit,
            data: data,
            nonce: nonce,
            timestamp: block.timestamp,
            deadline: block.timestamp + messageExpiry
        });

        storedMessages[messageId] = message;
        messageStatus[messageId] = MessageStatus.PENDING;
        totalMessagesSent++;

        emit MessageSent(
            messageId,
            targetChainId,
            msg.sender,
            target,
            value,
            data
        );

        // In production: Forward to canonical bridge adapter
        // address adapter = bridgeAdapters[targetChainId];
        // if (adapter != address(0)) {
        //     IBridgeAdapter(adapter).sendMessage{value: value}(message);
        // }
    }

    /*//////////////////////////////////////////////////////////////
                       INBOUND MESSAGES (L2 → L1)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and execute a message from L2
     * @param message The cross-chain message
     * @param proof Merkle proof or signature for verification
     */
    function receiveMessage(
        CrossChainMessage calldata message,
        bytes calldata proof
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify message hasn't been processed
        if (messageStatus[message.messageId] != MessageStatus.UNKNOWN) {
            revert MessageAlreadyProcessed(message.messageId);
        }

        // Verify source chain is configured
        address trustedRemote = trustedRemotes[message.sourceChainId];
        if (trustedRemote == address(0)) {
            revert UntrustedRemote(message.sourceChainId, message.sender);
        }

        // Verify message is not expired
        if (block.timestamp > message.deadline) {
            messageStatus[message.messageId] = MessageStatus.EXPIRED;
            revert MessageExpired(message.messageId);
        }

        // Verify nonce
        if (message.nonce != inboundNonces[message.sourceChainId]) {
            revert InvalidNonce(
                inboundNonces[message.sourceChainId],
                message.nonce
            );
        }

        // Verify proof (signature or merkle proof)
        if (!_verifyProof(message, proof)) {
            revert InvalidSignature();
        }

        inboundNonces[message.sourceChainId]++;
        messageStatus[message.messageId] = MessageStatus.RELAYED;
        storedMessages[message.messageId] = message;
        totalMessagesReceived++;

        emit MessageReceived(
            message.messageId,
            message.sourceChainId,
            message.sender,
            message.target
        );

        // Execute the message
        _executeMessage(message);
    }

    /**
     * @notice Execute a relayed message
     * @param message The message to execute
     */
    function _executeMessage(CrossChainMessage memory message) internal {
        if (message.target == address(0)) revert ZeroAddress();

        uint256 gasStart = gasleft();

        (bool success, bytes memory returnData) = message.target.call{
            value: message.value,
            gas: message.gasLimit
        }(message.data);

        uint256 gasUsed = gasStart - gasleft();

        executionResults[message.messageId] = ExecutionResult({
            success: success,
            returnData: returnData,
            gasUsed: gasUsed,
            executedAt: block.timestamp
        });

        if (success) {
            messageStatus[message.messageId] = MessageStatus.EXECUTED;
            totalMessagesExecuted++;
            emit MessageExecuted(message.messageId, true, returnData, gasUsed);
        } else {
            messageStatus[message.messageId] = MessageStatus.FAILED;
            emit MessageFailed(message.messageId, string(returnData));
            emit MessageExecuted(message.messageId, false, returnData, gasUsed);
        }
    }

    /**
     * @notice Retry a failed message execution
     * @param messageId The message ID to retry
     */
    function retryMessage(
        bytes32 messageId
    ) external nonReentrant whenNotPaused {
        MessageStatus status = messageStatus[messageId];

        if (status != MessageStatus.FAILED) {
            revert InvalidMessageStatus(
                messageId,
                status,
                MessageStatus.FAILED
            );
        }

        CrossChainMessage storage message = storedMessages[messageId];
        if (message.messageId == bytes32(0)) revert MessageNotFound(messageId);

        ExecutionResult storage lastResult = executionResults[messageId];
        if (block.timestamp < lastResult.executedAt + retryDelay) {
            revert RetryTooSoon(messageId, lastResult.executedAt + retryDelay);
        }

        // Check expiry
        if (block.timestamp > message.deadline) {
            messageStatus[messageId] = MessageStatus.EXPIRED;
            revert MessageExpired(messageId);
        }

        messageStatus[messageId] = MessageStatus.RELAYED;
        emit MessageRetried(messageId, 1);

        _executeMessage(message);
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive a batch of messages
     * @param messageIds Array of message IDs in the batch
     * @param merkleRoot Merkle root of the batch
     * @param sourceChainId Source chain ID
     * @param messages Array of messages
     * @param proofs Array of Merkle proofs
     */
    function receiveBatch(
        bytes32[] calldata messageIds,
        bytes32 merkleRoot,
        uint256 sourceChainId,
        CrossChainMessage[] calldata messages,
        bytes[] calldata proofs
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (messageIds.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge(messageIds.length, MAX_BATCH_SIZE);
        }
        if (
            messageIds.length != messages.length ||
            messages.length != proofs.length
        ) {
            revert InvalidNonce(messageIds.length, messages.length);
        }

        bytes32 batchId = keccak256(
            abi.encodePacked(merkleRoot, sourceChainId, block.timestamp)
        );

        messageBatches[batchId] = MessageBatch({
            batchId: batchId,
            messageIds: messageIds,
            merkleRoot: merkleRoot,
            sourceChainId: sourceChainId,
            timestamp: block.timestamp,
            finalized: false
        });

        emit BatchCreated(batchId, sourceChainId, messageIds.length);

        // Process each message
        for (uint256 i = 0; i < messages.length; i++) {
            if (messageStatus[messages[i].messageId] == MessageStatus.UNKNOWN) {
                if (_verifyProof(messages[i], proofs[i])) {
                    messageStatus[messages[i].messageId] = MessageStatus
                        .RELAYED;
                    storedMessages[messages[i].messageId] = messages[i];
                    totalMessagesReceived++;

                    emit MessageReceived(
                        messages[i].messageId,
                        sourceChainId,
                        messages[i].sender,
                        messages[i].target
                    );
                }
            }
        }

        messageBatches[batchId].finalized = true;
    }

    /**
     * @notice Execute all messages in a batch
     * @param batchId The batch ID
     */
    function executeBatch(bytes32 batchId) external nonReentrant whenNotPaused {
        MessageBatch storage batch = messageBatches[batchId];
        if (batch.batchId == bytes32(0)) revert MessageNotFound(batchId);
        if (!batch.finalized)
            revert InvalidMessageStatus(
                batchId,
                MessageStatus.PENDING,
                MessageStatus.RELAYED
            );

        for (uint256 i = 0; i < batch.messageIds.length; i++) {
            bytes32 msgId = batch.messageIds[i];
            if (messageStatus[msgId] == MessageStatus.RELAYED) {
                _executeMessage(storedMessages[msgId]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify message proof
     * @param message The message to verify
     * @param proof The proof bytes (signature or merkle)
     */
    function _verifyProof(
        CrossChainMessage calldata message,
        bytes calldata proof
    ) internal view returns (bool) {
        // Reconstruct message hash
        bytes32 messageHash = keccak256(
            abi.encode(
                message.messageId,
                message.sourceChainId,
                message.targetChainId,
                message.sender,
                message.target,
                message.value,
                message.gasLimit,
                keccak256(message.data),
                message.nonce,
                message.timestamp,
                message.deadline
            )
        );

        // Verify signature from trusted remote
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedHash.recover(proof);

        return signer == trustedRemotes[message.sourceChainId];
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set trusted remote contract for a chain
     * @param chainId The remote chain ID
     * @param remote The trusted contract address on that chain
     */
    function setTrustedRemote(
        uint256 chainId,
        address remote
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId(chainId);
        trustedRemotes[chainId] = remote;
        emit TrustedRemoteSet(chainId, remote);
    }

    /**
     * @notice Set bridge adapter for a chain
     * @param chainId The chain ID
     * @param adapter The bridge adapter address
     */
    function setBridgeAdapter(
        uint256 chainId,
        address adapter
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId(chainId);
        bridgeAdapters[chainId] = adapter;
        emit BridgeAdapterSet(chainId, adapter);
    }

    /**
     * @notice Set gas limits
     * @param _minGasLimit Minimum gas limit
     * @param _maxGasLimit Maximum gas limit
     */
    function setGasLimits(
        uint256 _minGasLimit,
        uint256 _maxGasLimit
    ) external onlyRole(OPERATOR_ROLE) {
        minGasLimit = _minGasLimit;
        maxGasLimit = _maxGasLimit;
    }

    /**
     * @notice Set message expiry duration
     * @param _expiry New expiry duration
     */
    function setMessageExpiry(
        uint256 _expiry
    ) external onlyRole(OPERATOR_ROLE) {
        messageExpiry = _expiry;
    }

    /**
     * @notice Pause the relay
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the relay
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get message details
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (CrossChainMessage memory) {
        return storedMessages[messageId];
    }

    /**
     * @notice Get message execution result
     */
    function getExecutionResult(
        bytes32 messageId
    ) external view returns (ExecutionResult memory) {
        return executionResults[messageId];
    }

    /**
     * @notice Check if a remote is trusted
     */
    function isTrustedRemote(
        uint256 chainId,
        address remote
    ) external view returns (bool) {
        return trustedRemotes[chainId] == remote;
    }

    /**
     * @notice Compute message ID
     */
    function computeMessageId(
        uint256 sourceChainId,
        uint256 targetChainId,
        address sender,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    sourceChainId,
                    targetChainId,
                    sender,
                    target,
                    value,
                    keccak256(data),
                    nonce,
                    timestamp
                )
            );
    }

    /**
     * @notice Get batch details
     */
    function getBatch(
        bytes32 batchId
    ) external view returns (MessageBatch memory) {
        return messageBatches[batchId];
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
