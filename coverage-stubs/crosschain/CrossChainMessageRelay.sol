// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free CrossChainMessageRelay
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {GasOptimizations} from "../libraries/GasOptimizations.sol";

contract CrossChainMessageRelay is AccessControl, ReentrancyGuard, Pausable {
    using GasOptimizations for *;

    enum MessageStatus {
        UNKNOWN,
        PENDING,
        RELAYED,
        EXECUTED,
        FAILED,
        EXPIRED
    }

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

    struct ExecutionResult {
        bool success;
        bytes returnData;
        uint256 gasUsed;
        uint256 executedAt;
    }
    struct MessageBatch {
        bytes32 batchId;
        bytes32[] messageIds;
        bytes32 merkleRoot;
        uint256 sourceChainId;
        uint256 timestamp;
        bool finalized;
    }

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;
    uint256 public constant ETHEREUM_CHAIN_ID = 1;
    uint256 public constant RETRY_DELAY = 1 hours;
    uint256 public constant MAX_BATCH_SIZE = 50;

    mapping(uint256 => uint256) public outboundNonces;
    mapping(uint256 => uint256) public inboundNonces;
    mapping(bytes32 => MessageStatus) public messageStatus;
    mapping(bytes32 => ExecutionResult) public executionResults;
    mapping(bytes32 => CrossChainMessage) public storedMessages;
    mapping(bytes32 => MessageBatch) public messageBatches;
    mapping(uint256 => address) public trustedRemotes;
    mapping(uint256 => address) public bridgeAdapters;
    uint256 public maxGasLimit;
    uint256 public minGasLimit;
    uint256 public messageExpiry;
    uint256 public totalMessagesSent;
    uint256 public totalMessagesReceived;
    uint256 public totalMessagesExecuted;
    address public zaseonProtocolHub;
    address public bridgeProofValidator;
    address public bridgeWatchtower;
    address public securityOracle;
    address public hybridCryptoVerifier;
    address public crossChainMessageVerifier;

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
    event GasLimitsUpdated(
        uint256 oldMin,
        uint256 newMin,
        uint256 oldMax,
        uint256 newMax
    );
    event MessageExpiryUpdated(uint256 oldExpiry, uint256 newExpiry);

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

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
        maxGasLimit = 5000000;
        minGasLimit = 21000;
        messageExpiry = 7 days;
    }

    function sendMessage(
        uint256 targetChainId,
        address target,
        bytes calldata data,
        uint256 gasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (targetChainId == 0) revert InvalidChainId(targetChainId);
        uint256 nonce = outboundNonces[targetChainId]++;
        messageId = keccak256(
            abi.encodePacked(block.chainid, targetChainId, nonce, msg.sender)
        );
        storedMessages[messageId] = CrossChainMessage(
            messageId,
            block.chainid,
            targetChainId,
            msg.sender,
            target,
            msg.value,
            gasLimit,
            data,
            nonce,
            block.timestamp,
            block.timestamp + messageExpiry
        );
        messageStatus[messageId] = MessageStatus.PENDING;
        totalMessagesSent++;
        emit MessageSent(
            messageId,
            targetChainId,
            msg.sender,
            target,
            msg.value,
            data
        );
    }

    function sendMessageWithValue(
        uint256 targetChainId,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 gasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (targetChainId == 0) revert InvalidChainId(targetChainId);
        uint256 nonce = outboundNonces[targetChainId]++;
        messageId = keccak256(
            abi.encodePacked(block.chainid, targetChainId, nonce, msg.sender)
        );
        storedMessages[messageId] = CrossChainMessage(
            messageId,
            block.chainid,
            targetChainId,
            msg.sender,
            target,
            value,
            gasLimit,
            data,
            nonce,
            block.timestamp,
            block.timestamp + messageExpiry
        );
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
    }

    function receiveMessage(
        CrossChainMessage calldata message,
        bytes calldata
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        if (messageStatus[message.messageId] != MessageStatus.UNKNOWN)
            revert MessageAlreadyProcessed(message.messageId);
        storedMessages[message.messageId] = message;
        messageStatus[message.messageId] = MessageStatus.RELAYED;
        totalMessagesReceived++;
        emit MessageReceived(
            message.messageId,
            message.sourceChainId,
            message.sender,
            message.target
        );
    }

    function retryMessage(bytes32 messageId) external {
        if (messageStatus[messageId] == MessageStatus.UNKNOWN)
            revert MessageNotFound(messageId);
        emit MessageRetried(messageId, 1);
    }

    function receiveBatch(
        bytes32[] calldata messageIds,
        bytes32 merkleRoot,
        uint256 sourceChainId,
        CrossChainMessage[] calldata messages_,
        bytes[] calldata /* proofs */
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        if (messages_.length > MAX_BATCH_SIZE)
            revert BatchTooLarge(messages_.length, MAX_BATCH_SIZE);
        bytes32 batchId = keccak256(
            abi.encodePacked(merkleRoot, block.timestamp)
        );
        for (uint256 i = 0; i < messages_.length; i++) {
            storedMessages[messages_[i].messageId] = messages_[i];
            messageStatus[messages_[i].messageId] = MessageStatus.RELAYED;
            totalMessagesReceived++;
        }
        messageBatches[batchId].batchId = batchId;
        messageBatches[batchId].messageIds = messageIds;
        messageBatches[batchId].merkleRoot = merkleRoot;
        messageBatches[batchId].sourceChainId = sourceChainId;
        messageBatches[batchId].timestamp = block.timestamp;
        emit BatchCreated(batchId, sourceChainId, messages_.length);
    }

    function executeBatch(bytes32 batchId) external nonReentrant {
        MessageBatch storage batch = messageBatches[batchId];
        for (uint256 i = 0; i < batch.messageIds.length; i++) {
            bytes32 mid = batch.messageIds[i];
            CrossChainMessage storage m = storedMessages[mid];
            (bool ok, bytes memory ret) = m.target.call{gas: m.gasLimit}(
                m.data
            );
            messageStatus[mid] = ok
                ? MessageStatus.EXECUTED
                : MessageStatus.FAILED;
            executionResults[mid] = ExecutionResult(
                ok,
                ret,
                m.gasLimit,
                block.timestamp
            );
            totalMessagesExecuted++;
            emit MessageExecuted(mid, ok, ret, m.gasLimit);
        }
        batch.finalized = true;
    }

    function setTrustedRemote(
        uint256 chainId,
        address remote
    ) external onlyRole(OPERATOR_ROLE) {
        trustedRemotes[chainId] = remote;
        emit TrustedRemoteSet(chainId, remote);
    }

    function setBridgeAdapter(
        uint256 chainId,
        address adapter
    ) external onlyRole(OPERATOR_ROLE) {
        bridgeAdapters[chainId] = adapter;
        emit BridgeAdapterSet(chainId, adapter);
    }

    function setGasLimits(
        uint256 _minGasLimit,
        uint256 _maxGasLimit
    ) external onlyRole(OPERATOR_ROLE) {
        emit GasLimitsUpdated(
            minGasLimit,
            _minGasLimit,
            maxGasLimit,
            _maxGasLimit
        );
        minGasLimit = _minGasLimit;
        maxGasLimit = _maxGasLimit;
    }

    function setMessageExpiry(
        uint256 _expiry
    ) external onlyRole(OPERATOR_ROLE) {
        emit MessageExpiryUpdated(messageExpiry, _expiry);
        messageExpiry = _expiry;
    }

    function setZaseonProtocolHub(address _hub) external onlyRole(OPERATOR_ROLE) {
        zaseonProtocolHub = _hub;
    }

    function setBridgeProofValidator(
        address _validator
    ) external onlyRole(OPERATOR_ROLE) {
        bridgeProofValidator = _validator;
    }

    function setBridgeWatchtower(
        address _watchtower
    ) external onlyRole(OPERATOR_ROLE) {
        bridgeWatchtower = _watchtower;
    }

    function setSecurityOracle(
        address _oracle
    ) external onlyRole(OPERATOR_ROLE) {
        securityOracle = _oracle;
    }

    function setHybridCryptoVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        hybridCryptoVerifier = _verifier;
    }

    function setCrossChainMessageVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        crossChainMessageVerifier = _verifier;
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function getMessage(
        bytes32 messageId
    ) external view returns (CrossChainMessage memory) {
        return storedMessages[messageId];
    }

    function getExecutionResult(
        bytes32 messageId
    ) external view returns (ExecutionResult memory) {
        return executionResults[messageId];
    }

    function isTrustedRemote(
        uint256 chainId,
        address remote
    ) external view returns (bool) {
        return trustedRemotes[chainId] == remote;
    }

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
                    nonce,
                    sender,
                    target,
                    value,
                    data,
                    timestamp
                )
            );
    }

    function getBatch(
        bytes32 batchId
    ) external view returns (MessageBatch memory) {
        return messageBatches[batchId];
    }
}
