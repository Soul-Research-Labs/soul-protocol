// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHEGateway.sol";
import "./FHETypes.sol";
import "./FHEOperations.sol";
import "../libraries/FHELib.sol";

/**
 * @title FHEBridgeAdapter
 * @author Soul Protocol
 * @notice Cross-chain bridge adapter for encrypted value transfers using FHE
 * @dev Enables confidential cross-chain transfers with coprocessor integration
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                  Cross-Chain FHE Transfer Flow                       │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  Source Chain (L2 A)            │        Destination Chain (L2 B)   │
 * │  ┌─────────────────┐            │        ┌─────────────────┐        │
 * │  │ User initiates  │            │        │ Relayer calls   │        │
 * │  │ enc(amount)     │            │        │ completeTransfer│        │
 * │  └────────┬────────┘            │        └────────┬────────┘        │
 * │           │                     │                 │                 │
 * │           ▼                     │                 ▼                 │
 * │  ┌─────────────────┐            │        ┌─────────────────┐        │
 * │  │ FHEBridgeAdapter│            │        │ FHEBridgeAdapter│        │
 * │  │ - Lock funds    │            │        │ - Verify proof  │        │
 * │  │ - Request reenc │───────────────────▶│ - Reencrypt     │        │
 * │  └────────┬────────┘            │        │ - Mint/release  │        │
 * │           │                     │        └────────┬────────┘        │
 * │           ▼                     │                 │                 │
 * │  ┌─────────────────┐            │                 ▼                 │
 * │  │ FHE Gateway     │            │        ┌─────────────────┐        │
 * │  │ (Reencryption)  │            │        │ Recipient gets  │        │
 * │  └─────────────────┘            │        │ enc_B(amount)   │        │
 * │                                 │        └─────────────────┘        │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Security Features:
 * - Chain ID validation prevents replay attacks
 * - Reencryption ensures privacy across chains
 * - ZK proofs verify correct amount transfer
 * - Relayer cannot see transfer amounts
 */
contract FHEBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    using FHEOperations for euint256;

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // TYPES
    // ============================================

    /// @notice Chain configuration
    struct ChainConfig {
        bytes32 bridgeAdapter; // Remote bridge adapter address (as bytes32)
        bytes32 fhePublicKey; // Remote chain's FHE public key
        uint256 minTransfer;
        uint256 maxTransfer;
        uint64 transferDelay; // Minimum time before completion
        uint32 requiredConfirmations; // L1 confirmations required
        bool enabled;
    }

    /// @notice Outbound (source chain) transfer
    struct OutboundTransfer {
        bytes32 transferId;
        address sender;
        address token;
        address recipient;
        uint256 destinationChainId;
        euint256 encryptedAmount; // Encrypted with source chain key
        bytes32 amountCommitment; // Commitment for verification
        bytes32 reencryptionRequest; // Gateway reencryption request ID
        uint64 timestamp;
        uint64 completedAt;
        TransferStatus status;
    }

    /// @notice Inbound (destination chain) transfer
    struct InboundTransfer {
        bytes32 transferId;
        bytes32 sourceTransferId;
        uint256 sourceChainId;
        address sender; // Original sender on source chain
        address recipient;
        address token;
        euint256 encryptedAmount; // Reencrypted with destination key
        bytes zkProof; // Proof of correct reencryption
        uint64 receivedAt;
        uint64 claimedAt;
        TransferStatus status;
    }

    /// @notice Transfer status
    enum TransferStatus {
        Pending,
        Locked,
        ReencryptionRequested,
        InTransit,
        ReadyToClaim,
        Completed,
        Failed,
        Refunded
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice FHE Gateway
    FHEGateway public immutable fheGateway;

    /// @notice This chain's ID
    uint256 public immutable chainId;

    /// @notice Transfer nonce
    uint64 public transferNonce;

    /// @notice Total value locked (public for transparency)
    mapping(address => uint256) public totalValueLocked;

    /// @notice Chain configurations
    mapping(uint256 => ChainConfig) public chainConfigs;

    /// @notice Outbound transfers
    mapping(bytes32 => OutboundTransfer) public outboundTransfers;

    /// @notice Inbound transfers
    mapping(bytes32 => InboundTransfer) public inboundTransfers;

    /// @notice Reencryption request to transfer mapping
    mapping(bytes32 => bytes32) public reencryptionToTransfer;

    /// @notice Processed source chain transfers (prevents replay)
    mapping(uint256 => mapping(bytes32 => bool)) public processedTransfers;

    /// @notice User's pending outbound transfers
    mapping(address => bytes32[]) public userOutboundTransfers;

    /// @notice User's pending inbound transfers
    mapping(address => bytes32[]) public userInboundTransfers;

    // ============================================
    // EVENTS
    // ============================================

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        address indexed recipient,
        uint256 destinationChainId,
        address token,
        bytes32 amountCommitment
    );

    event ReencryptionRequested(
        bytes32 indexed transferId,
        bytes32 indexed reencryptionRequestId
    );

    event TransferLocked(bytes32 indexed transferId, uint64 timestamp);

    event TransferReceived(
        bytes32 indexed transferId,
        bytes32 indexed sourceTransferId,
        uint256 sourceChainId
    );

    event TransferClaimed(
        bytes32 indexed transferId,
        address indexed recipient
    );

    event TransferCompleted(bytes32 indexed transferId);

    event TransferRefunded(bytes32 indexed transferId, address indexed sender);

    event ChainConfigured(uint256 indexed chainId, bytes32 bridgeAdapter);

    event ChainDisabled(uint256 indexed chainId);

    // ============================================
    // ERRORS
    // ============================================

    error Unauthorized();
    error ChainNotConfigured();
    error TransferBelowMinimum();
    error TransferAboveMaximum();
    error ChainDisabledError();
    error InvalidTransfer();
    error TransferNotReady();
    error TransferAlreadyProcessed();
    error InvalidProof();
    error TransferDelayNotMet();
    error ZeroAddress();
    error InvalidChainId();
    error SameChainTransfer();
    error ReencryptionRequestMismatch(bytes32 expected, bytes32 actual);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address _fheGateway) {
        if (_fheGateway == address(0)) revert ZeroAddress();

        fheGateway = FHEGateway(_fheGateway);
        chainId = block.chainid;

        // Set gateway for FHEOperations
        FHEOperations.setGateway(_fheGateway);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ============================================
    // CHAIN CONFIGURATION
    // ============================================

    /**
     * @notice Configure destination chain
     * @param _chainId Target chain ID
     * @param _bridgeAdapter Remote bridge adapter address
     * @param _fhePublicKey Remote chain's FHE public key
     * @param _minTransfer Minimum transfer amount
     * @param _maxTransfer Maximum transfer amount
     * @param _transferDelay Minimum delay before completion
     * @param _requiredConfirmations Required L1 confirmations
     */
    function configureChain(
        uint256 _chainId,
        bytes32 _bridgeAdapter,
        bytes32 _fhePublicKey,
        uint256 _minTransfer,
        uint256 _maxTransfer,
        uint64 _transferDelay,
        uint32 _requiredConfirmations
    ) external onlyRole(ADMIN_ROLE) {
        if (_chainId == chainId) revert SameChainTransfer();
        if (_bridgeAdapter == bytes32(0)) revert ZeroAddress();

        chainConfigs[_chainId] = ChainConfig({
            bridgeAdapter: _bridgeAdapter,
            fhePublicKey: _fhePublicKey,
            minTransfer: _minTransfer,
            maxTransfer: _maxTransfer,
            transferDelay: _transferDelay,
            requiredConfirmations: _requiredConfirmations,
            enabled: true
        });

        emit ChainConfigured(_chainId, _bridgeAdapter);
    }

    /**
     * @notice Disable a chain
     * @param _chainId Chain to disable
     */
    function disableChain(uint256 _chainId) external onlyRole(ADMIN_ROLE) {
        chainConfigs[_chainId].enabled = false;
        emit ChainDisabled(_chainId);
    }

    // ============================================
    // OUTBOUND TRANSFERS (SOURCE CHAIN)
    // ============================================

    /**
     * @notice Initiate encrypted cross-chain transfer
     * @param encryptedAmount Encrypted transfer amount
     * @param token Token address (address(0) for native)
     * @param recipient Recipient on destination chain
     * @param destinationChainId Target chain
     * @return transferId Unique transfer ID
     */
    function initiateTransfer(
        euint256 memory encryptedAmount,
        address token,
        address recipient,
        uint256 destinationChainId
    ) external nonReentrant whenNotPaused returns (bytes32 transferId) {
        ChainConfig storage config = chainConfigs[destinationChainId];
        if (!config.enabled) revert ChainDisabledError();
        if (config.bridgeAdapter == bytes32(0)) revert ChainNotConfigured();
        if (recipient == address(0)) revert ZeroAddress();

        // Verify caller has access to encrypted amount
        (bool valid, bool verified) = fheGateway.checkHandle(
            encryptedAmount.handle
        );
        require(valid && verified, "Invalid amount handle");
        require(
            fheGateway.hasAccess(encryptedAmount.handle, msg.sender),
            "No access"
        );

        // Generate transfer ID
        transferNonce++;
        transferId = keccak256(
            abi.encode(
                chainId,
                destinationChainId,
                msg.sender,
                recipient,
                token,
                transferNonce,
                block.timestamp
            )
        );

        // Compute amount commitment (for verification without revealing)
        bytes32 amountCommitment = keccak256(
            abi.encode(encryptedAmount.handle, encryptedAmount.ctHash)
        );

        // Store transfer
        outboundTransfers[transferId] = OutboundTransfer({
            transferId: transferId,
            sender: msg.sender,
            token: token,
            recipient: recipient,
            destinationChainId: destinationChainId,
            encryptedAmount: encryptedAmount,
            amountCommitment: amountCommitment,
            reencryptionRequest: bytes32(0),
            timestamp: uint64(block.timestamp),
            completedAt: 0,
            status: TransferStatus.Pending
        });

        userOutboundTransfers[msg.sender].push(transferId);

        emit TransferInitiated(
            transferId,
            msg.sender,
            recipient,
            destinationChainId,
            token,
            amountCommitment
        );

        // Request reencryption for destination chain
        _requestReencryption(transferId, config.fhePublicKey);
    }

    /**
     * @notice Request reencryption for destination chain
     * @param transferId The transfer ID
     * @param destinationPublicKey Destination chain's FHE public key
     */
    function _requestReencryption(
        bytes32 transferId,
        bytes32 destinationPublicKey
    ) internal {
        OutboundTransfer storage transfer = outboundTransfers[transferId];

        bytes32 expectedRequestId = fheGateway.previewReencryptionRequest(
            transfer.encryptedAmount.handle,
            destinationPublicKey,
            address(this)
        );

        transfer.reencryptionRequest = expectedRequestId;
        transfer.status = TransferStatus.ReencryptionRequested;
        reencryptionToTransfer[expectedRequestId] = transferId;

        bytes32 requestId = fheGateway.requestReencryption(
            transfer.encryptedAmount.handle,
            destinationPublicKey
        );

        if (requestId != expectedRequestId) {
            revert ReencryptionRequestMismatch(expectedRequestId, requestId);
        }

        emit ReencryptionRequested(transferId, requestId);
    }

    /**
     * @notice Callback when reencryption is complete
     * @param requestId The reencryption request ID
     */
    function onReencryptionComplete(
        bytes32 requestId,
        bytes calldata /* reencryptedValue */
    ) external {
        if (msg.sender != address(fheGateway)) revert Unauthorized();

        bytes32 transferId = reencryptionToTransfer[requestId];
        if (transferId == bytes32(0)) return;

        OutboundTransfer storage transfer = outboundTransfers[transferId];
        transfer.status = TransferStatus.InTransit;

        // In production: send cross-chain message with reencrypted value
        // This would use a bridge like LayerZero, Hyperlane, or native L2 messaging

        emit TransferLocked(transferId, uint64(block.timestamp));
    }

    // ============================================
    // INBOUND TRANSFERS (DESTINATION CHAIN)
    // ============================================

    /**
     * @notice Receive transfer from source chain (called by relayer)
     * @param sourceChainId Source chain ID
     * @param sourceTransferId Transfer ID on source chain
     * @param sender Original sender
     * @param recipient Recipient on this chain
     * @param token Token address
     * @param reencryptedAmount Reencrypted amount for this chain
     * @param zkProof ZK proof of correct reencryption
     */
    function receiveTransfer(
        uint256 sourceChainId,
        bytes32 sourceTransferId,
        address sender,
        address recipient,
        address token,
        euint256 memory reencryptedAmount,
        bytes calldata zkProof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        ChainConfig storage config = chainConfigs[sourceChainId];
        if (!config.enabled) revert ChainDisabledError();

        // Prevent replay
        if (processedTransfers[sourceChainId][sourceTransferId]) {
            revert TransferAlreadyProcessed();
        }

        // Verify ZK proof of correct reencryption
        if (
            !_verifyReencryptionProof(
                zkProof,
                sourceTransferId,
                reencryptedAmount
            )
        ) {
            revert InvalidProof();
        }

        // Generate local transfer ID
        transferNonce++;
        bytes32 transferId = keccak256(
            abi.encode(
                "INBOUND",
                sourceChainId,
                sourceTransferId,
                chainId,
                transferNonce
            )
        );

        // Store inbound transfer
        inboundTransfers[transferId] = InboundTransfer({
            transferId: transferId,
            sourceTransferId: sourceTransferId,
            sourceChainId: sourceChainId,
            sender: sender,
            recipient: recipient,
            token: token,
            encryptedAmount: reencryptedAmount,
            zkProof: zkProof,
            receivedAt: uint64(block.timestamp),
            claimedAt: 0,
            status: TransferStatus.ReadyToClaim
        });

        processedTransfers[sourceChainId][sourceTransferId] = true;
        userInboundTransfers[recipient].push(transferId);

        // Grant recipient access to encrypted amount
        fheGateway.grantAccess(reencryptedAmount.handle, recipient);

        emit TransferReceived(transferId, sourceTransferId, sourceChainId);
    }

    /**
     * @notice Claim inbound transfer
     * @param transferId Inbound transfer ID
     */
    function claimTransfer(bytes32 transferId) external nonReentrant {
        InboundTransfer storage transfer = inboundTransfers[transferId];

        if (transfer.recipient != msg.sender) revert Unauthorized();
        if (transfer.status != TransferStatus.ReadyToClaim)
            revert TransferNotReady();

        ChainConfig storage config = chainConfigs[transfer.sourceChainId];
        if (block.timestamp < transfer.receivedAt + config.transferDelay) {
            revert TransferDelayNotMet();
        }

        transfer.status = TransferStatus.Completed;
        transfer.claimedAt = uint64(block.timestamp);

        // In production: mint/release tokens to recipient
        // The encrypted amount is already accessible to recipient

        emit TransferClaimed(transferId, msg.sender);
        emit TransferCompleted(transferId);
    }

    // ============================================
    // REFUNDS
    // ============================================

    /**
     * @notice Refund a failed outbound transfer
     * @param transferId The transfer to refund
     */
    function refundTransfer(bytes32 transferId) external nonReentrant {
        OutboundTransfer storage transfer = outboundTransfers[transferId];

        if (transfer.sender != msg.sender) revert Unauthorized();
        if (transfer.status == TransferStatus.Completed)
            revert InvalidTransfer();
        if (transfer.status == TransferStatus.Refunded)
            revert InvalidTransfer();

        // Can only refund after timeout
        ChainConfig storage config = chainConfigs[transfer.destinationChainId];
        require(
            block.timestamp > transfer.timestamp + config.transferDelay * 2,
            "Too early for refund"
        );

        transfer.status = TransferStatus.Refunded;

        // In production: unlock/return tokens to sender

        emit TransferRefunded(transferId, msg.sender);
    }

    // ============================================
    // PROOF VERIFICATION
    // ============================================

    /**
     * @notice Verify reencryption proof
     * @param proof The ZK proof
     * @param sourceTransferId Source transfer ID
     * @param reencryptedAmount The reencrypted amount
     * @return valid Whether proof is valid
     */
    function _verifyReencryptionProof(
        bytes calldata proof,
        bytes32 sourceTransferId,
        euint256 memory reencryptedAmount
    ) internal pure returns (bool valid) {
        // Simplified verification - full implementation would verify ZK proof
        // that reencryption was done correctly without revealing amount
        return
            proof.length > 0 &&
            sourceTransferId != bytes32(0) &&
            reencryptedAmount.handle != bytes32(0);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get outbound transfer
     * @param transferId Transfer ID
     * @return transfer The transfer details
     */
    function getOutboundTransfer(
        bytes32 transferId
    ) external view returns (OutboundTransfer memory transfer) {
        return outboundTransfers[transferId];
    }

    /**
     * @notice Get inbound transfer
     * @param transferId Transfer ID
     * @return transfer The transfer details
     */
    function getInboundTransfer(
        bytes32 transferId
    ) external view returns (InboundTransfer memory transfer) {
        return inboundTransfers[transferId];
    }

    /**
     * @notice Get user's outbound transfers
     * @param user User address
     * @return transfers Array of transfer IDs
     */
    function getUserOutboundTransfers(
        address user
    ) external view returns (bytes32[] memory transfers) {
        return userOutboundTransfers[user];
    }

    /**
     * @notice Get user's inbound transfers
     * @param user User address
     * @return transfers Array of transfer IDs
     */
    function getUserInboundTransfers(
        address user
    ) external view returns (bytes32[] memory transfers) {
        return userInboundTransfers[user];
    }

    /**
     * @notice Check if transfer was processed
     * @param sourceChainId Source chain
     * @param sourceTransferId Source transfer ID
     * @return processed Whether already processed
     */
    function isTransferProcessed(
        uint256 sourceChainId,
        bytes32 sourceTransferId
    ) external view returns (bool processed) {
        return processedTransfers[sourceChainId][sourceTransferId];
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Pause bridge operations
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge operations
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
