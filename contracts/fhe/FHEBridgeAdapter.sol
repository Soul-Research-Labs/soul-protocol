// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHEGateway.sol";
import "./FHETypes.sol";

/**
 * @title FHEBridgeAdapter
 * @author Soul Protocol
 * @notice Cross-chain bridge adapter for encrypted value transfers using FHE
 * @dev Stub implementation - full FHE bridge requires TFHE library integration
 *
 * NOTE: This is a minimal stub. The full implementation is archived at
 * _archive/contracts_pending/FHEBridgeAdapter.sol pending proper FHE library integration.
 */
contract FHEBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    // FHE Gateway for re-encryption operations
    FHEGateway public fheGateway;

    // Chain configuration
    struct ChainConfig {
        bytes32 bridgeAdapter;
        bytes32 fhePublicKey;
        uint256 minTransfer;
        uint256 maxTransfer;
        uint64 transferDelay;
        bool enabled;
    }

    // Transfer tracking
    struct OutboundTransfer {
        address sender;
        address token;
        uint256 destinationChainId;
        bytes32 encryptedAmount;
        uint64 timestamp;
        bool completed;
    }

    mapping(uint256 => ChainConfig) public chainConfigs;
    mapping(bytes32 => OutboundTransfer) public outboundTransfers;
    /// @dev Maps FHE re-encryption request IDs to transfer IDs.
    /// @notice This mapping is populated when requesting re-encryption from the FHE gateway.
    /// Currently a placeholder for future FHE integration.
    mapping(bytes32 => bytes32) public reencryptionToTransfer;

    uint64 public transferNonce;

    // Errors
    error Unauthorized();
    error ChainNotConfigured();
    error TransferBelowMinimum();
    error TransferAboveMaximum();
    error ChainDisabled();
    error InvalidTransfer();

    // Events
    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        uint256 destinationChainId,
        address token,
        bytes32 encryptedAmount
    );

    event TransferCompleted(bytes32 indexed transferId);
    event ChainConfigured(uint256 indexed chainId);

    constructor(address _fheGateway) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        fheGateway = FHEGateway(_fheGateway);
    }

    /**
     * @notice Configure destination chain
     */
    function configureChain(
        uint256 _chainId,
        bytes32 _bridgeAdapter,
        bytes32 _fhePublicKey,
        uint256 _minTransfer,
        uint256 _maxTransfer,
        uint64 _transferDelay
    ) external onlyRole(ADMIN_ROLE) {
        chainConfigs[_chainId] = ChainConfig({
            bridgeAdapter: _bridgeAdapter,
            fhePublicKey: _fhePublicKey,
            minTransfer: _minTransfer,
            maxTransfer: _maxTransfer,
            transferDelay: _transferDelay,
            enabled: true
        });

        emit ChainConfigured(_chainId);
    }

    /**
     * @notice Initiate encrypted transfer (stub)
     */
    function initiateTransfer(
        bytes32 encryptedAmount,
        address token,
        uint256 destinationChainId
    ) external nonReentrant whenNotPaused returns (bytes32 transferId) {
        ChainConfig storage config = chainConfigs[destinationChainId];
        if (!config.enabled) revert ChainDisabled();
        if (config.bridgeAdapter == bytes32(0)) revert ChainNotConfigured();

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                token,
                destinationChainId,
                encryptedAmount,
                transferNonce++
            )
        );

        outboundTransfers[transferId] = OutboundTransfer({
            sender: msg.sender,
            token: token,
            destinationChainId: destinationChainId,
            encryptedAmount: encryptedAmount,
            timestamp: uint64(block.timestamp),
            completed: false
        });

        emit TransferInitiated(
            transferId,
            msg.sender,
            destinationChainId,
            token,
            encryptedAmount
        );
    }

    /**
     * @notice Complete transfer on destination (called by relayer)
     */
    function completeTransfer(
        bytes32 transferId,
        bytes32 /* proof */
    ) external onlyRole(RELAYER_ROLE) {
        OutboundTransfer storage transfer = outboundTransfers[transferId];
        if (transfer.sender == address(0)) revert InvalidTransfer();
        if (transfer.completed) revert InvalidTransfer();

        transfer.completed = true;
        emit TransferCompleted(transferId);
    }

    /**
     * @notice Re-encryption callback (stub)
     */
    function onReencrypted(
        bytes32 requestId,
        bytes32 /* reencryptedValue */
    ) external view {
        if (msg.sender != address(fheGateway)) revert Unauthorized();

        bytes32 transferId = reencryptionToTransfer[requestId];
        if (transferId == bytes32(0)) return;

        // Would process re-encryption result here
    }

    /**
     * @notice Pause bridge operations
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge operations
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
