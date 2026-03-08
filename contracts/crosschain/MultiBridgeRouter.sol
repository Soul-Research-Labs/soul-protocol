// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBridgeAdapter.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SimpleMultiBridgeRouter
 * @notice Simplified N-of-M bridge router for basic multi-bridge verification
 * @custom:deprecated Use contracts/bridge/MultiBridgeRouter.sol instead. This simplified N-of-M
 *                    router lacks Pausable, health monitoring, value-based routing, and fallback
 *                    cascade features present in the canonical bridge/MultiBridgeRouter. This
 *                    contract will be removed in v2.0.
 */
contract SimpleMultiBridgeRouter is AccessControl, ReentrancyGuard {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ADAPTER_ROLE = keccak256("ADAPTER_ROLE");

    struct MessageStatus {
        uint256 confirmations;
        bool executed;
        mapping(address => bool) hasConfirmed; // Adapter => Confirmed
    }

    // Config
    uint256 public requiredConfirmations; // N
    address[] public activeAdapters; // M

    // State
    mapping(bytes32 => MessageStatus) public messages;
    uint256 public nonce;

    event MessageSent(
        bytes32 indexed messageId,
        bytes32 payloadHash,
        uint256 adaptersUsed
    );
    event ConfirmationReceived(bytes32 indexed messageId, address adapter);
    event MessageExecuted(bytes32 indexed messageId, address target);
    event AdapterSendFailed(address indexed adapter, string reason);

    error InsufficientAdapters(uint256 available, uint256 required);
    error InsufficientConfirmations(uint256 succeeded, uint256 required);
    error AlreadyConfirmed(bytes32 messageId, address adapter);
    error ExecutionFailed(bytes32 messageId);
    error InvalidConfirmationThreshold(uint256 n, uint256 adapterCount);

    /// @notice Initializes the router with N-of-M confirmation threshold
    /// @param _admin Address to receive admin roles
    /// @param _requiredConfirmations Minimum bridge confirmations required (N)
    constructor(address _admin, uint256 _requiredConfirmations) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        requiredConfirmations = _requiredConfirmations;
    }

    /**
     * @notice Add a bridge adapter
     * @param _adapter The _adapter
     */
    function addAdapter(address _adapter) external onlyRole(ADMIN_ROLE) {
        _grantRole(ADAPTER_ROLE, _adapter);
        activeAdapters.push(_adapter);
    }

    /**
     * @notice Send a message via all active adapters
     * @param target The target
     * @param payload The message payload
     * @param refundAddress The refundAddress address
     * @return messageId The message id
     */
    function sendMultiBridgeMessage(
        address target,
        bytes calldata payload,
        address refundAddress
    ) external payable nonReentrant returns (bytes32 messageId) {
        if (activeAdapters.length < requiredConfirmations) {
            revert InsufficientAdapters(
                activeAdapters.length,
                requiredConfirmations
            );
        }

        // Generate unique ID
        messageId = keccak256(
            abi.encodePacked(target, payload, nonce++, block.chainid)
        );

        // Wrap payload with ID
        bytes memory wrappedPayload = abi.encode(messageId, payload);

        uint256 valuePerAdapter = msg.value / activeAdapters.length;
        uint256 successCount;
        uint256 unusedValue;

        for (uint256 i = 0; i < activeAdapters.length; i++) {
            try
                IBridgeAdapter(activeAdapters[i]).bridgeMessage{
                    value: valuePerAdapter
                }(address(this), wrappedPayload, refundAddress)
            returns (bytes32) {
                successCount++;
            } catch Error(string memory reason) {
                emit AdapterSendFailed(activeAdapters[i], reason);
                unusedValue += valuePerAdapter;
            } catch {
                emit AdapterSendFailed(activeAdapters[i], "Unknown error");
                unusedValue += valuePerAdapter;
            }
        }

        if (successCount < requiredConfirmations) {
            revert InsufficientConfirmations(
                successCount,
                requiredConfirmations
            );
        }

        // Refund unused ETH from failed adapters
        if (unusedValue > 0 && refundAddress != address(0)) {
            (bool refunded, ) = refundAddress.call{value: unusedValue}("");
            // Silently ignore refund failure — dust stays in router
            if (!refunded) {
                // no-op: ETH remains in router for admin recovery
            }
        }

        emit MessageSent(messageId, keccak256(payload), successCount);
    }

    /**
     * @notice Receive a message from an adapter
     * @dev Wrapper function that decodes valid MultiBridge payloads
     * @param wrappedPayload The wrapped payload
     */
    function receiveBridgeMessage(
        bytes calldata wrappedPayload
    ) external onlyRole(ADAPTER_ROLE) nonReentrant {
        (bytes32 messageId, bytes memory payload) = abi.decode(
            wrappedPayload,
            (bytes32, bytes)
        );

        MessageStatus storage status = messages[messageId];

        // If already executed, ignore? Or just return?
        if (status.executed) return;

        if (status.hasConfirmed[msg.sender])
            revert AlreadyConfirmed(messageId, msg.sender);

        status.hasConfirmed[msg.sender] = true;
        status.confirmations++;

        emit ConfirmationReceived(messageId, msg.sender);

        if (status.confirmations >= requiredConfirmations) {
            _execute(messageId, payload);
        }
    }

    function _execute(bytes32 messageId, bytes memory payload) internal {
        messages[messageId].executed = true;

        (address target, bytes memory data) = abi.decode(
            payload,
            (address, bytes)
        );

        (bool success, ) = target.call(data);
        if (!success) revert ExecutionFailed(messageId);

        emit MessageExecuted(messageId, target);
    }

    /**
     * @notice Set required confirmations (N)
     * @param _n The _n
     */
    function setRequiredConfirmations(
        uint256 _n
    ) external onlyRole(ADMIN_ROLE) {
        if (_n == 0 || _n > activeAdapters.length) {
            revert InvalidConfirmationThreshold(_n, activeAdapters.length);
        }
        requiredConfirmations = _n;
    }
}
