// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BridgeAdapterBase} from "../crosschain/base/BridgeAdapterBase.sol";

/**
 * @title NativeL2BridgeWrapper
 * @author ZASEON
 * @notice Unified `IBridgeAdapter` wrapper for native L2 bridges (Arbitrum, Optimism, Base, and
 *         any OP-Stack / Arbitrum-compatible messenger). One deployment per destination L2.
 * @dev Migrated to inherit from {BridgeAdapterBase}, eliminating ~120 LOC of boilerplate
 *      (roles, pause, reentrancy, payload bounds, refund, message-id derivation, event).
 *      Only the chain-specific dispatch logic remains in this file as the three
 *      `_deliver` / `_estimateFee` / `_verifyMessage` hooks.
 *
 *      Breaking-change notes relative to pre-migration (no tests depend on these):
 *        - `ADMIN_ROLE` is now `DEFAULT_ADMIN_ROLE` (from base).
 *        - `MessageSent` event replaced by the base's canonical `MessageBridged`.
 *        - `bridgeMessage` now enforces the shared 32 KiB payload cap and auto-refunds excess.
 */
contract NativeL2BridgeWrapper is BridgeAdapterBase {
    /// @notice Kind of native L2 bridge this wrapper targets.
    enum BridgeType {
        ARBITRUM_INBOX, // Arbitrum Delayed Inbox
        OP_CROSS_DOMAIN_MESSENGER, // OP Stack CrossDomainMessenger
        CUSTOM // Custom native bridge implementation
    }

    /// @notice Underlying native bridge contract address.
    address public nativeBridge;

    /// @notice Kind of native bridge.
    BridgeType public bridgeType;

    /// @notice Gas limit for cross-chain execution on the destination.
    uint256 public gasLimit;

    /// @notice Arbitrum max submission cost for retryable tickets.
    uint256 public maxSubmissionCost;

    /// @notice Arbitrum max fee-per-gas for L2 execution.
    uint256 public maxFeePerGas;

    /// @notice Messages that have been marked verified by the receive handler.
    mapping(bytes32 => bool) public verifiedMessages;

    event MessageVerified(bytes32 indexed messageId);
    event NativeBridgeUpdated(
        address indexed oldBridge,
        address indexed newBridge
    );
    event GasLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event ArbitrumParamsUpdated(
        uint256 maxSubmissionCost,
        uint256 maxFeePerGas
    );

    error InvalidBridge();
    error BridgeSendFailed();
    error GasLimitExceedsUint32();

    /// @param admin     Account granted DEFAULT_ADMIN_ROLE, OPERATOR_ROLE, EXECUTOR_ROLE, GUARDIAN_ROLE.
    /// @param _nativeBridge Underlying native bridge messenger.
    /// @param _bridgeType   Which messenger pattern to use.
    /// @param _gasLimit     L2 gas limit (defaults to 200_000 if zero).
    constructor(
        address admin,
        address _nativeBridge,
        BridgeType _bridgeType,
        uint256 _gasLimit
    ) BridgeAdapterBase(admin, admin) {
        if (_nativeBridge == address(0)) revert InvalidBridge();
        if (
            _bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER &&
            _gasLimit > type(uint32).max
        ) revert GasLimitExceedsUint32();

        nativeBridge = _nativeBridge;
        bridgeType = _bridgeType;
        gasLimit = _gasLimit > 0 ? _gasLimit : 200_000;
    }

    /*//////////////////////////////////////////////////////////////
                        BridgeAdapterBase HOOKS
    //////////////////////////////////////////////////////////////*/

    function _deliver(
        bytes32 /* messageId */,
        address target,
        bytes calldata payload,
        uint256 nativeFee
    ) internal override {
        bool success;
        if (bridgeType == BridgeType.ARBITRUM_INBOX) {
            uint256 submissionCost = maxSubmissionCost > 0
                ? maxSubmissionCost
                : 0.01 ether;
            (success, ) = nativeBridge.call{value: nativeFee}(
                abi.encodeWithSignature(
                    "createRetryableTicket(address,uint256,uint256,address,address,uint256,uint256,bytes)",
                    target,
                    0,
                    submissionCost,
                    msg.sender,
                    msg.sender,
                    gasLimit,
                    maxFeePerGas,
                    payload
                )
            );
        } else if (bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER) {
            (success, ) = nativeBridge.call{value: nativeFee}(
                abi.encodeWithSignature(
                    "sendMessage(address,bytes,uint32)",
                    target,
                    payload,
                    uint32(gasLimit)
                )
            );
        } else {
            (success, ) = nativeBridge.call{value: nativeFee}(
                abi.encodeWithSignature(
                    "sendMessage(address,bytes)",
                    target,
                    payload
                )
            );
        }
        if (!success) revert BridgeSendFailed();
    }

    function _estimateFee(
        address /* target */,
        bytes calldata /* payload */
    ) internal view override returns (uint256) {
        if (bridgeType == BridgeType.ARBITRUM_INBOX) return 0.005 ether;
        if (bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER)
            return 0.002 ether;
        return 0.01 ether;
    }

    function _verifyMessage(
        bytes32 messageId
    ) internal view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN / OBSERVABILITY
    //////////////////////////////////////////////////////////////*/

    /// @notice Mark a delivered cross-chain message as verified.
    function markVerified(bytes32 messageId) external onlyRole(EXECUTOR_ROLE) {
        verifiedMessages[messageId] = true;
        emit MessageVerified(messageId);
    }

    function setBridge(address _bridge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        emit NativeBridgeUpdated(nativeBridge, _bridge);
        nativeBridge = _bridge;
    }

    function setGasLimit(
        uint256 _gasLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER &&
            _gasLimit > type(uint32).max
        ) revert GasLimitExceedsUint32();
        emit GasLimitUpdated(gasLimit, _gasLimit);
        gasLimit = _gasLimit;
    }

    function setArbitrumParams(
        uint256 _maxSubmissionCost,
        uint256 _maxFeePerGas
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxSubmissionCost = _maxSubmissionCost;
        maxFeePerGas = _maxFeePerGas;
        emit ArbitrumParamsUpdated(_maxSubmissionCost, _maxFeePerGas);
    }
}
