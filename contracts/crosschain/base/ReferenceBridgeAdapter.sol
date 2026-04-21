// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BridgeAdapterBase} from "./BridgeAdapterBase.sol";

/**
 * @title ReferenceBridgeAdapter
 * @notice Minimal reference implementation of {BridgeAdapterBase}.
 * @dev Serves as a migration template for the 12 production adapters
 *      (Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Aztec,
 *      LayerZero, Hyperlane, BitVM, EthereumL1, Native). Each production
 *      adapter should subclass {BridgeAdapterBase} and override only:
 *         - {_deliver}       — wire to the chain-specific messenger
 *         - {_estimateFee}   — return messenger's fee for the payload
 *         - {_verifyMessage} — check destination-chain finality
 *
 *      This reference uses an in-contract queue (no external messenger) so it
 *      is exercisable in unit tests without any forked-network fixtures.
 *      It MUST NOT be deployed to production — it finalizes messages
 *      immediately on `confirmDelivery`, which has no security guarantees.
 */
contract ReferenceBridgeAdapter is BridgeAdapterBase {
    /// @notice Flat fee charged per message (settable by admin).
    uint256 public flatFeeWei;

    /// @notice Tracks which dispatched messages the operator has confirmed.
    mapping(bytes32 => bool) public delivered;

    /// @notice Queue of dispatched-but-unconfirmed message ids for observability.
    bytes32[] public queue;

    event FlatFeeUpdated(uint256 oldFee, uint256 newFee);
    event DeliveryConfirmed(bytes32 indexed messageId);

    constructor(
        address admin,
        address guardian,
        uint256 _flatFeeWei
    ) BridgeAdapterBase(admin, guardian) {
        flatFeeWei = _flatFeeWei;
    }

    /// @notice Admin-settable flat fee for deterministic tests.
    function setFlatFee(uint256 newFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit FlatFeeUpdated(flatFeeWei, newFee);
        flatFeeWei = newFee;
    }

    /// @notice Operator confirms off-chain delivery to mark `messageId` verified.
    function confirmDelivery(
        bytes32 messageId
    ) external onlyRole(EXECUTOR_ROLE) {
        delivered[messageId] = true;
        emit DeliveryConfirmed(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                          BridgeAdapterBase HOOKS
    //////////////////////////////////////////////////////////////*/

    function _deliver(
        bytes32 messageId,
        address /* target */,
        bytes calldata /* payload */,
        uint256 /* nativeFee */
    ) internal override {
        queue.push(messageId);
    }

    function _estimateFee(
        address /* target */,
        bytes calldata /* payload */
    ) internal view override returns (uint256) {
        return flatFeeWei;
    }

    function _verifyMessage(
        bytes32 messageId
    ) internal view override returns (bool) {
        return delivered[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                          INTROSPECTION
    //////////////////////////////////////////////////////////////*/

    function queueLength() external view returns (uint256) {
        return queue.length;
    }
}
