// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IRelayerAdapter.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Mock Gelato Interface
interface IGelatoRelay {
    function callWithSyncFee(
        address _target,
        bytes calldata _data,
        address _feeToken
    ) external returns (bytes32);

    function getFeeEstimate(
        address _target,
        bytes calldata _data,
        address _feeToken
    ) external view returns (uint256);
}

/**
 * @title GelatoRelayAdapter
 * @author Soul Protocol
 * @notice Adapter integrating Gelato Relay Network for gasless transaction relaying
 * @dev Wraps the IGelatoRelay interface to provide a unified IRelayerAdapter for the
 *      Soul Protocol relayer infrastructure. Uses callWithSyncFee where the caller
 *      pays in ETH and Gelato deducts the fee from the forwarded value.
 *
 *      This is a simplified integration — production deployments should use
 *      GelatoRelayContext or callWithSyncFeeERC2771 for meta-transaction support.
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract GelatoRelayAdapter is IRelayerAdapter, Ownable {
    /// @notice Address of the Gelato Relay contract (immutable, set at deployment)
    address public immutable GELATO_RELAY;

    /// @notice Sentinel address representing native ETH in Gelato fee payments
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice Thrown when a zero-address is provided for a critical parameter
    error ZeroAddress();

    /// @notice Thrown when the relay target is the zero address
    error InvalidTarget();

    /**
     * @notice Deploy the GelatoRelayAdapter
     * @param _gelatoRelay Address of the Gelato Relay contract
     */
    constructor(address _gelatoRelay) Ownable(msg.sender) {
        if (_gelatoRelay == address(0)) revert ZeroAddress();
        GELATO_RELAY = _gelatoRelay;
    }

    /**
     * @notice Relay a message through Gelato to a target contract
     * @dev Forwards the call to IGelatoRelay.callWithSyncFee, paying with native ETH.
     *      msg.value should cover the Gelato relay fee.
     * @param target The destination contract to call
     * @param payload The calldata to forward to the target
     * @return taskId The Gelato task ID for tracking the relayed transaction
     */
    function relayMessage(
        address target,
        bytes calldata payload,
        uint256 /* gasLimit */
    ) external payable override returns (bytes32) {
        if (target == address(0)) revert InvalidTarget();
        return IGelatoRelay(GELATO_RELAY).callWithSyncFee(target, payload, ETH);
    }

    /**
     * @notice Get the estimated fee for relaying a message
     * @dev Returns a fixed fee estimate. Production implementations should query
     *      Gelato's fee oracle for dynamic pricing based on gas costs.
     * @return fee The estimated relay fee in wei
     */
    function getFee(
        uint256 /* gasLimit */
    ) external pure override returns (uint256) {
        return 0.001 ether;
    }
}
