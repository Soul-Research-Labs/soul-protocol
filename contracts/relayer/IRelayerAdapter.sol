// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IRelayerAdapter
 * @notice Standard interface for relayer services (e.g. Gelato, native relayer)
 */
interface IRelayerAdapter {
    /// @notice Relay a message to a target contract
    /// @param target The destination contract to call
    /// @param payload The calldata to forward to the target
    /// @param gasLimit The gas limit for the relay execution
    /// @return taskId Unique identifier for tracking the relayed transaction
    function relayMessage(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable returns (bytes32 taskId);

    /// @notice Get the estimated fee for relaying a message
    /// @param gasLimit The gas limit to estimate the fee for
    /// @return fee The estimated relay fee in wei
    function getFee(uint256 gasLimit) external view returns (uint256 fee);
}
