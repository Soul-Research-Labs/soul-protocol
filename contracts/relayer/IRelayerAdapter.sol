// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IRelayerAdapter
 * @notice Standard interface for relayer services (e.g. Gelato, native relayer)
 */
interface IRelayerAdapter {
    function relayMessage(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable returns (bytes32 taskId);

    function getFee(
        uint256 gasLimit
    ) external view returns (uint256 fee);
}
