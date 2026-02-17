// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title SoulGovernance
 * @notice Governance contract for Soul Protocol based on TimelockController.
 * @dev Acts as the ultimate owner of the protocol.
 *      - Proposers can schedule transactions.
 *      - Executors can execute transactions after delay.
 *      - Admin can manage roles.
 */
contract SoulGovernance is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {}

    /**
     * @notice Update the minimum delay
     * @param newDelay The new minimum delay in seconds
     */
}
