// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title ZaseonGovernance
 * @notice Governance contract for ZASEON based on TimelockController.
 * @dev Acts as the ultimate owner of the protocol.
 *      - Proposers can schedule transactions.
 *      - Executors can execute transactions after delay.
 *      - Admin can manage roles.
 * @custom:deprecated Use ZaseonGovernor.sol instead. ZaseonGovernor provides full OZ Governor
 *                    functionality (voting, quorum, proposal lifecycle) while this contract
 *                    is only a thin TimelockController wrapper. This contract will be
 *                    removed in v2.0.
 */
contract ZaseonGovernance is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {}

    /**
     * @notice Update the minimum delay for timelock execution
     * @param newDelay The new minimum delay in seconds
     */
    function updateMinDelay(uint256 newDelay) external {
        // Only callable via governance (self-call through timelock)
        require(
            msg.sender == address(this),
            "ZaseonGovernance: caller must be timelock"
        );
        // TimelockController stores minDelay — schedule an updateDelay call
        this.updateDelay(newDelay);
    }
}
