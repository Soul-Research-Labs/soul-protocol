// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/IGovernor.sol";

/**
 * @title ISoulGovernor
 * @notice Interface for Soul Protocol on-chain governance.
 * @dev Extends OpenZeppelin's IGovernor with Soul-specific constants.
 *      See SoulGovernor.sol for the implementation.
 */
interface ISoulGovernor is IGovernor {
    /// @notice Default voting delay (1 day)
    function DEFAULT_VOTING_DELAY() external pure returns (uint48);

    /// @notice Default voting period (5 days)
    function DEFAULT_VOTING_PERIOD() external pure returns (uint32);

    /// @notice Default proposal threshold (100k tokens)
    function DEFAULT_PROPOSAL_THRESHOLD() external pure returns (uint256);

    /// @notice Default quorum percentage (4%)
    function DEFAULT_QUORUM_PERCENTAGE() external pure returns (uint256);
}
