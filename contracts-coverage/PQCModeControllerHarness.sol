// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {PQCModeController} from "../contracts/pqc/PQCModeController.sol";
import {HybridPQCVerifier} from "../contracts/pqc/HybridPQCVerifier.sol";

/**
 * @title PQCModeControllerHarness
 * @author Soul Protocol
 * @notice Test harness for coverage of PQCModeController
 * @dev Exposes internal state and provides test utilities
 */
contract PQCModeControllerHarness is PQCModeController {
    constructor(
        address _verifier,
        address admin,
        address[] memory proposers,
        address[] memory approvers
    ) PQCModeController(_verifier, admin, proposers, approvers) {}

    /**
     * @notice Gets the current emergency pause status
     */
    function getEmergencyPaused() external view returns (bool) {
        return emergencyPaused;
    }

    /**
     * @notice Gets proposal count
     */
    function getProposalCount() external view returns (uint256) {
        return proposalCount;
    }

    /**
     * @notice Gets mode history length
     */
    function getModeHistoryLength() external view returns (uint256) {
        return modeHistory.length;
    }

    /**
     * @notice Simulates time passing (use with vm.warp in tests)
     */
    function getTimelockExpiry(
        uint256 proposalId
    ) external view returns (uint256) {
        return proposals[proposalId].executeAfter;
    }

    /**
     * @notice Gets all approvers for a proposal
     */
    function getApproverCount(
        uint256 proposalId
    ) external view returns (uint256) {
        return approvalList[proposalId].length;
    }

    /**
     * @notice Checks if address has approved
     */
    function hasAddressApproved(
        uint256 proposalId,
        address approver
    ) external view returns (bool) {
        return hasApproved[proposalId][approver];
    }
}
