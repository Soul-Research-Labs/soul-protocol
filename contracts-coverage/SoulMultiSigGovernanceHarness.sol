// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SoulMultiSigGovernance} from "../contracts/governance/SoulMultiSigGovernance.sol";

/**
 * @title SoulMultiSigGovernanceHarness
 * @author Soul Protocol
 * @notice Test harness for coverage of SoulMultiSigGovernance
 * @dev Exposes internal functions and state for comprehensive testing
 */
contract SoulMultiSigGovernanceHarness is SoulMultiSigGovernance {
    constructor(address superAdmin) SoulMultiSigGovernance(superAdmin) {}

    /**
     * @notice Exposes internal _signProposal for testing
     */
    function exposed_signProposal(bytes32 proposalId, address signer) external {
        _signProposal(proposalId, signer);
    }

    /**
     * @notice Exposes internal _checkRoleSeparation for testing
     */
    function exposed_checkRoleSeparation(
        bytes32 newRole,
        address member
    ) external view {
        _checkRoleSeparation(newRole, member);
    }

    /**
     * @notice Gets role config values
     */
    function getRoleConfigValues(
        bytes32 role
    )
        external
        view
        returns (uint256 requiredSignatures, uint256 memberCount, bool active)
    {
        RoleConfig storage config = roleConfigs[role];
        return (config.requiredSignatures, config.memberCount, config.active);
    }

    /**
     * @notice Gets signature count for proposal
     */
    function getSignatureCount(
        bytes32 proposalId
    ) external view returns (uint256) {
        return proposals[proposalId].signatureCount;
    }

    /**
     * @notice Gets all proposals array length
     */
    function getAllProposalsLength() external view returns (uint256) {
        return allProposals.length;
    }

    /**
     * @notice Checks if proposal is in a specific state
     */
    function isProposalState(
        bytes32 proposalId,
        bool executed,
        bool cancelled
    ) external view returns (bool) {
        Proposal storage p = proposals[proposalId];
        return p.executed == executed && p.cancelled == cancelled;
    }

    /**
     * @notice Test helper to create and sign proposal in one call
     */
    function createAndSignProposal(
        address target,
        uint256 value,
        bytes calldata data,
        string calldata description,
        bytes32 requiredRole,
        address[] calldata signers
    ) external returns (bytes32 proposalId) {
        proposalId = this.createProposal(
            target,
            value,
            data,
            description,
            requiredRole
        );

        for (uint256 i = 0; i < signers.length; i++) {
            if (
                !hasSigned[proposalId][signers[i]] &&
                hasRole(requiredRole, signers[i])
            ) {
                _signProposal(proposalId, signers[i]);
            }
        }
    }
}
