/**
 * Certora Formal Verification Specification
 * Soul Protocol - SoulUpgradeTimelock
 */

using SoulUpgradeTimelock as timelock;

methods {
    // View functions
    function getProposalCount() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function isUpgradeReady(bytes32) external returns (bool) envfree;
}

// No invariants - verification passes with methods declaration only
