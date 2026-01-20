/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - MixnetNodeRegistryHarness
 * 
 * This spec verifies critical invariants for the MixnetNodeRegistry
 */

using MixnetNodeRegistryHarness as mnr;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalNodes() external returns (uint256) envfree;
    function activeNodes() external returns (uint256) envfree;
    function minStake() external returns (uint256) envfree;
    function slashPercent() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function nodeStake(bytes32) external returns (uint256) envfree;
    function nodeReputation(bytes32) external returns (uint256) envfree;
    function nodeOperator(bytes32) external returns (address) envfree;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Slash Percent Bounded
 * @notice Slash percent must be <= 10000 (100%)
 */
invariant slashPercentBounded()
    slashPercent() <= 10000;
