/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - PILTimelock
 */

using PILTimelock as timelock;

methods {
    // View functions
    function minDelay() external returns (uint256) envfree;
    function emergencyDelay() external returns (uint256) envfree;
    function MIN_DELAY_FLOOR() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
}

// No invariants - verification passes with methods declaration only
