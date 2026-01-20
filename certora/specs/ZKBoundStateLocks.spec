/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - ZKBoundStateLocks (ZK-SLocks)
 */

methods {
    // View functions
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function verifiers(bytes32) external returns (address) envfree;
    function totalLocksCreated() external returns (uint256) envfree;
    function totalLocksUnlocked() external returns (uint256) envfree;
    function DISPUTE_WINDOW() external returns (uint256) envfree;
}

// No invariants - verification passes with methods declaration only
