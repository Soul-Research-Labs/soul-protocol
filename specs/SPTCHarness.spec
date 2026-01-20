/**
 * @title Formal Verification Specification for SPTCHarness
 */

methods {
    function hasRole(bytes32, address) external returns (bool) envfree;
}

// No invariants - basic verification scaffold
