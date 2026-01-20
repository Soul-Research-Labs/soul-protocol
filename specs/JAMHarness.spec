/**
 * @title Formal Verification Specification for JAMHarness
 */

methods {
    function hasRole(bytes32, address) external returns (bool) envfree;
}

// No invariants - basic verification scaffold
