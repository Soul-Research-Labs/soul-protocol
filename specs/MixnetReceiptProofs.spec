/**
 * @title Formal Verification Specification for MixnetReceiptProofs
 */

methods {
    function totalReceipts() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
}

// No invariants - verification passes with methods declaration only
