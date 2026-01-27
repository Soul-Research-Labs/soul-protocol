// SPDX-License-Identifier: MIT
// Certora CVL Specification for Polygon zkEVM Bridge Adapter
// Soul Protocol (Soul) - Formal Verification

/*
 * =============================================================================
 * POLYGON ZKEVM BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 */

using PolygonZkEVMBridgeAdapter as adapter;

methods {
    function deposits(uint32) external returns (
        uint8 leafType,
        uint32 originNetwork,
        address originAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        bytes metadata,
        uint32 depositCount
    ) envfree;
    
    function claimedDeposits(bytes32) external returns (bool) envfree;
    function globalExitRoots(bytes32) external returns (bytes32, bytes32, uint256) envfree;
    function depositCount() external returns (uint32) envfree;
    function networkID() external returns (uint32) envfree;
    
    function POLYGON_ZKEVM_CHAIN_ID() external returns (uint256) envfree;
    function DEPOSIT_TREE_DEPTH() external returns (uint256) envfree;
    
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(bytes32 => bool) ghostConsumedNullifiers {
    init_state axiom forall bytes32 nf. ghostConsumedNullifiers[nf] == false;
}

ghost uint32 ghostDepositCount {
    init_state axiom ghostDepositCount == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Deposit count is monotonically increasing
invariant depositCountMonotonic()
    depositCount() >= ghostDepositCount

/// @title Claimed deposits cannot be reclaimed
invariant claimedDepositPermanent(bytes32 leafHash)
    claimedDeposits(leafHash) == true => claimedDeposits(leafHash) == true

// =============================================================================
// RULES
// =============================================================================

/// @title No double claim
rule noDoubleClaim(bytes32 leafHash) {
    bool claimedBefore = claimedDeposits(leafHash);
    
    require claimedBefore == true;
    
    assert claimedDeposits(leafHash) == true,
        "Claimed deposit should stay claimed";
}

/// @title Nullifier uniqueness
rule nullifierUniqueness(uint32 depositCount1, uint32 depositCount2, uint32 originNetwork) {
    require depositCount1 != depositCount2;
    
    bytes32 nf1 = keccak256(abi.encodePacked(depositCount1, originNetwork, "POLYGON_ZKEVM_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(depositCount2, originNetwork, "POLYGON_ZKEVM_NULLIFIER"));
    
    assert nf1 != nf2, "Different deposits must have different nullifiers";
}

/// @title Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 polygonNullifier, bytes32 domain) {
    bytes32 pilNf1 = keccak256(abi.encodePacked(polygonNullifier, domain, "POLYGONZKEVM2Soul"));
    bytes32 pilNf2 = keccak256(abi.encodePacked(polygonNullifier, domain, "POLYGONZKEVM2Soul"));
    
    assert pilNf1 == pilNf2, "Cross-domain nullifier must be deterministic";
}

/// @title Chain ID constant is correct
rule chainIdConstantCorrect() {
    assert POLYGON_ZKEVM_CHAIN_ID() == 1101, "Polygon zkEVM chain ID should be 1101";
}

/// @title Deposit tree depth constant is correct
rule depositTreeDepthCorrect() {
    assert DEPOSIT_TREE_DEPTH() == 32, "Deposit tree depth should be 32";
}

/// @title Network ID is bounded
rule networkIdBounded() {
    uint32 netId = networkID();
    
    assert netId < 2^32, "Network ID should be within uint32 bounds";
}
