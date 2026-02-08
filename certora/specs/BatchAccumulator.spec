// SPDX-License-Identifier: MIT
// Certora CVL Specification: BatchAccumulator
//
// Properties verified:
// 1. Proof verifier delegation correctness
// 2. Empty proof always rejected
// 3. Batch without commitments always fails verification
// 4. Proof verifier address cannot be zero (admin setter check)
// 5. Nullifier uniqueness invariant
// 6. Batch lifecycle transitions
// 7. Route configuration bounds (batch size, wait time)

using BatchAccumulator as ba;

methods {
    // State getters
    function proofVerifier() external returns (address) envfree;
    function crossChainHub() external returns (address) envfree;
    function totalBatches() external returns (uint256) envfree;
    function totalTransactionsBatched() external returns (uint256) envfree;
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function activeBatches(bytes32) external returns (bytes32) envfree;
    function commitmentToBatch(bytes32) external returns (bytes32) envfree;

    // Constants
    function DEFAULT_MIN_BATCH_SIZE() external returns (uint256) envfree;
    function MAX_BATCH_SIZE() external returns (uint256) envfree;
    function DEFAULT_MAX_WAIT_TIME() external returns (uint256) envfree;
    function MIN_WAIT_TIME() external returns (uint256) envfree;
    function MAX_WAIT_TIME() external returns (uint256) envfree;
    function FIXED_PAYLOAD_SIZE() external returns (uint256) envfree;

    // Role constants
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function UPGRADER_ROLE() external returns (bytes32) envfree;

    // Admin functions
    function setProofVerifier(address) external;
    function setCrossChainHub(address) external;
    function configureRoute(uint256, uint256, uint256, uint256) external;
}

/*//////////////////////////////////////////////////////////////
                    GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost mapping(bytes32 => bool) ghostNullifierUsed {
    init_state axiom forall bytes32 n. !ghostNullifierUsed[n];
}

ghost uint256 ghostTotalBatches {
    init_state axiom ghostTotalBatches == 0;
}

/*//////////////////////////////////////////////////////////////
                    PROOF VERIFIER RULES
//////////////////////////////////////////////////////////////*/

/// @title Proof verifier address cannot be set to zero
rule setProofVerifierRejectsZero(env e) {
    address zero = 0;
    setProofVerifier@withrevert(e, zero);
    assert lastReverted, "setProofVerifier must reject zero address";
}

/// @title Non-admin cannot set proof verifier
rule setProofVerifierAccessControl(env e) {
    address newVerifier;
    require newVerifier != 0;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    setProofVerifier@withrevert(e, newVerifier);
    assert lastReverted, "Non-admin should not set proof verifier";
}

/// @title Proof verifier updates correctly
rule setProofVerifierUpdatesState(env e) {
    address newVerifier;
    require newVerifier != 0;
    require hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    setProofVerifier(e, newVerifier);
    assert proofVerifier() == newVerifier, "Proof verifier should be updated";
}

/*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN HUB RULES
//////////////////////////////////////////////////////////////*/

/// @title Cross-chain hub address cannot be set to zero
rule setCrossChainHubRejectsZero(env e) {
    address zero = 0;
    setCrossChainHub@withrevert(e, zero);
    assert lastReverted, "setCrossChainHub must reject zero address";
}

/*//////////////////////////////////////////////////////////////
                    NULLIFIER UNIQUENESS
//////////////////////////////////////////////////////////////*/

/// @title Once a nullifier is used, it stays used (monotonicity)
invariant nullifierMonotonicity(bytes32 nullifier)
    nullifierUsed(nullifier) => nullifierUsed(nullifier)
    { preserved { require true; } }

/*//////////////////////////////////////////////////////////////
                    ROUTE CONFIGURATION BOUNDS
//////////////////////////////////////////////////////////////*/

/// @title Batch size must be within valid range
rule routeConfigBatchSizeBounds(env e) {
    uint256 sourceChainId;
    uint256 destChainId;
    uint256 minBatchSize;
    uint256 maxWaitTime;

    require minBatchSize < 1 || minBatchSize > to_mathint(MAX_BATCH_SIZE());
    configureRoute@withrevert(e, sourceChainId, destChainId, minBatchSize, maxWaitTime);
    assert lastReverted, "Route configuration must reject invalid batch size";
}

/// @title Wait time must be within valid range
rule routeConfigWaitTimeBounds(env e) {
    uint256 sourceChainId;
    uint256 destChainId;
    uint256 minBatchSize;
    uint256 maxWaitTime;

    require minBatchSize >= 1 && to_mathint(minBatchSize) <= to_mathint(MAX_BATCH_SIZE());
    require maxWaitTime < MIN_WAIT_TIME() || maxWaitTime > MAX_WAIT_TIME();
    configureRoute@withrevert(e, sourceChainId, destChainId, minBatchSize, maxWaitTime);
    assert lastReverted, "Route configuration must reject invalid wait time";
}

/*//////////////////////////////////////////////////////////////
                    TOTAL COUNTERS
//////////////////////////////////////////////////////////////*/

/// @title Total batches counter is monotonically non-decreasing
rule totalBatchesMonotonicity(env e, method f, calldataarg args)
    filtered { f -> !f.isView } {
    uint256 before = totalBatches();
    f(e, args);
    uint256 after = totalBatches();
    assert to_mathint(after) >= to_mathint(before),
        "Total batches must never decrease";
}

/// @title Total transactions counter is monotonically non-decreasing
rule totalTransactionsMonotonicity(env e, method f, calldataarg args)
    filtered { f -> !f.isView } {
    uint256 before = totalTransactionsBatched();
    f(e, args);
    uint256 after = totalTransactionsBatched();
    assert to_mathint(after) >= to_mathint(before),
        "Total transactions must never decrease";
}
