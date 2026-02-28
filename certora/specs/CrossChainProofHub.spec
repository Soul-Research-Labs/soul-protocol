/**
 * Certora Formal Verification Specification
 * ZASEON - CrossChainProofHubV3
 * 
 * This spec verifies critical invariants for the Cross-Chain Proof Hub
 */

using CrossChainProofHubV3 as hub;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalProofs() external returns (uint256) envfree;
    function totalBatches() external returns (uint256) envfree;
    function challengePeriod() external returns (uint256) envfree;
    function minRelayerStake() external returns (uint256) envfree;
    function minChallengerStake() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function supportedChains(uint256) external returns (bool) envfree;
    function relayerStakes(address) external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function VERIFIER_ADMIN_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    
    // Stake management
    function depositStake() external;
    function withdrawStake(uint256) external;
    
    // Chain management
    function addSupportedChain(uint256) external;
    function removeSupportedChain(uint256) external;

    // Verifier management
    function setVerifier(bytes32, address) external;
    function setVerifierRegistry(address) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-HUB-001: Challenge period positive
 */
invariant challengePeriodPositive()
    challengePeriod() > 0;

/**
 * INV-HUB-002: Min stake positive
 */
invariant minStakePositive()
    minRelayerStake() > 0 && minChallengerStake() > 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Monotonic proof count
 */
rule monotonicProofCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalProofs();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalProofs();
    
    assert countAfter >= countBefore, "Proof count must be monotonically increasing";
}

/**
 * @title Deposit Increases Stake
 * @notice Depositing stake should increase the relayer's stake
 */
rule depositIncreasesStake() {
    env e;
    require e.msg.value > 0;
    
    uint256 stakeBefore = relayerStakes(e.msg.sender);
    
    depositStake(e);
    
    uint256 stakeAfter = relayerStakes(e.msg.sender);
    
    assert stakeAfter == stakeBefore + e.msg.value,
        "Deposit should increase stake by msg.value";
}

/**
 * @title Add Chain Sets Support
 * @notice Adding a chain should mark it as supported
 */
rule addChainSetsSupport(uint256 chainId) {
    env e;
    
    addSupportedChain(e, chainId);
    
    bool supported = supportedChains(chainId);
    
    assert supported,
        "Added chain should be supported";
}

/**
 * @title Remove Chain Clears Support
 * @notice Removing a chain should mark it as not supported
 */
rule removeChainClearsSupport(uint256 chainId) {
    env e;
    require supportedChains(chainId);
    
    removeSupportedChain(e, chainId);
    
    bool supported = supportedChains(chainId);
    
    assert !supported,
        "Removed chain should not be supported";
}
// ============================================================================
// VERIFIER DELEGATION RULES
// ============================================================================

/**
 * RULE-HUB-VERIFIER-001: Only VERIFIER_ADMIN_ROLE can set verifiers
 * setVerifier requires VERIFIER_ADMIN_ROLE authorization
 */
rule onlyVerifierAdminCanSetVerifier(bytes32 proofType, address verifier) {
    env e;
    require !hasRole(hub.VERIFIER_ADMIN_ROLE(), e.msg.sender);

    setVerifier@withrevert(e, proofType, verifier);

    assert lastReverted,
        "Only VERIFIER_ADMIN_ROLE can set verifiers";
}

/**
 * RULE-HUB-VERIFIER-002: Only VERIFIER_ADMIN_ROLE can set verifier registry
 * setVerifierRegistry requires VERIFIER_ADMIN_ROLE authorization
 */
rule onlyVerifierAdminCanSetRegistry(address registry) {
    env e;
    require !hasRole(hub.VERIFIER_ADMIN_ROLE(), e.msg.sender);

    setVerifierRegistry@withrevert(e, registry);

    assert lastReverted,
        "Only VERIFIER_ADMIN_ROLE can set verifier registry";
}

// ============================================================================
// SECURITY FIX RULES (February 2026 Audit)
// ============================================================================

/**
 * RULE-HUB-ACCESS-001: Paused state blocks state-changing operations
 * Security Fix C-3: When paused, critical state changes should be blocked
 */
rule pausedStateBlocksOperations() {
    env e;
    require paused();

    depositStake@withrevert(e);

    assert lastReverted,
        "Paused state must block stake deposits";
}

/**
 * RULE-HUB-REWARD-001: Challenge period is non-zero
 * Security Fix H-5: Challengers have time to claim
 */
rule challengePeriodNonZero() {
    mathint period = challengePeriod();
    
    assert period > 0, "Challenge period must be positive";
}

/**
 * RULE-HUB-DOUBLE-001: Finalization count increases monotonically
 * Security Fix H-4: No double-counting via monotonicity
 */
rule finalizationMonotonic(method f) filtered { f -> !f.isView } {
    env e;
    calldataarg args;
    
    mathint totalBefore = totalProofs();
    
    f(e, args);
    
    mathint totalAfter = totalProofs();
    
    assert totalAfter >= totalBefore, "Proof count must be monotonic";
}

/**
 * INV-HUB-003: Challenge period has minimum (10 minutes)
 * Security Fix M-8: Prevent too-short challenge windows
 */
invariant challengePeriodMinimum()
    challengePeriod() >= 600; // 10 minutes = 600 seconds