/**
 * Certora Formal Verification Specification
 * Soul Protocol - CrossChainProofHubV3
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
    function challengePeriod() external returns (uint256) envfree;
    function minRelayerStake() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function supportedChains(uint256) external returns (bool) envfree;
    function relayerStakes(address) external returns (uint256) envfree;
    
    // Stake management
    function depositStake() external;
    function withdrawStake(uint256) external;
    
    // Chain management
    function addSupportedChain(uint256) external;
    function removeSupportedChain(uint256) external;
}

// ============================================================================
// RULES
// ============================================================================

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
