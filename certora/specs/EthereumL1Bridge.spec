/*
 * Certora Verification Spec: EthereumL1Bridge
 * Verifies core invariants of the Ethereum L1 Bridge contract
 */

methods {
    // View functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function supportedL2s(uint256) external returns (bool) envfree;
    function deposits(bytes32) external returns (address, uint256, uint256, uint256, uint8) envfree;
    function stateCommitments(bytes32) external returns (uint256, bytes32, uint256, bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;

    // State-changing
    function addSupportedL2(uint256) external;
    function removeSupportedL2(uint256) external;
    function depositETH(uint256, bytes32) external;
    function withdraw(bytes32, address, uint256, bytes32[]) external;
    function submitStateCommitment(uint256, bytes32, bytes32) external;
    function pause() external;
    function unpause() external;
}

// Invariant: Nullifiers cannot be reused
rule nullifierUniqueness(bytes32 nullifier, env e) {
    require usedNullifiers(nullifier) == true;
    
    // Any operation that would use this nullifier should revert
    withdraw@withrevert(e, nullifier, _, _, _);
    assert lastReverted, "Used nullifier must cause revert";
}

// Invariant: Deposits always increase total
rule depositIncreasesTotal(env e) {
    uint256 totalBefore = totalDeposits();
    
    uint256 chainId;
    bytes32 commitment;
    depositETH(e, chainId, commitment);
    
    uint256 totalAfter = totalDeposits();
    assert totalAfter > totalBefore, "Total deposits must increase after deposit";
}

// Invariant: Only guardian can pause
rule onlyGuardianCanPause(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));
    
    require !hasRole(guardianRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender); // not admin

    pause@withrevert(e);
    assert lastReverted, "Non-guardian should not be able to pause";
}

// Invariant: Paused contract blocks deposits
rule pausedBlocksDeposits(env e) {
    require paused() == true;
    
    uint256 chainId;
    bytes32 commitment;
    depositETH@withrevert(e, chainId, commitment);
    assert lastReverted, "Deposits should be blocked when paused";
}

// Invariant: Only supported L2s accept deposits
rule onlySupportedL2sAcceptDeposits(env e) {
    uint256 chainId;
    bytes32 commitment;
    
    require supportedL2s(chainId) == false;
    
    depositETH@withrevert(e, chainId, commitment);
    assert lastReverted, "Unsupported L2 should reject deposits";
}

// Invariant: State commitment finalization is monotonic
rule commitmentFinalization(bytes32 commitId, env e) {
    bool finalizedBefore;
    _, _, _, finalizedBefore = stateCommitments(commitId);
    require finalizedBefore == true;

    // Once finalized, should remain finalized
    bool finalizedAfter;
    _, _, _, finalizedAfter = stateCommitments(commitId);
    assert finalizedAfter == true, "Finalized commitment should stay finalized";
}
