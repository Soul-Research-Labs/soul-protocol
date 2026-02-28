/**
 * Certora Formal Verification Specification
 * ZASEON - ZKBoundStateLocks (ZK-SLocks)
 */

methods {
    // View functions
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function verifiers(bytes32) external returns (address) envfree;
    function totalLocksCreated() external returns (uint256) envfree;
    function totalLocksUnlocked() external returns (uint256) envfree;
    function totalOptimisticUnlocks() external returns (uint256) envfree;
    function totalDisputes() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function getActiveLockCount() external returns (uint256) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-ZKS-001: Total unlocks cannot exceed total created
 */
invariant unlocksCannotExceedCreated()
    totalLocksUnlocked() <= totalLocksCreated();

/**
 * INV-ZKS-002: Disputes cannot exceed optimistic unlocks
 */
invariant disputesCannotExceedOptimistic()
    totalDisputes() <= totalOptimisticUnlocks();

/**
 * INV-ZKS-003: Active locks bounded by created
 */
invariant activeLockBound()
    getActiveLockCount() <= totalLocksCreated();

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-ZKS-001: Monotonic lock creation
 */
rule monotonicLockCreation(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalLocksCreated();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalLocksCreated();
    
    assert countAfter >= countBefore, "Lock count must be monotonically increasing";
}

/**
 * RULE-ZKS-002: Monotonic unlock count
 */
rule monotonicUnlockCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalLocksUnlocked();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalLocksUnlocked();
    
    assert countAfter >= countBefore, "Unlock count must be monotonically increasing";
}

/**
 * RULE-ZKS-003: Nullifier permanence
 * Once a nullifier is marked used, no function can clear it.
 * (Subsumes former RULE-ZKS-004 which was an identical check)
 */
rule nullifierPermanence(bytes32 nullifier, method f) filtered { f -> !f.isView } {
    env e;
    calldataarg args;
    
    bool usedBefore = nullifierUsed(nullifier);
    
    f(e, args);
    
    bool usedAfter = nullifierUsed(nullifier);
    
    assert usedBefore => usedAfter, "Used nullifier must stay used";
}

/**
 * RULE-ZKS-004: MAX_ACTIVE_LOCKS enforced
 * Security Fix M-23: Prevents unbounded array growth
 */
rule maxActiveLocksEnforced(method f) filtered { f -> !f.isView } {
    env e;
    calldataarg args;
    
    f(e, args);
    
    mathint activeAfter = getActiveLockCount();
    
    assert activeAfter <= 1000000, "Active locks must not exceed max";
}

/**
 * INV-ZKS-004: Active locks bounded by MAX_ACTIVE_LOCKS
 */
invariant activeLocksWithinLimit()
    getActiveLockCount() <= 1000000;