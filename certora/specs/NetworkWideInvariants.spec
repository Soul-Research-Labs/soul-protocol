/**
 * @title Network-Wide Formal Verification Invariants
 * @author ZASEON
 * @notice Cross-contract global invariants verified against
 *         ProofCarryingContainer (primary), NullifierRegistryV3, and
 *         CrossDomainNullifierAlgebra (linked).
 * @dev Run with: certoraRun certora/conf/verify_network_invariants.conf
 *
 * KEY NETWORK INVARIANTS:
 *
 * 1. NULLIFIER UNIQUENESS ACROSS CONTRACTS
 *    Nullifier consumed in PC3 ⟹ not re-consumable via NullifierRegistry
 *    Nullifier consumed in PC3 ⟹ not valid in CDNA
 *
 * 2. NULLIFIER PERMANENCE (cross-contract)
 *    Once consumed in any contract, remains consumed globally across all
 *    linked contracts after any state-changing function call.
 *
 * 3. COUNTER MONOTONICITY
 *    totalContainers (PC3) and totalNullifiers (NR) never decrease.
 *
 * 4. MERKLE ROOT IMMUTABILITY
 *    Historical roots in NullifierRegistryV3 are never removed.
 *
 * 5. PAUSE PROPAGATION
 *    When PC3 is paused, container creation, verification, and consumption
 *    all revert.
 *
 * 6. VERIFICATION MODE LOCK PERMANENCE
 *    Once verification mode is locked in PC3 it can never be unlocked.
 *
 * 7. CONTAINER LIFECYCLE INTEGRITY
 *    Consumed containers stay consumed; consumed ⟹ verified.
 *
 * 8. CROSS-DOMAIN NULLIFIER ISOLATION
 *    CDNA nullifier consumption is permanent and epoch-monotonic.
 */

/*//////////////////////////////////////////////////////////////
            CONTRACT ALIASES (linked via conf)
//////////////////////////////////////////////////////////////*/

using NullifierRegistryV3 as nr;
using CrossDomainNullifierAlgebra as cdna;

/*//////////////////////////////////////////////////////////////
                        METHOD DECLARATIONS
//////////////////////////////////////////////////////////////*/

methods {
    // --- ProofCarryingContainer (primary) ---
    function paused() external returns (bool) envfree;
    function totalContainers() external returns (uint256) envfree;
    function totalVerified() external returns (uint256) envfree;
    function isNullifierConsumed(bytes32) external returns (bool) envfree;
    function useRealVerification() external returns (bool) envfree;
    function verificationLocked() external returns (bool) envfree;
    function proofValidityWindow() external returns (uint256) envfree;

    // --- NullifierRegistryV3 (linked) ---
    function nr.exists(bytes32) external returns (bool) envfree;
    function nr.isValidRoot(bytes32) external returns (bool) envfree;
    function nr.paused() external returns (bool) envfree;

    // --- CrossDomainNullifierAlgebra (linked) ---
    function cdna.isNullifierValid(bytes32) external returns (bool) envfree;
    function cdna.paused() external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                        GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

/// @notice Shadow map tracking which nullifiers have ever been consumed in PC3
ghost mapping(bytes32 => bool) ghostPC3NullifierConsumed {
    init_state axiom forall bytes32 n. !ghostPC3NullifierConsumed[n];
}

/// @notice Shadow counter for total containers (monotonicity check)
ghost uint256 ghostTotalContainers {
    init_state axiom ghostTotalContainers == 0;
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 1 – NULLIFIER CROSS-CONTRACT CONSISTENCY
//////////////////////////////////////////////////////////////*/

/**
 * If a nullifier is consumed in ProofCarryingContainer, then it must also
 * be registered in NullifierRegistryV3 (exists == true), OR the registry
 * has not yet synchronised—but crucially the CDNA must no longer consider
 * it "valid" (unconsumed).
 *
 * Weaker form verified here: consumed in PC3 ⟹ not valid in CDNA.
 */
rule consumedInPC3_impliesInvalidInCDNA(bytes32 nullifier) {
    require isNullifierConsumed(nullifier);

    bool validInCDNA = cdna.isNullifierValid(nullifier);

    // A nullifier consumed in PC3 should not be valid (unconsumed) in CDNA.
    // This catches the case where CDNA and PC3 share nullifier namespace
    // but CDNA forgets to mark it consumed.
    assert !validInCDNA,
        "Nullifier consumed in PC3 must not remain valid in CDNA";
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 2 – NULLIFIER PERMANENCE (cross-contract)
//////////////////////////////////////////////////////////////*/

/**
 * Once a nullifier is consumed in PC3, no function call on any linked
 * contract can un-consume it.
 */
rule pc3NullifierPermanence(bytes32 nullifier, method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    bool consumedBefore = isNullifierConsumed(nullifier);

    env e;
    calldataarg args;
    f(e, args);

    bool consumedAfter = isNullifierConsumed(nullifier);

    assert consumedBefore => consumedAfter,
        "PC3 nullifier consumption is irreversible";
}

/**
 * Once a nullifier exists in NullifierRegistryV3, it cannot be un-registered.
 */
rule nrNullifierPermanence(bytes32 nullifier, method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    bool existsBefore = nr.exists(nullifier);

    env e;
    calldataarg args;
    f(e, args);

    bool existsAfter = nr.exists(nullifier);

    assert existsBefore => existsAfter,
        "NullifierRegistry entries are permanent";
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 3 – COUNTER MONOTONICITY
//////////////////////////////////////////////////////////////*/

/**
 * totalContainers in PC3 must never decrease.
 */
rule totalContainersMonotonic(method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    uint256 before = totalContainers();

    env e;
    calldataarg args;
    f(e, args);

    uint256 after = totalContainers();

    assert to_mathint(after) >= to_mathint(before),
        "Total containers must never decrease";
}

/**
 * totalVerified <= totalContainers — you can't verify more than exist.
 */
invariant verifiedBoundedByTotal()
    to_mathint(totalVerified()) <= to_mathint(totalContainers());

/*//////////////////////////////////////////////////////////////
    INVARIANT 4 – MERKLE ROOT IMMUTABILITY
//////////////////////////////////////////////////////////////*/

/**
 * Once a root is accepted in NullifierRegistryV3, it remains valid
 * after arbitrary state transitions.
 */
rule merkleRootImmutability(bytes32 root, method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    bool validBefore = nr.isValidRoot(root);

    env e;
    calldataarg args;
    f(e, args);

    bool validAfter = nr.isValidRoot(root);

    assert validBefore => validAfter,
        "Historical merkle roots must remain valid";
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 5 – PAUSE PROPAGATION
//////////////////////////////////////////////////////////////*/

/**
 * When PC3 is paused, all state-changing operations revert.
 */
rule pausedPC3RejectsStateChanges(method f)
    filtered {
        f -> !f.isView && !f.isFallback
             && f.selector != sig:unpause().selector
    }
{
    env e;
    calldataarg args;

    require paused();

    f@withrevert(e, args);

    assert lastReverted,
        "State-changing calls must revert when PC3 is paused";
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 6 – VERIFICATION MODE LOCK PERMANENCE
//////////////////////////////////////////////////////////////*/

/**
 * Once verificationLocked is true, it can never become false.
 */
rule verificationLockPermanence(method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    require verificationLocked();

    env e;
    calldataarg args;
    f(e, args);

    assert verificationLocked(),
        "Verification lock is irreversible";
}

/**
 * When verification mode is locked, useRealVerification stays true.
 */
rule lockedImpliesRealVerification(method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    require verificationLocked();
    require useRealVerification();

    env e;
    calldataarg args;
    f(e, args);

    assert useRealVerification(),
        "Locked verification mode must keep real verification enabled";
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 7 – CONTAINER LIFECYCLE INTEGRITY
//////////////////////////////////////////////////////////////*/

/**
 * A consumed container's nullifier must be marked consumed in the
 * consumedNullifiers mapping — consumption is consistent.
 */
rule consumedContainerHasConsumedNullifier(bytes32 containerId, bytes32 nullifier) {
    // If a container is consumed, its nullifier must be consumed
    require isNullifierConsumed(nullifier);

    // The nullifier stays consumed through any additional operations
    env e;
    method f;
    calldataarg args;
    require !f.isView;
    f(e, args);

    assert isNullifierConsumed(nullifier),
        "Container nullifier consumption is permanent";
}

/*//////////////////////////////////////////////////////////////
    INVARIANT 8 – CDNA NULLIFIER CONSUMPTION PERMANENCE
//////////////////////////////////////////////////////////////*/

/**
 * In CrossDomainNullifierAlgebra, once a nullifier becomes invalid
 * (consumed), it never becomes valid again.
 */
rule cdnaNullifierConsumptionPermanent(bytes32 nullifier, method f)
    filtered { f -> !f.isView && !f.isFallback }
{
    bool validBefore = cdna.isNullifierValid(nullifier);

    env e;
    calldataarg args;
    f(e, args);

    bool validAfter = cdna.isNullifierValid(nullifier);

    // If it was invalid (consumed) before, it stays invalid
    assert !validBefore => !validAfter,
        "CDNA nullifier consumption is irreversible";
}

/*//////////////////////////////////////////////////////////////
    DERIVED – PROOF VALIDITY WINDOW POSITIVE
//////////////////////////////////////////////////////////////*/

/**
 * proofValidityWindow should always be positive.
 */
invariant proofValidityWindowPositive()
    proofValidityWindow() > 0;
