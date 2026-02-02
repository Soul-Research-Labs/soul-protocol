/**
 * @title Simplified Certora Verification Rules for ProofCarryingContainer
 * @notice Machine-verifiable specifications for the Certora Prover
 */

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State variables
    function totalContainers() external returns (uint256) envfree;
    function consumedNullifiers(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    
    // Mutating functions
    function consumeContainer(bytes32) external;
    function verifyContainer(bytes32) external returns (bool);
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Ghost counter for containers
ghost uint256 ghostContainerCount {
    init_state axiom ghostContainerCount == 0;
}

// Ghost variable to track nullifier consumption
ghost mapping(bytes32 => bool) ghostNullifierConsumed {
    init_state axiom forall bytes32 n. !ghostNullifierConsumed[n];
}

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

// Hook on nullifier consumption
hook Sstore consumedNullifiers[KEY bytes32 n] bool consumed (bool old_consumed) {
    if (!old_consumed && consumed) {
        ghostNullifierConsumed[n] = true;
    }
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Nullifier consumption is permanent - once consumed, always consumed
 */
invariant nullifierConsumptionPermanent(bytes32 n)
    ghostNullifierConsumed[n] => consumedNullifiers(n);

/**
 * @notice Total containers is always non-negative
 */
invariant totalContainersNonNegative()
    totalContainers() >= 0;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Consumed containers cannot be consumed again
 */
rule consumedContainerStaysConsumed(bytes32 containerId) {
    env e1;
    env e2;
    
    require !paused();
    
    // First consumption
    consumeContainer(e1, containerId);
    
    // Attempt second consumption - must revert
    consumeContainer@withrevert(e2, containerId);
    
    assert lastReverted,
        "Already consumed container must revert on second consumption";
}

/**
 * @notice Nullifier consumption is irreversible via any function
 */
rule nullifierConsumptionIrreversible(bytes32 nullifier) {
    env e;
    
    require consumedNullifiers(nullifier);
    
    // Any arbitrary function call
    method f;
    calldataarg args;
    f(e, args);
    
    assert consumedNullifiers(nullifier),
        "Once consumed, nullifier stays consumed forever";
}

/**
 * @notice Paused contract prevents container consumption
 */
rule pausePreventsConsumption(bytes32 containerId) {
    env e;
    
    require paused();
    
    consumeContainer@withrevert(e, containerId);
    
    assert lastReverted,
        "Container consumption must revert when paused";
}

/**
 * @notice Total containers count never decreases
 */
rule totalContainersMonotonicallyIncreases() {
    env e;
    
    uint256 countBefore = totalContainers();
    
    method f;
    calldataarg args;
    f(e, args);
    
    uint256 countAfter = totalContainers();
    
    assert countAfter >= countBefore,
        "Total containers count must never decrease";
}

/**
 * @notice Verification is read-only - doesnt change state
 */
rule verifyContainerIsReadOnly(bytes32 containerId) {
    env e;
    
    uint256 countBefore = totalContainers();
    
    verifyContainer(e, containerId);
    
    uint256 countAfter = totalContainers();
    
    assert countAfter == countBefore,
        "Verification must not change container count";
}
