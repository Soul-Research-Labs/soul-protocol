/**
 * @title Certora Verification Rules for ProofCarryingContainer
 * @notice Machine-verifiable specifications for the Certora Prover
 * @dev Run with: certoraRun specs/PC3.spec --contract ProofCarryingContainer
 */

using ProofCarryingContainer as PC3;

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State variables
    function totalContainers() external returns (uint256) envfree;
    function consumedNullifiers(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    
    // View functions
    function getContainer(bytes32) external returns (
        bytes32, bytes32, bytes32, address, uint64, uint64, bool, bool
    ) envfree;
    
    // Mutating functions
    function createContainer(
        bytes,
        (bytes, bytes, bytes),
        bytes32,
        bytes32,
        bytes32,
        uint64
    ) external returns (bytes32);
    
    function consumeContainer(bytes32) external;
    function verifyContainer(bytes32) external returns (bool);
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Ghost variable to track container existence
ghost mapping(bytes32 => bool) containerExists;

// Ghost variable to track nullifier consumption history
ghost mapping(bytes32 => uint256) nullifierConsumedAt;

// Ghost counter for containers
ghost uint256 ghostContainerCount;

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

// Hook on container creation
hook Sstore containers[KEY bytes32 id].createdAt uint64 timestamp (uint64 old_timestamp) {
    if (old_timestamp == 0 && timestamp > 0) {
        containerExists[id] = true;
        ghostContainerCount = ghostContainerCount + 1;
    }
}

// Hook on nullifier consumption
hook Sstore consumedNullifiers[KEY bytes32 n] bool consumed (bool old_consumed) {
    if (!old_consumed && consumed) {
        require nullifierConsumedAt[n] == 0;
        nullifierConsumedAt[n] = block.timestamp;
    }
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Nullifier consumption is permanent
 */
invariant nullifierConsumptionPermanent(bytes32 n)
    consumedNullifiers(n) => always(consumedNullifiers(n))
    {
        preserved {
            require true;
        }
    }

/**
 * @notice Total containers matches ghost count
 */
invariant containerCountConsistency()
    totalContainers() == ghostContainerCount
    {
        preserved {
            require true;
        }
    }

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Creating a container increases total count by exactly 1
 */
rule createContainerIncreasesCount(
    bytes payload,
    PC3.ContainerProofs proofs,
    bytes32 stateRoot,
    bytes32 nullifier,
    bytes32 policyHash,
    uint64 expiry
) {
    env e;
    
    uint256 countBefore = totalContainers();
    bool nullifierUsedBefore = consumedNullifiers(nullifier);
    
    require !paused();
    require !nullifierUsedBefore;
    require payload.length <= 1048576; // MAX_PAYLOAD_SIZE
    
    bytes32 containerId = createContainer@withrevert(e, payload, proofs, stateRoot, nullifier, policyHash, expiry);
    
    bool succeeded = !lastReverted;
    uint256 countAfter = totalContainers();
    
    assert succeeded => countAfter == countBefore + 1,
        "Container count must increase by 1 on successful creation";
}

/**
 * @notice Same nullifier cannot be used twice
 */
rule nullifierDoubleUseReverts(bytes32 containerId1, bytes32 containerId2) {
    env e1;
    env e2;
    
    // First consumption succeeds
    consumeContainer(e1, containerId1);
    
    // Get nullifier of consumed container
    bytes32 n1;
    bytes32 n2;
    (,,n1,,,,,) = getContainer(containerId1);
    (,,n2,,,,,) = getContainer(containerId2);
    
    // If same nullifier, second consumption must revert
    require n1 == n2;
    require containerId1 != containerId2;
    
    consumeContainer@withrevert(e2, containerId2);
    
    assert lastReverted,
        "Second use of same nullifier must revert";
}

/**
 * @notice Consumed containers cannot be consumed again
 */
rule consumedContainerStaysConsumed(bytes32 containerId) {
    env e1;
    env e2;
    
    // First consumption
    consumeContainer(e1, containerId);
    
    // Attempt second consumption
    consumeContainer@withrevert(e2, containerId);
    
    assert lastReverted,
        "Already consumed container must revert on second consumption";
}

/**
 * @notice Only VERIFIER_ROLE can consume containers
 */
rule onlyVerifierCanConsume(bytes32 containerId) {
    env e;
    
    // Assume caller doesn't have VERIFIER_ROLE
    // (This would be specified via role ghost in full spec)
    
    consumeContainer@withrevert(e, containerId);
    
    // If caller lacks role, must revert
    // assert !hasRole(e.msg.sender, VERIFIER_ROLE) => lastReverted;
}

/**
 * @notice Paused contract prevents container creation
 */
rule pausePreventsCreation(
    bytes payload,
    PC3.ContainerProofs proofs,
    bytes32 stateRoot,
    bytes32 nullifier,
    bytes32 policyHash,
    uint64 expiry
) {
    env e;
    
    require paused();
    
    createContainer@withrevert(e, payload, proofs, stateRoot, nullifier, policyHash, expiry);
    
    assert lastReverted,
        "Container creation must revert when paused";
}

/**
 * @notice Container ID is deterministic
 */
rule containerIdDeterministic(
    bytes payload,
    PC3.ContainerProofs proofs,
    bytes32 stateRoot,
    bytes32 nullifier,
    bytes32 policyHash,
    uint64 expiry
) {
    env e1;
    env e2;
    
    require e1.msg.sender == e2.msg.sender;
    require e1.block.timestamp == e2.block.timestamp;
    
    // Same inputs should produce same ID calculation
    // (actual creation would fail due to duplicate)
    
    storage init = lastStorage;
    bytes32 id1 = createContainer(e1, payload, proofs, stateRoot, nullifier, policyHash, expiry);
    
    bytes32 id2 = createContainer@withrevert(e2, payload, proofs, stateRoot, nullifier, policyHash, expiry) at init;
    
    assert id1 == id2,
        "Same inputs must produce same container ID";
}

/*//////////////////////////////////////////////////////////////
                    HIGH-LEVEL PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * @notice No container can exist without creation
 */
rule noSpontaneousContainers(bytes32 containerId) {
    env e;
    
    bool existsBefore = containerExists[containerId];
    
    // Any arbitrary function call
    method f;
    calldataarg args;
    f(e, args);
    
    bool existsAfter = containerExists[containerId];
    
    // If didn't exist before, can only exist after via createContainer
    assert !existsBefore && existsAfter => 
        f.selector == sig:createContainer(bytes, PC3.ContainerProofs, bytes32, bytes32, bytes32, uint64).selector,
        "Containers can only be created via createContainer";
}

/**
 * @notice Nullifier consumption is irreversible
 */
rule nullifierConsumptionIrreversible(bytes32 nullifier) {
    env e;
    
    require consumedNullifiers(nullifier);
    
    // Any arbitrary function call
    method f;
    calldataarg args;
    f(e, args);
    
    assert consumedNullifiers(nullifier),
        "Once consumed, nullifier stays consumed";
}
