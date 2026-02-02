/**
 * @title Certora Verification Rules for ExecutionAgnosticStateCommitments
 * @notice Machine-verifiable specifications for execution-agnostic state verification
 * @dev Run with: certoraRun specs/EASC.spec --contract ExecutionAgnosticStateCommitments
 */

using ExecutionAgnosticStateCommitments as EASC;

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State variables
    function totalCommitments() external returns (uint256) envfree;
    function totalBackends() external returns (uint256) envfree;
    function requiredAttestations() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    
    // View functions
    function getCommitment(bytes32) external returns (
        bytes32, bytes32, bytes32, address, uint256, uint256, bool, uint256
    ) envfree;
    function getBackend(bytes32) external returns (
        uint8, string, bytes32, bytes32, bool, uint256
    ) envfree;
    function isBackendActive(bytes32) external returns (bool) envfree;
    function hasBackendAttested(bytes32, bytes32) external returns (bool) envfree;
    
    // Mutating functions
    function createCommitment(bytes32, bytes32, bytes32) external returns (bytes32);
    function attestCommitment(bytes32, bytes32, bytes, bytes32) external;
    function registerBackend(uint8, string, bytes32, bytes32) external returns (bytes32);
    function deactivateBackend(bytes32) external;
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost mapping(bytes32 => bool) commitmentExists;
ghost mapping(bytes32 => uint256) commitmentAttestationCount;
ghost mapping(bytes32 => bool) commitmentFinalized;
ghost mapping(bytes32 => bool) backendActive;
ghost uint256 ghostCommitmentCount;
ghost uint256 ghostBackendCount;

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore commitments[KEY bytes32 id].createdAt uint256 timestamp (uint256 old_timestamp) {
    if (old_timestamp == 0 && timestamp > 0) {
        commitmentExists[id] = true;
        ghostCommitmentCount = ghostCommitmentCount + 1;
    }
}

hook Sstore commitments[KEY bytes32 id].attestationCount uint256 count (uint256 old_count) {
    commitmentAttestationCount[id] = count;
}

hook Sstore commitments[KEY bytes32 id].isFinalized bool finalized (bool old_finalized) {
    if (!old_finalized && finalized) {
        commitmentFinalized[id] = true;
    }
}

hook Sstore backends[KEY bytes32 id].isActive bool active (bool old_active) {
    backendActive[id] = active;
    if (!old_active && active) {
        ghostBackendCount = ghostBackendCount + 1;
    }
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Commitment count consistency
 */
invariant commitmentCountConsistent()
    totalCommitments() == ghostCommitmentCount
    {
        preserved {
            require true;
        }
    }

/**
 * @notice Finalization is permanent
 */
invariant finalizationPermanent(bytes32 commitmentId)
    commitmentFinalized[commitmentId] => always(commitmentFinalized[commitmentId])
    {
        preserved {
            require true;
        }
    }

/**
 * @notice Attestation count never decreases
 */
invariant attestationCountMonotonic(bytes32 commitmentId)
    commitmentAttestationCount[commitmentId] >= old(commitmentAttestationCount[commitmentId])
    {
        preserved {
            require true;
        }
    }

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Creating commitment increases count by 1
 */
rule createCommitmentIncreasesCount(
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 nullifier
) {
    env e;
    
    uint256 countBefore = totalCommitments();
    
    require !paused();
    
    bytes32 commitmentId = createCommitment@withrevert(e, stateHash, transitionHash, nullifier);
    
    bool succeeded = !lastReverted;
    uint256 countAfter = totalCommitments();
    
    assert succeeded => countAfter == countBefore + 1,
        "Commitment count must increase by 1 on successful creation";
}

/**
 * @notice Same nullifier cannot be used twice
 */
rule nullifierUniqueness(
    bytes32 stateHash1,
    bytes32 stateHash2,
    bytes32 transitionHash1,
    bytes32 transitionHash2,
    bytes32 nullifier
) {
    env e1;
    env e2;
    
    require !paused();
    
    createCommitment(e1, stateHash1, transitionHash1, nullifier);
    
    createCommitment@withrevert(e2, stateHash2, transitionHash2, nullifier);
    
    assert lastReverted,
        "Same nullifier cannot be used for multiple commitments";
}

/**
 * @notice Attestation increases count by 1
 */
rule attestationIncreasesCount(
    bytes32 commitmentId,
    bytes32 backendId,
    bytes attestationProof,
    bytes32 executionHash
) {
    env e;
    
    uint256 countBefore;
    (,,,,,, , countBefore) = getCommitment(commitmentId);
    
    require commitmentExists[commitmentId];
    require isBackendActive(backendId);
    require !hasBackendAttested(commitmentId, backendId);
    
    attestCommitment@withrevert(e, commitmentId, backendId, attestationProof, executionHash);
    
    bool succeeded = !lastReverted;
    
    uint256 countAfter;
    (,,,,,, , countAfter) = getCommitment(commitmentId);
    
    assert succeeded => countAfter == countBefore + 1,
        "Attestation count must increase by 1";
}

/**
 * @notice Backend cannot attest same commitment twice
 */
rule noDoubleAttestation(
    bytes32 commitmentId,
    bytes32 backendId,
    bytes proof1,
    bytes proof2,
    bytes32 hash1,
    bytes32 hash2
) {
    env e1;
    env e2;
    
    require commitmentExists[commitmentId];
    require isBackendActive(backendId);
    
    attestCommitment(e1, commitmentId, backendId, proof1, hash1);
    
    attestCommitment@withrevert(e2, commitmentId, backendId, proof2, hash2);
    
    assert lastReverted,
        "Backend cannot attest same commitment twice";
}

/**
 * @notice Finalization requires minimum attestations
 */
rule finalizationRequiresMinAttestations(bytes32 commitmentId) {
    env e;
    
    uint256 required = requiredAttestations();
    
    bool isFinalizedBefore;
    uint256 attestationsBefore;
    (,,,,,, isFinalizedBefore, attestationsBefore) = getCommitment(commitmentId);
    
    require !isFinalizedBefore;
    require attestationsBefore < required;
    
    // Any operation
    method f;
    calldataarg args;
    f(e, args);
    
    bool isFinalizedAfter;
    uint256 attestationsAfter;
    (,,,,,, isFinalizedAfter, attestationsAfter) = getCommitment(commitmentId);
    
    assert attestationsAfter < required => !isFinalizedAfter,
        "Cannot finalize with fewer than required attestations";
}

/**
 * @notice Only active backends can attest
 */
rule onlyActiveBackendsAttest(
    bytes32 commitmentId,
    bytes32 backendId,
    bytes proof,
    bytes32 hash
) {
    env e;
    
    require !isBackendActive(backendId);
    
    attestCommitment@withrevert(e, commitmentId, backendId, proof, hash);
    
    assert lastReverted,
        "Inactive backend cannot attest";
}

/**
 * @notice Backend deactivation is permanent
 */
rule backendDeactivationPermanent(bytes32 backendId) {
    env e1;
    env e2;
    
    require isBackendActive(backendId);
    
    deactivateBackend(e1, backendId);
    
    assert !isBackendActive(backendId),
        "Backend must be inactive after deactivation";
    
    // Any subsequent operation
    method f;
    calldataarg args;
    f(e2, args);
    
    assert !isBackendActive(backendId),
        "Deactivated backend cannot be reactivated";
}

/*//////////////////////////////////////////////////////////////
                    HIGH-LEVEL PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Multi-backend security - finalization requires heterogeneous attestation
 */
rule heterogeneousAttestationRequired(bytes32 commitmentId) {
    env e;
    
    // If requiredAttestations > 1, cannot finalize with single backend
    uint256 required = requiredAttestations();
    require required > 1;
    
    bool finalized;
    uint256 attestations;
    (,,,,,, finalized, attestations) = getCommitment(commitmentId);
    
    assert finalized => attestations >= required,
        "Finalization requires multiple backend attestations";
}

/**
 * @notice State hash immutability after creation
 */
rule stateHashImmutable(bytes32 commitmentId) {
    env e;
    
    bytes32 hashBefore;
    (hashBefore,,,,,,,) = getCommitment(commitmentId);
    
    require commitmentExists[commitmentId];
    
    // Any operation
    method f;
    calldataarg args;
    f(e, args);
    
    bytes32 hashAfter;
    (hashAfter,,,,,,,) = getCommitment(commitmentId);
    
    assert hashBefore == hashAfter,
        "State hash cannot change after commitment creation";
}
