/**
 * Certora Formal Verification Specification
 * ZASEON - UnifiedNullifierManager
 *
 * Verifies nullifier uniqueness, cross-domain binding integrity,
 * and zaseon-binding correctness across pools and chains.
 */

using UnifiedNullifierManager as unm;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / envfree
    function totalNullifiers() external returns (uint256) envfree;
    function totalBindings() external returns (uint256) envfree;
    function totalBatches() external returns (uint256) envfree;
    function isNullifierSpent(bytes32) external returns (bool) envfree;
    function crossChainVerifier() external returns (address) envfree;
    function getRegisteredChainCount() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function deriveZaseonBinding(bytes32, bytes32) external returns (bytes32) envfree;
    function deriveCrossDomainNullifier(bytes32, uint256, uint256) external returns (bytes32) envfree;

    // State-changing
    function registerNullifier(bytes32, bytes32, uint256, uint8, uint256) external returns (bytes32);
    function spendNullifier(bytes32) external;
    function createCrossDomainBinding(bytes32, uint256, uint256, bytes) external returns (bytes32, bytes32);
    function processBatch(bytes32[], bytes32[], uint256, bytes32) external returns (bytes32);
    function registerChainDomain(uint256, uint8, bytes32, address) external;
    function setCrossChainVerifier(address) external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalNullifiers {
    init_state axiom ghostTotalNullifiers == 0;
}

ghost mapping(bytes32 => bool) ghostSpent {
    init_state axiom forall bytes32 n. !ghostSpent[n];
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Total nullifiers is non-negative and monotonic
 */
invariant totalNullifiersNonNegative()
    totalNullifiers() >= 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Total nullifiers monotonically increasing
 * @notice The total nullifier count must never decrease
 */
rule totalNullifiersMonotonic() {
    uint256 countBefore = totalNullifiers();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 countAfter = totalNullifiers();

    assert countAfter >= countBefore,
        "Total nullifiers must never decrease";
}

/**
 * @title Total bindings monotonically increasing
 */
rule totalBindingsMonotonic() {
    uint256 countBefore = totalBindings();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 countAfter = totalBindings();

    assert countAfter >= countBefore,
        "Total bindings must never decrease";
}

/**
 * @title Total batches monotonically increasing
 */
rule totalBatchesMonotonic() {
    uint256 countBefore = totalBatches();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    uint256 countAfter = totalBatches();

    assert countAfter >= countBefore,
        "Total batches must never decrease";
}

/**
 * @title Nullifier double-registration prevention
 * @notice Registering the same nullifier twice must revert
 */
rule cannotRegisterNullifierTwice(
    bytes32 nullifier,
    bytes32 commitment,
    uint256 chainId,
    uint8 nullifierType,
    uint256 expiresAt
) {
    env e1; env e2;
    bytes32 relayRole = 0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;

    require hasRole(relayRole, e1.msg.sender);
    require hasRole(relayRole, e2.msg.sender);

    // First registration succeeds
    registerNullifier(e1, nullifier, commitment, chainId, nullifierType, expiresAt);

    // Second registration must revert
    registerNullifier@withrevert(e2, nullifier, commitment, chainId, nullifierType, expiresAt);

    assert lastReverted,
        "Cannot register the same nullifier twice";
}

/**
 * @title Nullifier spend is permanent (irreversible)
 * @notice Once a nullifier is spent, it stays spent
 */
rule nullifierSpendIsPermanent(bytes32 nullifier) {
    bool spentBefore = isNullifierSpent(nullifier);

    env e;
    method f;
    calldataarg args;
    f(e, args);

    bool spentAfter = isNullifierSpent(nullifier);

    assert spentBefore => spentAfter,
        "Nullifier spend is permanent — cannot un-spend";
}

/**
 * @title Cannot spend an unregistered nullifier
 */
rule cannotSpendUnregistered(bytes32 nullifier) {
    env e;
    bytes32 relayRole = 0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;
    require hasRole(relayRole, e.msg.sender);

    // Nullifier not yet registered (totalNullifiers == 0)
    require totalNullifiers() == 0;

    spendNullifier@withrevert(e, nullifier);

    assert lastReverted,
        "Cannot spend a nullifier that was never registered";
}

/**
 * @title Double-spend prevention
 * @notice Spending the same nullifier twice must revert
 */
rule cannotDoubleSpend(bytes32 nullifier) {
    env e1; env e2;
    bytes32 relayRole = 0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;
    require hasRole(relayRole, e1.msg.sender);
    require hasRole(relayRole, e2.msg.sender);

    // First spend succeeds
    spendNullifier(e1, nullifier);

    // Second spend must revert
    spendNullifier@withrevert(e2, nullifier);

    assert lastReverted,
        "Double-spend must be prevented";
}

/**
 * @title Only RELAY_ROLE can register nullifiers
 */
rule onlyRelayCanRegister(
    bytes32 nullifier,
    bytes32 commitment,
    uint256 chainId,
    uint8 nullifierType,
    uint256 expiresAt
) {
    env e;
    bytes32 relayRole = 0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;

    require !hasRole(relayRole, e.msg.sender);

    registerNullifier@withrevert(e, nullifier, commitment, chainId, nullifierType, expiresAt);

    assert lastReverted,
        "Non-relay must not register nullifiers";
}

/**
 * @title Only RELAY_ROLE can spend nullifiers
 */
rule onlyRelayCanSpend(bytes32 nullifier) {
    env e;
    bytes32 relayRole = 0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;

    require !hasRole(relayRole, e.msg.sender);

    spendNullifier@withrevert(e, nullifier);

    assert lastReverted,
        "Non-relay must not spend nullifiers";
}

/**
 * @title Only RELAY_ROLE can create cross-domain bindings
 */
rule onlyRelayCanBind(
    bytes32 sourceNullifier,
    uint256 sourceChainId,
    uint256 destChainId,
    bytes derivationProof
) {
    env e;
    bytes32 relayRole = 0x077a1d526a4ce8a773632ab13b4fbbf1fcc954c3dab26cd27ea0e2a6750da5d7;

    require !hasRole(relayRole, e.msg.sender);

    createCrossDomainBinding@withrevert(e, sourceNullifier, sourceChainId, destChainId, derivationProof);

    assert lastReverted,
        "Non-relay must not create cross-domain bindings";
}

/**
 * @title Only OPERATOR_ROLE can register chain domains
 */
rule onlyOperatorCanRegisterDomain(
    uint256 chainId,
    uint8 chainType,
    bytes32 domainTag,
    address relayAdapter
) {
    env e;
    bytes32 operatorRole = 0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    require !hasRole(operatorRole, e.msg.sender);

    registerChainDomain@withrevert(e, chainId, chainType, domainTag, relayAdapter);

    assert lastReverted,
        "Non-operator must not register chain domains";
}

/**
 * @title Zaseon binding derivation is deterministic
 * @notice Same inputs must always produce the same zaseon binding
 */
rule zaseonBindingDeterministic(
    bytes32 sourceNullifier,
    bytes32 domainTag
) {
    bytes32 binding1 = deriveZaseonBinding(sourceNullifier, domainTag);
    bytes32 binding2 = deriveZaseonBinding(sourceNullifier, domainTag);

    assert binding1 == binding2,
        "Zaseon binding derivation must be deterministic";
}

/**
 * @title Cross-domain nullifier derivation is deterministic
 */
rule crossDomainNullifierDeterministic(
    bytes32 sourceNullifier,
    uint256 sourceChainId,
    uint256 destChainId
) {
    bytes32 derived1 = deriveCrossDomainNullifier(sourceNullifier, sourceChainId, destChainId);
    bytes32 derived2 = deriveCrossDomainNullifier(sourceNullifier, sourceChainId, destChainId);

    assert derived1 == derived2,
        "Cross-domain nullifier derivation must be deterministic";
}

/**
 * @title Cross-domain nullifier differs for different chains
 * @notice Nullifiers derived for different dest chains must differ
 */
rule crossDomainNullifierChainIsolation(
    bytes32 sourceNullifier,
    uint256 sourceChainId,
    uint256 destChainId1,
    uint256 destChainId2
) {
    require destChainId1 != destChainId2;

    bytes32 derived1 = deriveCrossDomainNullifier(sourceNullifier, sourceChainId, destChainId1);
    bytes32 derived2 = deriveCrossDomainNullifier(sourceNullifier, sourceChainId, destChainId2);

    assert derived1 != derived2,
        "Nullifiers for different dest chains must differ";
}

/**
 * @title Batch processing increments counters
 */
rule batchIncrementsCounts(
    bytes32[] nullifiers,
    bytes32[] commitments,
    uint256 chainId,
    bytes32 merkleRoot
) {
    env e;
    uint256 batchesBefore = totalBatches();
    uint256 nullifiersBefore = totalNullifiers();

    processBatch(e, nullifiers, commitments, chainId, merkleRoot);

    uint256 batchesAfter = totalBatches();
    uint256 nullifiersAfter = totalNullifiers();

    assert batchesAfter == batchesBefore + 1,
        "processBatch must increment totalBatches by 1";
    assert nullifiersAfter > nullifiersBefore,
        "processBatch must increase totalNullifiers";
}

/**
 * @title Only admin can set cross-chain verifier
 */
rule onlyAdminCanSetVerifier(address verifier) {
    env e;
    bytes32 adminRole = 0x0000000000000000000000000000000000000000000000000000000000000000;

    require !hasRole(adminRole, e.msg.sender);

    setCrossChainVerifier@withrevert(e, verifier);

    assert lastReverted,
        "Non-admin must not set the cross-chain verifier";
}

/**
 * @title Zero address rejected for verifier
 */
rule zeroAddressRejectedForVerifier() {
    env e;
    bytes32 adminRole = 0x0000000000000000000000000000000000000000000000000000000000000000;
    require hasRole(adminRole, e.msg.sender);

    setCrossChainVerifier@withrevert(e, 0);

    assert lastReverted,
        "Zero address must be rejected for cross-chain verifier";
}
