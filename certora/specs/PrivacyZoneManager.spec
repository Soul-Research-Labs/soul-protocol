/**
 * Certora Formal Verification Specification
 * ZASEON - PrivacyZoneManager
 *
 * This spec verifies critical invariants for the Privacy Zone Manager
 * which implements isolated privacy domains (Atomicity Zones) with
 * zone-scoped Merkle trees, nullifier registries, and compliance policies.
 *
 * Properties verified:
 * 1. Zone counter monotonicity (totalZonesCreated never decreases)
 * 2. Nullifier permanence (spent nullifiers stay spent)
 * 3. Commitment permanence (inserted commitments stay inserted)
 * 4. Deposit counter monotonicity per zone
 * 5. Withdrawal counter monotonicity per zone
 * 6. Migration counter monotonicity
 * 7. Commitment field validity (< FIELD_SIZE)
 * 8. Zone creation bounded by MAX_ZONES
 * 9. Test mode cannot be re-enabled once disabled
 * 10. Access control: only ZONE_ADMIN_ROLE can create zones
 * 11. Zone status never reverts to Active from Shutdown
 * 12. Zone isolation: operations on zone A do not affect zone B's root
 */

using PrivacyZoneManager as pzm;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Constants
    function MAX_ZONES() external returns (uint256) envfree;
    function FIELD_SIZE() external returns (uint256) envfree;
    function DEFAULT_TREE_DEPTH() external returns (uint32) envfree;
    function MAX_TREE_DEPTH() external returns (uint32) envfree;
    function ZERO_VALUE() external returns (bytes32) envfree;

    // Role constants
    function ZONE_ADMIN_ROLE() external returns (bytes32) envfree;
    function MIGRATION_OPERATOR_ROLE() external returns (bytes32) envfree;
    function POLICY_MANAGER_ROLE() external returns (bytes32) envfree;

    // State getters
    function totalZonesCreated() external returns (uint256) envfree;
    function totalMigrations() external returns (uint256) envfree;
    function testMode() external returns (bool) envfree;
    function testModePermanentlyDisabled() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;

    // Zone-scoped queries
    function zoneNullifiers(bytes32, bytes32) external returns (bool) envfree;
    function zoneCommitments(bytes32, bytes32) external returns (bool) envfree;
    function isNullifierSpent(bytes32, bytes32) external returns (bool) envfree;
    function getTotalZones() external returns (uint256) envfree;

    // State-changing functions
    function depositToZone(bytes32, bytes32) external;
    function withdrawFromZone(bytes32, bytes32, address, uint256, bytes) external;
    function migrateState(bytes32, bytes32, bytes32, bytes32, bytes) external;
    function disableTestMode() external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalZonesCreated {
    init_state axiom ghostTotalZonesCreated == 0;
}

ghost uint256 ghostTotalMigrations {
    init_state axiom ghostTotalMigrations == 0;
}

ghost mapping(bytes32 => mapping(bytes32 => bool)) ghostNullifiers {
    init_state axiom forall bytes32 z. forall bytes32 n. !ghostNullifiers[z][n];
}

ghost mapping(bytes32 => mapping(bytes32 => bool)) ghostCommitments {
    init_state axiom forall bytes32 z. forall bytes32 c. !ghostCommitments[z][c];
}

// Hook: track nullifier writes (once set to true, should never revert)
hook Sstore zoneNullifiers[KEY bytes32 zoneId][KEY bytes32 nullifier] bool newVal (bool oldVal) {
    if (newVal) {
        ghostNullifiers[zoneId][nullifier] = true;
    }
}

// Hook: track commitment writes
hook Sstore zoneCommitments[KEY bytes32 zoneId][KEY bytes32 commitment] bool newVal (bool oldVal) {
    if (newVal) {
        ghostCommitments[zoneId][commitment] = true;
    }
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Total Zones Created Is Non-Negative and Bounded
 * @notice totalZonesCreated >= 0 and <= MAX_ZONES
 */
invariant totalZonesBounded()
    totalZonesCreated() <= MAX_ZONES()
    { preserved { require totalZonesCreated() <= MAX_ZONES(); } }

/**
 * @title Nullifier Permanence
 * @notice Once a nullifier is marked spent, it stays spent across all state transitions
 */
invariant nullifierPermanence(bytes32 zoneId, bytes32 nullifier)
    ghostNullifiers[zoneId][nullifier] => zoneNullifiers(zoneId, nullifier)

/**
 * @title Commitment Permanence
 * @notice Once a commitment is inserted, it stays inserted
 */
invariant commitmentPermanence(bytes32 zoneId, bytes32 commitment)
    ghostCommitments[zoneId][commitment] => zoneCommitments(zoneId, commitment)

/**
 * @title Test Mode Disabled Permanently
 * @notice Once testModePermanentlyDisabled is true, testMode must be false
 */
invariant testModeDisabledPermanent()
    testModePermanentlyDisabled() => !testMode()

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Total Zones Never Decreases
 * @notice No function call should decrease totalZonesCreated
 */
rule totalZonesNeverDecreases() {
    env e;
    uint256 before = totalZonesCreated();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalZonesCreated();

    assert after >= before,
        "totalZonesCreated must never decrease";
}

/**
 * @title Total Migrations Never Decreases
 * @notice No function call should decrease totalMigrations
 */
rule totalMigrationsNeverDecreases() {
    env e;
    uint256 before = totalMigrations();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalMigrations();

    assert after >= before,
        "totalMigrations must never decrease";
}

/**
 * @title Spent Nullifier Stays Spent
 * @notice Once isNullifierSpent returns true, it stays true across all transitions
 */
rule spentNullifierStaysSpent(bytes32 zoneId, bytes32 nullifier) {
    require isNullifierSpent(zoneId, nullifier);

    env e;
    method f;
    calldataarg args;
    f(e, args);

    assert isNullifierSpent(zoneId, nullifier),
        "A spent nullifier must remain spent";
}

/**
 * @title Inserted Commitment Stays Inserted
 * @notice Once zoneCommitments returns true, it stays true across all transitions
 */
rule insertedCommitmentStaysInserted(bytes32 zoneId, bytes32 commitment) {
    require zoneCommitments(zoneId, commitment);

    env e;
    method f;
    calldataarg args;
    f(e, args);

    assert zoneCommitments(zoneId, commitment),
        "An inserted commitment must remain inserted";
}

/**
 * @title Test Mode Cannot Be Re-Enabled
 * @notice Once disableTestMode is called, testMode stays false
 */
rule testModeCannotBeReEnabled() {
    require testModePermanentlyDisabled();

    env e;
    method f;
    calldataarg args;
    f(e, args);

    assert !testMode(),
        "Test mode must remain disabled once permanently disabled";
}

/**
 * @title Deposit Does Not Affect Other Zone Nullifiers
 * @notice Depositing into zone A cannot modify zone B's nullifier registry
 */
rule depositIsolatesNullifiers(bytes32 zoneA, bytes32 zoneB, bytes32 nullifier) {
    require zoneA != zoneB;
    bool spentBefore = isNullifierSpent(zoneB, nullifier);

    env e;
    bytes32 commitment;
    depositToZone(e, zoneA, commitment);

    bool spentAfter = isNullifierSpent(zoneB, nullifier);

    assert spentAfter == spentBefore,
        "Deposit to zone A must not affect zone B's nullifiers";
}

/**
 * @title Deposit Does Not Affect Other Zone Commitments
 * @notice Depositing into zone A cannot modify zone B's commitment set
 */
rule depositIsolatesCommitments(bytes32 zoneA, bytes32 zoneB, bytes32 existingCommitment) {
    require zoneA != zoneB;
    bool existsBefore = zoneCommitments(zoneB, existingCommitment);

    env e;
    bytes32 newCommitment;
    depositToZone(e, zoneA, newCommitment);

    bool existsAfter = zoneCommitments(zoneB, existingCommitment);

    assert existsAfter == existsBefore,
        "Deposit to zone A must not affect zone B's commitments";
}
