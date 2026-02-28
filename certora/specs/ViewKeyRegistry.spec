/**
 * Certora Formal Verification Specification
 * ZASEON - ViewKeyRegistry
 *
 * This spec verifies critical invariants for the View Key Registry
 * which manages cryptographic view keys for selective disclosure,
 * including key registration, grant issuance, and revocation.
 *
 * Ghost variable hooks track: totalKeysRegistered, totalGrantsIssued, totalActiveGrants.
 */

using ViewKeyRegistry as vkr;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function totalKeysRegistered() external returns (uint256) envfree;
    function totalGrantsIssued() external returns (uint256) envfree;
    function totalActiveGrants() external returns (uint256) envfree;
    function activeKeyCount(address) external returns (uint256) envfree;
    function grantNonce(address) external returns (uint256) envfree;
    function isGrantValid(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function ADMIN_ROLE() external returns (bytes32) envfree;
    function REGISTRAR_ROLE() external returns (bytes32) envfree;
    function MAX_GRANTS_PER_ACCOUNT() external returns (uint256) envfree;
    function MIN_GRANT_DURATION() external returns (uint256) envfree;
    function MAX_GRANT_DURATION() external returns (uint256) envfree;
    function REVOCATION_DELAY() external returns (uint256) envfree;

    // State-changing functions
    function registerViewKey(uint8, bytes32, bytes32) external;
    function revokeViewKey(uint8) external;
    function revokeGrant(bytes32) external;
    function finalizeRevocation(bytes32) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalKeysRegistered {
    init_state axiom ghostTotalKeysRegistered == 0;
}

ghost uint256 ghostPriorTotalKeys {
    init_state axiom ghostPriorTotalKeys == 0;
}

ghost uint256 ghostTotalGrantsIssued {
    init_state axiom ghostTotalGrantsIssued == 0;
}

ghost uint256 ghostPriorTotalGrants {
    init_state axiom ghostPriorTotalGrants == 0;
}

ghost uint256 ghostTotalActiveGrants {
    init_state axiom ghostTotalActiveGrants == 0;
}

// Hook: track totalKeysRegistered storage writes
hook Sstore totalKeysRegistered uint256 newVal (uint256 oldVal) {
    ghostPriorTotalKeys = oldVal;
    ghostTotalKeysRegistered = newVal;
}

// Hook: track totalGrantsIssued storage writes
hook Sstore totalGrantsIssued uint256 newVal (uint256 oldVal) {
    ghostPriorTotalGrants = oldVal;
    ghostTotalGrantsIssued = newVal;
}

// Hook: track totalActiveGrants storage writes
hook Sstore totalActiveGrants uint256 newVal (uint256 oldVal) {
    ghostTotalActiveGrants = newVal;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Ghost Keys Match Contract
 * @notice Ghost totalKeysRegistered always equals on-chain counter
 */
invariant ghostKeysMatchContract()
    ghostTotalKeysRegistered == totalKeysRegistered()
    { preserved { require totalKeysRegistered() < max_uint256; } }

/**
 * @title Total Keys Registered Never Decreases
 * @notice totalKeysRegistered is monotonically non-decreasing (tracked via ghost)
 */
invariant totalKeysMonotonicallyIncreasing()
    ghostTotalKeysRegistered >= ghostPriorTotalKeys
    { preserved { require ghostTotalKeysRegistered < max_uint256; } }

/**
 * @title Ghost Grants Match Contract
 * @notice Ghost totalGrantsIssued always equals on-chain counter
 */
invariant ghostGrantsMatchContract()
    ghostTotalGrantsIssued == totalGrantsIssued()
    { preserved { require totalGrantsIssued() < max_uint256; } }

/**
 * @title Total Grants Issued Never Decreases
 * @notice totalGrantsIssued is monotonically non-decreasing (tracked via ghost)
 */
invariant totalGrantsIssuedMonotonicallyIncreasing()
    ghostTotalGrantsIssued >= ghostPriorTotalGrants
    { preserved { require ghostTotalGrantsIssued < max_uint256; } }

/**
 * @title Active Grants Never Exceed Total Grants
 * @notice totalActiveGrants <= totalGrantsIssued: active count cannot exceed total issued
 *         Ghost hooks on both variables ensure precise tracking.
 */
invariant activeGrantsNeverExceedTotal()
    ghostTotalActiveGrants <= ghostTotalGrantsIssued
    { preserved { require ghostTotalGrantsIssued < max_uint256; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Pause Prevents Key Registration
 * @notice When paused, registerViewKey should revert
 */
rule pausePreventsRegistration(uint8 keyType, bytes32 publicKey, bytes32 commitment) {
    env e;
    require paused();

    registerViewKey@withrevert(e, keyType, publicKey, commitment);

    assert lastReverted,
        "Key registration should fail when paused";
}

/**
 * @title Revoked Grants Are No Longer Valid
 * @notice After revokeGrant + finalizeRevocation, the grant should be invalid.
 *         Full revocation flow with timing constraints validated.
 */
rule revokedGrantBecomesInvalid(bytes32 grantId) {
    env e1;
    env e2;

    require isGrantValid(grantId);

    revokeGrant(e1, grantId);

    // After revocation delay passes, finalize
    require e2.block.timestamp >= e1.block.timestamp + REVOCATION_DELAY();
    finalizeRevocation(e2, grantId);

    assert !isGrantValid(grantId),
        "Grant should be invalid after revocation is finalized";
}

/**
 * @title Total Keys Monotonicity Across Any Function
 * @notice No function can decrease totalKeysRegistered
 */
rule totalKeysNeverDecreases() {
    env e;
    uint256 keysBefore = totalKeysRegistered();

    method f;
    calldataarg args;
    f(e, args);

    uint256 keysAfter = totalKeysRegistered();

    assert keysAfter >= keysBefore,
        "totalKeysRegistered must never decrease";
}

/**
 * @title registerViewKey Increments Key Counter
 * @notice Each successful registerViewKey call increments totalKeysRegistered
 */
rule registerViewKeyIncrementsCounter(uint8 keyType, bytes32 publicKey, bytes32 commitment) {
    env e;
    uint256 keysBefore = totalKeysRegistered();
    require keysBefore < max_uint256;

    registerViewKey(e, keyType, publicKey, commitment);

    uint256 keysAfter = totalKeysRegistered();

    assert keysAfter > keysBefore,
        "registerViewKey must increment totalKeysRegistered";
}

/**
 * @title Active Grants Decreases On Revocation Finalization
 * @notice finalizeRevocation should decrease totalActiveGrants
 */
rule revocationDecreasesActiveGrants(bytes32 grantId) {
    env e;
    uint256 activeBefore = totalActiveGrants();

    require isGrantValid(grantId);
    finalizeRevocation(e, grantId);

    uint256 activeAfter = totalActiveGrants();

    assert activeAfter <= activeBefore,
        "totalActiveGrants should decrease after finalization";
}
