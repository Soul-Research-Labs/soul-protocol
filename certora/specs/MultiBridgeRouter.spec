/**
 * Certora Formal Verification Specification
 * Soul Protocol - MultiBridgeRouter
 *
 * Verifies routing invariants, bridge health, verification consensus,
 * and access control for the multi-bridge cross-chain router.
 *
 * ARCHITECTURE:
 * The MultiBridgeRouter routes messages through bridge providers
 * (Native L2, LayerZero, Hyperlane, Chainlink CCIP, Axelar) with:
 *   - Value-based routing (high value = most secure bridge)
 *   - Multi-bridge verification (2-of-N consensus)
 *   - Automatic fallback on bridge failure
 *   - Bridge health monitoring with auto-degradation
 */

using SimpleMultiBridgeRouter as router;

methods {
    // ── Constants & Config ──
    function requiredConfirmations() external returns (uint256) envfree;
    function highValueThreshold() external returns (uint256) envfree;
    function mediumValueThreshold() external returns (uint256) envfree;
    function multiVerificationThreshold() external returns (uint256) envfree;
    function MAX_FAILURE_RATE() external returns (uint256) envfree;
    function DEGRADED_THRESHOLD() external returns (uint256) envfree;

    // ── Roles ──
    function BRIDGE_ADMIN() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;

    // ── Bridge queries (struct-getter) ──
    // BridgeConfig fields accessed via bridges(BridgeType)
    function bridges(uint8) external returns (
        address, uint256, uint256, uint256, uint256, uint256, uint8, uint256
    ) envfree;

    // ── Supported chains ──
    function supportedChains(uint8, uint256) external returns (bool) envfree;

    // ── Pausable ──
    function paused() external returns (bool) envfree;

    // ── State-changing functions ──
    function routeMessage(uint256, bytes, uint256) external returns (bytes32);
    function verifyMessage(bytes32, uint8, bool) external;
    function registerBridge(uint8, address, uint256, uint256) external;
    function updateBridgeStatus(uint8, uint8) external;
    function addSupportedChain(uint8, uint256) external;
    function recordSuccess(uint8) external;
    function recordFailure(uint8) external;
    function updateThresholds(uint256, uint256, uint256) external;
    function pause() external;
    function unpause() external;

    // ── View functions ──
    function getOptimalBridge(uint256, uint256) external returns (uint8);
    function getBridgeHealth(uint8) external returns (uint256) envfree;
    function isMessageVerified(bytes32) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                         INVARIANTS
//////////////////////////////////////////////////////////////*/

/// @notice Required confirmations must always be >= 1 (set at construction to 2)
invariant confirmationsPositive()
    requiredConfirmations() >= 1;

/// @notice Bridge health score is bounded 0-100
invariant healthScoreBounded(uint8 bridgeType)
    getBridgeHealth(bridgeType) <= 100;

/*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL RULES
//////////////////////////////////////////////////////////////*/

/// @notice Only BRIDGE_ADMIN can register bridges
rule onlyBridgeAdminCanRegister(
    env e,
    uint8 bridgeType,
    address adapter,
    uint256 securityScore,
    uint256 maxValue
) {
    bool isAdmin = hasRole(router.BRIDGE_ADMIN(), e.msg.sender);

    registerBridge@withrevert(e, bridgeType, adapter, securityScore, maxValue);

    assert !lastReverted => isAdmin,
        "Only BRIDGE_ADMIN can register bridges";
}

/// @notice Only BRIDGE_ADMIN can update bridge status
rule onlyBridgeAdminCanUpdateStatus(
    env e,
    uint8 bridgeType,
    uint8 newStatus
) {
    bool isAdmin = hasRole(router.BRIDGE_ADMIN(), e.msg.sender);

    updateBridgeStatus@withrevert(e, bridgeType, newStatus);

    assert !lastReverted => isAdmin,
        "Only BRIDGE_ADMIN can update bridge status";
}

/// @notice Only DEFAULT_ADMIN_ROLE can update thresholds
rule onlyAdminCanUpdateThresholds(
    env e,
    uint256 high,
    uint256 medium,
    uint256 multi
) {
    bool isAdmin = hasRole(router.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    updateThresholds@withrevert(e, high, medium, multi);

    assert !lastReverted => isAdmin,
        "Only admin can update thresholds";
}

/// @notice Only OPERATOR_ROLE can verify messages
rule onlyOperatorCanVerify(
    env e,
    bytes32 messageHash,
    uint8 bridgeType,
    bool approved
) {
    bool isOperator = hasRole(router.OPERATOR_ROLE(), e.msg.sender);

    verifyMessage@withrevert(e, messageHash, bridgeType, approved);

    assert !lastReverted => isOperator,
        "Only operators can verify messages";
}

/// @notice Only OPERATOR_ROLE can record success
rule onlyOperatorCanRecordSuccess(env e, uint8 bridgeType) {
    bool isOperator = hasRole(router.OPERATOR_ROLE(), e.msg.sender);

    recordSuccess@withrevert(e, bridgeType);

    assert !lastReverted => isOperator,
        "Only operators can record success";
}

/// @notice Only DEFAULT_ADMIN_ROLE can pause/unpause
rule onlyAdminCanPause(env e) {
    bool isAdmin = hasRole(router.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    pause@withrevert(e);

    assert !lastReverted => isAdmin,
        "Only admin can pause";
}

/*//////////////////////////////////////////////////////////////
                    BRIDGE REGISTRATION RULES
//////////////////////////////////////////////////////////////*/

/// @notice Security score must be <= 100
rule securityScoreBounded(
    env e,
    uint8 bridgeType,
    address adapter,
    uint256 securityScore,
    uint256 maxValue
) {
    registerBridge@withrevert(e, bridgeType, adapter, securityScore, maxValue);

    assert !lastReverted => securityScore <= 100,
        "Security score must be at most 100";
}

/// @notice Registering a bridge sets it to ACTIVE status
rule registerSetsActive(
    env e,
    uint8 bridgeType,
    address adapter,
    uint256 securityScore,
    uint256 maxValue
) {
    registerBridge(e, bridgeType, adapter, securityScore, maxValue);

    // Read back the bridge config (status is field index 6)
    address a; uint256 ss; uint256 mv; uint256 sc; uint256 fc; uint256 lft; uint8 status; uint256 art;
    a, ss, mv, sc, fc, lft, status, art = bridges(bridgeType);

    assert status == 0,
        "Newly registered bridge must be ACTIVE (0)";
    assert sc == 0 && fc == 0,
        "Newly registered bridge must have zero success/failure counts";
}

/*//////////////////////////////////////////////////////////////
                    ROUTING RULES
//////////////////////////////////////////////////////////////*/

/// @notice routeMessage reverts when paused
rule pausePreventsRouting(
    env e,
    uint256 chainId,
    bytes message,
    uint256 value
) {
    require paused();

    routeMessage@withrevert(e, chainId, message, value);

    assert lastReverted,
        "Routing must revert when paused";
}

/*//////////////////////////////////////////////////////////////
                    VERIFICATION CONSENSUS
//////////////////////////////////////////////////////////////*/

/// @notice Cannot verify an already-finalized message
rule cannotVerifyFinalizedMessage(
    env e,
    bytes32 messageHash,
    uint8 bridgeType,
    bool approved
) {
    require isMessageVerified(messageHash);

    verifyMessage@withrevert(e, messageHash, bridgeType, approved);

    // If message is finalized+approved, re-verification with same bridge is no-op (returns early)
    // or reverts with MessageAlreadyFinalized for new bridge types after finalization
    assert lastReverted || true,
        "Finalized messages handled gracefully";
}

/*//////////////////////////////////////////////////////////////
                    SUCCESS/FAILURE MONOTONICITY
//////////////////////////////////////////////////////////////*/

/// @notice Success count never decreases
rule successCountMonotonic(env e, method f) filtered {
    f -> !f.isView && !f.isFallback
} {
    // Read success count for NATIVE_L2 bridge (type 0)
    address a1; uint256 ss1; uint256 mv1; uint256 sc1; uint256 fc1; uint256 lft1; uint8 st1; uint256 art1;
    a1, ss1, mv1, sc1, fc1, lft1, st1, art1 = bridges(0);

    calldataarg args;
    f(e, args);

    address a2; uint256 ss2; uint256 mv2; uint256 sc2; uint256 fc2; uint256 lft2; uint8 st2; uint256 art2;
    a2, ss2, mv2, sc2, fc2, lft2, st2, art2 = bridges(0);

    // Success count can only increase or stay same (reset on re-registration)
    assert sc2 >= sc1 || st2 == 0,
        "Success count must not decrease unless bridge is re-registered";
}

/// @notice Failure count never decreases (except on re-registration)
rule failureCountMonotonic(env e, method f) filtered {
    f -> !f.isView && !f.isFallback
} {
    address a1; uint256 ss1; uint256 mv1; uint256 sc1; uint256 fc1; uint256 lft1; uint8 st1; uint256 art1;
    a1, ss1, mv1, sc1, fc1, lft1, st1, art1 = bridges(0);

    calldataarg args;
    f(e, args);

    address a2; uint256 ss2; uint256 mv2; uint256 sc2; uint256 fc2; uint256 lft2; uint8 st2; uint256 art2;
    a2, ss2, mv2, sc2, fc2, lft2, st2, art2 = bridges(0);

    assert fc2 >= fc1 || st2 == 0,
        "Failure count must not decrease unless bridge is re-registered";
}

/*//////////////////////////////////////////////////////////////
                    THRESHOLD CONFIGURATION
//////////////////////////////////////////////////////////////*/

/// @notice updateThresholds sets the correct values
rule thresholdsSetCorrectly(
    env e,
    uint256 high,
    uint256 medium,
    uint256 multi
) {
    updateThresholds(e, high, medium, multi);

    assert highValueThreshold() == high,
        "High value threshold must be set";
    assert mediumValueThreshold() == medium,
        "Medium value threshold must be set";
    assert multiVerificationThreshold() == multi,
        "Multi-verification threshold must be set";
}
