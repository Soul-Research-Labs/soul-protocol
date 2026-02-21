// SPDX-License-Identifier: MIT
// Certora CVL Specification for SoulProtocolHub

using SoulProtocolHub as hub;

// ============================================================================
//                             METHOD DECLARATIONS
// ============================================================================

methods {
    // View / Pure — envfree
    function verifierRegistry() external returns (address) envfree;
    function universalVerifier() external returns (address) envfree;
    function multiProver() external returns (address) envfree;
    function crossChainMessageRelay() external returns (address) envfree;
    function crossChainPrivacyHub() external returns (address) envfree;
    function stealthAddressRegistry() external returns (address) envfree;
    function privateRelayerNetwork() external returns (address) envfree;
    function viewKeyRegistry() external returns (address) envfree;
    function shieldedPool() external returns (address) envfree;
    function nullifierManager() external returns (address) envfree;
    function complianceOracle() external returns (address) envfree;
    function proofTranslator() external returns (address) envfree;
    function privacyRouter() external returns (address) envfree;
    function bridgeProofValidator() external returns (address) envfree;
    function bridgeWatchtower() external returns (address) envfree;
    function bridgeCircuitBreaker() external returns (address) envfree;
    function zkBoundStateLocks() external returns (address) envfree;
    function proofCarryingContainer() external returns (address) envfree;
    function crossDomainNullifierAlgebra() external returns (address) envfree;
    function policyBoundProofs() external returns (address) envfree;
    function timelock() external returns (address) envfree;
    function upgradeTimelock() external returns (address) envfree;
    function isFullyConfigured() external returns (bool) envfree;
    function isChainSupported(uint256) external returns (bool) envfree;
    function MAX_BATCH_SIZE() external returns (uint256) envfree;

    // AccessControl (OZ)
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;

    // State-changing
    function setVerifierRegistry(address) external;
    function setUniversalVerifier(address) external;
    function setMultiProver(address) external;
    function setCrossChainMessageRelay(address) external;
    function setCrossChainPrivacyHub(address) external;
    function setStealthAddressRegistry(address) external;
    function setPrivateRelayerNetwork(address) external;
    function setViewKeyRegistry(address) external;
    function setShieldedPool(address) external;
    function setNullifierManager(address) external;
    function setComplianceOracle(address) external;
    function setProofTranslator(address) external;
    function setPrivacyRouter(address) external;
    function setBridgeProofValidator(address) external;
    function setBridgeWatchtower(address) external;
    function setBridgeCircuitBreaker(address) external;
    function setZKBoundStateLocks(address) external;
    function setProofCarryingContainer(address) external;
    function setCrossDomainNullifierAlgebra(address) external;
    function setPolicyBoundProofs(address) external;
    function setTimelock(address) external;
    function setUpgradeTimelock(address) external;
    function pause() external;
    function unpause() external;
    function deactivateVerifier(bytes32) external;
    function deactivateBridge(uint256) external;
}

// ============================================================================
//                             INVARIANTS
// ============================================================================

/// @title No zero address after setVerifierRegistry
/// @notice setVerifierRegistry reverts on zero address
rule setVerifierRegistryRejectsZero() {
    env e;
    setVerifierRegistry@withrevert(e, 0);
    assert lastReverted, "setVerifierRegistry must reject zero address";
}

/// @title No zero address after setUniversalVerifier
rule setUniversalVerifierRejectsZero() {
    env e;
    setUniversalVerifier@withrevert(e, 0);
    assert lastReverted, "setUniversalVerifier must reject zero address";
}

/// @title No zero address after setCrossChainMessageRelay
rule setCrossChainMessageRelayRejectsZero() {
    env e;
    setCrossChainMessageRelay@withrevert(e, 0);
    assert lastReverted, "setCrossChainMessageRelay must reject zero address";
}

/// @title No zero address after setStealthAddressRegistry
rule setStealthAddressRegistryRejectsZero() {
    env e;
    setStealthAddressRegistry@withrevert(e, 0);
    assert lastReverted, "setStealthAddressRegistry must reject zero address";
}

/// @title No zero address after setShieldedPool
rule setShieldedPoolRejectsZero() {
    env e;
    setShieldedPool@withrevert(e, 0);
    assert lastReverted, "setShieldedPool must reject zero address";
}

/// @title No zero address after setNullifierManager
rule setNullifierManagerRejectsZero() {
    env e;
    setNullifierManager@withrevert(e, 0);
    assert lastReverted, "setNullifierManager must reject zero address";
}

/// @title No zero address for timelock (admin-only setter)
rule setTimelockRejectsZero() {
    env e;
    setTimelock@withrevert(e, 0);
    assert lastReverted, "setTimelock must reject zero address";
}

/// @title No zero address for upgradeTimelock (admin-only setter)
rule setUpgradeTimelockRejectsZero() {
    env e;
    setUpgradeTimelock@withrevert(e, 0);
    assert lastReverted, "setUpgradeTimelock must reject zero address";
}

// ============================================================================
//                       REGISTRATION PERMANENCE
// ============================================================================

/// @title verifierRegistry cannot be set to zero once non-zero
/// @notice Once registered, any method call preserves a non-zero verifierRegistry
rule verifierRegistryPermanence(method f) filtered { f -> !f.isView } {
    address before = verifierRegistry();
    require before != 0;

    env e;
    calldataarg args;
    f(e, args);

    address after = verifierRegistry();
    assert after != 0,
        "verifierRegistry must stay non-zero once registered";
}

/// @title universalVerifier cannot be set to zero once non-zero
rule universalVerifierPermanence(method f) filtered { f -> !f.isView } {
    address before = universalVerifier();
    require before != 0;

    env e;
    calldataarg args;
    f(e, args);

    address after = universalVerifier();
    assert after != 0,
        "universalVerifier must stay non-zero once registered";
}

/// @title stealthAddressRegistry cannot be set to zero once non-zero
rule stealthAddressRegistryPermanence(method f) filtered { f -> !f.isView } {
    address before = stealthAddressRegistry();
    require before != 0;

    env e;
    calldataarg args;
    f(e, args);

    address after = stealthAddressRegistry();
    assert after != 0,
        "stealthAddressRegistry must stay non-zero once registered";
}

/// @title nullifierManager cannot be set to zero once non-zero
rule nullifierManagerPermanence(method f) filtered { f -> !f.isView } {
    address before = nullifierManager();
    require before != 0;

    env e;
    calldataarg args;
    f(e, args);

    address after = nullifierManager();
    assert after != 0,
        "nullifierManager must stay non-zero once registered";
}

/// @title timelock cannot be set to zero once non-zero
rule timelockPermanence(method f) filtered { f -> !f.isView } {
    address before = timelock();
    require before != 0;

    env e;
    calldataarg args;
    f(e, args);

    address after = timelock();
    assert after != 0,
        "timelock must stay non-zero once registered";
}

// ============================================================================
//                         ACCESS CONTROL
// ============================================================================

/// @title Only OPERATOR can set verifier registry
rule onlyOperatorCanSetVerifierRegistry(address newAddr) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);

    setVerifierRegistry@withrevert(e, newAddr);
    assert lastReverted,
        "Non-operator must not set verifierRegistry";
}

/// @title Only OPERATOR can set universal verifier
rule onlyOperatorCanSetUniversalVerifier(address newAddr) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);

    setUniversalVerifier@withrevert(e, newAddr);
    assert lastReverted,
        "Non-operator must not set universalVerifier";
}

/// @title Only OPERATOR can set stealth address registry
rule onlyOperatorCanSetStealthAddressRegistry(address newAddr) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);

    setStealthAddressRegistry@withrevert(e, newAddr);
    assert lastReverted,
        "Non-operator must not set stealthAddressRegistry";
}

/// @title Only GUARDIAN can pause
rule onlyGuardianCanPause() {
    env e;
    require !hasRole(GUARDIAN_ROLE(), e.msg.sender);

    pause@withrevert(e);
    assert lastReverted,
        "Non-guardian must not be able to pause";
}

/// @title Only OPERATOR can unpause
rule onlyOperatorCanUnpause() {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);

    unpause@withrevert(e);
    assert lastReverted,
        "Non-operator must not be able to unpause";
}

/// @title Only DEFAULT_ADMIN can set timelock
rule onlyAdminCanSetTimelock(address newAddr) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setTimelock@withrevert(e, newAddr);
    assert lastReverted,
        "Non-admin must not set timelock";
}

/// @title Only DEFAULT_ADMIN can set upgrade timelock
rule onlyAdminCanSetUpgradeTimelock(address newAddr) {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setUpgradeTimelock@withrevert(e, newAddr);
    assert lastReverted,
        "Non-admin must not set upgradeTimelock";
}

/// @title Only GUARDIAN can deactivate verifier
rule onlyGuardianCanDeactivateVerifier(bytes32 vType) {
    env e;
    require !hasRole(GUARDIAN_ROLE(), e.msg.sender);

    deactivateVerifier@withrevert(e, vType);
    assert lastReverted,
        "Non-guardian must not deactivate verifier";
}

/// @title Only GUARDIAN can deactivate bridge
rule onlyGuardianCanDeactivateBridge(uint256 chainId) {
    env e;
    require !hasRole(GUARDIAN_ROLE(), e.msg.sender);

    deactivateBridge@withrevert(e, chainId);
    assert lastReverted,
        "Non-guardian must not deactivate bridge";
}

// ============================================================================
//                       isFullyConfigured CONSISTENCY
// ============================================================================

/// @title isFullyConfigured requires all critical components
/// @notice If any of the 6 critical components is zero, isFullyConfigured is false
rule fullyConfiguredRequiresAllComponents() {
    bool configured = isFullyConfigured();

    assert configured => (
        verifierRegistry() != 0 &&
        universalVerifier() != 0 &&
        stealthAddressRegistry() != 0 &&
        nullifierManager() != 0 &&
        crossChainMessageRelay() != 0 &&
        bridgeProofValidator() != 0
    ), "isFullyConfigured must be false if any critical component is zero";
}

// ============================================================================
//                   MONOTONICITY / SUPPORTEDCHAINS
// ============================================================================

/// @title Chain support is monotonic
/// @notice Once a chainId is supported, no function makes it unsupported
rule chainSupportMonotonic(method f, uint256 chainId) filtered { f -> !f.isView } {
    bool supportedBefore = isChainSupported(chainId);
    require supportedBefore;

    env e;
    calldataarg args;
    f(e, args);

    bool supportedAfter = isChainSupported(chainId);
    assert supportedAfter,
        "Supported chain must remain supported after any state change";
}
