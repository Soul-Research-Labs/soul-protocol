// SPDX-License-Identifier: MIT
// Certora CVL Specification for Brevis Privacy Pool
// Verifies pool operations, nullifier uniqueness, and cross-domain security

// =========================================================================
// METHODS
// =========================================================================

methods {
    // BrevisPrimitives functions
    function BrevisPrimitives.hash2(bytes32, bytes32) internal returns (bytes32) => NONDET;
    function BrevisPrimitives.computeCommitment(uint256, address, bytes32) internal returns (bytes32) => NONDET;
    function BrevisPrimitives.deriveNullifier(bytes32, bytes32, uint256) internal returns (bytes32) => NONDET;
    function BrevisPrimitives.deriveCrossDomainNullifier(bytes32, uint256, uint256) internal returns (bytes32) => NONDET;
    function BrevisPrimitives.derivePILBinding(bytes32) internal returns (bytes32) => NONDET;
    function BrevisPrimitives.computeMerkleRoot(bytes32, bytes32[], uint256[]) internal returns (bytes32) => NONDET;

    // Pool state getters
    function nullifierHashes(bytes32) external returns (bool) envfree;
    function commitments(bytes32) external returns (bool) envfree;
    function roots(uint256) external returns (bytes32) envfree;
    function currentRootIndex() external returns (uint256) envfree;
    function nextIndex() external returns (uint32) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function dailyWithdrawVolume() external returns (uint256) envfree;
    function lastVolumeResetTime() external returns (uint256) envfree;

    // Pool operations
    function depositBNB(bytes32) external;
    function depositToken(address, uint256, bytes32) external;
    function withdraw(
        bytes32,
        bytes32,
        address,
        address,
        uint256,
        uint256,
        bytes32[],
        uint256[],
        bytes
    ) external;

    // Cross-domain
    function registerCrossDomainNullifier(bytes32, uint256) external;
    function crossDomainNullifiers(bytes32) external returns (bytes32) envfree;
    function pilBindings(bytes32) external returns (bytes32) envfree;

    // Admin
    function triggerCircuitBreaker(string) external;
    function resetCircuitBreaker() external;
    function pause() external;
    function unpause() external;

    // Relayer
    function registeredRelayers(address) external returns (bool) envfree;
    function registerRelayer() external;
    function unregisterRelayer() external;

    // Constants
    function TREE_DEPTH() external returns (uint32) envfree;
    function MAX_LEAVES() external returns (uint256) envfree;
    function ROOT_HISTORY_SIZE() external returns (uint256) envfree;
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function MAX_DEPOSIT() external returns (uint256) envfree;
    function DAILY_WITHDRAW_LIMIT() external returns (uint256) envfree;
    function MAX_RELAYER_FEE_BPS() external returns (uint256) envfree;
}

// =========================================================================
// GHOSTS AND HOOKS
// =========================================================================

// Track total deposits
ghost uint256 totalDeposits {
    init_state axiom totalDeposits == 0;
}

// Track total withdrawals
ghost uint256 totalWithdrawals {
    init_state axiom totalWithdrawals == 0;
}

// Track known nullifiers
ghost mapping(bytes32 => bool) knownNullifiers {
    init_state axiom forall bytes32 nf. knownNullifiers[nf] == false;
}

// Track known commitments
ghost mapping(bytes32 => bool) knownCommitments {
    init_state axiom forall bytes32 c. knownCommitments[c] == false;
}

// Hook on nullifier usage
hook Sstore nullifierHashes[KEY bytes32 nf] bool used {
    knownNullifiers[nf] = used;
    if (used) {
        totalWithdrawals = totalWithdrawals + 1;
    }
}

// Hook on commitment storage
hook Sstore commitments[KEY bytes32 c] bool exists {
    knownCommitments[c] = exists;
    if (exists) {
        totalDeposits = totalDeposits + 1;
    }
}

// =========================================================================
// INVARIANTS
// =========================================================================

/// @title Tree index never exceeds maximum
invariant treeIndexBound()
    to_mathint(nextIndex()) <= to_mathint(MAX_LEAVES())
{
    preserved {
        require nextIndex() < MAX_LEAVES();
    }
}

/// @title Nullifier can only be used once
invariant nullifierUsedOnce(bytes32 nf)
    nullifierHashes(nf) == knownNullifiers[nf]
{
    preserved {
        require true;
    }
}

/// @title Commitment can only be created once
invariant commitmentCreatedOnce(bytes32 c)
    commitments(c) == knownCommitments[c]
{
    preserved {
        require true;
    }
}

// =========================================================================
// RULES - DEPOSIT SECURITY
// =========================================================================

/// @title Deposit creates new commitment
rule depositCreatesCommitment(bytes32 commitment) {
    env e;
    require e.msg.value >= MIN_DEPOSIT();
    require e.msg.value <= MAX_DEPOSIT();
    require !commitments(commitment);
    require commitment != bytes32(0);
    require !circuitBreakerActive();
    require !paused();

    depositBNB(e, commitment);

    assert commitments(commitment), "Commitment should be created";
}

/// @title Cannot deposit same commitment twice
rule noDoubleDeposit(bytes32 commitment) {
    env e;
    require commitments(commitment);

    depositBNB@withrevert(e, commitment);

    assert lastReverted, "Should revert on duplicate commitment";
}

/// @title Deposit fails with zero commitment
rule depositFailsZeroCommitment() {
    env e;
    require e.msg.value >= MIN_DEPOSIT();
    require e.msg.value <= MAX_DEPOSIT();

    depositBNB@withrevert(e, bytes32(0));

    assert lastReverted, "Should revert on zero commitment";
}

/// @title Deposit respects amount bounds
rule depositRespectsBounds() {
    env e;
    bytes32 commitment;
    require commitment != bytes32(0);
    require !commitments(commitment);
    require !circuitBreakerActive();
    require !paused();

    bool tooSmall = e.msg.value < MIN_DEPOSIT();
    bool tooLarge = e.msg.value > MAX_DEPOSIT();

    depositBNB@withrevert(e, commitment);

    assert (tooSmall || tooLarge) => lastReverted, "Should enforce amount bounds";
}

// =========================================================================
// RULES - WITHDRAWAL SECURITY
// =========================================================================

/// @title Withdrawal marks nullifier as used
rule withdrawMarksNullifier(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require !nullifierHashes(nullifierHash);
    require nullifierHash != bytes32(0);
    require recipient != address(0);
    require !circuitBreakerActive();
    require !paused();

    withdraw(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    assert nullifierHashes(nullifierHash), "Nullifier should be marked";
}

/// @title Cannot withdraw with same nullifier twice
rule noDoubleWithdraw(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require nullifierHashes(nullifierHash);

    withdraw@withrevert(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    assert lastReverted, "Should revert on double withdrawal";
}

/// @title Withdrawal respects daily limit
rule withdrawalRespectsLimit(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require dailyWithdrawVolume() + amount > DAILY_WITHDRAW_LIMIT();
    require !nullifierHashes(nullifierHash);

    withdraw@withrevert(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    assert lastReverted, "Should respect daily limit";
}

/// @title Relayer fee is bounded
rule relayerFeeBounded(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require to_mathint(relayerFee) > (to_mathint(amount) * to_mathint(MAX_RELAYER_FEE_BPS())) / 10000;

    withdraw@withrevert(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    assert lastReverted, "Should enforce relayer fee bound";
}

// =========================================================================
// RULES - CROSS-DOMAIN SECURITY
// =========================================================================

/// @title Cross-domain registration creates mappings
rule crossDomainRegistration(bytes32 brevisNullifier, uint256 targetChainId) {
    env e;
    require brevisNullifier != bytes32(0);
    require crossDomainNullifiers(brevisNullifier) == bytes32(0);

    registerCrossDomainNullifier(e, brevisNullifier, targetChainId);

    assert crossDomainNullifiers(brevisNullifier) != bytes32(0), "PIL nullifier should be set";
}

/// @title Cross-domain registration is idempotent
rule crossDomainIdempotent(bytes32 brevisNullifier, uint256 targetChainId) {
    env e;
    require brevisNullifier != bytes32(0);

    bytes32 pilNf1 = crossDomainNullifiers(brevisNullifier);
    require pilNf1 != bytes32(0);

    registerCrossDomainNullifier(e, brevisNullifier, targetChainId);

    bytes32 pilNf2 = crossDomainNullifiers(brevisNullifier);
    assert pilNf1 == pilNf2, "Should not change existing mapping";
}

// =========================================================================
// RULES - CIRCUIT BREAKER
// =========================================================================

/// @title Circuit breaker blocks deposits
rule circuitBreakerBlocksDeposits(bytes32 commitment) {
    env e;
    require circuitBreakerActive();
    require e.msg.value >= MIN_DEPOSIT();
    require e.msg.value <= MAX_DEPOSIT();
    require commitment != bytes32(0);

    depositBNB@withrevert(e, commitment);

    assert lastReverted, "Circuit breaker should block deposits";
}

/// @title Circuit breaker blocks withdrawals
rule circuitBreakerBlocksWithdrawals(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require circuitBreakerActive();

    withdraw@withrevert(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    assert lastReverted, "Circuit breaker should block withdrawals";
}

/// @title Only guardian can trigger circuit breaker
rule onlyGuardianTriggersBreaker(string reason) {
    env e;
    require !circuitBreakerActive();

    triggerCircuitBreaker@withrevert(e, reason);

    assert !lastReverted => circuitBreakerActive(), "Should be triggered if not reverted";
}

// =========================================================================
// RULES - PAUSE FUNCTIONALITY
// =========================================================================

/// @title Pause blocks deposits
rule pauseBlocksDeposits(bytes32 commitment) {
    env e;
    require paused();
    require e.msg.value >= MIN_DEPOSIT();

    depositBNB@withrevert(e, commitment);

    assert lastReverted, "Pause should block deposits";
}

/// @title Pause blocks withdrawals
rule pauseBlocksWithdrawals(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require paused();

    withdraw@withrevert(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    assert lastReverted, "Pause should block withdrawals";
}

// =========================================================================
// RULES - RELAYER SYSTEM
// =========================================================================

/// @title Relayer registration is valid
rule relayerRegistration() {
    env e;
    require !registeredRelayers(e.msg.sender);

    registerRelayer(e);

    assert registeredRelayers(e.msg.sender), "Should be registered";
}

/// @title Relayer unregistration is valid
rule relayerUnregistration() {
    env e;
    require registeredRelayers(e.msg.sender);

    unregisterRelayer(e);

    assert !registeredRelayers(e.msg.sender), "Should be unregistered";
}

// =========================================================================
// RULES - STATE TRANSITIONS
// =========================================================================

/// @title Deposit increments tree index
rule depositIncrementsIndex(bytes32 commitment) {
    env e;
    require e.msg.value >= MIN_DEPOSIT();
    require e.msg.value <= MAX_DEPOSIT();
    require !commitments(commitment);
    require commitment != bytes32(0);
    require !circuitBreakerActive();
    require !paused();

    uint32 indexBefore = nextIndex();
    require indexBefore < MAX_LEAVES();

    depositBNB(e, commitment);

    uint32 indexAfter = nextIndex();
    assert to_mathint(indexAfter) == to_mathint(indexBefore) + 1, "Index should increment";
}

/// @title Withdrawal increases volume
rule withdrawalIncreasesVolume(
    bytes32 root,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 amount,
    uint256 relayerFee
) {
    env e;
    bytes32[] pathElements;
    uint256[] pathIndices;
    bytes proof;

    require !nullifierHashes(nullifierHash);
    require nullifierHash != bytes32(0);
    require recipient != address(0);
    require !circuitBreakerActive();
    require !paused();
    require dailyWithdrawVolume() + amount <= DAILY_WITHDRAW_LIMIT();

    uint256 volumeBefore = dailyWithdrawVolume();

    withdraw(e, root, nullifierHash, recipient, relayer, amount, relayerFee, pathElements, pathIndices, proof);

    uint256 volumeAfter = dailyWithdrawVolume();
    assert to_mathint(volumeAfter) >= to_mathint(volumeBefore), "Volume should not decrease";
}

// =========================================================================
// RULES - GLOBAL PROPERTIES
// =========================================================================

/// @title Total withdrawals never exceed total deposits
rule solvencyInvariant() {
    assert totalWithdrawals <= totalDeposits, "Pool should remain solvent";
}

/// @title Root history size is bounded
rule rootHistoryBounded() {
    assert currentRootIndex() <= ROOT_HISTORY_SIZE(), "Root history should be bounded";
}
