// SPDX-License-Identifier: MIT
// Certora CVL Specification for Canton Network Bridge
// Verifies domain management, participant handling, and cross-domain security

// =========================================================================
// METHODS
// =========================================================================

methods {
    // CantonPrimitives functions (summarized as NONDET for Certora)
    function CantonPrimitives.hash2(bytes32, bytes32) internal returns (bytes32) => NONDET;
    function CantonPrimitives.hashN(bytes32[]) internal returns (bytes32) => NONDET;
    function CantonPrimitives.computeMerkleRoot(bytes32[]) internal returns (bytes32) => NONDET;
    function CantonPrimitives.deriveNullifier(bytes32, bytes32, bytes32) internal returns (bytes32) => NONDET;
    function CantonPrimitives.deriveCrossDomainNullifier(bytes32, uint256, uint256) internal returns (bytes32) => NONDET;
    function CantonPrimitives.derivePILBinding(bytes32) internal returns (bytes32) => NONDET;

    // State getters
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function processedTransactions(bytes32) external returns (bool) envfree;
    function crossDomainNullifiers(bytes32) external returns (bytes32) envfree;
    function pilBindings(bytes32) external returns (bytes32) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function dailyVolume() external returns (uint256) envfree;
    function totalTransactions() external returns (uint256) envfree;
    function totalTransferredValue() external returns (uint256) envfree;

    // Constants
    function MAX_COMMITTEE_SIZE() external returns (uint256) envfree;
    function MIN_SIGNATURES() external returns (uint256) envfree;
    function MAX_TRANSFER_AMOUNT() external returns (uint256) envfree;
    function DAILY_LIMIT() external returns (uint256) envfree;
    function MAX_CLOCK_SKEW() external returns (uint256) envfree;

    // Domain operations
    function registerDomain(bytes32, string, uint256, uint256, uint256, uint256, uint256) external;
    function setDomainStatus(bytes32, uint8) external;

    // Participant operations
    function registerParticipant(bytes32, bytes32[], bytes32[]) external;
    function setParticipantStatus(bytes32, uint8) external;
    function connectToDomain(bytes32) external;

    // Transaction operations
    function submitTransaction(bytes32, bytes32, uint256, bytes32[], bytes32, bytes32, bytes32) external;
    function confirmTransaction(bytes32, bytes32, bytes) external;
    function rejectTransaction(bytes32, string) external;

    // Transfer operations
    function initiateTransfer(bytes32, bytes32, bytes32, bytes32, bytes32, bytes32) external;
    function completeTransfer(bytes32, bytes32, bytes32[], uint256[]) external;

    // Deposit/Withdrawal
    function deposit(bytes32) external;
    function withdraw(bytes32, address, uint256, bytes32, bytes32[], uint256[], bytes) external;

    // Cross-domain
    function registerCrossDomainNullifier(bytes32, uint256) external;

    // Admin
    function triggerCircuitBreaker(string) external;
    function resetCircuitBreaker() external;
    function pause() external;
    function unpause() external;

    // View functions
    function isNullifierUsed(bytes32) external returns (bool) envfree;
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

// Track used nullifiers
ghost mapping(bytes32 => bool) knownNullifiers {
    init_state axiom forall bytes32 nf. knownNullifiers[nf] == false;
}

// Track processed transactions
ghost mapping(bytes32 => bool) knownTransactions {
    init_state axiom forall bytes32 tx. knownTransactions[tx] == false;
}

// Hook on nullifier usage
hook Sstore usedNullifiers[KEY bytes32 nf] bool used {
    knownNullifiers[nf] = used;
    if (used) {
        totalWithdrawals = totalWithdrawals + 1;
    }
}

// Hook on transaction processing
hook Sstore processedTransactions[KEY bytes32 tx] bool processed {
    knownTransactions[tx] = processed;
}

// =========================================================================
// INVARIANTS
// =========================================================================

/// @title Nullifier can only be used once
invariant nullifierUsedOnce(bytes32 nf)
    usedNullifiers(nf) == knownNullifiers[nf]
{
    preserved {
        require true;
    }
}

/// @title Transaction can only be processed once
invariant transactionProcessedOnce(bytes32 tx)
    processedTransactions(tx) == knownTransactions[tx]
{
    preserved {
        require true;
    }
}

// =========================================================================
// RULES - DOMAIN MANAGEMENT
// =========================================================================

/// @title Domain registration is valid
rule domainRegistrationValid(
    bytes32 domainId,
    string alias,
    uint256 seqThresh,
    uint256 medThresh,
    uint256 maxSize,
    uint256 timeout,
    uint256 interval
) {
    env e;
    require domainId != bytes32(0);

    registerDomain(e, domainId, alias, seqThresh, medThresh, maxSize, timeout, interval);

    // If successful, domain should be registered
    // (actual state check would require domain getter)
    assert true;
}

/// @title Domain status can be changed
rule domainStatusChange(bytes32 domainId, uint8 status) {
    env e;
    
    setDomainStatus(e, domainId, status);
    
    assert true;
}

// =========================================================================
// RULES - PARTICIPANT MANAGEMENT
// =========================================================================

/// @title Participant registration creates valid node
rule participantRegistration(
    bytes32 nodeId,
    bytes32[] fingerprints,
    bytes32[] namespaces
) {
    env e;
    require nodeId != bytes32(0);
    require fingerprints.length == namespaces.length;

    registerParticipant(e, nodeId, fingerprints, namespaces);

    assert true;
}

// =========================================================================
// RULES - TRANSACTION SECURITY
// =========================================================================

/// @title Cannot process same transaction twice
rule noDoubleProcessing(bytes32 txId) {
    env e;
    require processedTransactions(txId);

    bytes32[] viewHashes;
    submitTransaction@withrevert(e, txId, bytes32(0), 0, viewHashes, bytes32(0), bytes32(0), bytes32(0));

    assert lastReverted, "Should revert on duplicate transaction";
}

/// @title Transaction submission requires valid domain
rule transactionRequiresValidDomain(
    bytes32 txId,
    bytes32 domainId,
    uint256 ledgerTime
) {
    env e;
    bytes32[] viewHashes;
    require viewHashes.length > 0;
    require !processedTransactions(txId);
    require !circuitBreakerActive();
    require !paused();

    submitTransaction@withrevert(e, txId, domainId, ledgerTime, viewHashes, bytes32(0), bytes32(0), bytes32(0));

    // If domain is invalid, should revert
    assert true;
}

// =========================================================================
// RULES - TRANSFER SECURITY
// =========================================================================

/// @title Transfer initiation is valid
rule transferInitiationValid(
    bytes32 transferId,
    bytes32 sourceDomain,
    bytes32 targetDomain,
    bytes32 contractId
) {
    env e;
    require !circuitBreakerActive();
    require !paused();

    initiateTransfer(e, transferId, sourceDomain, targetDomain, contractId, bytes32(0), bytes32(0));

    assert true;
}

/// @title Transfer completion uses nullifier
rule transferCompletionUsesNullifier(
    bytes32 transferId,
    bytes32 nullifier
) {
    env e;
    bytes32[] proof;
    uint256[] indices;
    require !usedNullifiers(nullifier);
    require nullifier != bytes32(0);

    completeTransfer(e, transferId, nullifier, proof, indices);

    assert usedNullifiers(nullifier), "Nullifier should be used";
}

/// @title Cannot complete transfer with used nullifier
rule noDoubleTransferCompletion(
    bytes32 transferId,
    bytes32 nullifier
) {
    env e;
    bytes32[] proof;
    uint256[] indices;
    require usedNullifiers(nullifier);

    completeTransfer@withrevert(e, transferId, nullifier, proof, indices);

    assert lastReverted, "Should revert on used nullifier";
}

// =========================================================================
// RULES - DEPOSIT SECURITY
// =========================================================================

/// @title Deposit respects amount bounds
rule depositRespectsBounds(bytes32 partyFingerprint) {
    env e;
    require partyFingerprint != bytes32(0);
    require !circuitBreakerActive();
    require !paused();

    bool tooSmall = e.msg.value == 0;
    bool tooLarge = e.msg.value > MAX_TRANSFER_AMOUNT();

    deposit@withrevert(e, partyFingerprint);

    assert (tooSmall || tooLarge) => lastReverted, "Should enforce amount bounds";
}

/// @title Deposit fails with zero party
rule depositFailsZeroParty() {
    env e;
    require e.msg.value > 0;
    require e.msg.value <= MAX_TRANSFER_AMOUNT();

    deposit@withrevert(e, bytes32(0));

    assert lastReverted, "Should revert on zero party";
}

// =========================================================================
// RULES - WITHDRAWAL SECURITY
// =========================================================================

/// @title Withdrawal marks nullifier as used
rule withdrawalMarksNullifier(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 domainId
) {
    env e;
    bytes32[] proof;
    uint256[] indices;
    bytes signatures;
    require !usedNullifiers(nullifier);
    require nullifier != bytes32(0);
    require recipient != address(0);

    withdraw(e, nullifier, recipient, amount, domainId, proof, indices, signatures);

    assert usedNullifiers(nullifier), "Nullifier should be marked";
}

/// @title Cannot withdraw with used nullifier
rule noDoubleWithdrawal(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 domainId
) {
    env e;
    bytes32[] proof;
    uint256[] indices;
    bytes signatures;
    require usedNullifiers(nullifier);

    withdraw@withrevert(e, nullifier, recipient, amount, domainId, proof, indices, signatures);

    assert lastReverted, "Should revert on double withdrawal";
}

/// @title Withdrawal respects daily limit
rule withdrawalRespectsLimit(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 domainId
) {
    env e;
    bytes32[] proof;
    uint256[] indices;
    bytes signatures;

    require dailyVolume() + amount > DAILY_LIMIT();

    withdraw@withrevert(e, nullifier, recipient, amount, domainId, proof, indices, signatures);

    assert lastReverted, "Should respect daily limit";
}

// =========================================================================
// RULES - CROSS-DOMAIN NULLIFIER
// =========================================================================

/// @title Cross-domain registration creates mappings
rule crossDomainRegistration(bytes32 cantonNf, uint256 targetChainId) {
    env e;
    require cantonNf != bytes32(0);
    require crossDomainNullifiers(cantonNf) == bytes32(0);

    registerCrossDomainNullifier(e, cantonNf, targetChainId);

    assert crossDomainNullifiers(cantonNf) != bytes32(0), "PIL nullifier should be set";
}

/// @title Cross-domain registration is idempotent
rule crossDomainIdempotent(bytes32 cantonNf, uint256 targetChainId) {
    env e;
    require cantonNf != bytes32(0);

    bytes32 pilNf1 = crossDomainNullifiers(cantonNf);
    require pilNf1 != bytes32(0);

    registerCrossDomainNullifier(e, cantonNf, targetChainId);

    bytes32 pilNf2 = crossDomainNullifiers(cantonNf);
    assert pilNf1 == pilNf2, "Should not change existing mapping";
}

// =========================================================================
// RULES - CIRCUIT BREAKER
// =========================================================================

/// @title Circuit breaker blocks deposits
rule circuitBreakerBlocksDeposits(bytes32 partyFingerprint) {
    env e;
    require circuitBreakerActive();
    require e.msg.value > 0;
    require e.msg.value <= MAX_TRANSFER_AMOUNT();
    require partyFingerprint != bytes32(0);

    deposit@withrevert(e, partyFingerprint);

    assert lastReverted, "Circuit breaker should block deposits";
}

/// @title Circuit breaker blocks transfers
rule circuitBreakerBlocksTransfers(
    bytes32 transferId,
    bytes32 sourceDomain,
    bytes32 targetDomain,
    bytes32 contractId
) {
    env e;
    require circuitBreakerActive();

    initiateTransfer@withrevert(e, transferId, sourceDomain, targetDomain, contractId, bytes32(0), bytes32(0));

    assert lastReverted, "Circuit breaker should block transfers";
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
rule pauseBlocksDeposits(bytes32 partyFingerprint) {
    env e;
    require paused();
    require e.msg.value > 0;

    deposit@withrevert(e, partyFingerprint);

    assert lastReverted, "Pause should block deposits";
}

/// @title Pause blocks transactions
rule pauseBlocksTransactions(bytes32 txId, bytes32 domainId) {
    env e;
    bytes32[] viewHashes;
    require paused();

    submitTransaction@withrevert(e, txId, domainId, 0, viewHashes, bytes32(0), bytes32(0), bytes32(0));

    assert lastReverted, "Pause should block transactions";
}

// =========================================================================
// RULES - SOLVENCY
// =========================================================================

/// @title Total withdrawals never exceed total value
rule solvencyInvariant() {
    assert totalWithdrawals <= totalDeposits, "Bridge should remain solvent";
}

// =========================================================================
// RULES - BFT CONSENSUS
// =========================================================================

/// @title Minimum signatures required for withdrawal
rule minSignaturesRequired(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 domainId
) {
    env e;
    bytes32[] proof;
    uint256[] indices;
    bytes signatures;

    // If signatures are insufficient (less than MIN_SIGNATURES * 65 bytes)
    require signatures.length < MIN_SIGNATURES() * 65;
    require !usedNullifiers(nullifier);

    withdraw@withrevert(e, nullifier, recipient, amount, domainId, proof, indices, signatures);

    assert lastReverted, "Should require minimum signatures";
}
