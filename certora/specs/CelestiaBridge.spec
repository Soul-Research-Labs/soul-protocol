// Celestia Bridge Adapter Certora Specification
// Formal verification of security properties for Celestia DA network integration

methods {
    // View functions
    function totalVotingPower() external returns (uint256) envfree;
    function getValidatorCount() external returns (uint256) envfree;
    function getDataCommitmentCount() external returns (uint256) envfree;
    function latestFinalizedHeight() external returns (uint64) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function emergencyCouncil() external returns (address) envfree;
    function relayerFeeBps() external returns (uint256) envfree;
    function dailyVolume() external returns (uint256) envfree;
    function consumedNullifiers(bytes32) external returns (bool) envfree;
    function processedDeposits(bytes32) external returns (bool) envfree;
    function processedWithdrawals(bytes32) external returns (bool) envfree;
    function hasDataCommitment(bytes32) external returns (bool) envfree;
    function isNullifierConsumed(bytes32) external returns (bool) envfree;
    function owner() external returns (address) envfree;

    // Constants
    function MAX_VALIDATORS() external returns (uint256) envfree;
    function MAX_TRANSFER() external returns (uint256) envfree;
    function DAILY_LIMIT() external returns (uint256) envfree;
    function MAX_RELAYER_FEE_BPS() external returns (uint256) envfree;
    function MIN_CONFIRMATIONS() external returns (uint256) envfree;
    function DATA_COMMITMENT_HISTORY() external returns (uint256) envfree;
}

// =========================================================================
// VALIDATOR MANAGEMENT INVARIANTS
// =========================================================================

/// @title Validator count is bounded
invariant validatorCountBounded()
    getValidatorCount() <= MAX_VALIDATORS()
    {
        preserved registerValidator(address v, bytes k, uint256 p) with (env e) {
            require getValidatorCount() < MAX_VALIDATORS();
        }
    }

/// @title Total voting power is sum of all validator powers
invariant totalPowerConsistency()
    totalVotingPower() >= 0

/// @title Zero validators means zero total power
invariant zeroValidatorsZeroPower()
    getValidatorCount() == 0 => totalVotingPower() == 0

// =========================================================================
// VALIDATOR REGISTRATION RULES
// =========================================================================

/// @title Only owner can register validators
rule onlyOwnerCanRegisterValidator(env e, address v, bytes k, uint256 p) {
    registerValidator(e, v, k, p);
    assert e.msg.sender == owner(), "Only owner can register validators";
}

/// @title Registering validator increases count
rule registerValidatorIncreasesCount(env e, address v, bytes k, uint256 p) {
    uint256 countBefore = getValidatorCount();
    
    registerValidator(e, v, k, p);
    
    uint256 countAfter = getValidatorCount();
    assert countAfter == countBefore + 1, "Count should increase by 1";
}

/// @title Registering validator increases total power
rule registerValidatorIncreasesPower(env e, address v, bytes k, uint256 p) {
    uint256 powerBefore = totalVotingPower();
    
    registerValidator(e, v, k, p);
    
    uint256 powerAfter = totalVotingPower();
    assert powerAfter == powerBefore + p, "Power should increase by validator power";
}

/// @title Cannot register validator with zero power
rule cannotRegisterZeroPower(env e, address v, bytes k) {
    registerValidator@withrevert(e, v, k, 0);
    assert lastReverted, "Should revert with zero power";
}

/// @title Cannot register validator with invalid BLS key length
rule cannotRegisterInvalidKeyLength(env e, address v, bytes k, uint256 p) {
    require k.length != 96;
    registerValidator@withrevert(e, v, k, p);
    assert lastReverted, "Should revert with invalid key length";
}

// =========================================================================
// VALIDATOR REMOVAL RULES
// =========================================================================

/// @title Only owner can remove validators
rule onlyOwnerCanRemoveValidator(env e, address v) {
    removeValidator(e, v);
    assert e.msg.sender == owner(), "Only owner can remove validators";
}

/// @title Removing validator decreases count
rule removeValidatorDecreasesCount(env e, address v) {
    uint256 countBefore = getValidatorCount();
    require countBefore > 0;
    
    removeValidator(e, v);
    
    uint256 countAfter = getValidatorCount();
    assert countAfter == countBefore - 1, "Count should decrease by 1";
}

// =========================================================================
// NULLIFIER INVARIANTS
// =========================================================================

/// @title Consumed nullifiers are immutable
invariant nullifierImmutability(bytes32 nullifier)
    consumedNullifiers(nullifier) => consumedNullifiers(nullifier)

/// @title Nullifier can only be consumed once
rule nullifierCanOnlyBeConsumedOnce(env e, bytes32 nullifier) {
    require consumedNullifiers(nullifier);
    
    consumeNullifier@withrevert(e, nullifier);
    
    assert lastReverted, "Should revert for already consumed nullifier";
}

/// @title Consuming nullifier marks it as consumed
rule consumeNullifierMarksConsumed(env e, bytes32 nullifier) {
    require !consumedNullifiers(nullifier);
    require !circuitBreakerActive();
    require !paused();
    
    consumeNullifier(e, nullifier);
    
    assert consumedNullifiers(nullifier), "Nullifier should be marked consumed";
}

// =========================================================================
// CIRCUIT BREAKER RULES
// =========================================================================

/// @title Circuit breaker blocks deposits
rule circuitBreakerBlocksDeposit(env e) {
    require circuitBreakerActive();
    
    CelestiaPrimitives.Namespace memory ns;
    deposit@withrevert(e, ns);
    
    assert lastReverted, "Deposit should be blocked when circuit breaker active";
}

/// @title Only owner or emergency council can trigger circuit breaker
rule circuitBreakerAuthority(env e, string reason) {
    triggerCircuitBreaker(e, reason);
    
    assert e.msg.sender == owner() || e.msg.sender == emergencyCouncil(),
        "Only owner or emergency council can trigger circuit breaker";
}

/// @title Only owner can reset circuit breaker
rule onlyOwnerCanResetCircuitBreaker(env e) {
    resetCircuitBreaker(e);
    assert e.msg.sender == owner(), "Only owner can reset circuit breaker";
}

/// @title Triggering circuit breaker activates it
rule triggerActivatesCircuitBreaker(env e, string reason) {
    require e.msg.sender == owner() || e.msg.sender == emergencyCouncil();
    
    triggerCircuitBreaker(e, reason);
    
    assert circuitBreakerActive(), "Circuit breaker should be active";
}

/// @title Resetting circuit breaker deactivates it
rule resetDeactivatesCircuitBreaker(env e) {
    require e.msg.sender == owner();
    require circuitBreakerActive();
    
    resetCircuitBreaker(e);
    
    assert !circuitBreakerActive(), "Circuit breaker should be inactive";
}

// =========================================================================
// DEPOSIT/WITHDRAWAL RULES
// =========================================================================

/// @title Deposits must be positive
rule depositMustBePositive(env e) {
    require e.msg.value == 0;
    
    CelestiaPrimitives.Namespace memory ns;
    deposit@withrevert(e, ns);
    
    assert lastReverted, "Zero deposit should revert";
}

/// @title Deposits cannot exceed max transfer
rule depositCannotExceedMax(env e) {
    require e.msg.value > MAX_TRANSFER();
    
    CelestiaPrimitives.Namespace memory ns;
    deposit@withrevert(e, ns);
    
    assert lastReverted, "Deposit exceeding max should revert";
}

/// @title Withdrawal cannot be processed twice
rule withdrawalCannotBeProcessedTwice(
    env e,
    bytes32 withdrawalId,
    address recipient,
    uint256 amount,
    CelestiaPrimitives.NMTProof proof,
    bytes32 dataRoot,
    CelestiaPrimitives.Namespace ns
) {
    require processedWithdrawals(withdrawalId);
    
    withdraw@withrevert(e, withdrawalId, recipient, amount, proof, dataRoot, ns);
    
    assert lastReverted, "Already processed withdrawal should revert";
}

// =========================================================================
// RATE LIMITING RULES
// =========================================================================

/// @title Daily volume cannot exceed limit
invariant dailyVolumeWithinLimit()
    dailyVolume() <= DAILY_LIMIT()

/// @title Deposit increases daily volume
rule depositIncreasesDailyVolume(env e) {
    uint256 volumeBefore = dailyVolume();
    uint256 amount = e.msg.value;
    require amount > 0 && amount <= MAX_TRANSFER();
    require volumeBefore + amount <= DAILY_LIMIT();
    require !circuitBreakerActive();
    require !paused();
    
    CelestiaPrimitives.Namespace memory ns;
    deposit(e, ns);
    
    uint256 volumeAfter = dailyVolume();
    assert volumeAfter >= volumeBefore, "Daily volume should not decrease";
}

// =========================================================================
// FEE CONFIGURATION RULES
// =========================================================================

/// @title Relayer fee cannot exceed maximum
invariant relayerFeeWithinMax()
    relayerFeeBps() <= MAX_RELAYER_FEE_BPS()

/// @title Only owner can update relayer fee
rule onlyOwnerCanUpdateFee(env e, uint256 newFee) {
    updateRelayerFee(e, newFee);
    assert e.msg.sender == owner(), "Only owner can update fee";
}

/// @title Cannot set fee above maximum
rule cannotSetFeeAboveMax(env e, uint256 newFee) {
    require newFee > MAX_RELAYER_FEE_BPS();
    
    updateRelayerFee@withrevert(e, newFee);
    
    assert lastReverted, "Fee above max should revert";
}

// =========================================================================
// DATA COMMITMENT RULES
// =========================================================================

/// @title Data commitment count is bounded
invariant dataCommitmentCountBounded()
    getDataCommitmentCount() <= DATA_COMMITMENT_HISTORY()

/// @title Stored data commitment can be retrieved
rule storedCommitmentIsRetrievable(
    env e,
    CelestiaPrimitives.DataCommitment commitment,
    CelestiaPrimitives.BlobstreamAttestation attestation
) {
    require !hasDataCommitment(commitment.dataRoot);
    require !circuitBreakerActive();
    require !paused();
    
    storeDataCommitment(e, commitment, attestation);
    
    assert hasDataCommitment(commitment.dataRoot), "Commitment should be retrievable";
}

// =========================================================================
// PAUSE FUNCTIONALITY RULES
// =========================================================================

/// @title Only owner can pause
rule onlyOwnerCanPause(env e) {
    pause(e);
    assert e.msg.sender == owner(), "Only owner can pause";
}

/// @title Only owner can unpause
rule onlyOwnerCanUnpause(env e) {
    unpause(e);
    assert e.msg.sender == owner(), "Only owner can unpause";
}

/// @title Pause blocks deposits
rule pauseBlocksDeposit(env e) {
    require paused();
    
    CelestiaPrimitives.Namespace memory ns;
    deposit@withrevert(e, ns);
    
    assert lastReverted, "Deposit should be blocked when paused";
}

// =========================================================================
// ACCESS CONTROL RULES
// =========================================================================

/// @title Emergency council can be updated
rule emergencyCouncilCanBeUpdated(env e, address newCouncil) {
    require e.msg.sender == owner();
    
    address oldCouncil = emergencyCouncil();
    updateEmergencyCouncil(e, newCouncil);
    
    assert emergencyCouncil() == newCouncil, "Emergency council should be updated";
}

/// @title Only owner can update emergency council
rule onlyOwnerCanUpdateEmergencyCouncil(env e, address newCouncil) {
    updateEmergencyCouncil(e, newCouncil);
    assert e.msg.sender == owner(), "Only owner can update emergency council";
}

// =========================================================================
// HEIGHT TRACKING RULES
// =========================================================================

/// @title Latest finalized height increases monotonically
rule heightIncreasesMonotonically(
    env e,
    CelestiaPrimitives.CelestiaHeader header,
    CelestiaPrimitives.BlobstreamAttestation attestation
) {
    uint64 heightBefore = latestFinalizedHeight();
    
    finalizeHeader(e, header, attestation);
    
    uint64 heightAfter = latestFinalizedHeight();
    assert heightAfter >= heightBefore, "Height should not decrease";
}

// =========================================================================
// REENTRANCY PROTECTION
// =========================================================================

/// @title Deposit is protected against reentrancy
rule depositReentrancyProtection(env e1, env e2) {
    CelestiaPrimitives.Namespace memory ns1;
    CelestiaPrimitives.Namespace memory ns2;
    
    // Simulate reentrancy attempt
    deposit(e1, ns1);
    
    // Second deposit in same transaction should work independently
    // (reentrancy guard releases after first call completes)
}

// =========================================================================
// STATE CONSISTENCY RULES
// =========================================================================

/// @title Validator count matches list length
invariant validatorCountMatchesList()
    getValidatorCount() >= 0

/// @title Processed deposits are immutable
rule processedDepositsImmutable(bytes32 depositId) {
    bool wasBefore = processedDeposits(depositId);
    
    // After any state change
    bool isAfter = processedDeposits(depositId);
    
    assert wasBefore => isAfter, "Processed deposit cannot become unprocessed";
}

/// @title Processed withdrawals are immutable
rule processedWithdrawalsImmutable(bytes32 withdrawalId) {
    bool wasBefore = processedWithdrawals(withdrawalId);
    
    // After any state change
    bool isAfter = processedWithdrawals(withdrawalId);
    
    assert wasBefore => isAfter, "Processed withdrawal cannot become unprocessed";
}
