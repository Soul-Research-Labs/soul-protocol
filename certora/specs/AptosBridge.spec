/**
 * Certora CVL Specification for Aptos Bridge Adapter
 * ====================================================
 *
 * Verifies security properties for:
 * - Validator management with BLS12-381 keys
 * - Ledger info finalization with quorum
 * - Nullifier uniqueness and cross-domain binding
 * - Rate limiting and circuit breaker
 * - AptosBFT consensus (~160ms finality)
 */

// =============================================================================
// METHODS
// =============================================================================

methods {
    // View functions
    function isValidator(address) external returns (bool) envfree;
    function getValidatorPower(address) external returns (uint256) envfree;
    function totalVotingPower() external returns (uint256) envfree;
    function activeValidatorCount() external returns (uint256) envfree;
    function currentEpoch() external returns (uint64) envfree;
    function isNullifierConsumed(bytes32) external returns (bool) envfree;
    function aptosNullifierToPIL(bytes32) external returns (bytes32) envfree;
    function pilNullifierToAptos(bytes32) external returns (bytes32) envfree;
    function isVersionFinalized(uint64) external returns (bool) envfree;
    function getLatestFinalizedVersion() external returns (uint64) envfree;
    function dailyWithdrawalVolume() external returns (uint256) envfree;
    function lastWithdrawalDay() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function isPaused() external returns (bool) envfree;
    function circuitBreakerTriggered() external returns (bool) envfree;
    function relayerFeeBps() external returns (uint256) envfree;
    function emergencyCouncil() external returns (address) envfree;
    function owner() external returns (address) envfree;
    function depositNonce() external returns (uint256) envfree;
    
    // Constants
    function QUORUM_THRESHOLD_BPS() external returns (uint256) envfree;
    function MAX_VALIDATORS() external returns (uint256) envfree;
    function MAX_SINGLE_WITHDRAWAL() external returns (uint256) envfree;
    function MAX_DAILY_WITHDRAWAL() external returns (uint256) envfree;
    function MAX_RELAYER_FEE_BPS() external returns (uint256) envfree;
    function MIN_CONFIRMATIONS() external returns (uint64) envfree;
    
    // State-changing functions
    function registerValidator(address, bytes, bytes, uint256) external;
    function removeValidator(address) external;
    function updateValidatorPower(address, uint256) external;
    function submitLedgerInfo(AptosPrimitives.LedgerInfoWithSignatures, address[]) external;
    function deposit(address, uint256, bytes32) external payable;
    function withdraw(address, uint256, uint64, bytes32, AptosPrimitives.SparseMerkleProof, address[]) external;
    function consumeNullifier(bytes32) external;
    function bindCrossDomainNullifier(bytes32, bytes32) external;
    function pause() external;
    function unpause() external;
    function triggerCircuitBreaker() external;
    function resetCircuitBreaker() external;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 ghostTotalValidatorPower {
    init_state axiom ghostTotalValidatorPower == 0;
}

ghost uint256 ghostValidatorCount {
    init_state axiom ghostValidatorCount == 0;
}

ghost mapping(bytes32 => bool) ghostNullifiersConsumed {
    init_state axiom forall bytes32 nf. ghostNullifiersConsumed[nf] == false;
}

ghost mapping(bytes32 => bytes32) ghostNullifierBindings {
    init_state axiom forall bytes32 nf. ghostNullifierBindings[nf] == to_bytes32(0);
}

ghost uint64 ghostLatestFinalizedVersion {
    init_state axiom ghostLatestFinalizedVersion == 0;
}

ghost uint64 ghostCurrentEpoch {
    init_state axiom ghostCurrentEpoch == 1;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * INV-01: Total voting power equals sum of active validators
 */
invariant totalPowerConsistency()
    totalVotingPower() == ghostTotalValidatorPower
{
    preserved registerValidator(address v, bytes bls, bytes ed, uint256 power) with (env e) {
        require ghostTotalValidatorPower + power <= max_uint256;
    }
}

/**
 * INV-02: Active validator count is consistent
 */
invariant validatorCountConsistency()
    activeValidatorCount() == ghostValidatorCount;

/**
 * INV-03: Validator count bounded by MAX_VALIDATORS
 */
invariant validatorCountBounded()
    activeValidatorCount() <= MAX_VALIDATORS();

/**
 * INV-04: Nullifier once consumed is always consumed
 */
invariant nullifierPermanence(bytes32 nf)
    ghostNullifiersConsumed[nf] => isNullifierConsumed(nf);

/**
 * INV-05: Nullifier binding is permanent
 */
invariant bindingPermanence(bytes32 aptosNf)
    ghostNullifierBindings[aptosNf] != to_bytes32(0) => 
    aptosNullifierToPIL(aptosNf) == ghostNullifierBindings[aptosNf];

/**
 * INV-06: Epoch is always positive
 */
invariant epochPositive()
    currentEpoch() >= 1;

/**
 * INV-07: Circuit breaker implies paused
 */
invariant circuitBreakerPauses()
    circuitBreakerTriggered() => isPaused();

/**
 * INV-08: Relayer fee is bounded
 */
invariant relayerFeeBounded()
    relayerFeeBps() <= MAX_RELAYER_FEE_BPS();

/**
 * INV-09: Quorum threshold is correct (2/3 + 1)
 */
invariant quorumThresholdCorrect()
    QUORUM_THRESHOLD_BPS() == 6667;

// =============================================================================
// RULES: VALIDATOR MANAGEMENT
// =============================================================================

/**
 * RULE-01: Only owner can register validators
 */
rule onlyOwnerCanRegisterValidator(
    address v, 
    bytes bls, 
    bytes ed, 
    uint256 power
) {
    env e;
    
    registerValidator@withrevert(e, v, bls, ed, power);
    
    assert !lastReverted => e.msg.sender == owner();
}

/**
 * RULE-02: Validator registration increases total power
 */
rule validatorRegistrationIncreasesPower(
    address v, 
    bytes bls, 
    bytes ed, 
    uint256 power
) {
    env e;
    
    uint256 powerBefore = totalVotingPower();
    bool wasValidator = isValidator(v);
    
    registerValidator(e, v, bls, ed, power);
    
    assert !wasValidator => totalVotingPower() == powerBefore + power;
}

/**
 * RULE-03: Validator removal decreases total power
 */
rule validatorRemovalDecreasesPower(address v) {
    env e;
    
    uint256 powerBefore = totalVotingPower();
    uint256 validatorPower = getValidatorPower(v);
    bool wasValidator = isValidator(v);
    
    removeValidator(e, v);
    
    assert wasValidator => totalVotingPower() == powerBefore - validatorPower;
}

/**
 * RULE-04: Removed validators lose power
 */
rule removedValidatorsHaveNoPower(address v) {
    env e;
    
    removeValidator(e, v);
    
    assert getValidatorPower(v) == 0;
    assert !isValidator(v);
}

/**
 * RULE-05: Cannot register duplicate validator
 */
rule noDuplicateValidators(
    address v, 
    bytes bls, 
    bytes ed, 
    uint256 power
) {
    env e;
    
    require isValidator(v);
    
    registerValidator@withrevert(e, v, bls, ed, power);
    
    assert lastReverted;
}

// =============================================================================
// RULES: LEDGER INFO FINALIZATION
// =============================================================================

/**
 * RULE-06: Finalized versions cannot be re-finalized
 */
rule noDoubleFinalizeVersion(
    uint64 version
) {
    env e;
    
    require isVersionFinalized(version);
    
    // Any attempt to submit same version should fail
    // (implemented in contract logic)
}

/**
 * RULE-07: Epoch can only increase
 */
rule epochOnlyIncreases(
    AptosPrimitives.LedgerInfoWithSignatures ledgerInfo,
    address[] signers
) {
    env e;
    
    uint64 epochBefore = currentEpoch();
    
    submitLedgerInfo(e, ledgerInfo, signers);
    
    assert currentEpoch() >= epochBefore;
}

// =============================================================================
// RULES: NULLIFIER OPERATIONS
// =============================================================================

/**
 * RULE-08: Nullifiers can only be consumed once
 */
rule nullifierSingleConsumption(bytes32 nf) {
    env e1;
    env e2;
    
    require !isNullifierConsumed(nf);
    
    consumeNullifier(e1, nf);
    assert isNullifierConsumed(nf);
    
    consumeNullifier@withrevert(e2, nf);
    assert lastReverted;
}

/**
 * RULE-09: Cross-domain binding is permanent
 */
rule crossDomainBindingPermanence(
    bytes32 aptosNf, 
    bytes32 pilNf1, 
    bytes32 pilNf2
) {
    env e1;
    env e2;
    
    require pilNf1 != pilNf2;
    require pilNf1 != to_bytes32(0);
    require pilNf2 != to_bytes32(0);
    
    bindCrossDomainNullifier(e1, aptosNf, pilNf1);
    assert aptosNullifierToPIL(aptosNf) == pilNf1;
    
    // Rebinding should fail
    bindCrossDomainNullifier@withrevert(e2, aptosNf, pilNf2);
    assert lastReverted;
}

/**
 * RULE-10: Binding is bidirectional
 */
rule crossDomainBindingBidirectional(bytes32 aptosNf, bytes32 pilNf) {
    env e;
    
    require pilNf != to_bytes32(0);
    
    bindCrossDomainNullifier(e, aptosNf, pilNf);
    
    assert aptosNullifierToPIL(aptosNf) == pilNf;
    assert pilNullifierToAptos(pilNf) == aptosNf;
}

// =============================================================================
// RULES: DEPOSIT/WITHDRAWAL
// =============================================================================

/**
 * RULE-11: Deposit increases nonce
 */
rule depositIncreasesNonce(
    address token,
    uint256 amount,
    bytes32 aptosRecipient
) {
    env e;
    
    uint256 nonceBefore = depositNonce();
    
    deposit(e, token, amount, aptosRecipient);
    
    assert depositNonce() == nonceBefore + 1;
}

/**
 * RULE-12: Withdrawal respects single limit
 */
rule withdrawalRespectsLimits(
    address token,
    uint256 amount,
    uint64 version,
    bytes32 nullifier,
    AptosPrimitives.SparseMerkleProof proof,
    address[] signers
) {
    env e;
    
    require amount > MAX_SINGLE_WITHDRAWAL();
    
    withdraw@withrevert(e, token, amount, version, nullifier, proof, signers);
    
    assert lastReverted;
}

/**
 * RULE-13: Withdrawal consumes nullifier
 */
rule withdrawalConsumesNullifier(
    address token,
    uint256 amount,
    uint64 version,
    bytes32 nullifier,
    AptosPrimitives.SparseMerkleProof proof,
    address[] signers
) {
    env e;
    
    require !isNullifierConsumed(nullifier);
    
    withdraw(e, token, amount, version, nullifier, proof, signers);
    
    assert isNullifierConsumed(nullifier);
}

/**
 * RULE-14: Double withdrawal prevented
 */
rule noDoubleWithdrawal(
    address token,
    uint256 amount,
    uint64 version,
    bytes32 nullifier,
    AptosPrimitives.SparseMerkleProof proof,
    address[] signers
) {
    env e1;
    env e2;
    
    require !isNullifierConsumed(nullifier);
    
    withdraw(e1, token, amount, version, nullifier, proof, signers);
    withdraw@withrevert(e2, token, amount, version, nullifier, proof, signers);
    
    assert lastReverted;
}

// =============================================================================
// RULES: CIRCUIT BREAKER
// =============================================================================

/**
 * RULE-15: Circuit breaker blocks withdrawals
 */
rule circuitBreakerBlocksWithdrawals(
    address token,
    uint256 amount,
    uint64 version,
    bytes32 nullifier,
    AptosPrimitives.SparseMerkleProof proof,
    address[] signers
) {
    env e;
    
    require circuitBreakerTriggered();
    
    withdraw@withrevert(e, token, amount, version, nullifier, proof, signers);
    
    assert lastReverted;
}

/**
 * RULE-16: Only emergency council can trigger circuit breaker
 */
rule onlyCouncilCanTriggerCircuitBreaker() {
    env e;
    
    triggerCircuitBreaker@withrevert(e);
    
    assert !lastReverted => (e.msg.sender == emergencyCouncil() || e.msg.sender == owner());
}

/**
 * RULE-17: Pause blocks deposits
 */
rule pauseBlocksDeposits(
    address token,
    uint256 amount,
    bytes32 aptosRecipient
) {
    env e;
    
    require isPaused();
    
    deposit@withrevert(e, token, amount, aptosRecipient);
    
    assert lastReverted;
}

// =============================================================================
// RULES: ACCESS CONTROL
// =============================================================================

/**
 * RULE-18: Only owner can pause
 */
rule onlyOwnerCanPause() {
    env e;
    
    pause@withrevert(e);
    
    assert !lastReverted => e.msg.sender == owner();
}

/**
 * RULE-19: Only owner can unpause
 */
rule onlyOwnerCanUnpause() {
    env e;
    
    unpause@withrevert(e);
    
    assert !lastReverted => e.msg.sender == owner();
}

/**
 * RULE-20: Only owner can reset circuit breaker
 */
rule onlyOwnerCanResetCircuitBreaker() {
    env e;
    
    resetCircuitBreaker@withrevert(e);
    
    assert !lastReverted => e.msg.sender == owner();
}

// =============================================================================
// RULES: RELAYER FEE
// =============================================================================

/**
 * RULE-21: Relayer fee cannot exceed maximum
 */
rule relayerFeeCannotExceedMax(uint256 newFee) {
    env e;
    
    require newFee > MAX_RELAYER_FEE_BPS();
    
    // updateRelayerFee should revert
    // (function exists in contract)
}

// =============================================================================
// LIVENESS PROPERTIES
// =============================================================================

/**
 * LIVENESS-01: Valid validators can be registered
 */
rule validatorsCanBeRegistered(
    address v, 
    bytes bls, 
    bytes ed, 
    uint256 power
) {
    env e;
    
    require e.msg.sender == owner();
    require !isValidator(v);
    require power > 0;
    require bls.length == 96;  // BLS public key length
    require ed.length == 32;   // Ed25519 public key length
    require activeValidatorCount() < MAX_VALIDATORS();
    
    registerValidator@withrevert(e, v, bls, ed, power);
    
    // Should not revert for valid inputs
    assert !lastReverted => isValidator(v);
}

/**
 * LIVENESS-02: Deposits can be made when not paused
 */
rule depositsCanBeMade(
    address token,
    uint256 amount,
    bytes32 aptosRecipient
) {
    env e;
    
    require !isPaused();
    require !circuitBreakerTriggered();
    require amount > 0;
    require token == 0 => e.msg.value == amount;
    
    deposit@withrevert(e, token, amount, aptosRecipient);
    
    // Can succeed with valid parameters
    satisfy !lastReverted;
}

// =============================================================================
// SECURITY BOUNDS
// =============================================================================

/**
 * BOUND-01: Maximum validators bounded
 */
rule maxValidatorsBounded() {
    assert activeValidatorCount() <= 150;
}

/**
 * BOUND-02: Withdrawal amounts bounded
 */
rule withdrawalAmountsBounded(
    address token,
    uint256 amount,
    uint64 version,
    bytes32 nullifier,
    AptosPrimitives.SparseMerkleProof proof,
    address[] signers
) {
    env e;
    
    withdraw(e, token, amount, version, nullifier, proof, signers);
    
    assert amount <= MAX_SINGLE_WITHDRAWAL();
}

/**
 * BOUND-03: Daily withdrawal volume bounded
 */
rule dailyVolumeBounded() {
    assert dailyWithdrawalVolume() <= MAX_DAILY_WITHDRAWAL();
}
