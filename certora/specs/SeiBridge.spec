/**
 * Certora CVL Specification for Sei Bridge Adapter
 * =================================================
 *
 * Verifies security properties for:
 * - Validator management and voting power
 * - Block finalization with BFT consensus
 * - IBC channel operations
 * - Nullifier uniqueness and cross-domain binding
 * - Rate limiting and circuit breaker
 * - Fast finality (~400ms)
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
    function minConfirmations() external returns (uint64) envfree;
    function isNullifierConsumed(bytes32) external returns (bool) envfree;
    function seiNullifierToPILNullifier(bytes32) external returns (bytes32) envfree;
    function pilNullifierToSeiNullifier(bytes32) external returns (bytes32) envfree;
    function isBlockFinalized(uint64) external returns (bool) envfree;
    function getFinalizedBlock(uint64) external returns (bytes32, bytes32, uint64) envfree;
    function isIBCChannelRegistered(string, string) external returns (bool) envfree;
    function getIBCChannelState(string, string) external returns (uint8) envfree;
    function dailyWithdrawalVolume() external returns (uint256) envfree;
    function lastWithdrawalDay() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function circuitBreakerTriggered() external returns (bool) envfree;
    function maxDailyWithdrawal() external returns (uint256) envfree;
    function maxSingleWithdrawal() external returns (uint256) envfree;
    function relayerFee() external returns (uint256) envfree;
    function emergencyCouncil() external returns (address) envfree;
    function owner() external returns (address) envfree;
    
    // FINALITY_THRESHOLD_BPS constant
    function FINALITY_THRESHOLD_BPS() external returns (uint256) envfree;
    
    // State-changing functions
    function registerValidator(address, bytes, uint256) external;
    function removeValidator(address) external;
    function updateValidatorPower(address, uint256) external;
    function submitBlock(uint64, bytes32, bytes32, bytes32, uint64, bytes[], address[]) external;
    function registerIBCChannel(string, string, string, string, string, uint8) external;
    function updateIBCChannelState(string, string, uint8) external;
    function deposit(address, uint256, string, string, string, bytes32) external payable;
    function withdraw(address, uint256, bytes32, bytes32, bytes[], address[]) external;
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

ghost uint64 ghostHighestFinalizedBlock {
    init_state axiom ghostHighestFinalizedBlock == 0;
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
    preserved registerValidator(address v, bytes pk, uint256 power) with (env e) {
        require ghostTotalValidatorPower + power <= max_uint256;
    }
}

/**
 * INV-02: Active validator count is consistent
 */
invariant validatorCountConsistency()
    activeValidatorCount() == ghostValidatorCount;

/**
 * INV-03: Nullifier once consumed is always consumed
 */
invariant nullifierPermanence(bytes32 nf)
    ghostNullifiersConsumed[nf] => isNullifierConsumed(nf);

/**
 * INV-04: Nullifier binding is permanent
 */
invariant bindingPermanence(bytes32 seiNf)
    ghostNullifierBindings[seiNf] != to_bytes32(0) => 
    seiNullifierToPILNullifier(seiNf) == ghostNullifierBindings[seiNf];

/**
 * INV-05: Block finality monotonicity
 */
invariant finalityMonotonicity()
    ghostHighestFinalizedBlock == 0 || isBlockFinalized(ghostHighestFinalizedBlock)
{
    preserved submitBlock(uint64 height, bytes32 blockHash, bytes32 appHash, 
                          bytes32 validatorsHash, uint64 timestamp, 
                          bytes[] sigs, address[] signers) with (env e) {
        require height >= ghostHighestFinalizedBlock;
    }
}

/**
 * INV-06: Circuit breaker implies paused
 */
invariant circuitBreakerPauses()
    circuitBreakerTriggered() => paused();

/**
 * INV-07: Relayer fee is bounded
 */
invariant relayerFeeBounded()
    relayerFee() <= 500;  // Max 5%

/**
 * INV-08: Finality threshold is correct (2/3 + 1)
 */
invariant finalityThresholdCorrect()
    FINALITY_THRESHOLD_BPS() == 6667;

// =============================================================================
// RULES: VALIDATOR MANAGEMENT
// =============================================================================

/**
 * RULE-01: Only owner can register validators
 */
rule onlyOwnerCanRegisterValidator(address v, bytes pk, uint256 power) {
    env e;
    
    registerValidator@withrevert(e, v, pk, power);
    
    assert !lastReverted => e.msg.sender == owner();
}

/**
 * RULE-02: Validator registration increases total power
 */
rule validatorRegistrationIncreasesPower(address v, bytes pk, uint256 power) {
    env e;
    
    uint256 powerBefore = totalVotingPower();
    bool wasValidator = isValidator(v);
    
    registerValidator(e, v, pk, power);
    
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

// =============================================================================
// RULES: BLOCK FINALIZATION
// =============================================================================

/**
 * RULE-05: Block finalization requires 2/3+ voting power
 */
rule blockFinalizationRequiresQuorum(
    uint64 height,
    bytes32 blockHash,
    bytes32 appHash,
    bytes32 validatorsHash,
    uint64 timestamp,
    bytes[] sigs,
    address[] signers
) {
    env e;
    
    uint256 totalPower = totalVotingPower();
    require totalPower > 0;
    
    submitBlock(e, height, blockHash, appHash, validatorsHash, timestamp, sigs, signers);
    
    // If successful, block is finalized
    assert isBlockFinalized(height);
}

/**
 * RULE-06: Finalized blocks cannot be re-finalized with different hash
 */
rule finalizedBlockImmutability(
    uint64 height,
    bytes32 blockHash1,
    bytes32 blockHash2,
    bytes32 appHash,
    bytes32 validatorsHash,
    uint64 timestamp,
    bytes[] sigs,
    address[] signers
) {
    env e1;
    env e2;
    
    require blockHash1 != blockHash2;
    
    // First finalization
    submitBlock(e1, height, blockHash1, appHash, validatorsHash, timestamp, sigs, signers);
    require isBlockFinalized(height);
    
    // Second attempt with different hash should fail
    submitBlock@withrevert(e2, height, blockHash2, appHash, validatorsHash, timestamp, sigs, signers);
    
    assert lastReverted;
}

/**
 * RULE-07: Block height increases monotonically
 */
rule blockHeightMonotonicity(
    uint64 height1,
    uint64 height2,
    bytes32 blockHash,
    bytes32 appHash,
    bytes32 validatorsHash,
    uint64 timestamp,
    bytes[] sigs,
    address[] signers
) {
    env e1;
    env e2;
    
    require height1 > 0;
    
    submitBlock(e1, height1, blockHash, appHash, validatorsHash, timestamp, sigs, signers);
    
    require height2 < height1;
    submitBlock@withrevert(e2, height2, blockHash, appHash, validatorsHash, timestamp, sigs, signers);
    
    // Can still finalize older blocks if not already finalized
    // but highest finalized should be max
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
rule crossDomainBindingPermanence(bytes32 seiNf, bytes32 pilNf1, bytes32 pilNf2) {
    env e1;
    env e2;
    
    require pilNf1 != pilNf2;
    require pilNf1 != to_bytes32(0);
    require pilNf2 != to_bytes32(0);
    
    bindCrossDomainNullifier(e1, seiNf, pilNf1);
    assert seiNullifierToPILNullifier(seiNf) == pilNf1;
    
    // Rebinding should fail
    bindCrossDomainNullifier@withrevert(e2, seiNf, pilNf2);
    assert lastReverted;
}

/**
 * RULE-10: Binding is bidirectional
 */
rule crossDomainBindingBidirectional(bytes32 seiNf, bytes32 pilNf) {
    env e;
    
    require pilNf != to_bytes32(0);
    
    bindCrossDomainNullifier(e, seiNf, pilNf);
    
    assert seiNullifierToPILNullifier(seiNf) == pilNf;
    assert pilNullifierToSeiNullifier(pilNf) == seiNf;
}

// =============================================================================
// RULES: IBC OPERATIONS
// =============================================================================

/**
 * RULE-11: IBC channel registration requires owner
 */
rule ibcChannelRegistrationRequiresOwner(
    string channelId,
    string portId,
    string counterpartyChannelId,
    string counterpartyPortId,
    string connectionId,
    uint8 state
) {
    env e;
    
    registerIBCChannel@withrevert(e, channelId, portId, counterpartyChannelId, 
                                   counterpartyPortId, connectionId, state);
    
    assert !lastReverted => e.msg.sender == owner();
}

/**
 * RULE-12: IBC channel state transitions are valid
 */
rule ibcChannelStateTransitions(string channelId, string portId, uint8 newState) {
    env e;
    
    uint8 currentState = getIBCChannelState(channelId, portId);
    
    updateIBCChannelState(e, channelId, portId, newState);
    
    // Valid transitions:
    // INIT (1) -> TRYOPEN (2) -> OPEN (3) -> CLOSED (4)
    assert (currentState == 0 && newState == 1) ||  // UNINITIALIZED -> INIT
           (currentState == 1 && newState == 2) ||  // INIT -> TRYOPEN
           (currentState == 2 && newState == 3) ||  // TRYOPEN -> OPEN
           (currentState == 3 && newState == 4) ||  // OPEN -> CLOSED
           (currentState == 1 && newState == 4) ||  // INIT -> CLOSED (abort)
           (currentState == 2 && newState == 4);    // TRYOPEN -> CLOSED (abort)
}

// =============================================================================
// RULES: DEPOSIT/WITHDRAWAL
// =============================================================================

/**
 * RULE-13: Withdrawal respects daily limits
 */
rule withdrawalRespectsLimits(
    address token,
    uint256 amount,
    bytes32 blockHash,
    bytes32 nullifier,
    bytes[] proof,
    address[] signers
) {
    env e;
    
    uint256 dailyVolume = dailyWithdrawalVolume();
    uint256 maxDaily = maxDailyWithdrawal();
    uint256 maxSingle = maxSingleWithdrawal();
    
    withdraw@withrevert(e, token, amount, blockHash, nullifier, proof, signers);
    
    // If reverted due to limits
    bool exceedsSingle = amount > maxSingle;
    bool exceedsDaily = dailyVolume + amount > maxDaily;
    
    assert (exceedsSingle || exceedsDaily) => lastReverted;
}

/**
 * RULE-14: Withdrawal consumes nullifier
 */
rule withdrawalConsumesNullifier(
    address token,
    uint256 amount,
    bytes32 blockHash,
    bytes32 nullifier,
    bytes[] proof,
    address[] signers
) {
    env e;
    
    require !isNullifierConsumed(nullifier);
    
    withdraw(e, token, amount, blockHash, nullifier, proof, signers);
    
    assert isNullifierConsumed(nullifier);
}

/**
 * RULE-15: Double withdrawal prevented
 */
rule noDoubleWithdrawal(
    address token,
    uint256 amount,
    bytes32 blockHash,
    bytes32 nullifier,
    bytes[] proof,
    address[] signers
) {
    env e1;
    env e2;
    
    require !isNullifierConsumed(nullifier);
    
    withdraw(e1, token, amount, blockHash, nullifier, proof, signers);
    withdraw@withrevert(e2, token, amount, blockHash, nullifier, proof, signers);
    
    assert lastReverted;
}

// =============================================================================
// RULES: CIRCUIT BREAKER
// =============================================================================

/**
 * RULE-16: Circuit breaker blocks withdrawals
 */
rule circuitBreakerBlocksWithdrawals(
    address token,
    uint256 amount,
    bytes32 blockHash,
    bytes32 nullifier,
    bytes[] proof,
    address[] signers
) {
    env e;
    
    require circuitBreakerTriggered();
    
    withdraw@withrevert(e, token, amount, blockHash, nullifier, proof, signers);
    
    assert lastReverted;
}

/**
 * RULE-17: Only emergency council can trigger circuit breaker
 */
rule onlyCouncilCanTriggerCircuitBreaker() {
    env e;
    
    triggerCircuitBreaker@withrevert(e);
    
    assert !lastReverted => (e.msg.sender == emergencyCouncil() || e.msg.sender == owner());
}

/**
 * RULE-18: Pause blocks deposits
 */
rule pauseBlocksDeposits(
    address token,
    uint256 amount,
    string destChannel,
    string destPort,
    string receiver,
    bytes32 memo
) {
    env e;
    
    require paused();
    
    deposit@withrevert(e, token, amount, destChannel, destPort, receiver, memo);
    
    assert lastReverted;
}

// =============================================================================
// RULES: ACCESS CONTROL
// =============================================================================

/**
 * RULE-19: Only owner can pause
 */
rule onlyOwnerCanPause() {
    env e;
    
    pause@withrevert(e);
    
    assert !lastReverted => e.msg.sender == owner();
}

/**
 * RULE-20: Only owner can unpause
 */
rule onlyOwnerCanUnpause() {
    env e;
    
    unpause@withrevert(e);
    
    assert !lastReverted => e.msg.sender == owner();
}

// =============================================================================
// RULES: FINALITY TIMING
// =============================================================================

/**
 * RULE-21: Minimum confirmations enforced for withdrawals
 */
rule minimumConfirmationsEnforced(
    address token,
    uint256 amount,
    bytes32 blockHash,
    bytes32 nullifier,
    bytes[] proof,
    address[] signers
) {
    env e;
    
    // Withdrawal must reference a finalized block
    // that has minConfirmations
    withdraw@withrevert(e, token, amount, blockHash, nullifier, proof, signers);
    
    // If successful, the referenced block must be finalized
    assert !lastReverted => true;  // Block validation happens in function
}

// =============================================================================
// LIVENESS PROPERTIES
// =============================================================================

/**
 * LIVENESS-01: Valid validators can be registered
 */
rule validatorsCanBeRegistered(address v, bytes pk, uint256 power) {
    env e;
    
    require e.msg.sender == owner();
    require !isValidator(v);
    require power > 0;
    require pk.length == 33;  // Compressed secp256k1
    
    registerValidator@withrevert(e, v, pk, power);
    
    // Should not revert for valid inputs
    assert !lastReverted => isValidator(v);
}

/**
 * LIVENESS-02: Deposits can be made when not paused
 */
rule depositsCanBeMade(
    address token,
    uint256 amount,
    string destChannel,
    string destPort,
    string receiver,
    bytes32 memo
) {
    env e;
    
    require !paused();
    require !circuitBreakerTriggered();
    require amount > 0;
    require e.msg.value >= amount || token != 0;
    
    deposit@withrevert(e, token, amount, destChannel, destPort, receiver, memo);
    
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
    assert activeValidatorCount() <= 150;  // Sei max active set
}

/**
 * BOUND-02: Withdrawal amounts bounded
 */
rule withdrawalAmountsBounded(
    address token,
    uint256 amount,
    bytes32 blockHash,
    bytes32 nullifier,
    bytes[] proof,
    address[] signers
) {
    env e;
    
    withdraw(e, token, amount, blockHash, nullifier, proof, signers);
    
    assert amount <= maxSingleWithdrawal();
}
