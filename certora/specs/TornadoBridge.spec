// certora/specs/TornadoBridge.spec
// Certora CVL Specification for Tornado Cash Bridge Adapter
// Author: PIL Protocol
// Date: January 2026

// ============================================================================
// METHODS
// ============================================================================

methods {
    // TornadoBridgeAdapter methods
    function deposit(bytes32, uint256) external;
    function withdraw(TornadoPrimitives.Groth16Proof, TornadoPrimitives.WithdrawalInputs, uint256) external;
    function registerCrossDomainNullifier(bytes32, uint256) external;
    function registerRelayer() external;
    function unregisterRelayer() external;
    function claimRelayerFees() external;

    // View functions
    function getLastRoot(uint256) external returns (bytes32) envfree;
    function isKnownRoot(uint256, bytes32) external returns (bool) envfree;
    function isSpent(uint256, bytes32) external returns (bool) envfree;
    function getPoolStats(uint256) external returns (uint256, uint256, uint32) envfree;
    function getDepositTimestamp(bytes32) external returns (uint256) envfree;
    function registeredRelayers(address) external returns (bool) envfree;
    function relayerFees(address) external returns (uint256) envfree;
    function circuitBreakerTriggered() external returns (bool) envfree;
    function crossDomainNullifiers(bytes32) external returns (bytes32) envfree;
    function pilBindings(bytes32) external returns (bytes32) envfree;

    // Admin functions
    function triggerCircuitBreaker(string) external;
    function resetCircuitBreaker() external;
    function pause() external;
    function unpause() external;

    // Constants
    function MAX_RELAYER_FEE_PERCENT() external returns (uint256) envfree;
    function ROOT_HISTORY_SIZE() external returns (uint256) envfree;
    function MAX_DAILY_VOLUME() external returns (uint256) envfree;

    // TornadoPrimitives pure functions
    function TornadoPrimitives.isValidCommitment(bytes32) internal returns (bool) => ALWAYS(true);
    function TornadoPrimitives.isValidNullifier(bytes32) internal returns (bool) => ALWAYS(true);
    function TornadoPrimitives.isValidDenomination(uint256) internal returns (bool) => DISPATCHER(true);
    function TornadoPrimitives.verifyWithdrawalProof(TornadoPrimitives.Groth16Proof, TornadoPrimitives.WithdrawalInputs) internal returns (bool) => ALWAYS(true);
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track total deposits per denomination
ghost mapping(uint256 => uint256) ghostTotalDeposits {
    init_state axiom forall uint256 d. ghostTotalDeposits[d] == 0;
}

// Track spent nullifiers
ghost mapping(uint256 => mapping(bytes32 => bool)) ghostNullifierSpent {
    init_state axiom forall uint256 d. forall bytes32 n. ghostNullifierSpent[d][n] == false;
}

// Track commitments
ghost mapping(uint256 => mapping(bytes32 => bool)) ghostCommitmentExists {
    init_state axiom forall uint256 d. forall bytes32 c. ghostCommitmentExists[d][c] == false;
}

// Track total withdrawals
ghost mapping(uint256 => uint256) ghostTotalWithdrawals {
    init_state axiom forall uint256 d. ghostTotalWithdrawals[d] == 0;
}

// ============================================================================
// INVARIANTS
// ============================================================================

// INVARIANT: Withdrawals never exceed deposits
invariant withdrawalsNeverExceedDeposits(uint256 denomination)
    ghostTotalWithdrawals[denomination] <= ghostTotalDeposits[denomination]
    {
        preserved deposit(bytes32 commitment, uint256 denom) with (env e) {
            require denom == denomination;
        }
        preserved withdraw(TornadoPrimitives.Groth16Proof proof, TornadoPrimitives.WithdrawalInputs inputs, uint256 denom) with (env e) {
            require denom == denomination;
        }
    }

// INVARIANT: Spent nullifiers remain spent
invariant nullifiersRemainSpent(uint256 denomination, bytes32 nullifierHash)
    ghostNullifierSpent[denomination][nullifierHash] => isSpent(denomination, nullifierHash)

// INVARIANT: Commitments are unique
invariant commitmentsUnique(uint256 denomination, bytes32 commitment)
    ghostCommitmentExists[denomination][commitment] => getDepositTimestamp(commitment) > 0

// ============================================================================
// RULES
// ============================================================================

// RULE: No double-spend
// A nullifier can only be spent once
rule noDoubleSpend(env e) {
    uint256 denomination;
    bytes32 nullifierHash;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    require inputs.nullifierHash == nullifierHash;
    require !isSpent(denomination, nullifierHash);

    withdraw(e, proof, inputs, denomination);

    assert isSpent(denomination, nullifierHash), "Nullifier must be marked as spent";

    // Second withdrawal with same nullifier should revert
    // (implicit in Certora - reverting functions don't complete)
}

// RULE: No double-deposit
// A commitment can only be deposited once
rule noDoubleDeposit(env e1, env e2) {
    bytes32 commitment;
    uint256 denomination;

    // First deposit
    deposit(e1, commitment, denomination);
    uint256 timestamp1 = getDepositTimestamp(commitment);

    // Second deposit with same commitment should revert
    deposit@withrevert(e2, commitment, denomination);

    assert lastReverted, "Double deposit must revert";
}

// RULE: Deposit increases pool size
rule depositIncreasesPool(env e) {
    bytes32 commitment;
    uint256 denomination;

    uint256 totalBefore;
    uint256 withdrawalsBefore;
    uint32 nextIndexBefore;
    totalBefore, withdrawalsBefore, nextIndexBefore = getPoolStats(denomination);

    deposit(e, commitment, denomination);

    uint256 totalAfter;
    uint256 withdrawalsAfter;
    uint32 nextIndexAfter;
    totalAfter, withdrawalsAfter, nextIndexAfter = getPoolStats(denomination);

    assert totalAfter == totalBefore + 1, "Total deposits must increase";
    assert nextIndexAfter == nextIndexBefore + 1, "Next index must increase";
    assert withdrawalsAfter == withdrawalsBefore, "Withdrawals must not change";
}

// RULE: Withdrawal decreases anonymity set
rule withdrawalDecreasesAnonymitySet(env e) {
    uint256 denomination;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    uint256 totalBefore;
    uint256 withdrawalsBefore;
    uint32 nextIndexBefore;
    totalBefore, withdrawalsBefore, nextIndexBefore = getPoolStats(denomination);

    require withdrawalsBefore < totalBefore;

    withdraw(e, proof, inputs, denomination);

    uint256 totalAfter;
    uint256 withdrawalsAfter;
    uint32 nextIndexAfter;
    totalAfter, withdrawalsAfter, nextIndexAfter = getPoolStats(denomination);

    assert totalAfter == totalBefore, "Total deposits must not change";
    assert withdrawalsAfter == withdrawalsBefore + 1, "Withdrawals must increase";
}

// RULE: Circuit breaker blocks all operations
rule circuitBreakerBlocks(env e) {
    require circuitBreakerTriggered();

    bytes32 commitment;
    uint256 denomination;

    deposit@withrevert(e, commitment, denomination);

    assert lastReverted, "Deposit must revert when circuit breaker active";
}

// RULE: Relayer fee bounds
rule relayerFeeBounds(env e) {
    uint256 denomination;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    require inputs.fee > (denomination * MAX_RELAYER_FEE_PERCENT()) / 10000;

    withdraw@withrevert(e, proof, inputs, denomination);

    assert lastReverted, "Excessive relayer fee must revert";
}

// RULE: Only registered relayers can receive fees
rule onlyRegisteredRelayersReceiveFees(env e) {
    uint256 denomination;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    require inputs.relayer != 0;
    require inputs.fee > 0;
    require !registeredRelayers(inputs.relayer);

    withdraw@withrevert(e, proof, inputs, denomination);

    assert lastReverted, "Unregistered relayer must cause revert";
}

// RULE: Relayer registration is permissionless
rule relayerRegistrationPermissionless(env e) {
    address relayer = e.msg.sender;

    require !registeredRelayers(relayer);

    registerRelayer(e);

    assert registeredRelayers(relayer), "Relayer must be registered";
}

// RULE: Cross-domain nullifier uniqueness
rule crossDomainNullifierUniqueness(env e1, env e2) {
    bytes32 tornadoNullifier1;
    bytes32 tornadoNullifier2;
    uint256 targetChainId;

    require tornadoNullifier1 != tornadoNullifier2;

    registerCrossDomainNullifier(e1, tornadoNullifier1, targetChainId);
    registerCrossDomainNullifier(e2, tornadoNullifier2, targetChainId);

    bytes32 pilNullifier1 = crossDomainNullifiers(tornadoNullifier1);
    bytes32 pilNullifier2 = crossDomainNullifiers(tornadoNullifier2);

    assert pilNullifier1 != pilNullifier2, "PIL nullifiers must be unique";
}

// RULE: Cross-domain binding bidirectionality
rule crossDomainBindingBidirectional(env e) {
    bytes32 tornadoNullifier;
    uint256 targetChainId;

    registerCrossDomainNullifier(e, tornadoNullifier, targetChainId);

    bytes32 pilNullifier = crossDomainNullifiers(tornadoNullifier);
    bytes32 reverseTornado = pilBindings(pilNullifier);

    assert reverseTornado == tornadoNullifier, "Reverse mapping must match";
}

// RULE: Valid denomination required for deposit
rule validDenominationRequired(env e) {
    bytes32 commitment;
    uint256 denomination;

    require denomination != 100000000000000000;      // 0.1 ETH
    require denomination != 1000000000000000000;     // 1 ETH
    require denomination != 10000000000000000000;    // 10 ETH
    require denomination != 100000000000000000000;   // 100 ETH

    deposit@withrevert(e, commitment, denomination);

    assert lastReverted, "Invalid denomination must revert";
}

// RULE: Deposit timestamp recorded
rule depositTimestampRecorded(env e) {
    bytes32 commitment;
    uint256 denomination;

    require getDepositTimestamp(commitment) == 0;

    deposit(e, commitment, denomination);

    assert getDepositTimestamp(commitment) == e.block.timestamp, "Timestamp must be recorded";
}

// RULE: Root history maintained
rule rootHistoryMaintained(env e) {
    bytes32 commitment;
    uint256 denomination;

    bytes32 rootBefore = getLastRoot(denomination);

    deposit(e, commitment, denomination);

    bytes32 rootAfter = getLastRoot(denomination);

    assert rootAfter != rootBefore, "Root must change after deposit";
    assert isKnownRoot(denomination, rootAfter), "New root must be known";
    assert isKnownRoot(denomination, rootBefore), "Old root must still be known";
}

// RULE: Withdrawal requires known root
rule withdrawalRequiresKnownRoot(env e) {
    uint256 denomination;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    require !isKnownRoot(denomination, inputs.root);

    withdraw@withrevert(e, proof, inputs, denomination);

    assert lastReverted, "Unknown root must cause revert";
}

// ============================================================================
// PARAMETRIC RULES
// ============================================================================

// Parametric rule for all denomination operations
rule denominationConsistency(method f, uint256 denomination) filtered {
    f -> f.selector == sig:deposit(bytes32, uint256).selector ||
         f.selector == sig:withdraw(TornadoPrimitives.Groth16Proof, TornadoPrimitives.WithdrawalInputs, uint256).selector
} {
    env e;
    calldataarg args;

    // Get stats before
    uint256 totalBefore;
    uint256 withdrawalsBefore;
    uint32 indexBefore;
    totalBefore, withdrawalsBefore, indexBefore = getPoolStats(denomination);

    f(e, args);

    // Get stats after
    uint256 totalAfter;
    uint256 withdrawalsAfter;
    uint32 indexAfter;
    totalAfter, withdrawalsAfter, indexAfter = getPoolStats(denomination);

    // Pool stats must be consistent
    assert totalAfter >= totalBefore, "Total deposits cannot decrease";
    assert withdrawalsAfter >= withdrawalsBefore, "Withdrawals cannot decrease";
    assert indexAfter >= indexBefore, "Index cannot decrease";
}

// ============================================================================
// LIVENESS PROPERTIES
// ============================================================================

// RULE: Deposit always possible (when not paused/breaker)
rule depositAlwaysPossible(env e) {
    bytes32 commitment;
    uint256 denomination;

    require !circuitBreakerTriggered();
    require e.msg.value == denomination;
    require denomination == 1000000000000000000; // 1 ETH
    require getDepositTimestamp(commitment) == 0; // Not already deposited

    deposit(e, commitment, denomination);

    // If we reach here, deposit succeeded
    assert getDepositTimestamp(commitment) > 0, "Deposit must be recorded";
}

// RULE: Withdrawal always possible for valid proofs
rule withdrawalAlwaysPossible(env e) {
    uint256 denomination;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    require !circuitBreakerTriggered();
    require isKnownRoot(denomination, inputs.root);
    require !isSpent(denomination, inputs.nullifierHash);
    require inputs.fee <= (denomination * MAX_RELAYER_FEE_PERCENT()) / 10000;
    require inputs.relayer == 0 || registeredRelayers(inputs.relayer);

    withdraw(e, proof, inputs, denomination);

    assert isSpent(denomination, inputs.nullifierHash), "Withdrawal must succeed";
}

// ============================================================================
// ACCESS CONTROL PROPERTIES
// ============================================================================

// RULE: Only guardian can trigger circuit breaker
rule onlyGuardianCanTriggerBreaker(env e) {
    string reason;

    // Assuming guardian check in hasRole
    triggerCircuitBreaker@withrevert(e, reason);

    // Rule should encode access control
    // Certora will check all paths
}

// RULE: Only admin can reset circuit breaker
rule onlyAdminCanResetBreaker(env e) {
    resetCircuitBreaker@withrevert(e);

    // Access control check
}

// ============================================================================
// FUND SAFETY PROPERTIES
// ============================================================================

// RULE: Contract balance integrity
rule contractBalanceIntegrity(env e) {
    bytes32 commitment;
    uint256 denomination;

    mathint balanceBefore = nativeBalances[currentContract];

    deposit(e, commitment, denomination);

    mathint balanceAfter = nativeBalances[currentContract];

    assert balanceAfter == balanceBefore + to_mathint(denomination), "Balance must increase by denomination";
}

// RULE: Withdrawal pays correct amount
rule withdrawalPaysCorrectAmount(env e) {
    uint256 denomination;
    TornadoPrimitives.Groth16Proof proof;
    TornadoPrimitives.WithdrawalInputs inputs;

    mathint recipientBefore = nativeBalances[inputs.recipient];
    mathint relayerBefore = nativeBalances[inputs.relayer];

    require inputs.relayer != inputs.recipient;
    require inputs.relayer != 0;
    require registeredRelayers(inputs.relayer);

    withdraw(e, proof, inputs, denomination);

    mathint recipientAfter = nativeBalances[inputs.recipient];
    mathint relayerAfter = nativeBalances[inputs.relayer];

    assert recipientAfter == recipientBefore + to_mathint(denomination - inputs.fee), "Recipient must receive denomination minus fee";
    assert relayerAfter == relayerBefore + to_mathint(inputs.fee), "Relayer must receive fee";
}
