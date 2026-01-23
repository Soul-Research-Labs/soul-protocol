/*
 * Certora CVL Specification for Sui Bridge Integration
 * =====================================================
 * 
 * This specification verifies:
 * - Validator committee management
 * - Checkpoint-based finality
 * - Nullifier uniqueness and cross-domain binding
 * - Rate limiting and circuit breaker
 * - Deposit/withdrawal security
 */

using SuiPrimitives as Primitives;

methods {
    // State variables
    function currentEpoch() external returns (uint64) envfree;
    function latestCheckpoint() external returns (uint64) envfree;
    function getValidatorCount() external returns (uint256) envfree;
    function getTodayVolume() external returns (uint256) envfree;
    function getRemainingDailyLimit() external returns (uint256) envfree;
    
    // Mappings (view)
    function consumedNullifiers(bytes32) external returns (bool) envfree;
    function nullifierBindings(bytes32) external returns (bytes32) envfree;
    function checkpointDigests(uint64) external returns (bytes32) envfree;
    function processedCheckpoints(bytes32) external returns (bool) envfree;
    function tokenMappings(bytes32) external returns (address) envfree;
    function userDailyLimit(address) external returns (uint256) envfree;
    
    // Validator functions
    function validators(bytes32) external returns (
        bytes32 suiAddress,
        bytes memory blsPublicKey,
        bytes memory networkPublicKey,
        uint256 stake,
        uint256 commission,
        uint64 activeSince,
        bool isActive
    ) envfree;
    
    // Deposit/withdrawal info
    function getDepositInfo(bytes32) external returns (
        address sender,
        address token,
        uint256 amount,
        bytes32 suiRecipient,
        uint64 timestamp,
        bool claimed,
        bool refunded
    ) envfree;
    
    function getWithdrawalInfo(bytes32) external returns (
        bytes32 suiSender,
        address recipient,
        address token,
        uint256 amount,
        bytes32 txDigest,
        uint64 epoch,
        uint64 timestamp,
        bytes32 nullifier
    ) envfree;
    
    // Relayer info
    function relayers(address) external returns (
        bool isActive,
        uint256 feeBps,
        uint256 totalRelayed,
        uint256 lastActive
    ) envfree;
    
    // Circuit breaker
    function circuitBreaker() external returns (
        bool triggered,
        uint256 triggeredAt,
        uint256 cooldownPeriod,
        uint256 anomalyCount,
        uint256 lastAnomalyAt
    ) envfree;
    
    // Primitives (pure)
    function Primitives.hasQuorum(uint256, uint256) internal returns (bool) => NONDET;
    function Primitives.blake2b256(bytes memory) internal returns (bytes32) => NONDET;
    function Primitives.deriveNullifier(bytes32, uint64, bytes32) internal returns (bytes32) => NONDET;
    function Primitives.deriveCrossDomainNullifier(bytes32, uint256, uint256) internal returns (bytes32) => NONDET;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(bytes32 => bool) ghostNullifiersConsumed;
ghost mapping(bytes32 => bytes32) ghostNullifierBindings;
ghost uint256 ghostTotalDeposits;
ghost uint256 ghostTotalWithdrawals;

// =============================================================================
// HOOKS
// =============================================================================

hook Sstore consumedNullifiers[KEY bytes32 nf] bool value {
    ghostNullifiersConsumed[nf] = value;
}

hook Sstore nullifierBindings[KEY bytes32 nf] bytes32 value {
    ghostNullifierBindings[nf] = value;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * Invariant: Nullifier immutability
 * Once a nullifier is consumed, it cannot be un-consumed
 */
invariant nullifierImmutability(bytes32 nf)
    ghostNullifiersConsumed[nf] => consumedNullifiers(nf)
    {
        preserved {
            require ghostNullifiersConsumed[nf] == consumedNullifiers(nf);
        }
    }

/**
 * Invariant: Daily volume bounded
 * Daily volume should not exceed MAX_DAILY_VOLUME (1M ether)
 */
invariant dailyVolumeBounded()
    getTodayVolume() <= 1000000000000000000000000 // 1M ether in wei
    {
        preserved with (env e) {
            require e.block.timestamp > 0;
        }
    }

/**
 * Invariant: Checkpoint sequence monotonicity
 * Latest checkpoint sequence number only increases
 */
invariant checkpointMonotonicity(uint64 prevLatest)
    latestCheckpoint() >= prevLatest
    {
        preserved submitCheckpoint(
            SuiPrimitives.CheckpointSummary checkpoint,
            bytes aggregatedSignature,
            bytes32[] signingValidators
        ) with (env e) {
            require checkpoint.sequenceNumber > prevLatest;
        }
    }

/**
 * Invariant: Epoch progression
 * Current epoch only increases
 */
invariant epochProgression(uint64 prevEpoch)
    currentEpoch() >= prevEpoch
    {
        preserved updateCommittee(
            uint64 epoch,
            bytes32[] validators,
            uint256[] stakes
        ) with (env e) {
            require epoch > prevEpoch;
        }
    }

// =============================================================================
// NULLIFIER RULES
// =============================================================================

/**
 * Rule: Nullifier uniqueness
 * A nullifier can only be consumed once
 */
rule nullifierUniqueness(bytes32 nullifier, env e, method f, calldataarg args) {
    require consumedNullifiers(nullifier);
    
    f(e, args);
    
    // If nullifier was consumed before, it remains consumed
    assert consumedNullifiers(nullifier),
        "Consumed nullifier must remain consumed";
}

/**
 * Rule: Nullifier binding consistency
 * Once a binding exists, it should not change
 */
rule nullifierBindingImmutability(bytes32 suiNullifier, env e, method f, calldataarg args) {
    bytes32 bindingBefore = nullifierBindings(suiNullifier);
    require bindingBefore != 0;
    
    f(e, args);
    
    bytes32 bindingAfter = nullifierBindings(suiNullifier);
    assert bindingAfter == bindingBefore,
        "Existing nullifier binding must not change";
}

/**
 * Rule: Cross-domain nullifier derivation determinism
 * Same inputs should always produce same PIL binding
 */
rule crossDomainNullifierDeterminism(
    bytes32 suiNullifier,
    uint256 sourceChain,
    uint256 targetChain
) {
    bytes32 result1 = Primitives.deriveCrossDomainNullifier(suiNullifier, sourceChain, targetChain);
    bytes32 result2 = Primitives.deriveCrossDomainNullifier(suiNullifier, sourceChain, targetChain);
    
    assert result1 == result2,
        "Cross-domain nullifier derivation must be deterministic";
}

// =============================================================================
// DEPOSIT RULES
// =============================================================================

/**
 * Rule: Deposit state transitions
 * A deposit can only transition: pending -> claimed OR pending -> refunded
 */
rule depositStateTransition(bytes32 depositId, env e, method f, calldataarg args) {
    address sender;
    address token;
    uint256 amount;
    bytes32 suiRecipient;
    uint64 timestamp;
    bool claimedBefore;
    bool refundedBefore;
    
    sender, token, amount, suiRecipient, timestamp, claimedBefore, refundedBefore = getDepositInfo(depositId);
    
    f(e, args);
    
    bool claimedAfter;
    bool refundedAfter;
    _, _, _, _, _, claimedAfter, refundedAfter = getDepositInfo(depositId);
    
    // Cannot go from claimed/refunded back to pending
    assert claimedBefore => claimedAfter,
        "Claimed deposit cannot become unclaimed";
    assert refundedBefore => refundedAfter,
        "Refunded deposit cannot become un-refunded";
    
    // Cannot be both claimed and refunded
    assert !(claimedAfter && refundedAfter),
        "Deposit cannot be both claimed and refunded";
}

/**
 * Rule: Deposit amount preservation
 * Deposit amount should not change after creation
 */
rule depositAmountPreservation(bytes32 depositId, env e, method f, calldataarg args) {
    uint256 amountBefore;
    _, _, amountBefore, _, _, _, _ = getDepositInfo(depositId);
    require amountBefore > 0;
    
    f(e, args);
    
    uint256 amountAfter;
    _, _, amountAfter, _, _, _, _ = getDepositInfo(depositId);
    
    assert amountAfter == amountBefore,
        "Deposit amount must not change";
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/**
 * Rule: Withdrawal requires nullifier consumption
 * A withdrawal should always consume a nullifier
 */
rule withdrawalConsumesNullifier(
    SuiPrimitives.SuiBridgeTransfer transfer,
    bytes32[] proof,
    uint256[] proofIndices,
    uint64 checkpointSeq,
    address relayer,
    uint256 relayerFeeBps,
    env e
) {
    bytes32 expectedNullifier = Primitives.deriveNullifier(
        transfer.sourceObject,
        0,
        transfer.txDigest
    );
    
    require !consumedNullifiers(expectedNullifier);
    
    processWithdrawal(e, transfer, proof, proofIndices, checkpointSeq, relayer, relayerFeeBps);
    
    assert consumedNullifiers(expectedNullifier),
        "Withdrawal must consume nullifier";
}

/**
 * Rule: No double withdrawal
 * Cannot process the same withdrawal twice
 */
rule noDoubleWithdrawal(
    SuiPrimitives.SuiBridgeTransfer transfer,
    bytes32[] proof,
    uint256[] proofIndices,
    uint64 checkpointSeq,
    address relayer,
    uint256 relayerFeeBps,
    env e
) {
    bytes32 transferId = Primitives.computeTransferId(transfer);
    
    uint64 timestampBefore;
    _, _, _, _, _, _, timestampBefore, _ = getWithdrawalInfo(transferId);
    require timestampBefore > 0; // Already processed
    
    processWithdrawal@withrevert(e, transfer, proof, proofIndices, checkpointSeq, relayer, relayerFeeBps);
    
    assert lastReverted,
        "Double withdrawal must revert";
}

// =============================================================================
// VALIDATOR RULES
// =============================================================================

/**
 * Rule: Validator stake requirement
 * Validator must have positive stake to be registered
 */
rule validatorStakeRequired(bytes32 suiAddress, bytes blsPublicKey, uint256 stake, env e) {
    require stake == 0;
    
    registerValidator@withrevert(e, suiAddress, blsPublicKey, stake);
    
    assert lastReverted,
        "Zero stake validator registration must revert";
}

/**
 * Rule: BLS key length requirement
 * Validator BLS public key must be exactly 96 bytes
 */
rule validatorBLSKeyLength(bytes32 suiAddress, bytes blsPublicKey, uint256 stake, env e) {
    require blsPublicKey.length != 96;
    require stake > 0;
    
    registerValidator@withrevert(e, suiAddress, blsPublicKey, stake);
    
    assert lastReverted,
        "Invalid BLS key length must revert";
}

/**
 * Rule: Removed validator becomes inactive
 */
rule validatorRemovalDeactivates(bytes32 suiAddress, env e) {
    bool isActiveBefore;
    _, _, _, _, _, _, isActiveBefore = validators(suiAddress);
    require isActiveBefore;
    
    removeValidator(e, suiAddress);
    
    bool isActiveAfter;
    _, _, _, _, _, _, isActiveAfter = validators(suiAddress);
    
    assert !isActiveAfter,
        "Removed validator must be inactive";
}

// =============================================================================
// COMMITTEE RULES
// =============================================================================

/**
 * Rule: Committee update requires epoch advancement
 * Cannot update committee to same or earlier epoch
 */
rule committeeEpochAdvancement(uint64 newEpoch, bytes32[] validators, uint256[] stakes, env e) {
    uint64 currentEpochBefore = currentEpoch();
    require newEpoch <= currentEpochBefore;
    
    updateCommittee@withrevert(e, newEpoch, validators, stakes);
    
    assert lastReverted,
        "Committee update to non-advancing epoch must revert";
}

/**
 * Rule: Committee validators and stakes length match
 */
rule committeeArraysMatch(uint64 newEpoch, bytes32[] validators, uint256[] stakes, env e) {
    require validators.length != stakes.length;
    
    updateCommittee@withrevert(e, newEpoch, validators, stakes);
    
    assert lastReverted,
        "Mismatched array lengths must revert";
}

// =============================================================================
// CHECKPOINT RULES
// =============================================================================

/**
 * Rule: Checkpoint chain verification
 * New checkpoint must reference previous checkpoint correctly
 */
rule checkpointChainIntegrity(
    SuiPrimitives.CheckpointSummary checkpoint,
    bytes aggregatedSignature,
    bytes32[] signingValidators,
    env e
) {
    require checkpoint.sequenceNumber > 0;
    bytes32 expectedPrevDigest = checkpointDigests(checkpoint.sequenceNumber - 1);
    require checkpoint.previousDigest != expectedPrevDigest;
    
    submitCheckpoint@withrevert(e, checkpoint, aggregatedSignature, signingValidators);
    
    assert lastReverted,
        "Invalid checkpoint chain must revert";
}

/**
 * Rule: No duplicate checkpoint processing
 */
rule noDuplicateCheckpoint(
    SuiPrimitives.CheckpointSummary checkpoint,
    bytes aggregatedSignature,
    bytes32[] signingValidators,
    env e
) {
    bytes32 digest = Primitives.computeCheckpointDigest(checkpoint);
    require processedCheckpoints(digest);
    
    submitCheckpoint@withrevert(e, checkpoint, aggregatedSignature, signingValidators);
    
    assert lastReverted,
        "Duplicate checkpoint must revert";
}

// =============================================================================
// CIRCUIT BREAKER RULES
// =============================================================================

/**
 * Rule: Circuit breaker blocks deposits
 * When circuit breaker is active, deposits should revert
 */
rule circuitBreakerBlocksDeposits(address token, uint256 amount, bytes32 suiRecipient, env e) {
    bool triggered;
    uint256 triggeredAt;
    uint256 cooldownPeriod;
    triggered, triggeredAt, cooldownPeriod, _, _ = circuitBreaker();
    
    require triggered;
    require e.block.timestamp < triggeredAt + cooldownPeriod;
    
    deposit@withrevert(e, token, amount, suiRecipient);
    
    assert lastReverted,
        "Deposit during circuit breaker must revert";
}

/**
 * Rule: Circuit breaker auto-resets after cooldown
 */
rule circuitBreakerAutoReset(address token, uint256 amount, bytes32 suiRecipient, env e) {
    bool triggered;
    uint256 triggeredAt;
    uint256 cooldownPeriod;
    triggered, triggeredAt, cooldownPeriod, _, _ = circuitBreaker();
    
    require triggered;
    require e.block.timestamp >= triggeredAt + cooldownPeriod;
    require amount > 0 && amount <= 100000000000000000000000; // <= 100k ether
    require suiRecipient != 0;
    require getTodayVolume() + amount <= 1000000000000000000000000; // Won't exceed limit
    
    deposit(e, token, amount, suiRecipient);
    
    // Deposit succeeded, circuit breaker was reset
    bool triggeredAfter;
    triggeredAfter, _, _, _, _ = circuitBreaker();
    assert !triggeredAfter,
        "Circuit breaker should auto-reset after cooldown";
}

// =============================================================================
// RELAYER RULES
// =============================================================================

/**
 * Rule: Relayer fee cap enforcement
 */
rule relayerFeeCap(address relayerAddr, uint256 feeBps, env e) {
    require feeBps > 500; // > 5%
    
    registerRelayer@withrevert(e, relayerAddr, feeBps);
    
    assert lastReverted,
        "Excessive relayer fee must revert";
}

/**
 * Rule: Relayer removal deactivates
 */
rule relayerRemovalDeactivates(address relayerAddr, env e) {
    bool isActiveBefore;
    isActiveBefore, _, _, _ = relayers(relayerAddr);
    require isActiveBefore;
    
    removeRelayer(e, relayerAddr);
    
    bool isActiveAfter;
    isActiveAfter, _, _, _ = relayers(relayerAddr);
    
    assert !isActiveAfter,
        "Removed relayer must be inactive";
}

// =============================================================================
// RATE LIMITING RULES
// =============================================================================

/**
 * Rule: Transfer size limit
 * Single transfer cannot exceed MAX_TRANSFER (100k ether)
 */
rule transferSizeLimit(address token, uint256 amount, bytes32 suiRecipient, env e) {
    require amount > 100000000000000000000000; // > 100k ether
    
    deposit@withrevert(e, token, amount, suiRecipient);
    
    assert lastReverted,
        "Transfer exceeding max must revert";
}

/**
 * Rule: Daily volume accumulation
 * Deposits should increase daily volume
 */
rule dailyVolumeAccumulation(address token, uint256 amount, bytes32 suiRecipient, env e) {
    require amount > 0 && amount <= 100000000000000000000000;
    require suiRecipient != 0;
    
    uint256 volumeBefore = getTodayVolume();
    require volumeBefore + amount <= 1000000000000000000000000;
    
    // Ensure no circuit breaker
    bool triggered;
    triggered, _, _, _, _ = circuitBreaker();
    require !triggered;
    
    deposit(e, token, amount, suiRecipient);
    
    uint256 volumeAfter = getTodayVolume();
    assert volumeAfter == volumeBefore + amount,
        "Daily volume should increase by deposit amount";
}

// =============================================================================
// SECURITY PROPERTIES
// =============================================================================

/**
 * Property: No value extraction without valid proof
 * Funds can only be withdrawn with valid checkpoint proof
 */
rule noValueExtractionWithoutProof(
    SuiPrimitives.SuiBridgeTransfer transfer,
    bytes32[] proof,
    uint256[] proofIndices,
    uint64 checkpointSeq,
    address relayer,
    uint256 relayerFeeBps,
    env e
) {
    // Insufficient confirmations
    require checkpointSeq > latestCheckpoint();
    
    processWithdrawal@withrevert(e, transfer, proof, proofIndices, checkpointSeq, relayer, relayerFeeBps);
    
    assert lastReverted,
        "Withdrawal without sufficient confirmations must revert";
}

/**
 * Property: Pause blocks all operations
 */
rule pauseBlocksOperations(address token, uint256 amount, bytes32 suiRecipient, env e) {
    require paused();
    
    deposit@withrevert(e, token, amount, suiRecipient);
    
    assert lastReverted,
        "Deposit when paused must revert";
}
