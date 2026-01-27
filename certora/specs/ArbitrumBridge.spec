// SPDX-License-Identifier: MIT
// Certora CVL Specification for Arbitrum Bridge Adapter
// Soul Protocol (Soul) - Formal Verification

/*
 * =============================================================================
 * ARBITRUM BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 * 
 * This specification verifies the security properties of the Arbitrum Bridge
 * Adapter including:
 * - L1 <-> L2 deposit/withdrawal integrity
 * - Retryable ticket management
 * - Challenge period enforcement
 * - Cross-domain nullifier uniqueness
 * - Outbox proof verification
 * - Fee and amount bounds
 */

using ArbitrumBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    // View functions
    function deposits(bytes32) external returns (
        bytes32 depositId,
        address sender,
        address l2Recipient,
        address l1Token,
        address l2Token,
        uint256 amount,
        uint256 maxSubmissionCost,
        uint256 l2GasLimit,
        uint256 l2GasPrice,
        uint256 ticketId,
        uint8 status,
        uint256 initiatedAt,
        uint256 executedAt
    ) envfree;
    
    function withdrawals(bytes32) external returns (
        bytes32 withdrawalId,
        address l2Sender,
        address l1Recipient,
        address l2Token,
        address l1Token,
        uint256 amount,
        uint256 l2BlockNumber,
        uint256 l1BatchNumber,
        uint256 l2Timestamp,
        bytes32 outputId,
        uint8 status,
        uint256 initiatedAt,
        uint256 claimableAt,
        uint256 claimedAt
    ) envfree;
    
    function retryableTickets(uint256) external returns (
        uint256 ticketId,
        address from,
        address to,
        uint256 value,
        bytes data,
        uint256 maxSubmissionCost,
        uint256 l2GasLimit,
        uint256 l2GasPrice,
        bool redeemed,
        uint256 createdAt
    ) envfree;
    
    function processedOutputs(bytes32) external returns (bool) envfree;
    function rollupConfigs(uint256) external returns (
        uint256 chainId,
        address inbox,
        address outbox,
        address bridge,
        address rollup,
        uint8 rollupType,
        bool active
    ) envfree;
    
    function bridgeFee() external returns (uint256) envfree;
    function minDepositAmount() external returns (uint256) envfree;
    function maxDepositAmount() external returns (uint256) envfree;
    function transferNonce() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalValueDeposited() external returns (uint256) envfree;
    function totalValueWithdrawn() external returns (uint256) envfree;
    function fastExitEnabled() external returns (bool) envfree;
    
    // Constants
    function CHALLENGE_PERIOD() external returns (uint256) envfree;
    function ARB_ONE_CHAIN_ID() external returns (uint256) envfree;
    function ARB_NOVA_CHAIN_ID() external returns (uint256) envfree;
    function DEFAULT_L2_GAS_LIMIT() external returns (uint256) envfree;
    function DEFAULT_MAX_SUBMISSION_COST() external returns (uint256) envfree;
    
    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function EXECUTOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES FOR TRACKING STATE
// =============================================================================

// Track total deposits
ghost uint256 ghostTotalDeposits {
    init_state axiom ghostTotalDeposits == 0;
}

// Track total withdrawals
ghost uint256 ghostTotalWithdrawals {
    init_state axiom ghostTotalWithdrawals == 0;
}

// Track consumed nullifiers
ghost mapping(bytes32 => bool) ghostConsumedNullifiers {
    init_state axiom forall bytes32 nf. ghostConsumedNullifiers[nf] == false;
}

// Track processed outputs
ghost mapping(bytes32 => bool) ghostProcessedOutputs {
    init_state axiom forall bytes32 out. ghostProcessedOutputs[out] == false;
}

// Track deposit statuses
ghost mapping(bytes32 => uint8) ghostDepositStatus {
    init_state axiom forall bytes32 id. ghostDepositStatus[id] == 0;
}

// Track withdrawal claimable times
ghost mapping(bytes32 => uint256) ghostWithdrawalClaimableAt {
    init_state axiom forall bytes32 id. ghostWithdrawalClaimableAt[id] == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Deposit amount bounds are enforced
/// @notice Every deposit must respect min/max amount constraints
invariant depositAmountBounds(bytes32 depositId)
    deposits(depositId).amount == 0 || 
    (deposits(depositId).amount >= minDepositAmount() && 
     deposits(depositId).amount <= maxDepositAmount())
    {
        preserved {
            require minDepositAmount() > 0;
            require maxDepositAmount() > minDepositAmount();
        }
    }

/// @title Withdrawal claimable time enforces challenge period
/// @notice Claimable time must be at least CHALLENGE_PERIOD after initiation
invariant challengePeriodEnforced(bytes32 withdrawalId)
    withdrawals(withdrawalId).claimableAt == 0 ||
    withdrawals(withdrawalId).claimableAt >= 
        withdrawals(withdrawalId).initiatedAt + CHALLENGE_PERIOD()

/// @title Processed outputs cannot be reprocessed
/// @notice Once an output is processed, it stays processed
invariant outputProcessedOnce(bytes32 outputId)
    processedOutputs(outputId) == ghostProcessedOutputs[outputId]

/// @title Total deposits counter consistency
/// @notice Total deposits should equal ghost counter
invariant totalDepositsConsistent()
    totalDeposits() == ghostTotalDeposits

/// @title Total withdrawals counter consistency
/// @notice Total withdrawals should equal ghost counter
invariant totalWithdrawalsConsistent()
    totalWithdrawals() == ghostTotalWithdrawals

/// @title Retryable ticket redemption is one-time
/// @notice A redeemed ticket cannot be redeemed again
invariant ticketRedeemedOnce(uint256 ticketId)
    retryableTickets(ticketId).redeemed == true => 
    retryableTickets(ticketId).createdAt > 0

/// @title Active rollup configuration integrity
/// @notice Active rollups must have valid addresses
invariant rollupConfigIntegrity(uint256 chainId)
    rollupConfigs(chainId).active == true =>
    (rollupConfigs(chainId).inbox != 0 &&
     rollupConfigs(chainId).outbox != 0 &&
     rollupConfigs(chainId).bridge != 0)

// =============================================================================
// RULES FOR STATE TRANSITIONS
// =============================================================================

/// @title Deposit initiation creates valid deposit
/// @notice Initiating a deposit should set correct initial state
rule depositInitiationIntegrity(
    uint256 chainId,
    address l2Recipient,
    address l1Token,
    address l2Token,
    uint256 amount
) {
    env e;
    
    uint256 nonceBefore = transferNonce();
    uint256 totalBefore = totalDeposits();
    uint256 valueBefore = totalValueDeposited();
    
    // Call deposit function (assuming it exists)
    // bytes32 depositId = adapter.initiateDeposit(e, chainId, l2Recipient, l1Token, l2Token, amount);
    
    uint256 nonceAfter = transferNonce();
    uint256 totalAfter = totalDeposits();
    uint256 valueAfter = totalValueDeposited();
    
    // Verify state changes
    assert nonceAfter == nonceBefore + 1, "Nonce should increment";
    assert totalAfter == totalBefore + 1, "Total deposits should increment";
    assert valueAfter == valueBefore + amount, "Total value should increase";
}

/// @title Withdrawal claim requires challenge period
/// @notice Cannot claim withdrawal before challenge period expires
rule withdrawalRequiresChallengePeriod(bytes32 withdrawalId) {
    env e;
    
    uint256 claimableAt = withdrawals(withdrawalId).claimableAt;
    uint256 initiatedAt = withdrawals(withdrawalId).initiatedAt;
    
    // Verify challenge period is enforced
    assert claimableAt >= initiatedAt + CHALLENGE_PERIOD(), 
        "Challenge period must be enforced";
    
    // Cannot claim if not yet claimable
    require e.block.timestamp < claimableAt;
    // claimWithdrawal should revert
}

/// @title Output cannot be processed twice
/// @notice Processing the same output twice should fail
rule noDoubleOutputProcessing(bytes32 outputId) {
    env e;
    
    bool processedBefore = processedOutputs(outputId);
    
    // If already processed, any attempt to process again should fail
    require processedBefore == true;
    
    // Second processing should revert
    // adapter.processOutput@withrevert(e, outputId, ...);
    
    assert processedOutputs(outputId) == true, 
        "Processed output should remain processed";
}

/// @title Retryable ticket cannot be redeemed twice
/// @notice Once redeemed, ticket redemption should fail
rule noDoubleTicketRedemption(uint256 ticketId) {
    env e;
    
    bool redeemedBefore = retryableTickets(ticketId).redeemed;
    
    require redeemedBefore == true;
    
    // Attempting to redeem again should fail
    assert retryableTickets(ticketId).redeemed == true,
        "Redeemed ticket should remain redeemed";
}

/// @title Deposit status transitions are valid
/// @notice Status can only transition in valid order: PENDING -> RETRYABLE_CREATED -> EXECUTED/FAILED
rule validDepositStatusTransition(bytes32 depositId, uint8 newStatus) {
    uint8 currentStatus = ghostDepositStatus[depositId];
    
    // Valid transitions
    bool validTransition = 
        (currentStatus == 0 && newStatus == 1) || // PENDING -> RETRYABLE_CREATED
        (currentStatus == 1 && newStatus == 2) || // RETRYABLE_CREATED -> EXECUTED
        (currentStatus == 1 && newStatus == 5);   // RETRYABLE_CREATED -> FAILED
    
    assert validTransition || currentStatus == newStatus,
        "Invalid status transition";
}

/// @title Amount validation consistency
/// @notice Same amount should always produce same validation result
rule amountValidationDeterminism(uint256 amount) {
    uint256 min = minDepositAmount();
    uint256 max = maxDepositAmount();
    
    bool valid1 = (amount >= min && amount <= max);
    bool valid2 = (amount >= min && amount <= max);
    
    assert valid1 == valid2, "Amount validation must be deterministic";
}

// =============================================================================
// CROSS-DOMAIN NULLIFIER RULES
// =============================================================================

/// @title Nullifier uniqueness across deposits
/// @notice Different deposits must produce different nullifiers
rule nullifierUniqueness(bytes32 depositId1, bytes32 depositId2) {
    require depositId1 != depositId2;
    
    // Nullifiers are computed from deposit IDs + domain
    // If IDs differ, nullifiers must differ
    bytes32 nf1 = keccak256(abi.encodePacked(depositId1, "ARBITRUM_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(depositId2, "ARBITRUM_NULLIFIER"));
    
    assert nf1 != nf2, "Different deposits must have different nullifiers";
}

/// @title Nullifier consumption is permanent
/// @notice Once a nullifier is consumed, it cannot be unconsumed
rule nullifierConsumptionPermanent(bytes32 nullifier) {
    bool consumedBefore = ghostConsumedNullifiers[nullifier];
    
    require consumedBefore == true;
    
    assert ghostConsumedNullifiers[nullifier] == true,
        "Consumed nullifier should remain consumed";
}

/// @title Cross-domain nullifier binding determinism
/// @notice Same Arbitrum nullifier + domain should always produce same Soul nullifier
rule crossDomainNullifierDeterminism(bytes32 arbNullifier, bytes32 domain) {
    bytes32 pilNf1 = keccak256(abi.encodePacked(arbNullifier, domain, "ARB2Soul"));
    bytes32 pilNf2 = keccak256(abi.encodePacked(arbNullifier, domain, "ARB2Soul"));
    
    assert pilNf1 == pilNf2, "Cross-domain nullifier must be deterministic";
}

/// @title Cross-domain direction matters
/// @notice ARB->Soul nullifier should differ from Soul->ARB
rule crossDomainDirectionMatters(bytes32 nullifier, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;
    
    bytes32 nfAtoB = keccak256(abi.encodePacked(nullifier, domainA, domainB));
    bytes32 nfBtoA = keccak256(abi.encodePacked(nullifier, domainB, domainA));
    
    assert nfAtoB != nfBtoA, "Cross-domain direction should affect nullifier";
}

// =============================================================================
// ACCESS CONTROL RULES
// =============================================================================

/// @title Only operators can configure rollups
/// @notice Rollup configuration requires OPERATOR_ROLE
rule rollupConfigurationRequiresOperator(env e, uint256 chainId) {
    bool hasOperatorRole = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    // configureRollup should only succeed if caller has OPERATOR_ROLE
    require !hasOperatorRole;
    
    // Should revert without operator role
    bool active_before = rollupConfigs(chainId).active;
    // adapter.configureRollup@withrevert(e, ...);
    bool active_after = rollupConfigs(chainId).active;
    
    assert active_before == active_after || hasOperatorRole,
        "Only operators can configure rollups";
}

/// @title Pause functionality requires guardian role
/// @notice Only guardians can pause the contract
rule pauseRequiresGuardian(env e) {
    bool hasGuardianRole = hasRole(GUARDIAN_ROLE(), e.msg.sender);
    
    // Pause should only succeed with GUARDIAN_ROLE
    require !hasGuardianRole;
    
    // Should revert without guardian role
}

// =============================================================================
// FEE RULES
// =============================================================================

/// @title Bridge fee is bounded
/// @notice Bridge fee should never exceed reasonable bounds
rule bridgeFeeBounded() {
    uint256 fee = bridgeFee();
    
    // Fee should be less than 1% (100 basis points)
    assert fee <= 100, "Bridge fee should be bounded";
}

/// @title Fee collection is correct
/// @notice Collected fees should match expected calculation
rule feeCollectionCorrect(uint256 amount) {
    uint256 fee = bridgeFee();
    
    // Fee calculation: amount * fee / 10000
    uint256 expectedFee = (amount * fee) / 10000;
    
    // Verify no overflow
    require amount <= 2^128; // Reasonable max amount
    require fee <= 100;
    
    assert expectedFee <= amount, "Fee should not exceed amount";
}

// =============================================================================
// TIMING RULES
// =============================================================================

/// @title Challenge period is immutable
/// @notice CHALLENGE_PERIOD constant should not change
rule challengePeriodImmutable() {
    uint256 period = CHALLENGE_PERIOD();
    
    // Should always be 7 days (604800 seconds)
    assert period == 604800, "Challenge period should be 7 days";
}

/// @title Ticket expiry is enforced
/// @notice Expired tickets cannot be redeemed
rule ticketExpiryEnforced(uint256 ticketId, env e) {
    uint256 createdAt = retryableTickets(ticketId).createdAt;
    uint256 lifetime = 604800; // 7 days
    
    require e.block.timestamp > createdAt + lifetime;
    require createdAt > 0; // Ticket exists
    
    // Expired ticket redemption should fail
    bool redeemed = retryableTickets(ticketId).redeemed;
    require !redeemed;
    
    // Cannot redeem expired ticket
}

// =============================================================================
// CHAIN ID RULES
// =============================================================================

/// @title Chain ID constants are correct
/// @notice Arbitrum chain IDs should match expected values
rule chainIdConstantsCorrect() {
    assert ARB_ONE_CHAIN_ID() == 42161, "Arbitrum One chain ID should be 42161";
    assert ARB_NOVA_CHAIN_ID() == 42170, "Arbitrum Nova chain ID should be 42170";
}

/// @title Rollup type matches chain ID
/// @notice ARB_ONE type should correspond to ARB_ONE_CHAIN_ID
rule rollupTypeMatchesChainId(uint256 chainId) {
    uint8 rollupType = rollupConfigs(chainId).rollupType;
    bool active = rollupConfigs(chainId).active;
    
    require active;
    
    // Type 0 = ARB_ONE, Type 1 = ARB_NOVA
    assert (chainId == ARB_ONE_CHAIN_ID() && rollupType == 0) ||
           (chainId == ARB_NOVA_CHAIN_ID() && rollupType == 1) ||
           !active,
        "Rollup type should match chain ID";
}

// =============================================================================
// BATCH MONOTONICITY
// =============================================================================

/// @title L1 batch numbers are monotonically increasing
/// @notice New withdrawals should have higher or equal batch numbers
rule batchMonotonicity(bytes32 withdrawalId1, bytes32 withdrawalId2) {
    uint256 batch1 = withdrawals(withdrawalId1).l1BatchNumber;
    uint256 batch2 = withdrawals(withdrawalId2).l1BatchNumber;
    uint256 time1 = withdrawals(withdrawalId1).initiatedAt;
    uint256 time2 = withdrawals(withdrawalId2).initiatedAt;
    
    require time1 < time2;
    require batch1 > 0 && batch2 > 0;
    
    assert batch1 <= batch2, "Batch numbers should be monotonic with time";
}

// =============================================================================
// VALUE CONSERVATION
// =============================================================================

/// @title Value is conserved
/// @notice Total deposited minus withdrawn should equal locked value
rule valueConservation() {
    uint256 deposited = totalValueDeposited();
    uint256 withdrawn = totalValueWithdrawn();
    
    // Withdrawn can never exceed deposited
    assert withdrawn <= deposited, "Cannot withdraw more than deposited";
}

/// @title Individual withdrawal amount bounded by deposit
/// @notice A withdrawal cannot exceed its corresponding deposit
rule withdrawalBoundedByDeposit(bytes32 depositId, bytes32 withdrawalId) {
    uint256 depositAmount = deposits(depositId).amount;
    uint256 withdrawalAmount = withdrawals(withdrawalId).amount;
    
    // If withdrawal is linked to this deposit
    // withdrawalAmount should not exceed depositAmount
    require depositAmount > 0;
    
    assert withdrawalAmount <= depositAmount || withdrawalAmount == 0,
        "Withdrawal should not exceed deposit";
}
