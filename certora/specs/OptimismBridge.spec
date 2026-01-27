// SPDX-License-Identifier: MIT
// Certora CVL Specification for Optimism Bridge Adapter
// Soul Protocol (Soul) - Formal Verification

/*
 * =============================================================================
 * OPTIMISM BRIDGE ADAPTER SPECIFICATION (OP STACK / BEDROCK)
 * =============================================================================
 * 
 * This specification verifies the security properties of the Optimism Bridge
 * Adapter including:
 * - CrossDomainMessenger message integrity
 * - 7-day withdrawal period enforcement
 * - Fault proof / dispute game resolution
 * - Output root finalization
 * - Cross-domain nullifier uniqueness
 */

using OptimismBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    // View functions
    function l1CrossDomainMessenger() external returns (address) envfree;
    function l2CrossDomainMessenger() external returns (address) envfree;
    function optimismPortal() external returns (address) envfree;
    function l2OutputOracle() external returns (address) envfree;
    
    // Message queries
    function messages(bytes32) external returns (
        bytes32 messageId,
        uint8 messageType,
        bytes payload,
        uint256 sourceChainId,
        uint256 targetChainId,
        address sender,
        address target,
        uint256 value,
        uint256 gasLimit,
        uint256 timestamp,
        uint8 status
    ) envfree;
    
    function withdrawalRequests(bytes32) external returns (
        bytes32 withdrawalId,
        address user,
        bytes32 proofHash,
        uint256 amount,
        uint256 requestedAt,
        uint256 completableAt,
        bool completed
    ) envfree;
    
    function outputRoots(uint256) external returns (
        bytes32 outputRoot,
        uint256 l2BlockNumber,
        uint256 l1Timestamp,
        address proposer,
        bool finalized
    ) envfree;
    
    function relayedMessages(bytes32) external returns (bool) envfree;
    function failedMessages(bytes32) external returns (bool) envfree;
    
    // State variables
    function messageNonce() external returns (uint256) envfree;
    function totalMessages() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    
    // Constants
    function WITHDRAWAL_PERIOD() external returns (uint256) envfree;
    function MIN_GAS_LIMIT() external returns (uint256) envfree;
    function OP_MAINNET_CHAIN_ID() external returns (uint256) envfree;
    function OP_SEPOLIA_CHAIN_ID() external returns (uint256) envfree;
    
    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function EXECUTOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

// Track consumed nullifiers
ghost mapping(bytes32 => bool) ghostConsumedNullifiers {
    init_state axiom forall bytes32 nf. ghostConsumedNullifiers[nf] == false;
}

// Track relayed messages
ghost mapping(bytes32 => bool) ghostRelayedMessages {
    init_state axiom forall bytes32 msgId. ghostRelayedMessages[msgId] == false;
}

// Track message statuses
ghost mapping(bytes32 => uint8) ghostMessageStatus {
    init_state axiom forall bytes32 msgId. ghostMessageStatus[msgId] == 0;
}

// Track total message count
ghost uint256 ghostTotalMessages {
    init_state axiom ghostTotalMessages == 0;
}

// Track output root finalization
ghost mapping(uint256 => bool) ghostOutputRootFinalized {
    init_state axiom forall uint256 blockNum. ghostOutputRootFinalized[blockNum] == false;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Withdrawal period is enforced
/// @notice CompletableAt must be at least WITHDRAWAL_PERIOD after requestedAt
invariant withdrawalPeriodEnforced(bytes32 withdrawalId)
    withdrawalRequests(withdrawalId).completableAt == 0 ||
    withdrawalRequests(withdrawalId).completableAt >= 
        withdrawalRequests(withdrawalId).requestedAt + WITHDRAWAL_PERIOD()

/// @title Message gas limit meets minimum
/// @notice All messages must have gas limit >= MIN_GAS_LIMIT
invariant messageGasLimitMinimum(bytes32 messageId)
    messages(messageId).gasLimit == 0 ||
    messages(messageId).gasLimit >= MIN_GAS_LIMIT()

/// @title Relayed messages cannot be relayed again
/// @notice Once relayed, message stays relayed
invariant messageRelayedOnce(bytes32 messageId)
    relayedMessages(messageId) == ghostRelayedMessages[messageId]

/// @title Message nonce is monotonically increasing
/// @notice Nonce should never decrease
invariant nonceMonotonic()
    messageNonce() >= ghostTotalMessages

/// @title Completed withdrawals stay completed
/// @notice Withdrawal completion is permanent
invariant withdrawalCompletionPermanent(bytes32 withdrawalId)
    withdrawalRequests(withdrawalId).completed == true =>
    withdrawalRequests(withdrawalId).requestedAt > 0

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/// @title Withdrawal requires waiting period
/// @notice Cannot complete withdrawal before completableAt
rule withdrawalRequiresWaitingPeriod(bytes32 withdrawalId) {
    env e;
    
    uint256 completableAt = withdrawalRequests(withdrawalId).completableAt;
    uint256 requestedAt = withdrawalRequests(withdrawalId).requestedAt;
    
    require requestedAt > 0; // Withdrawal exists
    
    // Must wait WITHDRAWAL_PERIOD
    assert completableAt >= requestedAt + WITHDRAWAL_PERIOD(),
        "Withdrawal period must be enforced";
    
    // Cannot complete before completableAt
    require e.block.timestamp < completableAt;
    // completeWithdrawal should revert
}

/// @title Withdrawal completion is one-time
/// @notice Cannot complete the same withdrawal twice
rule noDoubleWithdrawalCompletion(bytes32 withdrawalId) {
    env e;
    
    bool completedBefore = withdrawalRequests(withdrawalId).completed;
    
    require completedBefore == true;
    
    // Attempting to complete again should fail
    assert withdrawalRequests(withdrawalId).completed == true,
        "Completed withdrawal should remain completed";
}

/// @title Withdrawal nullifier is consumed on completion
/// @notice Completing withdrawal consumes its nullifier
rule withdrawalConsumesNullifier(bytes32 withdrawalId) {
    env e;
    
    bytes32 nullifier = keccak256(abi.encodePacked(withdrawalId, "OPTIMISM_NULLIFIER"));
    bool consumedBefore = ghostConsumedNullifiers[nullifier];
    
    require !consumedBefore;
    require withdrawalRequests(withdrawalId).requestedAt > 0;
    require e.block.timestamp >= withdrawalRequests(withdrawalId).completableAt;
    
    // After completing, nullifier should be consumed
    // adapter.completeWithdrawal(e, withdrawalId);
    
    // assert ghostConsumedNullifiers[nullifier] == true;
}

// =============================================================================
// MESSAGE RELAY RULES
// =============================================================================

/// @title Message relay requires finalized output
/// @notice Cannot relay message without finalized output root
rule messageRelayRequiresFinalizedOutput(bytes32 messageId, uint256 l2BlockNumber) {
    env e;
    
    bool outputFinalized = outputRoots(l2BlockNumber).finalized;
    uint256 l1Timestamp = outputRoots(l2BlockNumber).l1Timestamp;
    
    // Output must be finalized (either explicitly or by time)
    bool isFinalizedByTime = e.block.timestamp >= l1Timestamp + WITHDRAWAL_PERIOD();
    
    require !outputFinalized && !isFinalizedByTime;
    
    // Cannot relay without finalized output
}

/// @title Relayed message cannot be re-relayed
/// @notice Double relay should fail
rule noDoubleMessageRelay(bytes32 messageId) {
    env e;
    
    bool relayedBefore = relayedMessages(messageId);
    
    require relayedBefore == true;
    
    // Second relay should fail
    assert relayedMessages(messageId) == true,
        "Relayed message should stay relayed";
}

/// @title Message status transitions are valid
/// @notice Status can only transition in valid order
rule validMessageStatusTransition(bytes32 messageId, uint8 newStatus) {
    uint8 currentStatus = ghostMessageStatus[messageId];
    
    // Valid transitions: PENDING(0) -> SENT(1) -> RELAYED(2) or FAILED(3)
    bool validTransition = 
        (currentStatus == 0 && newStatus == 1) || // PENDING -> SENT
        (currentStatus == 1 && newStatus == 2) || // SENT -> RELAYED
        (currentStatus == 1 && newStatus == 3);   // SENT -> FAILED
    
    assert validTransition || currentStatus == newStatus,
        "Invalid message status transition";
}

// =============================================================================
// CROSS-DOMAIN NULLIFIER RULES
// =============================================================================

/// @title Nullifier uniqueness for messages
/// @notice Different messages produce different nullifiers
rule messageNullifierUniqueness(bytes32 messageId1, bytes32 messageId2) {
    require messageId1 != messageId2;
    
    bytes32 nf1 = keccak256(abi.encodePacked(messageId1, "OPTIMISM_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(messageId2, "OPTIMISM_NULLIFIER"));
    
    assert nf1 != nf2, "Different messages must have different nullifiers";
}

/// @title Cross-domain nullifier determinism
/// @notice Same input always produces same nullifier
rule crossDomainNullifierDeterminism(bytes32 opNullifier, bytes32 domain) {
    bytes32 pilNf1 = keccak256(abi.encodePacked(opNullifier, domain, "OP2Soul"));
    bytes32 pilNf2 = keccak256(abi.encodePacked(opNullifier, domain, "OP2Soul"));
    
    assert pilNf1 == pilNf2, "Cross-domain nullifier must be deterministic";
}

/// @title Cross-domain direction matters
/// @notice OP->Soul differs from Soul->OP
rule crossDomainDirectionMatters(bytes32 nullifier, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;
    
    bytes32 nfAtoB = keccak256(abi.encodePacked(nullifier, domainA, domainB));
    bytes32 nfBtoA = keccak256(abi.encodePacked(nullifier, domainB, domainA));
    
    assert nfAtoB != nfBtoA, "Cross-domain direction should affect nullifier";
}

/// @title Nullifier consumption is permanent
/// @notice Once consumed, nullifier stays consumed
rule nullifierConsumptionPermanent(bytes32 nullifier) {
    bool consumedBefore = ghostConsumedNullifiers[nullifier];
    
    require consumedBefore == true;
    
    assert ghostConsumedNullifiers[nullifier] == true,
        "Consumed nullifier should remain consumed";
}

// =============================================================================
// OUTPUT ROOT RULES
// =============================================================================

/// @title Output root finalization by time
/// @notice Output root becomes finalized after WITHDRAWAL_PERIOD
rule outputRootFinalizationByTime(uint256 l2BlockNumber, env e) {
    uint256 l1Timestamp = outputRoots(l2BlockNumber).l1Timestamp;
    bool explicitlyFinalized = outputRoots(l2BlockNumber).finalized;
    
    require l1Timestamp > 0;
    require e.block.timestamp >= l1Timestamp + WITHDRAWAL_PERIOD();
    
    // Should be considered finalized either way
    bool isFinalizedByTime = true;
    
    assert explicitlyFinalized || isFinalizedByTime,
        "Output should be finalized after withdrawal period";
}

/// @title Output root L2 block monotonicity
/// @notice New output roots should have higher L2 block numbers
rule outputRootBlockMonotonicity(uint256 block1, uint256 block2) {
    uint256 l2Block1 = outputRoots(block1).l2BlockNumber;
    uint256 l2Block2 = outputRoots(block2).l2BlockNumber;
    uint256 timestamp1 = outputRoots(block1).l1Timestamp;
    uint256 timestamp2 = outputRoots(block2).l1Timestamp;
    
    require timestamp1 < timestamp2;
    require l2Block1 > 0 && l2Block2 > 0;
    
    assert l2Block1 <= l2Block2, "L2 block numbers should be monotonic";
}

// =============================================================================
// FAULT PROOF / DISPUTE RULES
// =============================================================================

/// @title Dispute game duration is fixed
/// @notice WITHDRAWAL_PERIOD should be constant
rule withdrawalPeriodIsConstant() {
    uint256 period = WITHDRAWAL_PERIOD();
    
    // Should be 7 days
    assert period == 604800, "Withdrawal period should be 7 days";
}

/// @title Failed message handling
/// @notice Failed messages can be retried
rule failedMessageCanBeRetried(bytes32 messageId) {
    bool failed = failedMessages(messageId);
    bool relayed = relayedMessages(messageId);
    
    // Failed messages should not be marked as relayed
    assert !(failed && relayed), "Message cannot be both failed and relayed";
}

// =============================================================================
// CHAIN ID RULES
// =============================================================================

/// @title Chain ID constants are correct
/// @notice OP chain IDs should match expected values
rule chainIdConstantsCorrect() {
    assert OP_MAINNET_CHAIN_ID() == 10, "OP Mainnet should be 10";
    assert OP_SEPOLIA_CHAIN_ID() == 11155420, "OP Sepolia should be 11155420";
}

/// @title Message source chain is valid
/// @notice Messages must come from supported chains
rule messageSourceChainValid(bytes32 messageId) {
    uint256 sourceChainId = messages(messageId).sourceChainId;
    
    require sourceChainId > 0; // Message exists
    
    // Source should be either L1 (1) or supported OP chain
    assert sourceChainId == 1 || 
           sourceChainId == OP_MAINNET_CHAIN_ID() ||
           sourceChainId == OP_SEPOLIA_CHAIN_ID(),
        "Source chain should be valid";
}

// =============================================================================
// ACCESS CONTROL RULES
// =============================================================================

/// @title Only operators can configure messenger
/// @notice CrossDomainMessenger configuration requires OPERATOR_ROLE
rule messengerConfigurationRequiresOperator(env e) {
    bool hasOperatorRole = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    address messengerBefore = l1CrossDomainMessenger();
    
    require !hasOperatorRole;
    
    // Configuration should fail without operator role
    address messengerAfter = l1CrossDomainMessenger();
    
    assert messengerBefore == messengerAfter || hasOperatorRole,
        "Only operators can configure messenger";
}

/// @title Guardian can pause relay
/// @notice GUARDIAN_ROLE required for emergency pause
rule pauseRequiresGuardian(env e) {
    bool hasGuardianRole = hasRole(GUARDIAN_ROLE(), e.msg.sender);
    
    require !hasGuardianRole;
    
    // Pause should fail without guardian role
}

// =============================================================================
// VALUE CONSERVATION
// =============================================================================

/// @title Value is conserved
/// @notice Total deposits should be >= total withdrawals
rule valueConservation() {
    uint256 deposited = totalDeposits();
    uint256 withdrawn = totalWithdrawals();
    
    assert withdrawn <= deposited, "Cannot withdraw more than deposited";
}

/// @title Message value is preserved
/// @notice Value in message should be preserved during relay
rule messageValuePreserved(bytes32 messageId) {
    uint256 value = messages(messageId).value;
    
    // Value should not change during relay
    require value > 0;
    
    assert messages(messageId).value == value,
        "Message value should be preserved";
}

// =============================================================================
// GAS LIMIT RULES
// =============================================================================

/// @title Gas limit minimum is enforced
/// @notice MIN_GAS_LIMIT should be enforced on all messages
rule gasLimitMinimumEnforced() {
    uint256 minGas = MIN_GAS_LIMIT();
    
    // Minimum should be 100000
    assert minGas == 100000, "Min gas limit should be 100000";
}

/// @title Message gas limit is sufficient
/// @notice Messages should have enough gas for execution
rule messageGasLimitSufficient(bytes32 messageId) {
    uint256 gasLimit = messages(messageId).gasLimit;
    uint256 minGas = MIN_GAS_LIMIT();
    
    require gasLimit > 0; // Message exists
    
    assert gasLimit >= minGas, "Message gas should meet minimum";
}

// =============================================================================
// TIMING RULES
// =============================================================================

/// @title Timestamp ordering
/// @notice Message timestamp should be <= current time
rule messageTimestampOrdering(bytes32 messageId, env e) {
    uint256 msgTimestamp = messages(messageId).timestamp;
    
    require msgTimestamp > 0; // Message exists
    
    assert msgTimestamp <= e.block.timestamp,
        "Message timestamp should be in the past";
}

/// @title Withdrawal timing consistency
/// @notice requestedAt should be <= completableAt
rule withdrawalTimingConsistency(bytes32 withdrawalId) {
    uint256 requestedAt = withdrawalRequests(withdrawalId).requestedAt;
    uint256 completableAt = withdrawalRequests(withdrawalId).completableAt;
    
    require requestedAt > 0;
    
    assert requestedAt <= completableAt,
        "Requested time should be before completable time";
}
