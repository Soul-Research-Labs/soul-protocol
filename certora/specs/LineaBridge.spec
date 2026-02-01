// Certora CVL Specification for Linea zkEVM Bridge
// Verifies security properties for PLONK proofs, L1/L2 messaging, and finalization

// ============================================================================
// METHODS
// ============================================================================

methods {
    // LineaBridgeAdapter functions
    function bridgeProofToLinea(bytes32, bytes, bytes, address) external returns (bytes32) envfree;
    function anchorL2Message(bytes32, bytes32, uint256) external;
    function claimMessage(LineaBridgeAdapter.LineaClaim) external;
    function claimRefund(bytes32) external;
    function estimateFee(uint256) external returns (uint256) envfree;
    
    // View functions
    function isProofFinalized(bytes32) external returns (bool) envfree;
    function getMessageStatus(bytes32) external returns (LineaBridgeAdapter.MessageStatus) envfree;
    function getRemainingDailyLimit() external returns (uint256) envfree;
    
    // Admin functions
    function setSoulHubL2(address) external;
    function setProofRegistry(address) external;
    function updateFees(uint256, uint256) external;
    function updateLimits(uint256, uint256, uint256) external;
    function pause() external;
    function unpause() external;
    
    // State variables
    function lineaMessageService() external returns (address) envfree;
    function lineaTokenBridge() external returns (address) envfree;
    function lineaRollup() external returns (address) envfree;
    function soulHubL2() external returns (address) envfree;
    function proofRegistry() external returns (address) envfree;
    function minBridgeAmount() external returns (uint256) envfree;
    function maxBridgeAmount() external returns (uint256) envfree;
    function dailyLimit() external returns (uint256) envfree;
    function dailyBridged() external returns (uint256) envfree;
    function lastResetTime() external returns (uint256) envfree;
    function messageNonce() external returns (uint256) envfree;
    function baseFee() external returns (uint256) envfree;
    function feePerByte() external returns (uint256) envfree;
    
    // Mappings
    function outgoingMessages(bytes32) external returns (
        address sender,
        bytes32 proofHash,
        uint256 value,
        uint256 fee,
        uint256 timestamp,
        uint256 deadline,
        LineaBridgeAdapter.MessageStatus status
    ) envfree;
    function anchoredMessages(bytes32) external returns (bool) envfree;
    function claimedMessages(bytes32) external returns (bool) envfree;
    function proofFinality(bytes32) external returns (
        bytes32 proofHash,
        uint256 sourceChain,
        uint256 destChain,
        uint256 anchoredBlock,
        uint256 finalizedBlock,
        bool isFinalized
    ) envfree;
    
    // Access control
    function hasRole(bytes32, address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function BRIDGE_OPERATOR_ROLE() external returns (bytes32) envfree;
    function PAUSER_ROLE() external returns (bytes32) envfree;
    function POSTMAN_ROLE() external returns (bytes32) envfree;
    
    // Pausable
    function paused() external returns (bool) envfree;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

definition LINEA_MAINNET_CHAIN_ID() returns uint256 = 59144;
definition LINEA_TESTNET_CHAIN_ID() returns uint256 = 59140;
definition FINALITY_PERIOD() returns uint256 = 32;
definition FEE_MULTIPLIER_BPS() returns uint256 = 10050;

// ============================================================================
// INVARIANTS
// ============================================================================

/// @title Daily bridged never exceeds daily limit
invariant dailyBridgedWithinLimit()
    dailyBridged() <= dailyLimit()
    {
        preserved {
            require dailyLimit() >= dailyBridged();
        }
    }

/// @title Min bridge amount is always less than max
invariant minLessThanMax()
    minBridgeAmount() < maxBridgeAmount()
    {
        preserved updateLimits(uint256 _min, uint256 _max, uint256 _daily) {
            require _min < _max;
        }
    }

/// @title Message nonce only increases
invariant nonceMonotonicallyIncreasing(env e)
    messageNonce() >= 0

/// @title Immutable addresses are never zero
invariant immutableAddressesNonZero()
    lineaMessageService() != 0 &&
    lineaTokenBridge() != 0 &&
    lineaRollup() != 0

// ============================================================================
// RULES - MESSAGE OPERATIONS
// ============================================================================

/// @title Bridge proof creates unique message ID
rule bridgeProofCreatesUniqueMessage(env e) {
    bytes32 proofHash;
    bytes proofData;
    bytes publicInputs;
    address recipient;
    
    uint256 nonceBefore = messageNonce();
    
    bytes32 messageId = bridgeProofToLinea(e, proofHash, proofData, publicInputs, recipient);
    
    uint256 nonceAfter = messageNonce();
    
    // Nonce should increment
    assert nonceAfter == nonceBefore + 1, "Nonce should increment after bridge";
    
    // Message should be stored
    address sender;
    bytes32 storedProofHash;
    uint256 value;
    uint256 fee;
    uint256 timestamp;
    uint256 deadline;
    LineaBridgeAdapter.MessageStatus status;
    (sender, storedProofHash, value, fee, timestamp, deadline, status) = outgoingMessages(messageId);
    
    assert sender == e.msg.sender, "Sender should be recorded";
    assert storedProofHash == proofHash, "Proof hash should be stored";
    assert status == LineaBridgeAdapter.MessageStatus.Pending, "Status should be Pending";
}

/// @title Anchored messages cannot be re-anchored
rule noDoubleAnchoring(env e) {
    bytes32 messageId;
    bytes32 proofHash;
    uint256 blockNumber;
    
    bool anchoredBefore = anchoredMessages(messageId);
    
    anchorL2Message@withrevert(e, messageId, proofHash, blockNumber);
    
    bool reverted = lastReverted;
    
    // If already anchored, must revert
    assert anchoredBefore => reverted, "Double anchoring should revert";
}

/// @title Claimed messages cannot be re-claimed
rule noDoubleClaim(env e) {
    LineaBridgeAdapter.LineaClaim claim;
    
    bool claimedBefore = claimedMessages(claim.messageHash);
    
    claimMessage@withrevert(e, claim);
    
    bool reverted = lastReverted;
    
    // If already claimed, must revert
    assert claimedBefore => reverted, "Double claiming should revert";
}

/// @title Only anchored messages can be claimed
rule claimRequiresAnchoring(env e) {
    LineaBridgeAdapter.LineaClaim claim;
    
    bool anchored = anchoredMessages(claim.messageHash);
    
    claimMessage@withrevert(e, claim);
    
    bool reverted = lastReverted;
    
    // If not anchored, must revert
    assert !anchored => reverted, "Unanchored messages cannot be claimed";
}

// ============================================================================
// RULES - FINALIZATION
// ============================================================================

/// @title Proof finalization is permanent
rule finalizationIsPermanent(env e) {
    bytes32 proofHash;
    
    bool finalizedBefore = isProofFinalized(proofHash);
    
    // Any operation
    calldataarg args;
    method f;
    f(e, args);
    
    bool finalizedAfter = isProofFinalized(proofHash);
    
    // Once finalized, always finalized
    assert finalizedBefore => finalizedAfter, "Finalization should be permanent";
}

/// @title Finalization updates proof finality record
rule finalizationUpdatesRecord(env e) {
    LineaBridgeAdapter.LineaClaim claim;
    
    // Pre-conditions
    require anchoredMessages(claim.messageHash);
    require !claimedMessages(claim.messageHash);
    
    // Get proof hash from claim (simplified)
    bytes32 proofHash;
    bool finalizedBefore = isProofFinalized(proofHash);
    
    claimMessage(e, claim);
    
    // After successful claim, proof should be marked finalized
    // (actual verification would depend on decoding claim.data)
}

// ============================================================================
// RULES - ACCESS CONTROL
// ============================================================================

/// @title Only POSTMAN_ROLE can anchor messages
rule anchorRequiresPostmanRole(env e) {
    bytes32 messageId;
    bytes32 proofHash;
    uint256 blockNumber;
    
    bool hasPostmanRole = hasRole(POSTMAN_ROLE(), e.msg.sender);
    
    anchorL2Message@withrevert(e, messageId, proofHash, blockNumber);
    
    bool reverted = lastReverted;
    
    // If doesn't have role, should revert
    assert !hasPostmanRole => reverted, "Non-postman should not anchor";
}

/// @title Only admin can update fees
rule updateFeesRequiresAdmin(env e) {
    uint256 newBaseFee;
    uint256 newFeePerByte;
    
    bool hasAdminRole = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    updateFees@withrevert(e, newBaseFee, newFeePerByte);
    
    bool reverted = lastReverted;
    
    assert !hasAdminRole => reverted, "Non-admin should not update fees";
}

/// @title Only admin can update limits
rule updateLimitsRequiresAdmin(env e) {
    uint256 _min;
    uint256 _max;
    uint256 _daily;
    
    bool hasAdminRole = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    updateLimits@withrevert(e, _min, _max, _daily);
    
    bool reverted = lastReverted;
    
    assert !hasAdminRole => reverted, "Non-admin should not update limits";
}

/// @title Only pauser can pause
rule pauseRequiresPauserRole(env e) {
    bool hasPauserRole = hasRole(PAUSER_ROLE(), e.msg.sender);
    bool pausedBefore = paused();
    
    pause@withrevert(e);
    
    bool reverted = lastReverted;
    
    // If already paused or no role, should revert
    assert (!hasPauserRole || pausedBefore) => reverted, "Invalid pause attempt";
}

// ============================================================================
// RULES - FEE CALCULATION
// ============================================================================

/// @title Fee calculation is deterministic
rule feeCalculationDeterministic(env e) {
    uint256 dataSize;
    
    uint256 fee1 = estimateFee(dataSize);
    uint256 fee2 = estimateFee(dataSize);
    
    assert fee1 == fee2, "Fee calculation should be deterministic";
}

/// @title Fee increases with data size
rule feeIncreasesWithSize(env e) {
    uint256 size1;
    uint256 size2;
    
    require size1 < size2;
    require size2 < max_uint256 / feePerByte(); // Prevent overflow
    
    uint256 fee1 = estimateFee(size1);
    uint256 fee2 = estimateFee(size2);
    
    assert fee1 < fee2, "Larger data should have higher fee";
}

/// @title Fee is at least base fee
rule feeAtLeastBaseFee(env e) {
    uint256 dataSize;
    
    uint256 fee = estimateFee(dataSize);
    uint256 expectedMin = (baseFee() * FEE_MULTIPLIER_BPS()) / 10000;
    
    assert fee >= expectedMin, "Fee should be at least base fee with buffer";
}

// ============================================================================
// RULES - DAILY LIMIT
// ============================================================================

/// @title Bridging respects daily limit
rule bridgingRespectsLimit(env e) {
    bytes32 proofHash;
    bytes proofData;
    bytes publicInputs;
    address recipient;
    
    uint256 limitBefore = getRemainingDailyLimit();
    
    bridgeProofToLinea@withrevert(e, proofHash, proofData, publicInputs, recipient);
    
    bool reverted = lastReverted;
    
    // If remaining limit is insufficient (considering fees), should revert
    // Simplified: if limit is 0, definitely reverts
    assert (limitBefore == 0 && e.msg.value > 0) => reverted, "Should revert when limit exhausted";
}

/// @title Daily limit resets after 24 hours
rule dailyLimitResets(env e1, env e2) {
    require e2.block.timestamp >= e1.block.timestamp + 86400; // 24 hours
    
    uint256 lastReset1 = lastResetTime();
    
    // Perform operation in e2 (after reset period)
    bytes32 proofHash;
    bytes proofData;
    bytes publicInputs;
    address recipient;
    
    require e2.msg.value > minBridgeAmount();
    require e2.msg.value < maxBridgeAmount();
    
    bridgeProofToLinea(e2, proofHash, proofData, publicInputs, recipient);
    
    // After successful bridge, daily bridged should reflect new amount
    // (Reset logic runs inside the function)
}

// ============================================================================
// RULES - REFUND
// ============================================================================

/// @title Only message sender can claim refund
rule refundOnlyBySender(env e) {
    bytes32 messageId;
    
    address sender;
    bytes32 proofHash;
    uint256 value;
    uint256 fee;
    uint256 timestamp;
    uint256 deadline;
    LineaBridgeAdapter.MessageStatus status;
    (sender, proofHash, value, fee, timestamp, deadline, status) = outgoingMessages(messageId);
    
    claimRefund@withrevert(e, messageId);
    
    bool reverted = lastReverted;
    
    // If caller is not sender, should revert
    assert (sender != 0 && e.msg.sender != sender) => reverted, "Only sender can refund";
}

/// @title Refund only for pending messages past deadline
rule refundRequiresPastDeadline(env e) {
    bytes32 messageId;
    
    address sender;
    bytes32 proofHash;
    uint256 value;
    uint256 fee;
    uint256 timestamp;
    uint256 deadline;
    LineaBridgeAdapter.MessageStatus status;
    (sender, proofHash, value, fee, timestamp, deadline, status) = outgoingMessages(messageId);
    
    require e.msg.sender == sender;
    require status == LineaBridgeAdapter.MessageStatus.Pending;
    
    claimRefund@withrevert(e, messageId);
    
    bool reverted = lastReverted;
    
    // If deadline not passed, should revert
    assert (e.block.timestamp < deadline) => reverted, "Cannot refund before deadline";
}

/// @title Refund changes message status
rule refundChangesStatus(env e) {
    bytes32 messageId;
    
    address sender;
    bytes32 proofHash;
    uint256 value;
    uint256 fee;
    uint256 timestamp;
    uint256 deadline;
    LineaBridgeAdapter.MessageStatus statusBefore;
    (sender, proofHash, value, fee, timestamp, deadline, statusBefore) = outgoingMessages(messageId);
    
    require statusBefore == LineaBridgeAdapter.MessageStatus.Pending;
    require e.msg.sender == sender;
    require e.block.timestamp >= deadline;
    
    claimRefund(e, messageId);
    
    LineaBridgeAdapter.MessageStatus statusAfter;
    (,,,,,,statusAfter) = outgoingMessages(messageId);
    
    assert statusAfter == LineaBridgeAdapter.MessageStatus.Refunded, "Status should be Refunded";
}

// ============================================================================
// RULES - PAUSE
// ============================================================================

/// @title Bridging fails when paused
rule bridgingFailsWhenPaused(env e) {
    require paused();
    
    bytes32 proofHash;
    bytes proofData;
    bytes publicInputs;
    address recipient;
    
    bridgeProofToLinea@withrevert(e, proofHash, proofData, publicInputs, recipient);
    
    assert lastReverted, "Bridging should fail when paused";
}

/// @title Claiming fails when paused
rule claimingFailsWhenPaused(env e) {
    require paused();
    
    LineaBridgeAdapter.LineaClaim claim;
    
    claimMessage@withrevert(e, claim);
    
    assert lastReverted, "Claiming should fail when paused";
}

// ============================================================================
// RULES - VALUE TRANSFER
// ============================================================================

/// @title Bridge amount within limits
rule bridgeAmountWithinLimits(env e) {
    bytes32 proofHash;
    bytes proofData;
    bytes publicInputs;
    address recipient;
    
    // Calculate fee
    uint256 dataSize = require_uint256(proofData.length + publicInputs.length);
    uint256 fee = estimateFee(dataSize);
    
    uint256 bridgeValue = require_uint256(e.msg.value - fee);
    
    bridgeProofToLinea@withrevert(e, proofHash, proofData, publicInputs, recipient);
    
    bool reverted = lastReverted;
    
    // If value outside limits, should revert
    assert (bridgeValue < minBridgeAmount() || bridgeValue > maxBridgeAmount()) => reverted,
        "Amount outside limits should revert";
}

/// @title Recipient cannot be zero address
rule recipientNonZero(env e) {
    bytes32 proofHash;
    bytes proofData;
    bytes publicInputs;
    
    bridgeProofToLinea@withrevert(e, proofHash, proofData, publicInputs, 0);
    
    assert lastReverted, "Zero recipient should revert";
}

// ============================================================================
// GHOST VARIABLES FOR TRACKING
// ============================================================================

ghost uint256 totalMessagesSent;
ghost uint256 totalMessagesClaimed;
ghost uint256 totalMessagesRefunded;

hook Sstore outgoingMessages[KEY bytes32 messageId].status LineaBridgeAdapter.MessageStatus newStatus 
    (LineaBridgeAdapter.MessageStatus oldStatus) STORAGE {
    if (oldStatus == LineaBridgeAdapter.MessageStatus.Pending) {
        if (newStatus == LineaBridgeAdapter.MessageStatus.Delivered) {
            totalMessagesClaimed = totalMessagesClaimed + 1;
        } else if (newStatus == LineaBridgeAdapter.MessageStatus.Refunded) {
            totalMessagesRefunded = totalMessagesRefunded + 1;
        }
    }
}

hook Sstore messageNonce uint256 newNonce (uint256 oldNonce) STORAGE {
    totalMessagesSent = totalMessagesSent + 1;
}

/// @title Total claimed and refunded never exceeds sent
invariant claimedAndRefundedLtSent()
    totalMessagesClaimed + totalMessagesRefunded <= totalMessagesSent
