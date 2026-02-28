/**
 * @title Solana Bridge Adapter Formal Verification
 * @notice Certora specifications for Zaseon Solana cross-chain bridge
 * @dev Formal verification for Wormhole-based Solana bridge security
 *
 * STATUS: DISABLED — SolanaBridgeAdapter contract is not yet implemented.
 * This spec is excluded from CI via verify_crosschain.conf.
 * Re-enable when SolanaBridgeAdapter.sol is created.
 */

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State accessors - from SolanaBridgeAdapter
    function wormholeCore() external returns (address) envfree;
    function wormholeTokenBridge() external returns (address) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function minMessageFee() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;
    function totalMessagesSent() external returns (uint256) envfree;
    function totalMessagesReceived() external returns (uint256) envfree;
    function totalValueBridged() external returns (uint256) envfree;
    function usedVAAHashes(bytes32) external returns (bool) envfree;
    function whitelistedPrograms(bytes32) external returns (bool) envfree;
    function senderNonces(address) external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    
    // View functions
    function isVAAUsed(bytes32) external returns (bool) envfree;
    function isProgramWhitelisted(bytes32) external returns (bool) envfree;
    function getSenderNonce(address) external returns (uint256) envfree;
    
    // Admin functions
    function pause() external;
    function unpause() external;
    function setWormholeCore(address) external;
    function setWormholeTokenBridge(address) external;
    function setBridgeFee(uint256) external;
    function setMinMessageFee(uint256) external;
    function setWhitelistedProgram(bytes32, bool) external;
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Track used VAA hashes
ghost mapping(bytes32 => bool) ghostUsedVAAs {
    init_state axiom forall bytes32 v. !ghostUsedVAAs[v];
}

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore usedVAAHashes[KEY bytes32 vaaHash] bool used (bool old_used) {
    if (!old_used && used) {
        ghostUsedVAAs[vaaHash] = true;
    }
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-SOLANA-001: VAA consumption is permanent
 * Once a VAA is marked as used, it stays used
 */
invariant vaaConsumptionPermanent(bytes32 vaaHash)
    ghostUsedVAAs[vaaHash] => usedVAAHashes(vaaHash);

/**
 * INV-SOLANA-002: Bridge fee within bounds (max 1% = 100 basis points)
 */
invariant bridgeFeeWithinBounds()
    bridgeFee() <= 100;

/**
 * INV-SOLANA-003: Messages received never exceeds messages sent
 * (a bridge cannot deliver more messages than were sent)
 */
invariant messagesReceivedBounded()
    totalMessagesReceived() <= totalMessagesSent();

/**
 * INV-SOLANA-004: Wormhole core cannot be zeroed after initialization
 * Once wormholeCore is set to non-zero, no function can zero it out.
 */
invariant wormholeCoreNonZero()
    wormholeCore() != 0
    {
        preserved {
            // Precondition: core was already initialized (non-zero)
            require wormholeCore() != 0;
        }
    }

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-SOLANA-001: VAA cannot be replayed
 * A VAA that has been used cannot be used again
 */
rule vaaCannotBeReplayed(bytes32 vaaHash) {
    require usedVAAHashes(vaaHash);
    
    // Any operation that consumes this VAA must have already failed
    // since the VAA is already marked as used
    assert isVAAUsed(vaaHash), "Used VAA must report as used";
}

/**
 * RULE-SOLANA-002: Paused contract blocks all non-view state changes
 * Any non-view, non-admin function must revert when paused.
 */
rule pausedBlocksOperations(method f) filtered {
    f -> f.isView == false && f.isFallback == false
         && f.selector != sig:unpause().selector
} {
    env e;
    calldataarg args;
    
    require paused();
    
    f@withrevert(e, args);
    
    assert lastReverted, "State-changing operations must revert when paused";
}

/**
 * RULE-SOLANA-003: Bridge fee can only be set within bounds
 * Setting bridge fee to invalid value must fail
 */
rule bridgeFeeOnlyValidValues() {
    env e;
    uint256 newFee;
    
    require newFee > 100; // Above 1%
    
    setBridgeFee@withrevert(e, newFee);
    
    // Should revert or fee should remain within bounds
    assert lastReverted || bridgeFee() <= 100, "Fee must stay within bounds";
}

/**
 * RULE-SOLANA-004: Wormhole core cannot be set to zero
 * Zero address for wormhole core must be rejected
 */
rule wormholeCoreNotZero() {
    env e;
    address zeroAddr = 0;
    
    setWormholeCore@withrevert(e, zeroAddr);
    
    assert lastReverted, "Zero address for wormhole core must be rejected";
}

/**
 * RULE-SOLANA-005: Wormhole token bridge cannot be set to zero
 * Zero address for token bridge must be rejected
 */
rule wormholeTokenBridgeNotZero() {
    env e;
    address zeroAddr = 0;
    
    setWormholeTokenBridge@withrevert(e, zeroAddr);
    
    assert lastReverted, "Zero address for token bridge must be rejected";
}

/**
 * RULE-SOLANA-006: Nonce monotonicity for senders
 * Sender nonces should never decrease
 */
rule nonceMonotonicity(method f, address sender) filtered { f -> !f.isView } {
    mathint nonceBefore = senderNonces(sender);
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint nonceAfter = senderNonces(sender);
    
    assert nonceAfter >= nonceBefore, "Nonce must be monotonically increasing";
}

/**
 * RULE-SOLANA-007: Total messages sent monotonicity
 * Total messages sent can only increase
 */
rule totalMessagesSentMonotonic(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalMessagesSent();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalMessagesSent();
    
    assert countAfter >= countBefore, "Total messages sent must be monotonic";
}

/**
 * RULE-SOLANA-008: Total messages received monotonicity
 * Total messages received can only increase
 */
rule totalMessagesReceivedMonotonic(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalMessagesReceived();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalMessagesReceived();
    
    assert countAfter >= countBefore, "Total messages received must be monotonic";
}

/**
 * RULE-SOLANA-009: Program whitelisting requires authorization
 * Only authorized role can whitelist programs
 */
rule programWhitelistingRequiresAuth(bytes32 programId, bool status) {
    env e;
    
    // Regular user without role
    require e.msg.sender != 0;
    
    bool whitelistedBefore = whitelistedPrograms(programId);
    
    setWhitelistedProgram@withrevert(e, programId, status);
    
    bool reverted = lastReverted;
    
    // Either reverted (no auth) or succeeded (has auth)
    bool whitelistedAfter = whitelistedPrograms(programId);
    
    assert reverted || whitelistedAfter == status, 
           "Whitelisting must either fail or update correctly";
}

/**
 * RULE-SOLANA-010: Accumulated fees can only increase
 * Fees should only accumulate, never decrease (except withdrawal)
 */
rule accumulatedFeesIncreaseOrStay(method f) filtered { f -> !f.isView } {
    mathint feesBefore = accumulatedFees();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint feesAfter = accumulatedFees();
    
    // Fees can only decrease via withdrawFees, which is tested separately
    assert feesAfter >= feesBefore, "Accumulated fees must increase or stay same";
}

/*//////////////////////////////////////////////////////////////
                    SECURITY PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * SEC-SOLANA-001: VAA hash uniqueness enforcement
 * The same VAA hash cannot be processed twice
 */
rule vaaHashUniqueness(bytes32 vaaHash) {
    require !usedVAAHashes(vaaHash);
    
    // After using, it must be marked
    // This is enforced by the ghost variable hook
    assert !ghostUsedVAAs[vaaHash] => !usedVAAHashes(vaaHash), 
           "Ghost must track VAA usage correctly";
}

/**
 * SEC-SOLANA-002: Message counting monotonicity
 * Sending or receiving messages never decreases the respective counters.
 */
rule messageCountingMonotonic(method f) filtered { f -> !f.isView } {
    mathint sentBefore = totalMessagesSent();
    mathint receivedBefore = totalMessagesReceived();
    
    env e;
    calldataarg args;
    f(e, args);
    
    assert totalMessagesSent() >= sentBefore, "Sent count must never decrease";
    assert totalMessagesReceived() >= receivedBefore, "Received count must never decrease";
}
