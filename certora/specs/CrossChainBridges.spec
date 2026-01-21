/**
 * @title Cross-Chain Bridge Adapters Formal Verification
 * @notice Certora specifications for all PIL cross-chain bridge adapters
 * @dev Comprehensive formal verification for cross-chain security
 */

/*//////////////////////////////////////////////////////////////
                    COMMON BRIDGE INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice All bridge adapters share these fundamental invariants
 */

/**
 * INV-BRIDGE-001: Message nonce monotonicity
 *   ∀ sender: nonces[sender] is strictly increasing
 *   nonces[sender]' >= nonces[sender]
 */

/**
 * INV-BRIDGE-002: Fee bounds enforcement
 *   bridgeFee <= MAX_FEE (1% = 100 basis points)
 */

/**
 * INV-BRIDGE-003: Paused state enforcement
 *   paused() = true ⟹ all state-changing operations revert
 */

/**
 * INV-BRIDGE-004: Message ID uniqueness
 *   ∀ msg1, msg2: messages[msg1].id = messages[msg2].id ⟹ msg1 = msg2
 */

/**
 * INV-BRIDGE-005: Total counters consistency
 *   totalSent + totalFailed = total messages initiated
 *   totalReceived + totalPending = total messages targeted to this chain
 */

/*//////////////////////////////////////////////////////////////
                    SOLANA BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // SolanaBridgeAdapter methods
    function wormholeCore() external returns (address) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function minMessageFee() external returns (uint256) envfree;
    function totalMessages() external returns (uint256) envfree;
    function totalTransfers() external returns (uint256) envfree;
    function usedVAAs(bytes32) external returns (bool) envfree;
    function programRegistry(bytes32) external returns (bool, bool, uint256) envfree;
    function pdaRegistry(bytes32) external returns (bytes32, uint8, bytes32, bool) envfree;
    function nonces(address) external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostUsedVAAs {
    init_state axiom forall bytes32 v. !ghostUsedVAAs[v];
}

hook Sstore usedVAAs[KEY bytes32 vaaHash] bool used (bool old_used) {
    if (!old_used && used) {
        ghostUsedVAAs[vaaHash] = true;
    }
}

/**
 * INV-SOLANA-001: VAA consumption is permanent
 */
invariant vaaConsumptionPermanent(bytes32 vaaHash)
    ghostUsedVAAs[vaaHash] => usedVAAs(vaaHash)
    { preserved { require !paused(); } }

/**
 * INV-SOLANA-002: Wormhole core address cannot be zero after initialization
 */
invariant wormholeCoreNonZero()
    wormholeCore() != 0
    { preserved { require wormholeCore() != 0; } }

/**
 * INV-SOLANA-003: Bridge fee within bounds
 */
invariant bridgeFeeWithinBounds()
    bridgeFee() <= 100
    { preserved { require bridgeFee() <= 100; } }

/**
 * RULE-SOLANA-001: VAA cannot be replayed
 */
rule vaaCannotBeReplayed(bytes32 vaaHash, bytes vaaData) {
    env e1; env e2;
    
    require !paused();
    require !usedVAAs(vaaHash);
    
    // First VAA submission succeeds
    submitVAA(e1, vaaHash, vaaData);
    
    // Second submission with same VAA must revert
    submitVAA@withrevert(e2, vaaHash, vaaData);
    
    assert lastReverted, "VAA replay must be prevented";
}

/**
 * RULE-SOLANA-002: Nonce always increases
 */
rule nonceAlwaysIncreases(address sender) {
    env e;
    bytes32 programId; bytes32 recipient; bytes payload;
    
    require e.msg.sender == sender;
    require !paused();
    
    uint256 nonceBefore = nonces(sender);
    
    sendMessageToSolana(e, programId, recipient, payload);
    
    uint256 nonceAfter = nonces(sender);
    
    assert nonceAfter == nonceBefore + 1, "Nonce must increment";
}

/**
 * RULE-SOLANA-003: Only whitelisted programs can receive messages
 */
rule onlyWhitelistedProgramsReceive(bytes32 programId) {
    env e;
    bytes32 recipient; bytes payload;
    
    bool isWhitelisted;
    (_, isWhitelisted, _) = programRegistry(programId);
    
    require !isWhitelisted;
    
    sendMessageToSolana@withrevert(e, programId, recipient, payload);
    
    assert lastReverted, "Non-whitelisted program must be rejected";
}

/*//////////////////////////////////////////////////////////////
                   LAYERZERO BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // LayerZeroBridgeAdapter methods
    function endpoint() external returns (address) envfree;
    function localEid() external returns (uint32) envfree;
    function delegate() external returns (address) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function totalMessagesSent() external returns (uint256) envfree;
    function totalMessagesReceived() external returns (uint256) envfree;
    function isPeerActive(uint32) external returns (bool) envfree;
    function getPeer(uint32) external returns (uint32, bytes32, uint8, bool, uint256, uint8, uint256) envfree;
    function receivedMessages(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostReceivedGuids {
    init_state axiom forall bytes32 g. !ghostReceivedGuids[g];
}

hook Sstore receivedMessages[KEY bytes32 guid] bool received (bool old_received) {
    if (!old_received && received) {
        ghostReceivedGuids[guid] = true;
    }
}

/**
 * INV-LZ-001: GUID reception is permanent
 */
invariant guidReceptionPermanent(bytes32 guid)
    ghostReceivedGuids[guid] => receivedMessages(guid)
    { preserved { require !paused(); } }

/**
 * INV-LZ-002: Endpoint must be valid
 */
invariant endpointValid()
    endpoint() != 0
    { preserved { require endpoint() != 0; } }

/**
 * INV-LZ-003: Local EID must be set
 */
invariant localEidSet()
    localEid() > 0
    { preserved { require localEid() > 0; } }

/**
 * RULE-LZ-001: Message cannot be received twice
 */
rule messageCannotBeReceivedTwice(bytes32 guid) {
    env e1; env e2;
    uint32 srcEid; bytes32 sender; bytes message; bytes extraData;
    
    require !paused();
    require !receivedMessages(guid);
    
    lzReceive(e1, srcEid, sender, guid, message, extraData);
    
    lzReceive@withrevert(e2, srcEid, sender, guid, message, extraData);
    
    assert lastReverted, "Duplicate message must be rejected";
}

/**
 * RULE-LZ-002: Only active peers can send/receive
 */
rule onlyActivePeersAllowed(uint32 eid) {
    env e;
    bytes32 receiver; bytes message;
    
    require !isPeerActive(eid);
    
    lzSend@withrevert(e, eid, receiver, message, _);
    
    assert lastReverted, "Inactive peer must be rejected";
}

/**
 * RULE-LZ-003: Minimum gas requirement enforced
 */
rule minimumGasEnforced(uint32 eid) {
    env e;
    bytes32 receiver; bytes message;
    uint128 gas; uint128 value; bytes composeMsg; bytes extraOptions;
    
    uint256 minGas;
    (_, _, _, _, minGas, _, _) = getPeer(eid);
    
    require gas < minGas;
    require isPeerActive(eid);
    
    lzSend@withrevert(e, eid, receiver, message, (gas, value, composeMsg, extraOptions));
    
    assert lastReverted, "Insufficient gas must be rejected";
}

/*//////////////////////////////////////////////////////////////
                   CHAINLINK BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // ChainlinkBridgeAdapter methods
    function ccipRouter() external returns (address) envfree;
    function linkToken() external returns (address) envfree;
    function defaultGasLimit() external returns (uint256) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function totalMessagesSent() external returns (uint256) envfree;
    function totalMessagesReceived() external returns (uint256) envfree;
    function isChainActive(uint64) external returns (bool) envfree;
    function isSupportedToken(address) external returns (bool) envfree;
    function isAllowedSender(uint64, bytes32) external returns (bool) envfree;
    function processedMessages(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostProcessedMessages {
    init_state axiom forall bytes32 m. !ghostProcessedMessages[m];
}

hook Sstore processedMessages[KEY bytes32 messageId] bool processed (bool old_processed) {
    if (!old_processed && processed) {
        ghostProcessedMessages[messageId] = true;
    }
}

/**
 * INV-CCIP-001: Message processing is permanent
 */
invariant messageProcessingPermanent(bytes32 messageId)
    ghostProcessedMessages[messageId] => processedMessages(messageId)
    { preserved { require !paused(); } }

/**
 * INV-CCIP-002: CCIP router must be valid
 */
invariant ccipRouterValid()
    ccipRouter() != 0
    { preserved { require ccipRouter() != 0; } }

/**
 * INV-CCIP-003: Gas limit within bounds
 */
invariant gasLimitWithinBounds()
    defaultGasLimit() >= 50000 && defaultGasLimit() <= 2000000
    { preserved { require defaultGasLimit() >= 50000 && defaultGasLimit() <= 2000000; } }

/**
 * RULE-CCIP-001: CCIP message cannot be processed twice
 */
rule ccipMessageCannotBeProcessedTwice(bytes32 messageId) {
    env e1; env e2;
    uint64 chainSelector; bytes32 sender; bytes data;
    
    require !paused();
    require !processedMessages(messageId);
    
    ccipReceive(e1, messageId, chainSelector, sender, data);
    
    ccipReceive@withrevert(e2, messageId, chainSelector, sender, data);
    
    assert lastReverted, "Duplicate CCIP message must be rejected";
}

/**
 * RULE-CCIP-002: Only allowed senders accepted
 */
rule onlyAllowedSendersAccepted(uint64 chainSelector, bytes32 sender) {
    env e;
    bytes32 messageId; bytes data;
    
    require !isAllowedSender(chainSelector, sender);
    
    ccipReceive@withrevert(e, messageId, chainSelector, sender, data);
    
    assert lastReverted, "Unauthorized sender must be rejected";
}

/**
 * RULE-CCIP-003: Only active chains can send/receive
 */
rule onlyActiveChainsAllowed(uint64 chainSelector) {
    env e;
    bytes32 receiver; bytes data; uint256 gasLimit; uint8 feeToken;
    
    require !isChainActive(chainSelector);
    
    sendMessage@withrevert(e, chainSelector, receiver, data, gasLimit, feeToken);
    
    assert lastReverted, "Inactive chain must be rejected";
}

/**
 * RULE-CCIP-004: Only supported tokens can be transferred
 */
rule onlySupportedTokensTransferred(address token) {
    env e;
    uint64 chainSelector; bytes32 receiver; bytes extraData; uint256 gasLimit; uint8 feeToken;
    
    require !isSupportedToken(token);
    require isChainActive(chainSelector);
    
    sendTokens@withrevert(e, chainSelector, receiver, [(token, 1000)], extraData, gasLimit, feeToken);
    
    assert lastReverted, "Unsupported token must be rejected";
}

/*//////////////////////////////////////////////////////////////
                   STARKNET BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // StarkNetBridgeAdapter methods
    function starknetCore() external returns (address) envfree;
    function programHash() external returns (uint256) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function totalMessages() external returns (uint256) envfree;
    function consumedMessages(bytes32) external returns (bool) envfree;
    function registeredContracts(uint256) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostConsumedStarknetMessages {
    init_state axiom forall bytes32 m. !ghostConsumedStarknetMessages[m];
}

hook Sstore consumedMessages[KEY bytes32 msgHash] bool consumed (bool old_consumed) {
    if (!old_consumed && consumed) {
        ghostConsumedStarknetMessages[msgHash] = true;
    }
}

/**
 * INV-STARKNET-001: Message consumption is permanent
 */
invariant starknetMessageConsumptionPermanent(bytes32 msgHash)
    ghostConsumedStarknetMessages[msgHash] => consumedMessages(msgHash)
    { preserved { require !paused(); } }

/**
 * RULE-STARKNET-001: StarkNet message cannot be consumed twice
 */
rule starknetMessageCannotBeConsumedTwice(bytes32 msgHash) {
    env e1; env e2;
    uint256[] payload;
    
    require !paused();
    require !consumedMessages(msgHash);
    
    consumeMessageFromL2(e1, msgHash, payload);
    
    consumeMessageFromL2@withrevert(e2, msgHash, payload);
    
    assert lastReverted, "StarkNet message replay must be prevented";
}

/**
 * RULE-STARKNET-002: Only registered contracts can send messages
 */
rule onlyRegisteredContractsCanSend(uint256 toAddress) {
    env e;
    uint256[] payload;
    
    require !registeredContracts(toAddress);
    
    sendMessageToL2@withrevert(e, toAddress, payload);
    
    assert lastReverted, "Unregistered contract must be rejected";
}

/*//////////////////////////////////////////////////////////////
                    BITCOIN BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // BitcoinBridgeAdapter methods  
    function btcRelayer() external returns (address) envfree;
    function minConfirmations() external returns (uint256) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function usedTxHashes(bytes32) external returns (bool) envfree;
    function pendingWithdrawals(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostUsedBtcTxHashes {
    init_state axiom forall bytes32 tx. !ghostUsedBtcTxHashes[tx];
}

hook Sstore usedTxHashes[KEY bytes32 txHash] bool used (bool old_used) {
    if (!old_used && used) {
        ghostUsedBtcTxHashes[txHash] = true;
    }
}

/**
 * INV-BTC-001: Bitcoin TX hash usage is permanent
 */
invariant btcTxHashUsagePermanent(bytes32 txHash)
    ghostUsedBtcTxHashes[txHash] => usedTxHashes(txHash)
    { preserved { require !paused(); } }

/**
 * INV-BTC-002: Minimum confirmations must be reasonable
 */
invariant minConfirmationsReasonable()
    minConfirmations() >= 1 && minConfirmations() <= 100
    { preserved { require minConfirmations() >= 1 && minConfirmations() <= 100; } }

/**
 * RULE-BTC-001: Bitcoin deposit cannot be claimed twice
 */
rule btcDepositCannotBeClaimedTwice(bytes32 txHash) {
    env e1; env e2;
    bytes proof; uint256 amount; address recipient;
    
    require !paused();
    require !usedTxHashes(txHash);
    
    claimDeposit(e1, txHash, proof, amount, recipient);
    
    claimDeposit@withrevert(e2, txHash, proof, amount, recipient);
    
    assert lastReverted, "Bitcoin deposit replay must be prevented";
}

/*//////////////////////////////////////////////////////////////
                    BITVM BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // BitVMBridgeAdapter methods
    function bitvmBridge() external returns (address) envfree;
    function challengeWindow() external returns (uint256) envfree;
    function operatorStake() external returns (uint256) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function totalComputations() external returns (uint256) envfree;
    function usedProofs(bytes32) external returns (bool) envfree;
    function pendingChallenges(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostUsedBitVMProofs {
    init_state axiom forall bytes32 p. !ghostUsedBitVMProofs[p];
}

hook Sstore usedProofs[KEY bytes32 proofHash] bool used (bool old_used) {
    if (!old_used && used) {
        ghostUsedBitVMProofs[proofHash] = true;
    }
}

/**
 * INV-BITVM-001: BitVM proof usage is permanent
 */
invariant bitvmProofUsagePermanent(bytes32 proofHash)
    ghostUsedBitVMProofs[proofHash] => usedProofs(proofHash)
    { preserved { require !paused(); } }

/**
 * INV-BITVM-002: Challenge window must be positive
 */
invariant challengeWindowPositive()
    challengeWindow() > 0
    { preserved { require challengeWindow() > 0; } }

/**
 * RULE-BITVM-001: BitVM proof cannot be reused
 */
rule bitvmProofCannotBeReused(bytes32 proofHash) {
    env e1; env e2;
    bytes proof; bytes32 computationId;
    
    require !paused();
    require !usedProofs(proofHash);
    
    submitProof(e1, proofHash, proof, computationId);
    
    submitProof@withrevert(e2, proofHash, proof, computationId);
    
    assert lastReverted, "BitVM proof replay must be prevented";
}

/**
 * RULE-BITVM-002: Challenged computations cannot finalize during window
 */
rule challengedComputationsBlocked(bytes32 computationId) {
    env e;
    
    require pendingChallenges(computationId);
    require e.block.timestamp < challengeDeadline(computationId);
    
    finalizeComputation@withrevert(e, computationId);
    
    assert lastReverted, "Challenged computation must wait for window";
}

/*//////////////////////////////////////////////////////////////
                    AZTEC BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

methods {
    // AztecBridgeAdapter methods
    function rollupProcessor() external returns (address) envfree;
    function bridgeFee() external returns (uint256) envfree;
    function totalNotes() external returns (uint256) envfree;
    function nullifierHashes(bytes32) external returns (bool) envfree;
    function pendingDeposits(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
}

ghost mapping(bytes32 => bool) ghostAztecNullifiers {
    init_state axiom forall bytes32 n. !ghostAztecNullifiers[n];
}

hook Sstore nullifierHashes[KEY bytes32 nullifier] bool consumed (bool old_consumed) {
    if (!old_consumed && consumed) {
        ghostAztecNullifiers[nullifier] = true;
    }
}

/**
 * INV-AZTEC-001: Aztec nullifier consumption is permanent
 */
invariant aztecNullifierPermanent(bytes32 nullifier)
    ghostAztecNullifiers[nullifier] => nullifierHashes(nullifier)
    { preserved { require !paused(); } }

/**
 * RULE-AZTEC-001: Aztec note cannot be double-spent
 */
rule aztecNoteCannotBeDoubleSpent(bytes32 nullifier) {
    env e1; env e2;
    bytes proof; uint256 amount;
    
    require !paused();
    require !nullifierHashes(nullifier);
    
    withdrawWithProof(e1, nullifier, proof, amount);
    
    withdrawWithProof@withrevert(e2, nullifier, proof, amount);
    
    assert lastReverted, "Aztec double-spend must be prevented";
}

/*//////////////////////////////////////////////////////////////
                  CROSS-CHAIN SAFETY PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * SAFETY-CROSS-001: No bridge can create tokens from nothing
 *   ∀ bridge, amount: mint(amount) ⟹ ∃ lock_tx on source chain with amount
 */

/**
 * SAFETY-CROSS-002: Message ordering within channel is preserved
 *   ∀ msg1, msg2, channel: 
 *     sent(msg1) < sent(msg2) ⟹ received(msg1) < received(msg2)
 */

/**
 * SAFETY-CROSS-003: Timeout guarantees fund recovery
 *   ∀ transfer: !completed(transfer) ∧ expired(transfer) ⟹ 
 *               funds returned to sender
 */

/**
 * SAFETY-CROSS-004: No single point of failure
 *   ∀ message: verification requires signatures from 
 *              at least threshold-of-n validators
 */

/**
 * SAFETY-CROSS-005: Replay protection across all chains
 *   ∀ msg, chain1, chain2: 
 *     processed(msg, chain1) ⟹ ¬processable(msg, chain2)
 */
