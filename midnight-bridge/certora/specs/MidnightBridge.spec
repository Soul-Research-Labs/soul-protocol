/**
 * @title Midnight Bridge Formal Verification Specifications
 * @notice Certora CVL specifications for MidnightBridgeHub security properties
 * @dev Run with: certoraRun certora/conf/verify_midnight_bridge.conf
 *
 * These specifications define critical invariants, pre/post conditions,
 * and safety properties for the Midnight Network bridge contracts.
 */

/*//////////////////////////////////////////////////////////////
                    CRITICAL INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-BRIDGE-001: Nullifier uniqueness (Double-spend protection)
 *   ∀ n: usedNullifiers[n] = true ⟹ □(usedNullifiers[n] = true)
 *   (Once a nullifier is marked used, it MUST remain used forever)
 *   
 *   This is the MOST CRITICAL security property of the bridge.
 *   A violation enables double-spending of bridged assets.
 */
rule nullifierPermanence(bytes32 nullifier) {
    require usedNullifiers[nullifier] == true;
    
    // Any function call
    method f;
    env e;
    calldataarg args;
    f(e, args);
    
    assert usedNullifiers[nullifier] == true,
        "Nullifier consumption must be permanent";
}

/**
 * INV-BRIDGE-002: Withdrawal requires valid proof
 *   ∀ withdrawal w: w.executed ⟹ proofVerifier.verify(w.proof) = true
 *   (No withdrawal can complete without a valid ZK proof)
 */
rule withdrawalRequiresValidProof(
    bytes32 nullifier,
    address token,
    address recipient,
    uint256 amount,
    bytes proof
) {
    env e;
    
    // Assume proof verification fails
    require proofVerifier.verifyBridgeTransfer(_, _, _, proof) == false;
    
    // Withdrawal must revert
    completeWithdrawal@withrevert(e, nullifier, token, recipient, amount, proof);
    
    assert lastReverted,
        "Withdrawal must fail with invalid proof";
}

/**
 * INV-BRIDGE-003: Solvency preservation
 *   balanceOf(hub, token) >= sum(deposits[token]) - sum(withdrawals[token])
 *   (Bridge must always have sufficient funds to cover obligations)
 */
ghost uint256 ghostTotalDeposits;
ghost uint256 ghostTotalWithdrawals;

hook Sstore totalDeposited[KEY address token] uint256 newValue (uint256 oldValue) STORAGE {
    ghostTotalDeposits = ghostTotalDeposits + (newValue - oldValue);
}

hook Sstore totalWithdrawn[KEY address token] uint256 newValue (uint256 oldValue) STORAGE {
    ghostTotalWithdrawals = ghostTotalWithdrawals + (newValue - oldValue);
}

invariant solvency(address token)
    token.balanceOf(currentContract) >= ghostTotalDeposits - ghostTotalWithdrawals
    filtered { f -> !f.isView }

/**
 * INV-BRIDGE-004: Token whitelist enforcement
 *   ∀ deposit d: d.executed ⟹ whitelistedTokens[d.token] = true
 *   (Only whitelisted tokens can be deposited)
 */
rule onlyWhitelistedTokensDepositable(address token, uint256 amount) {
    env e;
    require whitelistedTokens[token] == false;
    
    depositForBridge@withrevert(e, token, amount, _, _);
    
    assert lastReverted,
        "Non-whitelisted tokens must be rejected";
}

/**
 * INV-BRIDGE-005: Chain ID validation
 *   ∀ deposit d: d.destChainId ∈ SUPPORTED_CHAINS
 *   (Deposits can only target supported L2 chains)
 */
rule destinationChainValidation(uint256 destChainId) {
    env e;
    
    require destChainId != 42161;  // Arbitrum
    require destChainId != 10;     // Optimism
    require destChainId != 8453;   // Base
    require destChainId != 324;    // zkSync
    require destChainId != 534352; // Scroll
    require destChainId != 59144;  // Linea
    require destChainId != 1101;   // Polygon zkEVM
    
    depositForBridge@withrevert(e, _, _, destChainId, _);
    
    assert lastReverted,
        "Unsupported chain IDs must be rejected";
}

/*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * INV-BRIDGE-006: Only relayer can complete withdrawals
 *   ∀ withdrawal w: w.caller must have RELAYER_ROLE
 */
rule onlyRelayerCanWithdraw(address caller) {
    env e;
    require e.msg.sender == caller;
    require !hasRole(RELAYER_ROLE(), caller);
    
    completeWithdrawal@withrevert(e, _, _, _, _, _);
    
    assert lastReverted,
        "Non-relayer addresses cannot complete withdrawals";
}

/**
 * INV-BRIDGE-007: Only admin can modify critical settings
 *   ∀ setting change c: c.caller must have DEFAULT_ADMIN_ROLE
 */
rule onlyAdminCanModifySettings(address caller) {
    env e;
    require e.msg.sender == caller;
    require !hasRole(DEFAULT_ADMIN_ROLE(), caller);
    
    // Token whitelisting
    whitelistToken@withrevert(e, _, _);
    assert lastReverted, "Non-admin cannot whitelist tokens";
    
    // Pause/unpause
    pause@withrevert(e);
    assert lastReverted, "Non-admin cannot pause";
}

/*//////////////////////////////////////////////////////////////
                    STATE TRANSITION PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * INV-BRIDGE-008: Deposit ID monotonicity
 *   ∀ d1, d2: d1.id < d2.id ⟹ d1.timestamp ≤ d2.timestamp
 *   (Deposit IDs are strictly increasing)
 */
rule depositIdMonotonicity() {
    uint256 idBefore = nextDepositId;
    env e;
    depositForBridge(e, _, _, _, _);
    uint256 idAfter = nextDepositId;
    
    assert idAfter == idBefore + 1,
        "Deposit ID must increment by exactly 1";
}

/**
 * INV-BRIDGE-009: Deposit creates valid commitment
 *   ∀ deposit d: deposits[d.id].commitment ≠ 0
 *   (Every deposit has a non-zero commitment hash)
 */
rule depositCreatesValidCommitment() {
    env e;
    uint256 depositId = depositForBridge(e, _, _, _, _);
    
    assert deposits[depositId].commitment != bytes32(0),
        "Deposit must create non-zero commitment";
}

/*//////////////////////////////////////////////////////////////
                    ECONOMIC SECURITY PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * INV-BRIDGE-010: Withdrawal amount matches proof claim
 *   ∀ withdrawal w: w.amount = extractAmount(w.proof)
 *   (Cannot withdraw more than proven amount)
 */
rule withdrawalAmountIntegrity(uint256 claimedAmount, bytes proof) {
    env e;
    
    uint256 provenAmount = proofVerifier.extractAmount(proof);
    require claimedAmount > provenAmount;
    
    completeWithdrawal@withrevert(e, _, _, _, claimedAmount, proof);
    
    assert lastReverted,
        "Cannot withdraw more than proven amount";
}

/**
 * INV-BRIDGE-011: No front-running protection bypass
 *   ∀ withdrawal w: w.recipient = extractRecipient(w.proof)
 *   (Cannot redirect funds to different recipient)
 */
rule withdrawalRecipientIntegrity(address recipient, bytes proof) {
    env e;
    
    address provenRecipient = proofVerifier.extractRecipient(proof);
    require recipient != provenRecipient;
    
    completeWithdrawal@withrevert(e, _, _, recipient, _, proof);
    
    assert lastReverted,
        "Cannot redirect funds to unproven recipient";
}

/*//////////////////////////////////////////////////////////////
                    PAUSE FUNCTIONALITY
//////////////////////////////////////////////////////////////*/

/**
 * INV-BRIDGE-012: Paused state blocks deposits
 */
rule pauseBlocksDeposits() {
    require paused() == true;
    env e;
    
    depositForBridge@withrevert(e, _, _, _, _);
    
    assert lastReverted,
        "Deposits must fail when paused";
}

/**
 * INV-BRIDGE-013: Paused state blocks withdrawals
 */
rule pauseBlocksWithdrawals() {
    require paused() == true;
    env e;
    
    completeWithdrawal@withrevert(e, _, _, _, _, _);
    
    assert lastReverted,
        "Withdrawals must fail when paused";
}

/*//////////////////////////////////////////////////////////////
                    REENTRANCY PROTECTION
//////////////////////////////////////////////////////////////*/

/**
 * INV-BRIDGE-014: State updates before external calls
 *   ∀ withdrawal w: usedNullifiers[w.nullifier] is set BEFORE token transfer
 */
rule stateBeforeExternalCall(bytes32 nullifier) {
    env e;
    require usedNullifiers[nullifier] == false;
    
    // After withdrawal call (successful or not)
    completeWithdrawal@withrevert(e, nullifier, _, _, _, _);
    
    // If succeeded, nullifier must be marked used
    assert !lastReverted => usedNullifiers[nullifier] == true,
        "Nullifier must be marked before potential reentrancy";
}

/*//////////////////////////////////////////////////////////////
                    LIVENESS PROPERTIES  
//////////////////////////////////////////////////////////////*/

/**
 * LIVE-BRIDGE-001: Valid deposits always succeed
 *   ∀ valid deposit d: ¬paused ∧ whitelisted(d.token) ∧ d.amount > 0 
 *                      ⟹ depositForBridge(d) succeeds
 */
rule validDepositsSucceed(
    address token,
    uint256 amount,
    uint256 destChainId,
    bytes32 recipient
) {
    env e;
    
    require paused() == false;
    require whitelistedTokens[token] == true;
    require amount > 0;
    require recipient != bytes32(0);
    require destChainId == 42161; // Arbitrum - known valid
    require token.allowance(e.msg.sender, currentContract) >= amount;
    require token.balanceOf(e.msg.sender) >= amount;
    
    depositForBridge@withrevert(e, token, amount, destChainId, recipient);
    
    assert !lastReverted,
        "Valid deposits should succeed";
}

/**
 * LIVE-BRIDGE-002: Valid withdrawals always succeed  
 *   ∀ valid withdrawal w: ¬paused ∧ validProof(w) ∧ ¬usedNullifier(w.nullifier)
 *                        ⟹ completeWithdrawal(w) succeeds
 */
rule validWithdrawalsSucceed(
    bytes32 nullifier,
    address token,
    address recipient,
    uint256 amount,
    bytes proof
) {
    env e;
    
    require paused() == false;
    require hasRole(RELAYER_ROLE(), e.msg.sender);
    require usedNullifiers[nullifier] == false;
    require proofVerifier.verifyBridgeTransfer(_, _, _, proof) == true;
    require token.balanceOf(currentContract) >= amount;
    
    completeWithdrawal@withrevert(e, nullifier, token, recipient, amount, proof);
    
    assert !lastReverted,
        "Valid withdrawals should succeed";
}
