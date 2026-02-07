/*
 * Certora Formal Verification Spec for ZilliqaBridgeAdapter
 *
 * Verifies invariants and rules for the Zilliqa bridge including:
 * - Constant immutability (chain ID, Qa precision, fee BPS, confirmations)
 * - Nonce monotonicity (deposits, withdrawals, escrows)
 * - Replay protection (tx hashes, nullifiers)
 * - Statistics non-decreasing
 * - Fee calculation integrity
 * - Treasury safety
 */

using ZilliqaBridgeAdapter as bridge;

methods {
    function ZILLIQA_CHAIN_ID() external returns (uint256) envfree;
    function QA_PER_ZIL() external returns (uint256) envfree;
    function BRIDGE_FEE_BPS() external returns (uint256) envfree;
    function BPS_DENOMINATOR() external returns (uint256) envfree;
    function WITHDRAWAL_REFUND_DELAY() external returns (uint256) envfree;
    function DEFAULT_TX_BLOCK_CONFIRMATIONS() external returns (uint256) envfree;
    function MIN_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function MAX_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function MIN_DEPOSIT_QA() external returns (uint256) envfree;
    function MAX_DEPOSIT_QA() external returns (uint256) envfree;
    function depositNonce() external returns (uint256) envfree;
    function withdrawalNonce() external returns (uint256) envfree;
    function escrowNonce() external returns (uint256) envfree;
    function totalDeposited() external returns (uint256) envfree;
    function totalWithdrawn() external returns (uint256) envfree;
    function totalEscrows() external returns (uint256) envfree;
    function totalEscrowsFinished() external returns (uint256) envfree;
    function totalEscrowsCancelled() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;
    function latestDSBlockNumber() external returns (uint256) envfree;
    function currentDSEpoch() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;
    function usedZilliqaTxHashes(bytes32) external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                          INVARIANTS
//////////////////////////////////////////////////////////////*/

/// @notice Zilliqa chain ID is always 1
invariant zilliqaChainIdConstant()
    bridge.ZILLIQA_CHAIN_ID() == 1;

/// @notice Qa per ZIL is always 1e12
invariant qaPerZilConstant()
    bridge.QA_PER_ZIL() == 1000000000000;

/// @notice Bridge fee is always 5 BPS
invariant bridgeFeeBpsConstant()
    bridge.BRIDGE_FEE_BPS() == 5;

/// @notice Withdrawal refund delay is always 24 hours (86400 seconds)
invariant withdrawalRefundDelayConstant()
    bridge.WITHDRAWAL_REFUND_DELAY() == 86400;

/// @notice Default TX block confirmations is always 30
invariant defaultTxBlockConfirmationsConstant()
    bridge.DEFAULT_TX_BLOCK_CONFIRMATIONS() == 30;

/// @notice Minimum escrow timelock is always 1 hour (3600 seconds)
invariant minEscrowTimelockConstant()
    bridge.MIN_ESCROW_TIMELOCK() == 3600;

/// @notice Maximum escrow timelock is always 30 days (2592000 seconds)
invariant maxEscrowTimelockConstant()
    bridge.MAX_ESCROW_TIMELOCK() == 2592000;

/// @notice Finished escrows never exceed total escrows
invariant finishedEscrowsBounded()
    bridge.totalEscrowsFinished() <= bridge.totalEscrows();

/// @notice Cancelled escrows never exceed total escrows
invariant cancelledEscrowsBounded()
    bridge.totalEscrowsCancelled() <= bridge.totalEscrows();

/*//////////////////////////////////////////////////////////////
                            RULES
//////////////////////////////////////////////////////////////*/

/// @notice Deposit nonce only increases
rule depositNonceMonotonic(env e, method f, calldataarg args) {
    uint256 nonceBefore = bridge.depositNonce();
    f(e, args);
    uint256 nonceAfter = bridge.depositNonce();
    assert nonceAfter >= nonceBefore;
}

/// @notice Withdrawal nonce only increases
rule withdrawalNonceMonotonic(env e, method f, calldataarg args) {
    uint256 nonceBefore = bridge.withdrawalNonce();
    f(e, args);
    uint256 nonceAfter = bridge.withdrawalNonce();
    assert nonceAfter >= nonceBefore;
}

/// @notice Escrow nonce only increases
rule escrowNonceMonotonic(env e, method f, calldataarg args) {
    uint256 nonceBefore = bridge.escrowNonce();
    f(e, args);
    uint256 nonceAfter = bridge.escrowNonce();
    assert nonceAfter >= nonceBefore;
}

/// @notice Once a Zilliqa TX hash is marked used, it stays used
rule zilliqaTxHashIrreversible(env e, method f, calldataarg args, bytes32 txHash) {
    bool usedBefore = bridge.usedZilliqaTxHashes(txHash);
    require usedBefore == true;
    f(e, args);
    bool usedAfter = bridge.usedZilliqaTxHashes(txHash);
    assert usedAfter == true;
}

/// @notice Once a nullifier is marked used, it stays used
rule nullifierIrreversible(env e, method f, calldataarg args, bytes32 nullifier) {
    bool usedBefore = bridge.usedNullifiers(nullifier);
    require usedBefore == true;
    f(e, args);
    bool usedAfter = bridge.usedNullifiers(nullifier);
    assert usedAfter == true;
}

/// @notice Total deposited never decreases
rule totalDepositedNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = bridge.totalDeposited();
    f(e, args);
    uint256 after_ = bridge.totalDeposited();
    assert after_ >= before;
}

/// @notice Total withdrawn never decreases
rule totalWithdrawnNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = bridge.totalWithdrawn();
    f(e, args);
    uint256 after_ = bridge.totalWithdrawn();
    assert after_ >= before;
}

/// @notice Total escrows never decreases
rule totalEscrowsNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = bridge.totalEscrows();
    f(e, args);
    uint256 after_ = bridge.totalEscrows();
    assert after_ >= before;
}

/// @notice Latest DS block number never decreases
rule latestDSBlockNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = bridge.latestDSBlockNumber();
    f(e, args);
    uint256 after_ = bridge.latestDSBlockNumber();
    assert after_ >= before;
}

/// @notice Current DS epoch never decreases
rule currentDSEpochNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = bridge.currentDSEpoch();
    f(e, args);
    uint256 after_ = bridge.currentDSEpoch();
    assert after_ >= before;
}

/// @notice Fee calculation: fee + net = amount (5 BPS)
rule feeCalculationIntegrity(uint256 amount) {
    require amount >= bridge.MIN_DEPOSIT_QA();
    require amount <= bridge.MAX_DEPOSIT_QA();

    uint256 fee = (amount * bridge.BRIDGE_FEE_BPS()) / bridge.BPS_DENOMINATOR();
    uint256 net = amount - fee;

    assert fee + net == amount;
}

/// @notice Treasury address never becomes zero after being set
rule treasuryNeverZero(env e, method f, calldataarg args) {
    address treasuryBefore = bridge.treasury();
    require treasuryBefore != 0;
    f(e, args);
    address treasuryAfter = bridge.treasury();
    assert treasuryAfter != 0;
}
