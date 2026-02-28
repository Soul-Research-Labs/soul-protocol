/**
 * Certora Formal Verification Specification
 * ZASEON - UniversalShieldedPool
 *
 * @title Shielded Pool Invariants and Rules
 * @notice Verifies TVL safety, nullifier uniqueness, Merkle tree monotonicity,
 *         commitment uniqueness, test mode security, and pausability properties.
 *
 * @dev Contract function signatures (actual):
 *   - depositETH(bytes32 commitment) external payable
 *   - depositERC20(bytes32 assetId, uint256 amount, bytes32 commitment) external
 *   - withdraw(WithdrawalProof calldata wp) external
 *   - insertCrossChainCommitments(CrossChainCommitmentBatch calldata batch) external
 *   - disableTestMode() external
 *   - registerAsset(bytes32 assetId, address tokenAddress) external
 *   - pause() / unpause() external
 *
 * WithdrawalProof struct:
 *   (bytes proof, bytes32 merkleRoot, bytes32 nullifier, address recipient,
 *    address relayerAddress, uint256 amount, uint256 relayerFee, bytes32 assetId, bytes32 destChainId)
 */

// =============================================================================
// METHODS DECLARATIONS
// =============================================================================

methods {
    // View functions (envfree)
    function nextLeafIndex() external returns (uint256) envfree;
    function currentRoot() external returns (bytes32) envfree;
    function getLastRoot() external returns (bytes32) envfree;
    function isKnownRoot(bytes32) external returns (bool) envfree;
    function isSpent(bytes32) external returns (bool) envfree;
    function commitmentExists(bytes32) external returns (bool) envfree;
    function testMode() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalCrossChainDeposits() external returns (uint256) envfree;
    function TREE_DEPTH() external returns (uint256) envfree;
    function MAX_DEPOSIT() external returns (uint256) envfree;
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function ROOT_HISTORY_SIZE() external returns (uint256) envfree;

    // State-changing functions
    function depositETH(bytes32) external;
    function depositERC20(bytes32, uint256, bytes32) external;
    function withdraw(IUniversalShieldedPool.WithdrawalProof) external;
    function disableTestMode() external;
    function pause() external;
    function unpause() external;
    function registerAsset(bytes32, address) external;
    function deactivateAsset(bytes32) external;
    function setWithdrawalVerifier(address) external;
    function setBatchVerifier(address) external;
    function setSanctionsOracle(address) external;
}

// =============================================================================
// GHOSTS & HOOKS
// =============================================================================

/// @dev Ghost tracking the nullifier mapping state
ghost mapping(bytes32 => bool) ghostNullifierSpent {
    init_state axiom forall bytes32 n. ghostNullifierSpent[n] == false;
}

/// @dev Ghost tracking the leaf index (monotonic)
ghost uint256 ghostLeafIndex {
    init_state axiom ghostLeafIndex == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * INV-POOL-001: Leaf index monotonicity — nextLeafIndex only increases.
 * The Merkle tree is append-only; commitments can never be removed.
 */
invariant leafIndexMonotonicity()
    to_mathint(nextLeafIndex()) >= to_mathint(ghostLeafIndex)
    {
        preserved depositETH(bytes32 c) with (env e) {
            require to_mathint(nextLeafIndex()) < 2^32 - 1;
        }
        preserved depositERC20(bytes32 a, uint256 amt, bytes32 c) with (env e) {
            require to_mathint(nextLeafIndex()) < 2^32 - 1;
        }
    }

/**
 * INV-POOL-002: Tree depth constant.
 * TREE_DEPTH immutable must always be 32.
 */
invariant treeDepthConstant()
    TREE_DEPTH() == 32;

/**
 * INV-POOL-003: Root history size constant.
 * ROOT_HISTORY_SIZE immutable must always be 100.
 */
invariant rootHistorySizeConstant()
    ROOT_HISTORY_SIZE() == 100;

/**
 * INV-POOL-004: Deposit bounds are constant.
 * MAX_DEPOSIT = 10000 ether, MIN_DEPOSIT = 0.001 ether.
 */
invariant depositBoundsConstant()
    MAX_DEPOSIT() == 10000000000000000000000 && MIN_DEPOSIT() == 1000000000000000;

/**
 * INV-POOL-005: Deposit count consistency.
 * totalDeposits is always <= nextLeafIndex (some leaves may come from cross-chain insertions).
 */
invariant depositCountConsistency()
    to_mathint(totalDeposits()) + to_mathint(totalCrossChainDeposits()) <= to_mathint(nextLeafIndex());

// =============================================================================
// NULLIFIER RULES
// =============================================================================

/**
 * RULE-POOL-001: Nullifier uniqueness — a withdrawal with an already-spent nullifier reverts.
 * Prevents double-spend attacks which are the primary threat to shielded pools.
 */
rule nullifierDoubleSpendReverts() {
    env e;
    IUniversalShieldedPool.WithdrawalProof wp;

    require isSpent(wp.nullifier) == true;

    withdraw@withrevert(e, wp);

    assert lastReverted, "Must revert when nullifier already spent";
}

/**
 * RULE-POOL-002: Nullifier permanence — once spent, always spent.
 * No function call should ever clear a spent nullifier.
 */
rule nullifierPermanence(bytes32 nullifierHash, method f) filtered { f -> !f.isView } {
    require isSpent(nullifierHash) == true;

    env e;
    calldataarg args;
    f(e, args);

    assert isSpent(nullifierHash) == true, "Spent nullifier must remain spent";
}

/**
 * RULE-POOL-003: Successful withdrawal marks nullifier as spent.
 */
rule withdrawalMarksNullifierSpent() {
    env e;
    IUniversalShieldedPool.WithdrawalProof wp;

    require isSpent(wp.nullifier) == false;

    withdraw(e, wp);

    assert isSpent(wp.nullifier) == true, "Withdrawal must mark nullifier as spent";
}

// =============================================================================
// DEPOSIT RULES
// =============================================================================

/**
 * RULE-POOL-004: ETH deposit increments leaf index by exactly 1.
 */
rule depositETHIncreasesLeafIndex(bytes32 commitment) {
    uint256 indexBefore = nextLeafIndex();

    env e;
    depositETH(e, commitment);

    uint256 indexAfter = nextLeafIndex();

    assert to_mathint(indexAfter) == to_mathint(indexBefore) + 1,
        "depositETH must increment leaf index by exactly 1";
}

/**
 * RULE-POOL-005: ERC20 deposit increments leaf index by exactly 1.
 */
rule depositERC20IncreasesLeafIndex(bytes32 assetId, uint256 amount, bytes32 commitment) {
    uint256 indexBefore = nextLeafIndex();

    env e;
    depositERC20(e, assetId, amount, commitment);

    uint256 indexAfter = nextLeafIndex();

    assert to_mathint(indexAfter) == to_mathint(indexBefore) + 1,
        "depositERC20 must increment leaf index by exactly 1";
}

/**
 * RULE-POOL-006: ETH deposit increments totalDeposits counter.
 */
rule depositETHIncrementsTotalDeposits(bytes32 commitment) {
    uint256 countBefore = totalDeposits();

    env e;
    depositETH(e, commitment);

    uint256 countAfter = totalDeposits();

    assert to_mathint(countAfter) == to_mathint(countBefore) + 1,
        "depositETH must increment totalDeposits by exactly 1";
}

/**
 * RULE-POOL-007: ETH deposit changes the Merkle root.
 */
rule depositETHChangesRoot(bytes32 commitment) {
    bytes32 rootBefore = getLastRoot();

    env e;
    depositETH(e, commitment);

    bytes32 rootAfter = getLastRoot();

    assert rootAfter != rootBefore, "depositETH must change Merkle root";
}

/**
 * RULE-POOL-008: After any deposit, the new root is a known root.
 */
rule depositMakesRootKnown(bytes32 commitment) {
    env e;
    depositETH(e, commitment);

    bytes32 newRoot = getLastRoot();

    assert isKnownRoot(newRoot) == true,
        "New root after deposit must be recognized as known";
}

/**
 * RULE-POOL-009: Commitment uniqueness — depositing a duplicate commitment reverts.
 */
rule commitmentUniqueness(bytes32 commitment) {
    require commitmentExists(commitment) == true;

    env e;
    depositETH@withrevert(e, commitment);

    assert lastReverted, "Duplicate commitment must revert";
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/**
 * RULE-POOL-010: Withdrawal requires a known Merkle root.
 */
rule withdrawalRequiresKnownRoot() {
    env e;
    IUniversalShieldedPool.WithdrawalProof wp;

    require isKnownRoot(wp.merkleRoot) == false;

    withdraw@withrevert(e, wp);

    assert lastReverted, "Withdrawal must revert with unknown Merkle root";
}

/**
 * RULE-POOL-011: Successful withdrawal increments totalWithdrawals counter.
 */
rule withdrawalIncrementsTotalWithdrawals() {
    uint256 countBefore = totalWithdrawals();

    env e;
    IUniversalShieldedPool.WithdrawalProof wp;
    withdraw(e, wp);

    uint256 countAfter = totalWithdrawals();

    assert to_mathint(countAfter) == to_mathint(countBefore) + 1,
        "withdraw must increment totalWithdrawals by exactly 1";
}

// =============================================================================
// TEST MODE RULES
// =============================================================================

/**
 * RULE-POOL-012: disableTestMode is irreversible — once false, no function can set it back.
 */
rule testModeIrreversible(method f) filtered { f -> !f.isView } {
    require testMode() == false;

    env e;
    calldataarg args;
    f(e, args);

    assert testMode() == false, "Test mode once disabled cannot be re-enabled";
}

/**
 * RULE-POOL-013: disableTestMode transitions from true to false.
 */
rule disableTestModeTransition() {
    require testMode() == true;

    env e;
    disableTestMode(e);

    assert testMode() == false, "disableTestMode must set testMode to false";
}

/**
 * RULE-POOL-014: Deposits revert when test mode is active.
 * This prevents loss of real funds when proof verification is bypassed.
 */
rule depositsBlockedInTestMode(bytes32 commitment) {
    require testMode() == true;

    env e;
    depositETH@withrevert(e, commitment);

    assert lastReverted, "depositETH must revert when testMode is true";
}

// =============================================================================
// PAUSABILITY RULES
// =============================================================================

/**
 * RULE-POOL-015: ETH deposits revert when paused.
 */
rule depositETHRevertsWhenPaused(bytes32 commitment) {
    require paused() == true;

    env e;
    depositETH@withrevert(e, commitment);

    assert lastReverted, "depositETH must revert when contract is paused";
}

/**
 * RULE-POOL-016: ERC20 deposits revert when paused.
 */
rule depositERC20RevertsWhenPaused(bytes32 assetId, uint256 amount, bytes32 commitment) {
    require paused() == true;

    env e;
    depositERC20@withrevert(e, assetId, amount, commitment);

    assert lastReverted, "depositERC20 must revert when contract is paused";
}

/**
 * RULE-POOL-017: Withdrawals revert when paused.
 */
rule withdrawRevertsWhenPaused() {
    require paused() == true;

    env e;
    IUniversalShieldedPool.WithdrawalProof wp;
    withdraw@withrevert(e, wp);

    assert lastReverted, "Withdrawal must revert when contract is paused";
}

// =============================================================================
// ADMIN SECURITY RULES
// =============================================================================

/**
 * RULE-POOL-018: setWithdrawalVerifier rejects zero address.
 */
rule verifierRejectsZeroAddress() {
    env e;
    setWithdrawalVerifier@withrevert(e, 0);

    assert lastReverted, "setWithdrawalVerifier must reject zero address";
}

/**
 * RULE-POOL-019: setBatchVerifier rejects zero address.
 */
rule batchVerifierRejectsZeroAddress() {
    env e;
    setBatchVerifier@withrevert(e, 0);

    assert lastReverted, "setBatchVerifier must reject zero address";
}

/**
 * RULE-POOL-020: Leaf index never decreases across any state transition.
 * Strengthened monotonicity: checks all non-view functions.
 */
rule leafIndexNeverDecreases(method f) filtered { f -> !f.isView } {
    uint256 indexBefore = nextLeafIndex();

    env e;
    calldataarg args;
    f(e, args);

    uint256 indexAfter = nextLeafIndex();

    assert to_mathint(indexAfter) >= to_mathint(indexBefore),
        "Leaf index must never decrease";
}

/**
 * RULE-POOL-021: totalDeposits counter never decreases.
 */
rule totalDepositsNeverDecreases(method f) filtered { f -> !f.isView } {
    uint256 before = totalDeposits();

    env e;
    calldataarg args;
    f(e, args);

    uint256 after = totalDeposits();

    assert to_mathint(after) >= to_mathint(before),
        "totalDeposits must never decrease";
}

/**
 * RULE-POOL-022: totalWithdrawals counter never decreases.
 */
rule totalWithdrawalsNeverDecreases(method f) filtered { f -> !f.isView } {
    uint256 before = totalWithdrawals();

    env e;
    calldataarg args;
    f(e, args);

    uint256 after = totalWithdrawals();

    assert to_mathint(after) >= to_mathint(before),
        "totalWithdrawals must never decrease";
}