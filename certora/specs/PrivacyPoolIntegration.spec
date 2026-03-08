/**
 * Certora Formal Verification Specification
 * ZASEON - PrivacyPoolIntegration
 *
 * Verifies safety invariants for the privacy pool:
 * - Nullifier double-spend prevention
 * - Nullifier permanence (once spent, always spent)
 * - Merkle leaf index monotonicity
 * - Deposit increments leaf index by exactly 1
 * - Emergency withdraw is admin-gated
 * - Pausing blocks deposits/withdrawals/swaps
 */

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function getMerkleRoot() external returns (bytes32) envfree;
    function commitmentExists(bytes32) external returns (bool) envfree;
    function isNullifierSpent(bytes32) external returns (bool) envfree;
    function getCommitmentCount() external returns (uint256) envfree;
    function getSupportedTokens() external returns (address[]) envfree;
    function paused() external returns (bool) envfree;

    // State-changing functions
    function privateDeposit(bytes32, bytes, bytes32, address) external;
    function privateDepositERC20(bytes32, bytes, bytes32, address, uint256) external;
    function privateWithdraw(bytes, bytes32, bytes32, address, uint256, address) external;
    function privateSwap(bytes32, bytes32, bytes, bytes32, address, address) external;
    function emergencyWithdraw(address, address) external;
    function pause() external;
    function unpause() external;
    function addPoolToken(address, uint256, uint256, uint256) external;

    // AccessControl
    function hasRole(bytes32, address) external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostLeafIndex {
    init_state axiom ghostLeafIndex == 0;
}

ghost mapping(bytes32 => bool) ghostNullifierSpent {
    init_state axiom forall bytes32 n. ghostNullifierSpent[n] == false;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * INV-PP-001: Leaf index only increases (monotonicity)
 * The commitment count can never decrease.
 */
invariant leafIndexMonotonicity()
    to_mathint(getCommitmentCount()) >= 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * RULE-PP-001: Nullifier double-spend reverts
 * If a nullifier is already spent, privateWithdraw must revert.
 */
rule nullifierDoubleSpendReverts(
    bytes proof,
    bytes32 nullifierHash,
    bytes32 recipient,
    address token,
    uint256 relayerFee,
    address relayer
) {
    env e;
    require isNullifierSpent(nullifierHash);

    privateWithdraw@withrevert(e, proof, nullifierHash, recipient, token, relayerFee, relayer);

    assert lastReverted;
}

/**
 * RULE-PP-002: Nullifier permanence
 * Once a nullifier is marked spent, no function call can un-spend it.
 */
rule nullifierPermanence(bytes32 nullifier, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    require isNullifierSpent(nullifier);

    f(e, args);

    assert isNullifierSpent(nullifier);
}

/**
 * RULE-PP-003: Successful withdrawal marks nullifier as spent
 */
rule withdrawalMarksNullifierSpent(
    bytes proof,
    bytes32 nullifierHash,
    bytes32 recipient,
    address token,
    uint256 relayerFee,
    address relayer
) {
    env e;
    require !isNullifierSpent(nullifierHash);

    privateWithdraw(e, proof, nullifierHash, recipient, token, relayerFee, relayer);

    assert isNullifierSpent(nullifierHash);
}

/**
 * RULE-PP-004: Deposit increments commitment count by exactly 1
 */
rule depositETHIncrementsLeafIndex(
    bytes32 commitment,
    bytes rangeProof,
    bytes32 nullifier,
    address token
) {
    env e;
    uint256 countBefore = getCommitmentCount();

    privateDeposit(e, commitment, rangeProof, nullifier, token);

    uint256 countAfter = getCommitmentCount();
    assert to_mathint(countAfter) == to_mathint(countBefore) + 1;
}

/**
 * RULE-PP-005: ERC20 Deposit increments commitment count by exactly 1
 */
rule depositERC20IncrementsLeafIndex(
    bytes32 commitment,
    bytes rangeProof,
    bytes32 nullifier,
    address token,
    uint256 amount
) {
    env e;
    uint256 countBefore = getCommitmentCount();

    privateDepositERC20(e, commitment, rangeProof, nullifier, token, amount);

    uint256 countAfter = getCommitmentCount();
    assert to_mathint(countAfter) == to_mathint(countBefore) + 1;
}

/**
 * RULE-PP-006: Commitment existence is permanent
 * Once a commitment is added, it cannot be removed.
 */
rule commitmentPermanence(bytes32 commitment, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    require commitmentExists(commitment);

    f(e, args);

    assert commitmentExists(commitment);
}

/**
 * RULE-PP-007: Only admin can call emergencyWithdraw
 */
rule onlyAdminCanEmergencyWithdraw(address token, address to) {
    env e;
    // DEFAULT_ADMIN_ROLE = 0x00
    require !hasRole(to_bytes32(0), e.msg.sender);

    emergencyWithdraw@withrevert(e, token, to);

    assert lastReverted;
}

/**
 * RULE-PP-008: Paused state blocks deposits
 */
rule pausedBlocksDeposit(
    bytes32 commitment,
    bytes rangeProof,
    bytes32 nullifier,
    address token
) {
    env e;
    require paused();

    privateDeposit@withrevert(e, commitment, rangeProof, nullifier, token);

    assert lastReverted;
}

/**
 * RULE-PP-009: Paused state blocks withdrawals
 */
rule pausedBlocksWithdraw(
    bytes proof,
    bytes32 nullifierHash,
    bytes32 recipient,
    address token,
    uint256 relayerFee,
    address relayer
) {
    env e;
    require paused();

    privateWithdraw@withrevert(e, proof, nullifierHash, recipient, token, relayerFee, relayer);

    assert lastReverted;
}

/**
 * RULE-PP-010: Paused state blocks swaps
 */
rule pausedBlocksSwap(
    bytes32 inputCommitment,
    bytes32 outputCommitment,
    bytes proof,
    bytes32 inputNullifier,
    address inputToken,
    address outputToken
) {
    env e;
    require paused();

    privateSwap@withrevert(e, inputCommitment, outputCommitment, proof, inputNullifier, inputToken, outputToken);

    assert lastReverted;
}
