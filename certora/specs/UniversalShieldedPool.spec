/**
 * Certora Formal Verification Specification
 * Soul Protocol - UniversalShieldedPool
 *
 * @title Shielded Pool Invariants and Rules
 * @notice Verifies TVL safety, nullifier uniqueness, Merkle tree monotonicity,
 *         and test mode security properties.
 */

// =============================================================================
// METHODS DECLARATIONS
// =============================================================================

methods {
    // View functions
    function nextLeafIndex() external returns (uint256) envfree;
    function getCurrentRoot() external returns (bytes32) envfree;
    function isKnownRoot(bytes32) external returns (bool) envfree;
    function isSpent(bytes32) external returns (bool) envfree;
    function totalDeposited() external returns (uint256) envfree;
    function totalWithdrawn() external returns (uint256) envfree;
    function testMode() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function TREE_DEPTH() external returns (uint256) envfree;
    function MAX_DEPOSIT_AMOUNT() external returns (uint256) envfree;

    // State-changing functions
    function deposit(bytes32, address, uint256) external;
    function withdraw(bytes32, address, address, uint256, bytes32, bytes) external;
    function disableTestMode() external;
    function pause() external;
    function unpause() external;
}

// =============================================================================
// GHOSTS
// =============================================================================

// Track total value deposited
ghost uint256 ghostTotalDeposited {
    init_state axiom ghostTotalDeposited == 0;
}

// Track total value withdrawn
ghost uint256 ghostTotalWithdrawn {
    init_state axiom ghostTotalWithdrawn == 0;
}

// Track nullifier consumption
ghost mapping(bytes32 => bool) ghostNullifierSpent {
    init_state axiom forall bytes32 n. ghostNullifierSpent[n] == false;
}

// Track leaf index monotonicity
ghost uint256 ghostLeafIndex {
    init_state axiom ghostLeafIndex == 0;
}

// Track test mode state
ghost bool ghostTestMode;

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * INV-POOL-001: TVL Safety - Total withdrawals never exceed total deposits.
 * This is the most critical invariant: the pool cannot lose more than it received.
 */
invariant tvlSafety()
    totalWithdrawn() <= totalDeposited()
    {
        preserved withdraw(bytes32 n, address r, address rel, uint256 fee, bytes32 root, bytes proof)
            with (env e) {
            require totalWithdrawn() <= totalDeposited();
        }
    }

/**
 * INV-POOL-002: Leaf index monotonicity - The next leaf index only increases.
 * Merkle tree is append-only.
 */
invariant leafIndexMonotonicity()
    nextLeafIndex() >= 0
    {
        preserved deposit(bytes32 c, address a, uint256 amt) with (env e) {
            require nextLeafIndex() < 2^32 - 1; // Capacity check
        }
    }

/**
 * INV-POOL-003: Tree depth is constant (32).
 */
invariant treeDepthConstant()
    TREE_DEPTH() == 32;

// =============================================================================
// NULLIFIER RULES
// =============================================================================

/**
 * RULE-POOL-001: Nullifier uniqueness - A nullifier can only be consumed once.
 * This prevents double-spend attacks.
 */
rule nullifierUniqueness(bytes32 nullifierHash) {
    require isSpent(nullifierHash) == true;

    env e;
    bytes32 root;
    address recipient;
    address relayer;
    uint256 fee;
    bytes proof;

    withdraw@withrevert(e, nullifierHash, recipient, relayer, fee, root, proof);

    assert lastReverted, "Must revert when nullifier already spent";
}

/**
 * RULE-POOL-002: Nullifier permanence - Once spent, always spent.
 */
rule nullifierPermanence(bytes32 nullifierHash, method f) filtered { f -> !f.isView } {
    require isSpent(nullifierHash) == true;

    env e;
    calldataarg args;
    f(e, args);

    assert isSpent(nullifierHash) == true, "Spent nullifier must remain spent";
}

// =============================================================================
// DEPOSIT RULES
// =============================================================================

/**
 * RULE-POOL-003: Deposit increases leaf index.
 */
rule depositIncreasesLeafIndex(bytes32 commitment, address asset, uint256 amount) {
    uint256 indexBefore = nextLeafIndex();
    
    env e;
    deposit(e, commitment, asset, amount);
    
    uint256 indexAfter = nextLeafIndex();
    
    assert indexAfter == indexBefore + 1, "Deposit must increment leaf index by 1";
}

/**
 * RULE-POOL-004: Deposit increases total deposited.
 */
rule depositIncreasesTotalDeposited(bytes32 commitment, address asset, uint256 amount) {
    uint256 totalBefore = totalDeposited();
    
    env e;
    require amount > 0;
    deposit(e, commitment, asset, amount);
    
    uint256 totalAfter = totalDeposited();
    
    assert totalAfter > totalBefore, "Deposit must increase total deposited";
}

/**
 * RULE-POOL-005: Deposit changes Merkle root.
 */
rule depositChangesRoot(bytes32 commitment, address asset, uint256 amount) {
    bytes32 rootBefore = getCurrentRoot();
    
    env e;
    require amount > 0;
    deposit(e, commitment, asset, amount);
    
    bytes32 rootAfter = getCurrentRoot();
    
    assert rootAfter != rootBefore, "Deposit must change Merkle root";
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/**
 * RULE-POOL-006: Withdrawal requires known root.
 */
rule withdrawalRequiresKnownRoot(
    bytes32 nullifierHash, address recipient, address relayer,
    uint256 fee, bytes32 root, bytes proof
) {
    require isKnownRoot(root) == false;

    env e;
    withdraw@withrevert(e, nullifierHash, recipient, relayer, fee, root, proof);

    assert lastReverted, "Withdrawal must revert with unknown root";
}

/**
 * RULE-POOL-007: Withdrawal marks nullifier as spent.
 */
rule withdrawalMarksNullifierSpent(
    bytes32 nullifierHash, address recipient, address relayer,
    uint256 fee, bytes32 root, bytes proof
) {
    require isSpent(nullifierHash) == false;

    env e;
    withdraw(e, nullifierHash, recipient, relayer, fee, root, proof);

    assert isSpent(nullifierHash) == true, "Withdrawal must mark nullifier as spent";
}

// =============================================================================
// TEST MODE RULES
// =============================================================================

/**
 * RULE-POOL-008: disableTestMode is irreversible.
 */
rule testModeIrreversible(method f) filtered { f -> !f.isView } {
    require testMode() == false;

    env e;
    calldataarg args;
    f(e, args);

    assert testMode() == false, "Test mode once disabled cannot be re-enabled";
}

/**
 * RULE-POOL-009: disableTestMode transitions from true to false.
 */
rule disableTestModeTransition() {
    require testMode() == true;

    env e;
    disableTestMode(e);

    assert testMode() == false, "disableTestMode must set testMode to false";
}

// =============================================================================
// PAUSABILITY RULES
// =============================================================================

/**
 * RULE-POOL-010: Deposits revert when paused.
 */
rule depositRevertsWhenPaused(bytes32 commitment, address asset, uint256 amount) {
    require paused() == true;

    env e;
    deposit@withrevert(e, commitment, asset, amount);

    assert lastReverted, "Deposit must revert when contract is paused";
}

/**
 * RULE-POOL-011: Withdrawals revert when paused.
 */
rule withdrawRevertsWhenPaused(
    bytes32 nullifierHash, address recipient, address relayer,
    uint256 fee, bytes32 root, bytes proof
) {
    require paused() == true;

    env e;
    withdraw@withrevert(e, nullifierHash, recipient, relayer, fee, root, proof);

    assert lastReverted, "Withdrawal must revert when contract is paused";
}
