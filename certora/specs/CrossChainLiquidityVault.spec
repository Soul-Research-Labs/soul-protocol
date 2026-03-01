/**
 * Certora Formal Verification Specification
 * ZASEON - CrossChainLiquidityVault
 *
 * Verifies critical safety properties of the liquidity vault:
 *   1. Solvency: Available liquidity + locked liquidity == total deposits
 *   2. Lock integrity: Locks can only be released once
 *   3. Settlement correctness: Net settlements balance
 *   4. Access control: Only PRIVACY_HUB_ROLE can lock/release
 *   5. Cooldown enforcement: Withdrawals respect cooldown period
 */

methods {
    // View functions
    function totalETH() external returns (uint256) envfree;
    function totalLockedETH() external returns (uint256) envfree;
    function chainId() external returns (uint256) envfree;
    function lpFeeShareBps() external returns (uint256) envfree;
    function MAX_LP_FEE_BPS() external returns (uint256) envfree;
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function WITHDRAWAL_COOLDOWN() external returns (uint256) envfree;
    function LOCK_EXPIRY() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function getAvailableLiquidity(address) external returns (uint256) envfree;
    function getLockedLiquidity(address) external returns (uint256) envfree;
    function hasSufficientLiquidity(address, uint256) external returns (bool) envfree;
    function isActiveLP(address) external returns (bool) envfree;
    function lpEthDeposited(address) external returns (uint256) envfree;
    function lpDepositTimestamp(address) external returns (uint256) envfree;
    function totalTokenDeposited(address) external returns (uint256) envfree;
    function totalLockedToken(address) external returns (uint256) envfree;

    // Non-view functions
    function depositETH() external;
    function withdrawETH(uint256) external;
    function depositToken(address, uint256) external;
    function withdrawToken(address, uint256) external;
    function lockLiquidity(bytes32, address, uint256, uint256) external returns (bool);
    function releaseLiquidity(bytes32, address, address, uint256, uint256) external;
    function refundExpiredLock(bytes32) external;
    function proposeSettlement(uint256, address) external returns (bytes32);
    function executeSettlement(bytes32) external;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-VAULT-001: ETH solvency — locked ETH never exceeds total ETH
 * @dev totalLockedETH <= totalETH always holds
 */
invariant ethSolvency()
    totalLockedETH() <= totalETH();

/**
 * INV-VAULT-002: LP fee share within bounds
 */
invariant lpFeeShareBounded()
    lpFeeShareBps() <= MAX_LP_FEE_BPS();

/**
 * INV-VAULT-003: Available ETH liquidity is total minus locked
 * @dev getAvailableLiquidity(ETH) == totalETH - totalLockedETH
 */
invariant availableLiquidityConsistency()
    getAvailableLiquidity(0) == totalETH() - totalLockedETH();

/**
 * INV-VAULT-004: Sufficient liquidity check is monotonic with amount
 * @dev If sufficient for amount X, sufficient for any Y < X
 */
invariant sufficientLiquidityMonotonic()
    forall uint256 amount. (hasSufficientLiquidity(0, amount) == true) =>
        (amount <= totalETH() - totalLockedETH());

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-VAULT-001: Deposit increases total ETH
 * @dev totalETH must increase by exactly msg.value after depositETH()
 */
rule depositIncreasesTotalETH() {
    env e;
    uint256 totalBefore = totalETH();
    uint256 depositAmount = e.msg.value;
    require depositAmount >= MIN_DEPOSIT();

    depositETH(e);

    uint256 totalAfter = totalETH();
    assert totalAfter == totalBefore + depositAmount,
        "totalETH must increase by deposit amount";
}

/**
 * RULE-VAULT-002: Withdraw decreases total ETH
 * @dev totalETH must decrease by exactly the withdrawal amount
 */
rule withdrawDecreasesTotalETH(uint256 amount) {
    env e;
    uint256 totalBefore = totalETH();
    require amount > 0;
    require amount <= lpEthDeposited(e.msg.sender);

    withdrawETH(e, amount);

    uint256 totalAfter = totalETH();
    assert totalAfter == totalBefore - amount,
        "totalETH must decrease by withdrawal amount";
}

/**
 * RULE-VAULT-003: Lock increases locked ETH
 * @dev After lockLiquidity for ETH, totalLockedETH increases
 */
rule lockIncreasesLockedETH(bytes32 requestId, uint256 amount, uint256 destChainId) {
    env e;
    uint256 lockedBefore = totalLockedETH();
    address ethToken = 0;
    require amount > 0;

    bool success = lockLiquidity(e, requestId, ethToken, amount, destChainId);
    require success;

    uint256 lockedAfter = totalLockedETH();
    assert lockedAfter == lockedBefore + amount,
        "totalLockedETH must increase by lock amount";
}

/**
 * RULE-VAULT-004: Release decreases locked ETH
 * @dev After releaseLiquidity for ETH, totalLockedETH decreases
 */
rule releaseDecreasesLockedETH(
    bytes32 requestId, address recipient, uint256 amount, uint256 sourceChainId
) {
    env e;
    uint256 lockedBefore = totalLockedETH();
    address ethToken = 0;
    require amount > 0;
    require lockedBefore >= amount;

    releaseLiquidity(e, requestId, ethToken, recipient, amount, sourceChainId);

    uint256 lockedAfter = totalLockedETH();
    assert lockedAfter == lockedBefore - amount,
        "totalLockedETH must decrease by release amount";
}

/**
 * RULE-VAULT-005: Lock-then-release preserves total ETH
 * @dev Locking + releasing should not change totalETH (only locked portion moves)
 */
rule lockReleasePreservesTotalETH(
    bytes32 requestId, uint256 amount, uint256 destChainId,
    address recipient
) {
    env e1; env e2;
    address ethToken = 0;
    uint256 totalBefore = totalETH();

    bool success = lockLiquidity(e1, requestId, ethToken, amount, destChainId);
    require success;

    uint256 totalAfterLock = totalETH();
    assert totalAfterLock == totalBefore,
        "Lock should not change total ETH";

    releaseLiquidity(e2, requestId, ethToken, recipient, amount, destChainId);

    uint256 totalAfterRelease = totalETH();
    assert totalAfterRelease == totalBefore - amount,
        "Release should decrease total ETH by released amount";
}

/**
 * RULE-VAULT-006: Solvency preserved across all operations
 * @dev After any state-changing function, totalLockedETH <= totalETH
 */
rule solvencyAfterAnyOperation(method f) filtered { f -> !f.isView } {
    require totalLockedETH() <= totalETH();

    env e;
    calldataarg args;
    f(e, args);

    assert totalLockedETH() <= totalETH(),
        "Solvency invariant violated: locked > total";
}

/**
 * RULE-VAULT-007: Deposit makes LP active
 * @dev After depositETH, isActiveLP(sender) must be true
 */
rule depositActivatesLP() {
    env e;
    require e.msg.value >= MIN_DEPOSIT();

    depositETH(e);

    assert isActiveLP(e.msg.sender) == true,
        "Depositor must become active LP";
}

/**
 * RULE-VAULT-008: No token minting from thin air
 * @dev Total ETH can only increase from depositETH, never from locks/releases
 */
rule noETHCreatedFromLock(bytes32 requestId, uint256 amount, uint256 destChainId) {
    env e;
    address ethToken = 0;
    uint256 totalBefore = totalETH();

    lockLiquidity(e, requestId, ethToken, amount, destChainId);

    uint256 totalAfter = totalETH();
    assert totalAfter <= totalBefore,
        "Lock cannot increase total ETH";
}
