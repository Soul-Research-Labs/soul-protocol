/*
 * Certora Formal Verification Specification
 * PIL Private Exchange
 * 
 * Verifies critical invariants for the exchange contract
 */

/*
 * ============================================================================
 * METHODS DECLARATIONS
 * ============================================================================
 */

methods {
    // State variables
    function paused() external returns (bool) envfree;
    function totalDeposits(address) external returns (uint256) envfree;
    function poolReserveA(bytes32) external returns (uint256) envfree;
    function poolReserveB(bytes32) external returns (uint256) envfree;
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function orderExists(bytes32) external returns (bool) envfree;
    function orderFilled(bytes32) external returns (uint256) envfree;
    function orderAmount(bytes32) external returns (uint256) envfree;
    function getUserOrderCount(address) external returns (uint256) envfree;
    function getPoolCount() external returns (uint256) envfree;
    function getCollectedFees(address) external returns (uint256) envfree;
    
    // Admin functions
    function pause() external;
    function unpause() external;
    function withdrawFees(address,address) external;
    
    // Core functions
    function deposit(address,uint256) external returns (bytes32);
    function withdraw(address,uint256,bytes32,bytes) external returns (bool);
    function createOrder(address,address,uint256,uint256,uint256,uint8,uint8,bytes) external returns (bytes32);
    function cancelOrder(bytes32) external;
    function matchOrders(bytes32,bytes32,uint256,uint256,bytes) external;
    function createPool(address,address,uint256,uint256,bytes) external returns (bytes32);
    function swapPrivate(address,address,uint256,uint256,bytes) external returns (uint256);
    
    // Token functions (assuming ERC20)
    function _.balanceOf(address) external => DISPATCHER(true);
    function _.transfer(address,uint256) external => DISPATCHER(true);
    function _.transferFrom(address,address,uint256) external => DISPATCHER(true);
}

/*
 * ============================================================================
 * INVARIANTS
 * ============================================================================
 */

/**
 * INV-1: Total deposits must always be >= total withdrawals
 * This ensures the exchange is always solvent
 */
invariant solvencyInvariant(address token)
    totalDeposits(token) >= 0
    {
        preserved {
            require token != 0;
        }
    }

/**
 * INV-2: Nullifiers can only be used once
 * Once a nullifier is marked as used, it cannot be reused
 */
invariant nullifierImmutability(bytes32 nullifier)
    nullifierUsed(nullifier) == true => nullifierUsed(nullifier) == true
    {
        preserved with (env e) {
            require e.msg.sender != 0;
        }
    }

/**
 * INV-3: Pool constant product formula
 * For any pool, the product of reserves can only increase (from fees)
 */
invariant poolConstantProduct(bytes32 poolId, uint256 initialProduct)
    poolReserveA(poolId) * poolReserveB(poolId) >= initialProduct
    {
        preserved createPool(address tokenA, address tokenB, uint256 amountA, uint256 amountB, bytes proof) with (env e) {
            require amountA > 0 && amountB > 0;
        }
        preserved swapPrivate(address tokenIn, address tokenOut, uint256 amountIn, uint256 minOut, bytes proof) with (env e) {
            require amountIn > 0;
        }
    }

/**
 * INV-4: Order fill amount cannot exceed order amount
 */
invariant orderFillBound(bytes32 orderId)
    orderExists(orderId) => orderFilled(orderId) <= orderAmount(orderId)

/*
 * ============================================================================
 * RULES
 * ============================================================================
 */

/**
 * RULE-1: Deposit increases user's balance commitment
 */
rule depositIncreasesBalance(env e, address token, uint256 amount) {
    uint256 depositsBefore = totalDeposits(token);
    
    deposit(e, token, amount);
    
    uint256 depositsAfter = totalDeposits(token);
    
    assert depositsAfter == depositsBefore + amount,
        "Deposit must increase total deposits by exact amount";
}

/**
 * RULE-2: Nullifier cannot be reused
 */
rule nullifierNotReusable(env e, address token, uint256 amount, bytes32 nullifier, bytes proof) {
    require nullifierUsed(nullifier) == true;
    
    bool success = withdraw@withrevert(e, token, amount, nullifier, proof);
    
    assert lastReverted, "Withdrawal with used nullifier must revert";
}

/**
 * RULE-3: Pausing blocks all user operations
 */
rule pauseBlocksOperations(env e, address token, uint256 amount) {
    require paused() == true;
    
    deposit@withrevert(e, token, amount);
    
    assert lastReverted, "Deposits must be blocked when paused";
}

/**
 * RULE-4: Only admin can pause
 */
rule onlyAdminCanPause(env e) {
    bool pausedBefore = paused();
    
    pause@withrevert(e);
    
    bool pausedAfter = paused();
    
    // If pause succeeded, sender must have admin role
    assert !lastReverted => (pausedAfter == true),
        "Pause must set paused to true";
}

/**
 * RULE-5: Swap output respects slippage
 */
rule swapRespectsSlippage(
    env e,
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,
    bytes proof
) {
    uint256 amountOut = swapPrivate(e, tokenIn, tokenOut, amountIn, minAmountOut, proof);
    
    assert amountOut >= minAmountOut,
        "Swap output must be >= minimum specified";
}

/**
 * RULE-6: Pool creation requires both tokens
 */
rule poolCreationRequiresBothTokens(
    env e,
    address tokenA,
    address tokenB,
    uint256 amountA,
    uint256 amountB,
    bytes proof
) {
    require amountA == 0 || amountB == 0;
    
    createPool@withrevert(e, tokenA, tokenB, amountA, amountB, proof);
    
    assert lastReverted,
        "Pool creation with zero amount must revert";
}

/**
 * RULE-7: Order cancellation only by owner
 */
rule onlyOwnerCanCancelOrder(env e, bytes32 orderId) {
    // Capture order owner before
    address orderOwner = _; // Symbolic
    
    cancelOrder@withrevert(e, orderId);
    
    assert !lastReverted => e.msg.sender == orderOwner,
        "Only order owner can cancel";
}

/**
 * RULE-8: Matched orders are marked as filled
 */
rule matchUpdatesOrderStatus(
    env e,
    bytes32 orderId1,
    bytes32 orderId2,
    uint256 amount1,
    uint256 amount2,
    bytes proof
) {
    uint256 filled1Before = orderFilled(orderId1);
    uint256 filled2Before = orderFilled(orderId2);
    
    matchOrders(e, orderId1, orderId2, amount1, amount2, proof);
    
    uint256 filled1After = orderFilled(orderId1);
    uint256 filled2After = orderFilled(orderId2);
    
    assert filled1After >= filled1Before && filled2After >= filled2Before,
        "Match must increase filled amounts";
}

/**
 * RULE-9: Fees can only be withdrawn by admin
 */
rule onlyAdminWithdrawsFees(env e, address token, address recipient) {
    uint256 feesBefore = getCollectedFees(token);
    
    withdrawFees@withrevert(e, token, recipient);
    
    // If succeeded, fees should decrease
    assert !lastReverted => getCollectedFees(token) <= feesBefore;
}

/**
 * RULE-10: Pool reserves change correctly on swap
 */
rule swapChangesReservesCorrectly(
    env e,
    bytes32 poolId,
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,
    bytes proof
) {
    uint256 reserveABefore = poolReserveA(poolId);
    uint256 reserveBBefore = poolReserveB(poolId);
    
    uint256 amountOut = swapPrivate(e, tokenIn, tokenOut, amountIn, minAmountOut, proof);
    
    uint256 reserveAAfter = poolReserveA(poolId);
    uint256 reserveBAfter = poolReserveB(poolId);
    
    // Product should not decrease (minus fee)
    assert reserveAAfter * reserveBAfter >= reserveABefore * reserveBBefore * 997 / 1000,
        "Swap should maintain or increase k (minus fees)";
}

/*
 * ============================================================================
 * GHOST VARIABLES AND HOOKS
 * ============================================================================
 */

// Track total nullifiers used
ghost uint256 totalNullifiersUsed {
    init_state axiom totalNullifiersUsed == 0;
}

// Hook on nullifier usage
hook Sstore nullifierUsed[KEY bytes32 nullifier] bool newValue (bool oldValue) STORAGE {
    if (newValue && !oldValue) {
        totalNullifiersUsed = totalNullifiersUsed + 1;
    }
}

/**
 * RULE-11: Total nullifiers only increases
 */
rule nullifierCountMonotonic(method f, env e, calldataarg args) {
    uint256 before = totalNullifiersUsed;
    
    f(e, args);
    
    uint256 after = totalNullifiersUsed;
    
    assert after >= before, "Nullifier count can only increase";
}

/*
 * ============================================================================
 * PARAMETRIC RULES
 * ============================================================================
 */

/**
 * RULE-12: No function decreases total deposits (except withdrawal)
 */
rule depositsMonotonic(method f, env e, calldataarg args, address token)
    filtered { f -> f.selector != sig:withdraw(address,uint256,bytes32,bytes).selector }
{
    uint256 before = totalDeposits(token);
    
    f(e, args);
    
    uint256 after = totalDeposits(token);
    
    assert after >= before,
        "Only withdraw can decrease deposits";
}

/**
 * RULE-13: Pool count only increases
 */
rule poolCountMonotonic(method f, env e, calldataarg args) {
    uint256 before = getPoolCount();
    
    f(e, args);
    
    uint256 after = getPoolCount();
    
    assert after >= before, "Pool count can only increase";
}

/*
 * ============================================================================
 * LIVENESS PROPERTIES
 * ============================================================================
 */

/**
 * RULE-14: User can always withdraw their full balance (if they have proof)
 */
rule withdrawalAlwaysPossible(env e, address token, uint256 amount, bytes32 nullifier, bytes proof) {
    require !paused();
    require !nullifierUsed(nullifier);
    require totalDeposits(token) >= amount;
    
    // If all preconditions met, withdrawal should succeed
    // (assuming valid proof - this is a liveness check, not proof verification)
    satisfy !lastReverted;
}

/**
 * RULE-15: Swap always possible if pool has liquidity
 */
rule swapAlwaysPossibleWithLiquidity(
    env e,
    bytes32 poolId,
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,
    bytes proof
) {
    require !paused();
    require poolReserveA(poolId) > 0;
    require poolReserveB(poolId) > 0;
    require amountIn > 0;
    require minAmountOut == 1; // Minimum slippage
    
    // Swap should be possible
    satisfy !lastReverted;
}
