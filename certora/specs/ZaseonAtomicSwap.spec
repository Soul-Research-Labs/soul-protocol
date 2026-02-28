/**
 * Certora Formal Verification Specification
 * ZASEON - ZaseonAtomicSwapV2
 */

methods {
    // View functions
    function protocolFeeBps() external returns (uint256) envfree;
    function MAX_FEE_BPS() external returns (uint256) envfree;
    function MIN_TIMELOCK() external returns (uint256) envfree;
    function MAX_TIMELOCK() external returns (uint256) envfree;
    function FEE_WITHDRAWAL_DELAY() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function owner() external returns (address) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-SWAP-001: Fee within bounds
 */
invariant feeBounded()
    protocolFeeBps() <= MAX_FEE_BPS();

/**
 * INV-SWAP-002: MAX_FEE_BPS is constant
 */
invariant maxFeeConstant()
    MAX_FEE_BPS() == 100;

/**
 * INV-SWAP-003: MIN_TIMELOCK less than MAX_TIMELOCK
 */
invariant timelockBoundsValid()
    MIN_TIMELOCK() < MAX_TIMELOCK();

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-SWAP-001: Protocol fee monotonicity bounds
 */
rule protocolFeeAlwaysBounded(method f) filtered { f -> !f.isView } {
    uint256 feeBefore = protocolFeeBps();
    require feeBefore <= MAX_FEE_BPS();
    
    env e;
    calldataarg args;
    f(e, args);
    
    uint256 feeAfter = protocolFeeBps();
    
    assert feeAfter <= MAX_FEE_BPS(), "Protocol fee must stay within bounds";
}
