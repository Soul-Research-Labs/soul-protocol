// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IRebalanceSwapAdapter
 * @author ZASEON
 * @notice Interface for DEX adapters used during settlement rebalancing
 *
 * @dev Settlement rebalancing may require swapping between tokens when vaults
 *      on different chains hold mismatched token inventories. For example:
 *        - Vault A has excess USDC after settlement
 *        - Vault A needs ETH to replenish LP availability
 *        - Adapter swaps USDC → ETH on Uniswap V3 before bridging
 *
 *      Any DEX (Uniswap, 1inch, SushiSwap) can be integrated by implementing
 *      this interface. The vault holds a configurable adapter reference.
 *
 *      SECURITY: The adapter is called by the vault with pre-approved tokens.
 *      Implementations MUST:
 *        - Return exact output amounts (no hidden fees)
 *        - Enforce slippage via minAmountOut
 *        - Not hold user funds between calls
 *        - Validate pool/path existence before executing
 */
interface IRebalanceSwapAdapter {
    // =========================================================================
    // ERRORS
    // =========================================================================

    /// @notice Swap output was below the minimum acceptable amount
    error SlippageExceeded(uint256 amountOut, uint256 minAmountOut);

    /// @notice The requested swap path is not supported or invalid
    error InvalidSwapPath(address tokenIn, address tokenOut);

    /// @notice The swap deadline has passed
    error SwapDeadlineExpired();

    // =========================================================================
    // EVENTS
    // =========================================================================

    /// @notice Emitted when a rebalance swap is executed
    event RebalanceSwapExecuted(
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        address indexed recipient
    );

    // =========================================================================
    // CORE FUNCTIONS
    // =========================================================================

    /**
     * @notice Execute a token swap for settlement rebalancing
     * @dev Caller must have approved this adapter to spend `amountIn` of `tokenIn`.
     *      The adapter transfers `tokenIn` from caller, executes the swap, and
     *      sends `tokenOut` to the specified `recipient`.
     * @param tokenIn Token to sell (address(0) for ETH)
     * @param tokenOut Token to buy (address(0) for ETH)
     * @param amountIn Exact amount of tokenIn to swap
     * @param minAmountOut Minimum acceptable output (slippage protection)
     * @param recipient Address to receive the swapped tokens
     * @param deadline Timestamp after which the swap reverts
     * @return amountOut Actual amount of tokenOut received
     */
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient,
        uint256 deadline
    ) external payable returns (uint256 amountOut);

    /**
     * @notice Get an estimated output amount for a swap (view-only quote)
     * @param tokenIn Token to sell (address(0) for ETH)
     * @param tokenOut Token to buy (address(0) for ETH)
     * @param amountIn Amount of tokenIn
     * @return estimatedOut Estimated amount of tokenOut
     */
    function getQuote(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external view returns (uint256 estimatedOut);

    /**
     * @notice Check if a swap path is supported
     * @param tokenIn Token to sell
     * @param tokenOut Token to buy
     * @return supported True if the adapter can execute this swap
     */
    function isSwapSupported(
        address tokenIn,
        address tokenOut
    ) external view returns (bool supported);
}
