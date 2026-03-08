// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IRebalanceSwapAdapter} from "../interfaces/IRebalanceSwapAdapter.sol";

/**
 * @title MockRebalanceSwapAdapter
 * @notice Test mock for IRebalanceSwapAdapter — simulates DEX swaps at a configurable rate
 * @dev Mints output tokens (via MockERC20) or transfers ETH at a fixed exchange rate.
 *      Used in Foundry tests for CrossChainLiquidityVault settlement-with-swap flows.
 */
contract MockRebalanceSwapAdapter is IRebalanceSwapAdapter {
    using SafeERC20 for IERC20;

    /// @notice Exchange rate in basis points (10000 = 1:1, 9500 = 5% slippage)
    uint256 public exchangeRateBps;

    /// @notice If true, the next swap will revert (for testing failure paths)
    bool public shouldRevert;

    /// @notice Track swap calls for test assertions
    uint256 public swapCallCount;

    constructor(uint256 _exchangeRateBps) {
        exchangeRateBps = _exchangeRateBps;
    }

    function setExchangeRate(uint256 _rateBps) external {
        exchangeRateBps = _rateBps;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient,
        uint256 deadline
    ) external payable override returns (uint256 amountOut) {
        require(!shouldRevert, "MockSwap: forced revert");
        if (block.timestamp > deadline) revert SwapDeadlineExpired();

        amountOut = (amountIn * exchangeRateBps) / 10000;

        if (amountOut < minAmountOut) {
            revert SlippageExceeded(amountOut, minAmountOut);
        }

        // Handle input
        if (tokenIn == address(0)) {
            require(msg.value == amountIn, "ETH mismatch");
        } else {
            IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        }

        // Handle output
        if (tokenOut == address(0)) {
            (bool sent, ) = recipient.call{value: amountOut}("");
            require(sent, "ETH send failed");
        } else {
            IERC20(tokenOut).safeTransfer(recipient, amountOut);
        }

        swapCallCount++;

        emit RebalanceSwapExecuted(tokenIn, tokenOut, amountIn, amountOut, recipient);
    }

    function getQuote(
        address,
        address,
        uint256 amountIn
    ) external view override returns (uint256) {
        return (amountIn * exchangeRateBps) / 10000;
    }

    function isSwapSupported(
        address tokenIn,
        address tokenOut
    ) external pure override returns (bool) {
        return tokenIn != tokenOut;
    }

    /// @notice Accept ETH for swap outputs
    receive() external payable {}
}
