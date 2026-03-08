// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IRebalanceSwapAdapter} from "../interfaces/IRebalanceSwapAdapter.sol";

// =========================================================================
// UNISWAP V3 MINIMAL INTERFACES
// =========================================================================

/// @dev Uniswap V3 SwapRouter exactInputSingle params
struct ExactInputSingleParams {
    address tokenIn;
    address tokenOut;
    uint24 fee;
    address recipient;
    uint256 deadline;
    uint256 amountIn;
    uint256 amountOutMinimum;
    uint160 sqrtPriceLimitX96;
}

/// @dev Minimal Uniswap V3 SwapRouter interface
interface ISwapRouter {
    function exactInputSingle(
        ExactInputSingleParams calldata params
    ) external payable returns (uint256 amountOut);
}

/// @dev Minimal Uniswap V3 Quoter interface
interface IQuoterV2 {
    function quoteExactInputSingle(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountIn,
        uint160 sqrtPriceLimitX96
    ) external returns (uint256 amountOut);
}

/// @dev Minimal Uniswap V3 Factory interface
interface IUniswapV3Factory {
    function getPool(
        address tokenA,
        address tokenB,
        uint24 fee
    ) external view returns (address pool);
}

/// @dev Minimal WETH interface
interface IWETH {
    function deposit() external payable;

    function withdraw(uint256) external;
}

/**
 * @title UniswapV3RebalanceAdapter
 * @author ZASEON
 * @notice Adapter for executing settlement rebalancing swaps via Uniswap V3 Router
 *
 * @dev Used by CrossChainLiquidityVault during settlement to swap between tokens
 *      when vault inventories are mismatched across chains.
 *
 *      EXAMPLE FLOW:
 *      1. Vault on Arbitrum has excess USDC from settlements, needs more ETH
 *      2. Settler calls executeSettlementWithSwap() on vault
 *      3. Vault approves this adapter, calls swap(USDC, WETH, amount, minOut)
 *      4. Adapter routes through Uniswap V3 with configured fee tier
 *      5. WETH returned to vault, increasing ETH liquidity for LPs
 *
 *      SECURITY:
 *      - Only whitelisted callers (the vault) can execute swaps
 *      - Slippage protection via minAmountOut
 *      - Deadline enforcement on all swaps
 *      - Fee tiers are configurable per token pair by OPERATOR
 *      - No token approvals persist between calls (exact-amount approve pattern)
 */
contract UniswapV3RebalanceAdapter is
    IRebalanceSwapAdapter,
    AccessControl,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @notice Maximum swap deadline extension from current time (1 hour)
    uint256 public constant MAX_DEADLINE_EXTENSION = 1 hours;

    /// @notice Default Uniswap V3 fee tier (0.3%)
    uint24 public constant DEFAULT_FEE_TIER = 3000;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Uniswap V3 SwapRouter address
    ISwapRouter public immutable swapRouter;

    /// @notice Uniswap V3 QuoterV2 address
    IQuoterV2 public immutable quoter;

    /// @notice Uniswap V3 Factory address
    IUniswapV3Factory public immutable factory;

    /// @notice WETH address for ETH<>token swaps
    IWETH public immutable weth;

    /// @notice Whitelisted callers (vault addresses)
    mapping(address => bool) public authorizedCallers;

    /// @notice Custom fee tier overrides per token pair: keccak256(tokenA, tokenB) => fee
    mapping(bytes32 => uint24) public feeTierOverrides;

    // =========================================================================
    // ERRORS
    // =========================================================================

    error UnauthorizedCaller();
    error ZeroAddress();
    error ZeroAmount();
    error ETHAmountMismatch(uint256 sent, uint256 expected);
    error ETHTransferFailed();

    // =========================================================================
    // EVENTS
    // =========================================================================

    event CallerAuthorized(address indexed caller, bool authorized);
    event FeeTierOverrideSet(
        address indexed tokenA,
        address indexed tokenB,
        uint24 feeTier
    );

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /**
     * @param _admin Admin address with DEFAULT_ADMIN_ROLE
     * @param _operator Operator for configuration
     * @param _swapRouter Uniswap V3 SwapRouter address
     * @param _quoter Uniswap V3 QuoterV2 address
     * @param _factory Uniswap V3 Factory address
     * @param _weth WETH contract address
     */
    constructor(
        address _admin,
        address _operator,
        address _swapRouter,
        address _quoter,
        address _factory,
        address _weth
    ) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_operator == address(0)) revert ZeroAddress();
        if (_swapRouter == address(0)) revert ZeroAddress();
        if (_quoter == address(0)) revert ZeroAddress();
        if (_factory == address(0)) revert ZeroAddress();
        if (_weth == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _operator);

        swapRouter = ISwapRouter(_swapRouter);
        quoter = IQuoterV2(_quoter);
        factory = IUniswapV3Factory(_factory);
        weth = IWETH(_weth);
    }

    // =========================================================================
    // CORE SWAP
    // =========================================================================

    /// @inheritdoc IRebalanceSwapAdapter
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient,
        uint256 deadline
    ) external payable override nonReentrant returns (uint256 amountOut) {
        if (!authorizedCallers[msg.sender]) revert UnauthorizedCaller();
        if (amountIn == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();
        if (block.timestamp > deadline) revert SwapDeadlineExpired();

        // Resolve ETH to WETH for Uniswap V3
        address actualTokenIn = tokenIn == address(0) ? address(weth) : tokenIn;
        address actualTokenOut = tokenOut == address(0)
            ? address(weth)
            : tokenOut;

        if (actualTokenIn == actualTokenOut)
            revert InvalidSwapPath(tokenIn, tokenOut);

        uint24 fee = _getFeeTier(actualTokenIn, actualTokenOut);

        // Handle ETH input: wrap to WETH
        if (tokenIn == address(0)) {
            if (msg.value != amountIn)
                revert ETHAmountMismatch(msg.value, amountIn);
            weth.deposit{value: amountIn}();
            // Approve router to spend WETH
            IERC20(address(weth)).forceApprove(address(swapRouter), amountIn);
        } else {
            // Pull tokens from caller
            IERC20(tokenIn).safeTransferFrom(
                msg.sender,
                address(this),
                amountIn
            );
            // Approve router — use forceApprove to reset to 0 first (safe pattern)
            IERC20(tokenIn).forceApprove(address(swapRouter), amountIn);
        }

        // Determine swap recipient: if output is ETH, send WETH to this contract first
        address swapRecipient = (tokenOut == address(0))
            ? address(this)
            : recipient;

        // Execute swap via Uniswap V3 exactInputSingle
        amountOut = swapRouter.exactInputSingle(
            ExactInputSingleParams({
                tokenIn: actualTokenIn,
                tokenOut: actualTokenOut,
                fee: fee,
                recipient: swapRecipient,
                deadline: deadline,
                amountIn: amountIn,
                amountOutMinimum: minAmountOut,
                sqrtPriceLimitX96: 0 // No price limit — rely on minAmountOut
            })
        );

        // Enforce our own slippage check (defense-in-depth, router also checks)
        if (amountOut < minAmountOut) {
            revert SlippageExceeded(amountOut, minAmountOut);
        }

        // Handle ETH output: unwrap WETH and forward
        if (tokenOut == address(0)) {
            weth.withdraw(amountOut);
            (bool sent, ) = recipient.call{value: amountOut}("");
            if (!sent) revert ETHTransferFailed();
        }

        // Reset approval to 0 (safety — forceApprove already handles this)
        if (tokenIn != address(0)) {
            IERC20(tokenIn).forceApprove(address(swapRouter), 0);
        } else {
            IERC20(address(weth)).forceApprove(address(swapRouter), 0);
        }

        emit RebalanceSwapExecuted(
            tokenIn,
            tokenOut,
            amountIn,
            amountOut,
            recipient
        );
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc IRebalanceSwapAdapter
    function getQuote(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external view override returns (uint256 estimatedOut) {
        // NOTE: QuoterV2.quoteExactInputSingle is not a view function in practice
        // (it simulates the swap). For on-chain view usage, we check pool existence
        // and return 0 if unsupported — callers should use off-chain quoting.
        address actualIn = tokenIn == address(0) ? address(weth) : tokenIn;
        address actualOut = tokenOut == address(0) ? address(weth) : tokenOut;

        uint24 fee = _getFeeTier(actualIn, actualOut);
        address pool = factory.getPool(actualIn, actualOut, fee);
        if (pool == address(0)) return 0;

        // Return amountIn as rough estimate — callers should use off-chain quote
        // for accurate pricing. On-chain quoting via QuoterV2 requires a call, not staticcall.
        return amountIn;
    }

    /// @inheritdoc IRebalanceSwapAdapter
    function isSwapSupported(
        address tokenIn,
        address tokenOut
    ) external view override returns (bool supported) {
        address actualIn = tokenIn == address(0) ? address(weth) : tokenIn;
        address actualOut = tokenOut == address(0) ? address(weth) : tokenOut;

        if (actualIn == actualOut) return false;

        uint24 fee = _getFeeTier(actualIn, actualOut);
        address pool = factory.getPool(actualIn, actualOut, fee);
        return pool != address(0);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /**
     * @notice Authorize or revoke a caller (vault) for swap execution
     * @param caller Address to authorize/revoke
     * @param authorized Whether to authorize
     */
    function setAuthorizedCaller(
        address caller,
        bool authorized
    ) external onlyRole(OPERATOR_ROLE) {
        if (caller == address(0)) revert ZeroAddress();
        authorizedCallers[caller] = authorized;
        emit CallerAuthorized(caller, authorized);
    }

    /**
     * @notice Set a custom fee tier for a specific token pair
     * @dev Use this to route through optimal pools (e.g., 500 for stablecoin pairs,
     *      10000 for exotic pairs). Order-independent (sorted internally).
     * @param tokenA First token
     * @param tokenB Second token
     * @param feeTier Uniswap V3 fee tier (100, 500, 3000, 10000)
     */
    function setFeeTierOverride(
        address tokenA,
        address tokenB,
        uint24 feeTier
    ) external onlyRole(OPERATOR_ROLE) {
        if (tokenA == address(0) || tokenB == address(0)) revert ZeroAddress();
        bytes32 key = _pairKey(tokenA, tokenB);
        feeTierOverrides[key] = feeTier;
        emit FeeTierOverrideSet(tokenA, tokenB, feeTier);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    /**
     * @dev Get the fee tier for a token pair, using override if set, else default
     */
    function _getFeeTier(
        address tokenA,
        address tokenB
    ) internal view returns (uint24) {
        bytes32 key = _pairKey(tokenA, tokenB);
        uint24 override_ = feeTierOverrides[key];
        return override_ != 0 ? override_ : DEFAULT_FEE_TIER;
    }

    /**
     * @dev Generate a canonical key for a token pair (order-independent)
     */
    function _pairKey(
        address tokenA,
        address tokenB
    ) internal pure returns (bytes32) {
        (address t0, address t1) = tokenA < tokenB
            ? (tokenA, tokenB)
            : (tokenB, tokenA);
        return keccak256(abi.encodePacked(t0, t1));
    }

    // =========================================================================
    // RECEIVE
    // =========================================================================

    /// @notice Accept ETH from WETH unwrapping
    receive() external payable {}
}
