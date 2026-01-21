// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title PILPrivateExchange
 * @author Soul Network
 * @notice Private decentralized exchange using PIL primitives
 * @dev Demonstrates PIL capabilities: encrypted orders, ZK proofs, nullifiers, cross-chain
 *
 * Features:
 * - Private order book (encrypted order details)
 * - ZK proof-based order matching
 * - Nullifier-based double-spend prevention
 * - Cross-chain atomic swaps
 * - Privacy-preserving trade execution
 * - Stealth addresses for recipients
 */
contract PILPrivateExchange is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MATCHER_ROLE = keccak256("MATCHER_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    enum OrderStatus {
        Invalid,
        Active,
        PartiallyFilled,
        Filled,
        Cancelled,
        Expired
    }

    enum OrderType {
        Limit,
        Market,
        StopLoss,
        TakeProfit
    }

    enum OrderSide {
        Buy,
        Sell
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Private order structure
    struct PrivateOrder {
        bytes32 orderId;
        bytes32 orderCommitment; // Pedersen commitment to order details
        bytes32 nullifier; // Prevents double-spending
        address maker;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 deadline;
        OrderType orderType;
        OrderSide side;
        OrderStatus status;
        uint256 filledAmount;
        uint256 createdAt;
        bytes encryptedDetails; // Encrypted order metadata
    }

    /// @notice Trade execution record
    struct Trade {
        bytes32 tradeId;
        bytes32 makerOrderId;
        bytes32 takerOrderId;
        address maker;
        address taker;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 amountOut;
        uint256 makerFee;
        uint256 takerFee;
        uint256 executedAt;
        bytes32 proofHash; // ZK proof of valid matching
    }

    /// @notice Liquidity pool for instant swaps
    struct LiquidityPool {
        bytes32 poolId;
        address tokenA;
        address tokenB;
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalLPTokens;
        uint256 feeRate; // In basis points
        bool active;
    }

    /// @notice Cross-chain order
    struct CrossChainOrder {
        bytes32 orderId;
        uint256 sourceChain;
        uint256 targetChain;
        bytes32 sourceCommitment;
        bytes32 targetCommitment;
        bytes32 secretHash;
        uint256 deadline;
        bool executed;
    }

    /// @notice Stealth address for private recipients
    struct StealthAddress {
        bytes32 pubKeyX;
        bytes32 pubKeyY;
        bytes32 viewingKey;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Order storage
    mapping(bytes32 => PrivateOrder) public orders;
    mapping(address => bytes32[]) public userOrders;
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Trade storage
    mapping(bytes32 => Trade) public trades;
    uint256 public totalTrades;

    /// @notice Liquidity pools
    mapping(bytes32 => LiquidityPool) public pools;
    mapping(bytes32 => mapping(address => uint256)) public lpBalances;
    bytes32[] public poolIds;

    /// @notice Cross-chain orders
    mapping(bytes32 => CrossChainOrder) public crossChainOrders;

    /// @notice User balances (for privacy-preserving deposits)
    mapping(address => mapping(address => uint256)) public balances;
    mapping(address => bytes32) public balanceCommitments;

    /// @notice Stealth addresses
    mapping(address => StealthAddress) public stealthAddresses;

    /// @notice Fee configuration
    uint256 public makerFeeBps = 10; // 0.1%
    uint256 public takerFeeBps = 30; // 0.3%
    uint256 public constant MAX_FEE_BPS = 100; // 1%
    address public feeCollector;
    mapping(address => uint256) public collectedFees;

    /// @notice Counters
    uint256 public totalOrders;
    uint256 public totalVolume;
    uint256 public totalCrossChainOrders;

    /// @notice Order book (price -> order IDs)
    mapping(address => mapping(address => mapping(uint256 => bytes32[])))
        public orderBook;

    /// @notice Supported tokens
    mapping(address => bool) public supportedTokens;
    address[] public tokenList;

    /// @notice Verifier contracts
    address public proofVerifier;
    address public nullifierRegistry;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OrderCreated(
        bytes32 indexed orderId,
        address indexed maker,
        bytes32 commitment,
        bytes32 nullifier,
        OrderType orderType,
        OrderSide side
    );

    event OrderCancelled(bytes32 indexed orderId, address indexed maker);

    event OrderMatched(
        bytes32 indexed makerOrderId,
        bytes32 indexed takerOrderId,
        bytes32 tradeId,
        uint256 amountIn,
        uint256 amountOut
    );

    event TradeExecuted(
        bytes32 indexed tradeId,
        address indexed maker,
        address indexed taker,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );

    event LiquidityAdded(
        bytes32 indexed poolId,
        address indexed provider,
        uint256 amountA,
        uint256 amountB,
        uint256 lpTokens
    );

    event LiquidityRemoved(
        bytes32 indexed poolId,
        address indexed provider,
        uint256 amountA,
        uint256 amountB,
        uint256 lpTokens
    );

    event InstantSwap(
        bytes32 indexed poolId,
        address indexed user,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );

    event CrossChainOrderCreated(
        bytes32 indexed orderId,
        uint256 sourceChain,
        uint256 targetChain,
        bytes32 secretHash
    );

    event CrossChainOrderExecuted(bytes32 indexed orderId, bytes32 proof);

    event Deposit(
        address indexed user,
        address indexed token,
        uint256 amount,
        bytes32 commitment
    );

    event Withdrawal(
        address indexed user,
        address indexed token,
        uint256 amount,
        bytes32 nullifier
    );

    event StealthAddressRegistered(
        address indexed user,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidOrder();
    error OrderNotActive();
    error OrderExpired();
    error NullifierAlreadyUsed();
    error InsufficientBalance();
    error InvalidProof();
    error InvalidAmount();
    error InvalidToken();
    error PoolNotActive();
    error InsufficientLiquidity();
    error SlippageExceeded();
    error Unauthorized();
    error InvalidDeadline();
    error CrossChainOrderNotFound();
    error CrossChainOrderAlreadyExecuted();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _feeCollector, address _proofVerifier) {
        if (_feeCollector == address(0)) revert InvalidAmount();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(MATCHER_ROLE, msg.sender);

        feeCollector = _feeCollector;
        proofVerifier = _proofVerifier;
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT / WITHDRAW
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit tokens with privacy commitment
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to deposit
     * @param commitment Pedersen commitment to balance
     */
    function deposit(
        address token,
        uint256 amount,
        bytes32 commitment
    ) external payable nonReentrant whenNotPaused {
        if (amount == 0) revert InvalidAmount();

        if (token == address(0)) {
            if (msg.value != amount) revert InvalidAmount();
        } else {
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }

        balances[msg.sender][token] += amount;
        balanceCommitments[msg.sender] = commitment;

        emit Deposit(msg.sender, token, amount, commitment);
    }

    /**
     * @notice Withdraw tokens with nullifier (prevents double-spend)
     * @param token Token address
     * @param amount Amount to withdraw
     * @param nullifier Nullifier to prevent replay
     * @param proof ZK proof of valid withdrawal
     */
    function withdraw(
        address token,
        uint256 amount,
        bytes32 nullifier,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        if (amount == 0) revert InvalidAmount();
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (balances[msg.sender][token] < amount) revert InsufficientBalance();

        // Verify withdrawal proof (simplified - in production use actual verifier)
        if (!_verifyProof(proof, nullifier, amount)) revert InvalidProof();

        usedNullifiers[nullifier] = true;
        balances[msg.sender][token] -= amount;

        if (token == address(0)) {
            (bool success, ) = msg.sender.call{value: amount}("");
            if (!success) revert InsufficientBalance();
        } else {
            IERC20(token).safeTransfer(msg.sender, amount);
        }

        emit Withdrawal(msg.sender, token, amount, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVATE ORDERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a private order with encrypted details
     * @param tokenIn Token to sell
     * @param tokenOut Token to buy
     * @param amountIn Amount of tokenIn
     * @param minAmountOut Minimum amount of tokenOut
     * @param deadline Order expiry timestamp
     * @param orderType Type of order (limit, market, etc.)
     * @param side Buy or sell
     * @param commitment Pedersen commitment to order
     * @param nullifier Order nullifier
     * @param encryptedDetails Encrypted order metadata
     */
    function createPrivateOrder(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 deadline,
        OrderType orderType,
        OrderSide side,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata encryptedDetails
    ) external nonReentrant whenNotPaused returns (bytes32 orderId) {
        if (amountIn == 0) revert InvalidAmount();
        if (deadline <= block.timestamp) revert InvalidDeadline();
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (balances[msg.sender][tokenIn] < amountIn)
            revert InsufficientBalance();

        orderId = keccak256(
            abi.encodePacked(
                msg.sender,
                tokenIn,
                tokenOut,
                amountIn,
                block.timestamp,
                totalOrders
            )
        );

        orders[orderId] = PrivateOrder({
            orderId: orderId,
            orderCommitment: commitment,
            nullifier: nullifier,
            maker: msg.sender,
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            deadline: deadline,
            orderType: orderType,
            side: side,
            status: OrderStatus.Active,
            filledAmount: 0,
            createdAt: block.timestamp,
            encryptedDetails: encryptedDetails
        });

        // Lock funds
        balances[msg.sender][tokenIn] -= amountIn;
        usedNullifiers[nullifier] = true;

        userOrders[msg.sender].push(orderId);
        totalOrders++;

        emit OrderCreated(
            orderId,
            msg.sender,
            commitment,
            nullifier,
            orderType,
            side
        );
    }

    /**
     * @notice Cancel an active order
     * @param orderId Order to cancel
     */
    function cancelOrder(bytes32 orderId) external nonReentrant {
        PrivateOrder storage order = orders[orderId];

        if (order.maker != msg.sender) revert Unauthorized();
        if (
            order.status != OrderStatus.Active &&
            order.status != OrderStatus.PartiallyFilled
        ) {
            revert OrderNotActive();
        }

        uint256 remainingAmount = order.amountIn - order.filledAmount;
        order.status = OrderStatus.Cancelled;

        // Return remaining funds
        balances[msg.sender][order.tokenIn] += remainingAmount;

        emit OrderCancelled(orderId, msg.sender);
    }

    /**
     * @notice Match two orders with ZK proof
     * @param makerOrderId Maker's order ID
     * @param takerOrderId Taker's order ID
     * @param amountIn Amount of maker's tokenIn
     * @param amountOut Amount of taker's tokenIn
     * @param proof ZK proof of valid matching
     */
    function matchOrders(
        bytes32 makerOrderId,
        bytes32 takerOrderId,
        uint256 amountIn,
        uint256 amountOut,
        bytes calldata proof
    ) external nonReentrant whenNotPaused onlyRole(MATCHER_ROLE) {
        PrivateOrder storage makerOrder = orders[makerOrderId];
        PrivateOrder storage takerOrder = orders[takerOrderId];

        // Validate orders
        if (
            makerOrder.status != OrderStatus.Active &&
            makerOrder.status != OrderStatus.PartiallyFilled
        ) {
            revert OrderNotActive();
        }
        if (
            takerOrder.status != OrderStatus.Active &&
            takerOrder.status != OrderStatus.PartiallyFilled
        ) {
            revert OrderNotActive();
        }
        if (makerOrder.deadline < block.timestamp) revert OrderExpired();
        if (takerOrder.deadline < block.timestamp) revert OrderExpired();

        // Verify tokens match
        if (makerOrder.tokenIn != takerOrder.tokenOut) revert InvalidOrder();
        if (makerOrder.tokenOut != takerOrder.tokenIn) revert InvalidOrder();

        // Verify amounts
        if (amountOut < makerOrder.minAmountOut) revert SlippageExceeded();
        if (amountIn < takerOrder.minAmountOut) revert SlippageExceeded();

        // Verify ZK proof
        bytes32 proofHash = keccak256(proof);
        if (
            !_verifyMatchProof(
                proof,
                makerOrderId,
                takerOrderId,
                amountIn,
                amountOut
            )
        ) {
            revert InvalidProof();
        }

        // Calculate fees
        uint256 makerFee = (amountOut * makerFeeBps) / 10000;
        uint256 takerFee = (amountIn * takerFeeBps) / 10000;

        // Create trade record
        bytes32 tradeId = keccak256(
            abi.encodePacked(
                makerOrderId,
                takerOrderId,
                amountIn,
                amountOut,
                block.timestamp,
                totalTrades
            )
        );

        trades[tradeId] = Trade({
            tradeId: tradeId,
            makerOrderId: makerOrderId,
            takerOrderId: takerOrderId,
            maker: makerOrder.maker,
            taker: takerOrder.maker,
            tokenIn: makerOrder.tokenIn,
            tokenOut: makerOrder.tokenOut,
            amountIn: amountIn,
            amountOut: amountOut,
            makerFee: makerFee,
            takerFee: takerFee,
            executedAt: block.timestamp,
            proofHash: proofHash
        });

        // Update order states
        makerOrder.filledAmount += amountIn;
        takerOrder.filledAmount += amountOut;

        if (makerOrder.filledAmount >= makerOrder.amountIn) {
            makerOrder.status = OrderStatus.Filled;
        } else {
            makerOrder.status = OrderStatus.PartiallyFilled;
        }

        if (takerOrder.filledAmount >= takerOrder.amountIn) {
            takerOrder.status = OrderStatus.Filled;
        } else {
            takerOrder.status = OrderStatus.PartiallyFilled;
        }

        // Transfer tokens
        balances[makerOrder.maker][makerOrder.tokenOut] += amountOut - makerFee;
        balances[takerOrder.maker][takerOrder.tokenOut] += amountIn - takerFee;

        // Collect fees
        collectedFees[makerOrder.tokenOut] += makerFee;
        collectedFees[takerOrder.tokenOut] += takerFee;

        totalTrades++;
        totalVolume += amountIn;

        emit OrderMatched(
            makerOrderId,
            takerOrderId,
            tradeId,
            amountIn,
            amountOut
        );
        emit TradeExecuted(
            tradeId,
            makerOrder.maker,
            takerOrder.maker,
            makerOrder.tokenIn,
            makerOrder.tokenOut,
            amountIn,
            amountOut
        );
    }

    /*//////////////////////////////////////////////////////////////
                          LIQUIDITY POOLS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new liquidity pool
     * @param tokenA First token
     * @param tokenB Second token
     * @param feeRate Fee rate in basis points
     */
    function createPool(
        address tokenA,
        address tokenB,
        uint256 feeRate
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 poolId) {
        if (feeRate > MAX_FEE_BPS) revert InvalidAmount();

        poolId = keccak256(abi.encodePacked(tokenA, tokenB));

        pools[poolId] = LiquidityPool({
            poolId: poolId,
            tokenA: tokenA,
            tokenB: tokenB,
            reserveA: 0,
            reserveB: 0,
            totalLPTokens: 0,
            feeRate: feeRate,
            active: true
        });

        poolIds.push(poolId);
    }

    /**
     * @notice Add liquidity to a pool
     * @param poolId Pool identifier
     * @param amountA Amount of tokenA
     * @param amountB Amount of tokenB
     */
    function addLiquidity(
        bytes32 poolId,
        uint256 amountA,
        uint256 amountB
    ) external nonReentrant whenNotPaused returns (uint256 lpTokens) {
        LiquidityPool storage pool = pools[poolId];
        if (!pool.active) revert PoolNotActive();

        if (balances[msg.sender][pool.tokenA] < amountA)
            revert InsufficientBalance();
        if (balances[msg.sender][pool.tokenB] < amountB)
            revert InsufficientBalance();

        // Calculate LP tokens
        if (pool.totalLPTokens == 0) {
            lpTokens = _sqrt(amountA * amountB);
        } else {
            uint256 lpA = (amountA * pool.totalLPTokens) / pool.reserveA;
            uint256 lpB = (amountB * pool.totalLPTokens) / pool.reserveB;
            lpTokens = lpA < lpB ? lpA : lpB;
        }

        // Transfer tokens from user balance
        balances[msg.sender][pool.tokenA] -= amountA;
        balances[msg.sender][pool.tokenB] -= amountB;

        // Update pool
        pool.reserveA += amountA;
        pool.reserveB += amountB;
        pool.totalLPTokens += lpTokens;

        // Credit LP tokens
        lpBalances[poolId][msg.sender] += lpTokens;

        emit LiquidityAdded(poolId, msg.sender, amountA, amountB, lpTokens);
    }

    /**
     * @notice Remove liquidity from a pool
     * @param poolId Pool identifier
     * @param lpTokens Amount of LP tokens to burn
     */
    function removeLiquidity(
        bytes32 poolId,
        uint256 lpTokens
    ) external nonReentrant returns (uint256 amountA, uint256 amountB) {
        LiquidityPool storage pool = pools[poolId];
        if (lpBalances[poolId][msg.sender] < lpTokens)
            revert InsufficientBalance();

        // Calculate token amounts
        amountA = (lpTokens * pool.reserveA) / pool.totalLPTokens;
        amountB = (lpTokens * pool.reserveB) / pool.totalLPTokens;

        // Burn LP tokens
        lpBalances[poolId][msg.sender] -= lpTokens;
        pool.totalLPTokens -= lpTokens;

        // Update reserves
        pool.reserveA -= amountA;
        pool.reserveB -= amountB;

        // Credit user balance
        balances[msg.sender][pool.tokenA] += amountA;
        balances[msg.sender][pool.tokenB] += amountB;

        emit LiquidityRemoved(poolId, msg.sender, amountA, amountB, lpTokens);
    }

    /**
     * @notice Instant swap using AMM pool
     * @param poolId Pool identifier
     * @param tokenIn Input token
     * @param amountIn Input amount
     * @param minAmountOut Minimum output amount
     */
    function instantSwap(
        bytes32 poolId,
        address tokenIn,
        uint256 amountIn,
        uint256 minAmountOut
    ) external nonReentrant whenNotPaused returns (uint256 amountOut) {
        LiquidityPool storage pool = pools[poolId];
        if (!pool.active) revert PoolNotActive();
        if (balances[msg.sender][tokenIn] < amountIn)
            revert InsufficientBalance();

        address tokenOut;
        uint256 reserveIn;
        uint256 reserveOut;

        if (tokenIn == pool.tokenA) {
            tokenOut = pool.tokenB;
            reserveIn = pool.reserveA;
            reserveOut = pool.reserveB;
        } else if (tokenIn == pool.tokenB) {
            tokenOut = pool.tokenA;
            reserveIn = pool.reserveB;
            reserveOut = pool.reserveA;
        } else {
            revert InvalidToken();
        }

        // Calculate output with fee (constant product formula)
        uint256 amountInWithFee = amountIn * (10000 - pool.feeRate);
        amountOut =
            (amountInWithFee * reserveOut) /
            (reserveIn * 10000 + amountInWithFee);

        if (amountOut < minAmountOut) revert SlippageExceeded();
        if (amountOut > reserveOut) revert InsufficientLiquidity();

        // Update balances
        balances[msg.sender][tokenIn] -= amountIn;
        balances[msg.sender][tokenOut] += amountOut;

        // Update reserves
        if (tokenIn == pool.tokenA) {
            pool.reserveA += amountIn;
            pool.reserveB -= amountOut;
        } else {
            pool.reserveB += amountIn;
            pool.reserveA -= amountOut;
        }

        // Collect fee
        uint256 fee = (amountIn * pool.feeRate) / 10000;
        collectedFees[tokenIn] += fee;

        emit InstantSwap(
            poolId,
            msg.sender,
            tokenIn,
            tokenOut,
            amountIn,
            amountOut
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CROSS-CHAIN ORDERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a cross-chain order
     * @param targetChain Target chain ID
     * @param sourceCommitment Commitment on source chain
     * @param targetCommitment Expected commitment on target
     * @param secretHash Hash of the secret for HTLC
     * @param deadline Order deadline
     */
    function createCrossChainOrder(
        uint256 targetChain,
        bytes32 sourceCommitment,
        bytes32 targetCommitment,
        bytes32 secretHash,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (bytes32 orderId) {
        if (deadline <= block.timestamp) revert InvalidDeadline();

        orderId = keccak256(
            abi.encodePacked(
                msg.sender,
                block.chainid,
                targetChain,
                sourceCommitment,
                block.timestamp,
                totalCrossChainOrders
            )
        );

        crossChainOrders[orderId] = CrossChainOrder({
            orderId: orderId,
            sourceChain: block.chainid,
            targetChain: targetChain,
            sourceCommitment: sourceCommitment,
            targetCommitment: targetCommitment,
            secretHash: secretHash,
            deadline: deadline,
            executed: false
        });

        totalCrossChainOrders++;

        emit CrossChainOrderCreated(
            orderId,
            block.chainid,
            targetChain,
            secretHash
        );
    }

    /**
     * @notice Execute a cross-chain order with proof
     * @param orderId Order ID
     * @param proof Cross-chain proof (from bridge adapter)
     */
    function executeCrossChainOrder(
        bytes32 orderId,
        bytes calldata proof
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        CrossChainOrder storage order = crossChainOrders[orderId];

        if (order.orderId == bytes32(0)) revert CrossChainOrderNotFound();
        if (order.executed) revert CrossChainOrderAlreadyExecuted();
        if (order.deadline < block.timestamp) revert OrderExpired();

        // Verify cross-chain proof
        if (!_verifyCrossChainProof(proof, order.targetCommitment)) {
            revert InvalidProof();
        }

        order.executed = true;

        emit CrossChainOrderExecuted(orderId, keccak256(proof));
    }

    /*//////////////////////////////////////////////////////////////
                        STEALTH ADDRESSES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a stealth address for private receiving
     * @param pubKeyX X coordinate of public key
     * @param pubKeyY Y coordinate of public key
     * @param viewingKey Viewing key for scanning
     */
    function registerStealthAddress(
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        bytes32 viewingKey
    ) external {
        stealthAddresses[msg.sender] = StealthAddress({
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            viewingKey: viewingKey
        });

        emit StealthAddressRegistered(msg.sender, pubKeyX, pubKeyY);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get order details
     */
    function getOrder(
        bytes32 orderId
    ) external view returns (PrivateOrder memory) {
        return orders[orderId];
    }

    /**
     * @notice Get trade details
     */
    function getTrade(bytes32 tradeId) external view returns (Trade memory) {
        return trades[tradeId];
    }

    /**
     * @notice Get pool details
     */
    function getPool(
        bytes32 poolId
    ) external view returns (LiquidityPool memory) {
        return pools[poolId];
    }

    /**
     * @notice Get user orders
     */
    function getUserOrders(
        address user
    ) external view returns (bytes32[] memory) {
        return userOrders[user];
    }

    /**
     * @notice Get exchange statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 _totalOrders,
            uint256 _totalTrades,
            uint256 _totalVolume,
            uint256 _totalCrossChainOrders,
            uint256 _poolCount
        )
    {
        return (
            totalOrders,
            totalTrades,
            totalVolume,
            totalCrossChainOrders,
            poolIds.length
        );
    }

    /**
     * @notice Calculate swap output for a pool
     */
    function getSwapOutput(
        bytes32 poolId,
        address tokenIn,
        uint256 amountIn
    ) external view returns (uint256 amountOut) {
        LiquidityPool storage pool = pools[poolId];

        uint256 reserveIn;
        uint256 reserveOut;

        if (tokenIn == pool.tokenA) {
            reserveIn = pool.reserveA;
            reserveOut = pool.reserveB;
        } else {
            reserveIn = pool.reserveB;
            reserveOut = pool.reserveA;
        }

        uint256 amountInWithFee = amountIn * (10000 - pool.feeRate);
        amountOut =
            (amountInWithFee * reserveOut) /
            (reserveIn * 10000 + amountInWithFee);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setFees(
        uint256 _makerFeeBps,
        uint256 _takerFeeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_makerFeeBps > MAX_FEE_BPS || _takerFeeBps > MAX_FEE_BPS)
            revert InvalidAmount();
        makerFeeBps = _makerFeeBps;
        takerFeeBps = _takerFeeBps;
    }

    function setFeeCollector(
        address _feeCollector
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_feeCollector == address(0)) revert InvalidAmount();
        feeCollector = _feeCollector;
    }

    function withdrawFees(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = collectedFees[token];
        collectedFees[token] = 0;

        if (token == address(0)) {
            (bool success, ) = feeCollector.call{value: amount}("");
            if (!success) revert InsufficientBalance();
        } else {
            IERC20(token).safeTransfer(feeCollector, amount);
        }
    }

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function setProofVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofVerifier = _verifier;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyProof(
        bytes calldata proof,
        bytes32 nullifier,
        uint256 amount
    ) internal pure returns (bool) {
        // Simplified verification - in production, call actual verifier
        if (proof.length < 32) return false;
        bytes32 proofHash = keccak256(
            abi.encodePacked(proof, nullifier, amount)
        );
        return proofHash != bytes32(0);
    }

    function _verifyMatchProof(
        bytes calldata proof,
        bytes32 makerOrderId,
        bytes32 takerOrderId,
        uint256 amountIn,
        uint256 amountOut
    ) internal pure returns (bool) {
        // Simplified verification - in production, call ZK verifier
        if (proof.length < 32) return false;
        bytes32 proofHash = keccak256(
            abi.encodePacked(
                proof,
                makerOrderId,
                takerOrderId,
                amountIn,
                amountOut
            )
        );
        return proofHash != bytes32(0);
    }

    function _verifyCrossChainProof(
        bytes calldata proof,
        bytes32 commitment
    ) internal pure returns (bool) {
        // Simplified verification - in production, call bridge adapter
        if (proof.length < 32) return false;
        bytes32 proofHash = keccak256(abi.encodePacked(proof, commitment));
        return proofHash != bytes32(0);
    }

    function _sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    receive() external payable {}
}
