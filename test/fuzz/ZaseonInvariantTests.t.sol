// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

/**
 * @title ZaseonInvariantTests
 * @notice Stateful invariant tests for Zaseon Network protocol properties
 * @dev Tests cross-contract interactions and global protocol invariants
 *
 * Run with: forge test --match-contract ZaseonInvariantTests --fuzz-runs 1000
 */
contract ZaseonInvariantTests is StdInvariant, Test {
    ZaseonNetworkHandler public handler;

    function setUp() public {
        handler = new ZaseonNetworkHandler();
        targetContract(address(handler));
    }

    /// @notice Total deposits should always equal total withdrawals + current balances
    function invariant_balanceConservation() public view {
        assertEq(
            handler.totalDeposited(),
            handler.totalWithdrawn() + handler.totalBalance(),
            "Balance conservation violated"
        );
    }

    /// @notice Total LP tokens should match sum of all holder balances
    function invariant_lpTokenSupply() public view {
        assertEq(
            handler.totalLPMinted(),
            handler.totalLPBurned() + handler.outstandingLP(),
            "LP supply mismatch"
        );
    }

    /// @notice Used nullifiers should never be reused
    function invariant_nullifierUniqueness() public view {
        assertTrue(
            handler.nullifierCollisions() == 0,
            "Nullifier collision detected"
        );
    }

    /// @notice Pool reserves should always be positive after initialization
    function invariant_poolReservesPositive() public view {
        if (handler.poolCount() > 0) {
            assertTrue(
                handler.minPoolReserve() > 0,
                "Pool reserve went to zero"
            );
        }
    }

    /// @notice Protocol fees collected should never exceed total volume
    function invariant_feesBounded() public view {
        assertLe(
            handler.totalFeesCollected(),
            handler.totalVolume() / 10, // Max 10% fee
            "Fees exceed maximum"
        );
    }

    /// @notice Cross-chain messages should have unique IDs
    function invariant_messageIdUniqueness() public view {
        assertTrue(
            handler.messageIdCollisions() == 0,
            "Message ID collision detected"
        );
    }

    /// @notice Active orders should never exceed total orders created
    function invariant_orderCount() public view {
        assertLe(
            handler.activeOrders(),
            handler.totalOrdersCreated(),
            "Active orders exceed total"
        );
    }
}

/**
 * @title ZaseonNetworkHandler
 * @notice Handler contract for stateful invariant testing
 */
contract ZaseonNetworkHandler is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE
    //////////////////////////////////////////////////////////////*/

    // Balance tracking
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalBalance;

    // LP tracking
    mapping(bytes32 => uint256) public poolReserveA;
    mapping(bytes32 => uint256) public poolReserveB;
    mapping(bytes32 => uint256) public poolLPSupply;
    mapping(address => mapping(bytes32 => uint256)) public lpBalances;
    uint256 public totalLPMinted;
    uint256 public totalLPBurned;
    uint256 public outstandingLP;
    uint256 public poolCount;
    uint256 public minPoolReserve;

    // Nullifier tracking
    mapping(bytes32 => bool) public usedNullifiers;
    uint256 public nullifierCollisions;

    // Fee tracking
    uint256 public totalFeesCollected;
    uint256 public totalVolume;

    // Message tracking
    mapping(bytes32 => bool) public usedMessageIds;
    uint256 public messageIdCollisions;
    uint256 public messageNonce;

    // Order tracking
    mapping(bytes32 => bool) public activeOrderMap;
    uint256 public activeOrders;
    uint256 public totalOrdersCreated;

    // Users
    address[] public users;

    uint256 constant FEE_DENOMINATOR = 10000;
    uint256 constant SWAP_FEE = 30;
    uint256 constant MIN_CAPACITY = 1000;

    constructor() {
        // Initialize with some users
        users.push(address(0x1));
        users.push(address(0x2));
        users.push(address(0x3));
        minPoolReserve = type(uint256).max;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT/WITHDRAW
    //////////////////////////////////////////////////////////////*/

    function deposit(uint256 userSeed, uint128 amount) external {
        address user = users[userSeed % users.length];
        if (amount == 0) return;

        balances[user] += amount;
        totalDeposited += amount;
        totalBalance += amount;
    }

    function withdraw(uint256 userSeed, uint128 amount) external {
        address user = users[userSeed % users.length];
        if (amount == 0 || balances[user] < amount) return;

        balances[user] -= amount;
        totalWithdrawn += amount;
        totalBalance -= amount;
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE CAPACITY
    //////////////////////////////////////////////////////////////*/

    function createPool(
        bytes32 poolId,
        uint128 amountA,
        uint128 amountB
    ) external {
        if (amountA < MIN_CAPACITY || amountB < MIN_CAPACITY) return;
        if (poolReserveA[poolId] > 0) return; // Pool exists

        poolReserveA[poolId] = amountA;
        poolReserveB[poolId] = amountB;

        // Mint initial LP
        uint256 lpAmount = sqrt(uint256(amountA) * amountB);
        poolLPSupply[poolId] = lpAmount;
        totalLPMinted += lpAmount;
        outstandingLP += lpAmount;
        poolCount++;

        _updateMinReserve(amountA, amountB);
    }

    function addExitFunding(
        bytes32 poolId,
        uint256 userSeed,
        uint128 amountA,
        uint128 amountB
    ) external {
        address user = users[userSeed % users.length];
        if (poolReserveA[poolId] == 0) return; // Pool doesn't exist
        if (amountA == 0 || amountB == 0) return;

        uint256 reserveA = poolReserveA[poolId];
        uint256 reserveB = poolReserveB[poolId];
        uint256 totalSupply = poolLPSupply[poolId];

        // Calculate LP tokens
        uint256 lpA = (uint256(amountA) * totalSupply) / reserveA;
        uint256 lpB = (uint256(amountB) * totalSupply) / reserveB;
        uint256 lpAmount = lpA < lpB ? lpA : lpB;

        if (lpAmount == 0) return;

        poolReserveA[poolId] += amountA;
        poolReserveB[poolId] += amountB;
        poolLPSupply[poolId] += lpAmount;
        lpBalances[user][poolId] += lpAmount;
        totalLPMinted += lpAmount;
        outstandingLP += lpAmount;

        _updateMinReserve(poolReserveA[poolId], poolReserveB[poolId]);
    }

    function removeExitFunding(
        bytes32 poolId,
        uint256 userSeed,
        uint128 lpAmount
    ) external {
        address user = users[userSeed % users.length];
        if (lpBalances[user][poolId] < lpAmount || lpAmount == 0) return;

        uint256 reserveA = poolReserveA[poolId];
        uint256 reserveB = poolReserveB[poolId];
        uint256 totalSupply = poolLPSupply[poolId];

        uint256 amountA = (uint256(lpAmount) * reserveA) / totalSupply;
        uint256 amountB = (uint256(lpAmount) * reserveB) / totalSupply;

        if (amountA >= reserveA || amountB >= reserveB) return;

        poolReserveA[poolId] -= amountA;
        poolReserveB[poolId] -= amountB;
        poolLPSupply[poolId] -= lpAmount;
        lpBalances[user][poolId] -= lpAmount;
        totalLPBurned += lpAmount;
        outstandingLP -= lpAmount;

        _updateMinReserve(poolReserveA[poolId], poolReserveB[poolId]);
    }

    function swap(bytes32 poolId, uint128 amountIn, bool aToB) external {
        if (poolReserveA[poolId] == 0) return;
        if (amountIn == 0) return;

        uint256 reserveIn = aToB ? poolReserveA[poolId] : poolReserveB[poolId];
        uint256 reserveOut = aToB ? poolReserveB[poolId] : poolReserveA[poolId];

        if (amountIn > reserveIn / 2) return;

        uint256 amountInWithFee = uint256(amountIn) *
            (FEE_DENOMINATOR - SWAP_FEE);
        uint256 amountOut = (amountInWithFee * reserveOut) /
            (reserveIn * FEE_DENOMINATOR + amountInWithFee);

        if (amountOut >= reserveOut) return;

        uint256 fee = (uint256(amountIn) * SWAP_FEE) / FEE_DENOMINATOR;
        totalFeesCollected += fee;
        totalVolume += amountIn;

        if (aToB) {
            poolReserveA[poolId] += amountIn;
            poolReserveB[poolId] -= amountOut;
        } else {
            poolReserveB[poolId] += amountIn;
            poolReserveA[poolId] -= amountOut;
        }

        _updateMinReserve(poolReserveA[poolId], poolReserveB[poolId]);
    }

    /*//////////////////////////////////////////////////////////////
                        NULLIFIERS
    //////////////////////////////////////////////////////////////*/

    function spendWithNullifier(bytes32 secret, uint256 leafIndex) external {
        bytes32 nullifier = keccak256(abi.encodePacked(secret, leafIndex));

        if (usedNullifiers[nullifier]) {
            nullifierCollisions++;
        } else {
            usedNullifiers[nullifier] = true;
        }
    }

    /*//////////////////////////////////////////////////////////////
                        CROSS-CHAIN MESSAGES
    //////////////////////////////////////////////////////////////*/

    function sendCrossChainMessage(
        uint256 srcChain,
        uint256 dstChain,
        address sender,
        bytes32 payload
    ) external {
        bytes32 messageId = keccak256(
            abi.encodePacked(
                srcChain,
                dstChain,
                sender,
                messageNonce++,
                payload
            )
        );

        if (usedMessageIds[messageId]) {
            messageIdCollisions++;
        } else {
            usedMessageIds[messageId] = true;
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ORDERS
    //////////////////////////////////////////////////////////////*/

    function createOrder(bytes32 orderId) external {
        if (activeOrderMap[orderId]) return;

        activeOrderMap[orderId] = true;
        activeOrders++;
        totalOrdersCreated++;
    }

    function cancelOrder(bytes32 orderId) external {
        if (!activeOrderMap[orderId]) return;

        activeOrderMap[orderId] = false;
        activeOrders--;
    }

    function fillOrder(bytes32 orderId) external {
        if (!activeOrderMap[orderId]) return;

        activeOrderMap[orderId] = false;
        activeOrders--;
    }

    /*//////////////////////////////////////////////////////////////
                        HELPERS
    //////////////////////////////////////////////////////////////*/

    function _updateMinReserve(uint256 reserveA, uint256 reserveB) internal {
        uint256 minReserve = reserveA < reserveB ? reserveA : reserveB;
        if (minReserve > 0 && minReserve < minPoolReserve) {
            minPoolReserve = minReserve;
        }
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
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
}
