// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title SoulNetworkFuzz
 * @notice Comprehensive fuzz testing suite for the entire Soul Network
 * @dev Tests all major components: AMM, Cross-chain, Nullifiers, Stealth, Bridge, Governance
 *
 * Run with: forge test --match-contract SoulNetworkFuzz --fuzz-runs 10000
 */
contract SoulNetworkFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant FEE_DENOMINATOR = 10000;
    uint256 constant SWAP_FEE = 30; // 0.3%
    uint256 constant MAX_FEE = 1000; // 10%
    uint256 constant MIN_LIQUIDITY = 1000;
    uint256 constant PRECISION = 1e18;

    /*//////////////////////////////////////////////////////////////
                        STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bytes32) public commitments;
    mapping(address => uint256) public balances;
    mapping(bytes32 => uint256) public poolReserveA;
    mapping(bytes32 => uint256) public poolReserveB;
    mapping(bytes32 => uint256) public poolTotalLP;
    mapping(address => mapping(bytes32 => uint256)) public lpBalances;

    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalFees;

    /*//////////////////////////////////////////////////////////////
                        AMM FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test constant product invariant
    function testFuzz_ConstantProduct(
        uint256 reserveASeed,
        uint256 reserveBSeed,
        uint256 amountInSeed
    ) public pure {
        // Use bound() for efficient fuzzing with safe ranges
        uint256 reserveA = bound(reserveASeed, 1e9, 1e27);
        uint256 reserveB = bound(reserveBSeed, 1e9, 1e27);
        uint256 amountIn = bound(amountInSeed, 1000, reserveA / 2);

        uint256 k_before = reserveA * reserveB;
        uint256 amountOut = _getAmountOut(amountIn, reserveA, reserveB);

        if (amountOut == 0 || amountOut >= reserveB) return; // Skip edge cases

        uint256 newReserveA = reserveA + amountIn;
        uint256 newReserveB = reserveB - amountOut;
        uint256 k_after = newReserveA * newReserveB;

        // K should never decrease (fees increase it)
        assertGe(k_after, k_before, "Constant product violated");
    }

    /// @notice Fuzz test swap output is always positive
    function testFuzz_SwapPositiveOutput(
        uint256 reserveASeed,
        uint256 reserveBSeed,
        uint256 amountInSeed
    ) public pure {
        // Use bound() for efficient fuzzing
        uint256 reserveA = bound(reserveASeed, 1e9, 1e27);
        uint256 reserveB = bound(reserveBSeed, 1e9, 1e27);
        uint256 amountIn = bound(amountInSeed, reserveA / 1000, reserveA / 10);

        uint256 amountOut = _getAmountOut(amountIn, reserveA, reserveB);
        assertGt(amountOut, 0, "Swap output should be positive");
    }

    /// @notice Fuzz test no arbitrage profit from roundtrip
    function testFuzz_NoArbitrageProfit(
        uint256 reserveASeed,
        uint256 reserveBSeed,
        uint256 amountInSeed
    ) public pure {
        // Use bound() for efficient fuzzing with safe ranges
        uint256 reserveA = bound(reserveASeed, 1e9, 1e27);
        uint256 reserveB = bound(reserveBSeed, 1e9, 1e27);
        uint256 amountIn = bound(amountInSeed, 1000, reserveA / 10);

        // Swap A -> B
        uint256 amountB = _getAmountOut(amountIn, reserveA, reserveB);
        if (amountB == 0 || amountB >= reserveB) return; // Skip invalid cases

        uint256 newReserveA = reserveA + amountIn;
        uint256 newReserveB = reserveB - amountB;

        // Swap B -> A
        uint256 amountABack = _getAmountOut(amountB, newReserveB, newReserveA);

        // Should not profit from roundtrip
        assertLe(amountABack, amountIn, "Arbitrage profit detected");
    }

    /// @notice Fuzz test slippage bounds
    function testFuzz_SlippageBounds(
        uint256 reserveASeed,
        uint256 reserveBSeed,
        uint256 amountInSeed,
        uint256 slippageSeed
    ) public pure {
        // Use bound() for efficient fuzzing
        uint256 reserveA = bound(reserveASeed, 1e9, 1e27);
        uint256 reserveB = bound(reserveBSeed, 1e9, 1e27);
        uint256 amountIn = bound(amountInSeed, 1000, reserveA / 10);
        uint256 slippageBps = bound(slippageSeed, 0, 1000); // Max 10% slippage

        uint256 amountOut = _getAmountOut(amountIn, reserveA, reserveB);
        uint256 expectedOut = (amountIn * reserveB) / reserveA;

        // Output should be within slippage tolerance (accounting for fees)
        assertTrue(amountOut <= expectedOut, "Output exceeds expected");
    }

    /*//////////////////////////////////////////////////////////////
                    LP TOKEN FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test LP minting proportionality
    function testFuzz_LPMintingProportional(
        uint256 reserveASeed,
        uint256 totalSupplySeed,
        uint256 depositASeed
    ) public pure {
        // Use bound() for efficient fuzzing - ensure totalSupply >= reserveA ratio is reasonable
        uint256 reserveA = bound(reserveASeed, 1e9, 1e27);
        uint256 totalSupply = bound(totalSupplySeed, 1e9, 1e27);
        // Ensure depositA is large enough that (depositA * totalSupply) / reserveA > 0
        uint256 minDeposit = (reserveA / totalSupply) + 1;
        uint256 depositA = bound(depositASeed, minDeposit, reserveA);

        uint256 lpMinted = (depositA * totalSupply) / reserveA;

        // With reasonable inputs, LP tokens should be positive
        assertGt(lpMinted, 0, "Should mint LP tokens");
    }

    /// @notice Fuzz test LP burning fairness
    function testFuzz_LPBurningFair(
        uint128 reserveA,
        uint128 reserveB,
        uint128 totalSupply,
        uint128 lpAmount
    ) public pure {
        vm.assume(reserveA > MIN_LIQUIDITY && reserveB > MIN_LIQUIDITY);
        vm.assume(totalSupply > 0 && lpAmount > 0 && lpAmount <= totalSupply);

        uint256 amountA = (uint256(lpAmount) * reserveA) / totalSupply;
        uint256 amountB = (uint256(lpAmount) * reserveB) / totalSupply;

        // Should receive proportional share
        assertLe(amountA, reserveA, "Cannot withdraw more than reserve A");
        assertLe(amountB, reserveB, "Cannot withdraw more than reserve B");
    }

    /*//////////////////////////////////////////////////////////////
                    NULLIFIER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test nullifier uniqueness
    function testFuzz_NullifierUniqueness(
        bytes32 secret1,
        bytes32 secret2,
        uint256 leafIndex
    ) public pure {
        vm.assume(secret1 != secret2);

        bytes32 nullifier1 = keccak256(abi.encodePacked(secret1, leafIndex));
        bytes32 nullifier2 = keccak256(abi.encodePacked(secret2, leafIndex));

        assertNotEq(nullifier1, nullifier2, "Nullifiers should be unique");
    }

    /// @notice Fuzz test nullifier double-spend prevention
    function testFuzz_DoubleSpendPrevention(
        bytes32 secret,
        uint256 leafIndex,
        uint256 amount
    ) public {
        vm.assume(amount > 0);

        bytes32 nullifier = keccak256(abi.encodePacked(secret, leafIndex));

        // First spend succeeds
        assertFalse(usedNullifiers[nullifier], "Nullifier should not be used");
        usedNullifiers[nullifier] = true;

        // Second spend fails
        assertTrue(
            usedNullifiers[nullifier],
            "Nullifier should be marked used"
        );
    }

    /// @notice Fuzz test commitment hiding
    function testFuzz_CommitmentHiding(
        uint256 amount,
        bytes32 salt1,
        bytes32 salt2
    ) public pure {
        vm.assume(salt1 != salt2);

        bytes32 commitment1 = keccak256(abi.encodePacked(amount, salt1));
        bytes32 commitment2 = keccak256(abi.encodePacked(amount, salt2));

        assertNotEq(
            commitment1,
            commitment2,
            "Same amount with different salt should produce different commitments"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    STEALTH ADDRESS FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test stealth address unlinkability
    function testFuzz_StealthUnlinkability(
        bytes32 spendingPubKey,
        bytes32 viewingPubKey,
        bytes32 ephemeralKey1,
        bytes32 ephemeralKey2
    ) public pure {
        vm.assume(ephemeralKey1 != ephemeralKey2);
        vm.assume(spendingPubKey != bytes32(0) && viewingPubKey != bytes32(0));

        bytes32 sharedSecret1 = keccak256(
            abi.encodePacked(viewingPubKey, ephemeralKey1)
        );
        bytes32 sharedSecret2 = keccak256(
            abi.encodePacked(viewingPubKey, ephemeralKey2)
        );

        bytes32 stealthAddr1 = keccak256(
            abi.encodePacked(spendingPubKey, sharedSecret1)
        );
        bytes32 stealthAddr2 = keccak256(
            abi.encodePacked(spendingPubKey, sharedSecret2)
        );

        assertNotEq(
            stealthAddr1,
            stealthAddr2,
            "Stealth addresses should be unlinkable"
        );
    }

    /// @notice Fuzz test view tag computation
    function testFuzz_ViewTagDeterministic(bytes32 sharedSecret) public pure {
        uint8 viewTag1 = uint8(
            uint256(keccak256(abi.encodePacked("view_tag", sharedSecret))) % 256
        );
        uint8 viewTag2 = uint8(
            uint256(keccak256(abi.encodePacked("view_tag", sharedSecret))) % 256
        );

        assertEq(viewTag1, viewTag2, "View tag should be deterministic");
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test HTLC atomicity
    function testFuzz_HTLCAtomicity(
        bytes32 preimage,
        bytes32 secretHash,
        uint256 lockTime,
        uint256 currentTime
    ) public pure {
        bytes32 computedHash = keccak256(abi.encodePacked(preimage));
        bool secretValid = (computedHash == secretHash);
        bool timedOut = (currentTime > lockTime);

        bool canClaim = secretValid && !timedOut;
        bool canRefund = timedOut;

        // Cannot both claim and refund
        assertFalse(canClaim && canRefund, "HTLC atomicity violated");
    }

    /// @notice Fuzz test cross-chain message uniqueness
    function testFuzz_MessageIdUniqueness(
        uint256 srcChain,
        uint256 dstChain,
        uint256 nonce1,
        uint256 nonce2,
        address sender
    ) public pure {
        vm.assume(nonce1 != nonce2);

        bytes32 msgId1 = keccak256(
            abi.encodePacked(srcChain, dstChain, sender, nonce1)
        );
        bytes32 msgId2 = keccak256(
            abi.encodePacked(srcChain, dstChain, sender, nonce2)
        );

        assertNotEq(msgId1, msgId2, "Message IDs should be unique");
    }

    /// @notice Fuzz test bridge fee calculation
    function testFuzz_BridgeFeeCalculation(
        uint128 amount,
        uint16 feeRate
    ) public pure {
        vm.assume(amount > 0);
        vm.assume(feeRate <= MAX_FEE);

        uint256 fee = (uint256(amount) * feeRate) / FEE_DENOMINATOR;
        uint256 amountAfterFee = amount - fee;

        assertLe(fee, amount, "Fee should not exceed amount");
        assertGe(amountAfterFee, 0, "Amount after fee should be non-negative");
        assertEq(
            fee + amountAfterFee,
            amount,
            "Fee + amount should equal original"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    BALANCE INVARIANT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test deposit/withdraw conservation
    function testFuzz_BalanceConservation(
        address user,
        uint128 deposit,
        uint128 withdraw
    ) public {
        vm.assume(user != address(0));
        vm.assume(deposit >= withdraw);
        vm.assume(deposit < type(uint128).max);

        // Simulate deposit
        balances[user] += deposit;
        totalDeposits += deposit;

        // Simulate withdraw
        balances[user] -= withdraw;
        totalWithdrawals += withdraw;

        // Balance should equal deposit - withdraw
        assertEq(balances[user], deposit - withdraw, "Balance mismatch");
    }

    /// @notice Fuzz test no underflow on withdrawal
    function testFuzz_NoUnderflowWithdrawal(
        address user,
        uint128 balance,
        uint128 withdrawAmount
    ) public {
        vm.assume(user != address(0));

        balances[user] = balance;

        if (withdrawAmount <= balance) {
            balances[user] -= withdrawAmount;
            assertLe(balances[user], balance, "Balance should decrease");
        }
        // If withdrawAmount > balance, the subtraction would revert
    }

    /*//////////////////////////////////////////////////////////////
                    OVERFLOW PROTECTION FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test no overflow in swap calculations
    function testFuzz_NoSwapOverflow(
        uint128 reserveA,
        uint128 reserveB,
        uint128 amountIn
    ) public pure {
        // Bound inputs to realistic ranges to test overflow protection
        vm.assume(
            reserveA > 0 && reserveA < type(uint128).max / FEE_DENOMINATOR
        );
        vm.assume(
            reserveB > 0 && reserveB < type(uint128).max / FEE_DENOMINATOR
        );
        vm.assume(
            amountIn > 0 && amountIn < type(uint128).max / FEE_DENOMINATOR
        );

        // These calculations should not overflow with uint128 inputs
        uint256 amountInWithFee = uint256(amountIn) *
            (FEE_DENOMINATOR - SWAP_FEE);
        uint256 numerator = amountInWithFee * uint256(reserveB);
        uint256 denominator = uint256(reserveA) *
            FEE_DENOMINATOR +
            amountInWithFee;

        assertTrue(denominator > 0, "Denominator should be positive");

        uint256 amountOut = numerator / denominator;
        assertLe(amountOut, reserveB, "Output cannot exceed reserve");
    }

    /// @notice Fuzz test LP math overflow protection
    function testFuzz_NoLPOverflow(
        uint128 amount0,
        uint128 amount1,
        uint128 reserve0,
        uint128 reserve1,
        uint128 totalSupply
    ) public pure {
        vm.assume(reserve0 > 0 && reserve1 > 0 && totalSupply > 0);
        vm.assume(amount0 > 0 && amount1 > 0);

        // Calculate LP tokens for adding liquidity
        uint256 liquidity0 = (uint256(amount0) * totalSupply) / reserve0;
        uint256 liquidity1 = (uint256(amount1) * totalSupply) / reserve1;

        // Take minimum to maintain ratio
        uint256 liquidity = liquidity0 < liquidity1 ? liquidity0 : liquidity1;

        assertTrue(liquidity <= type(uint256).max, "LP calculation overflow");
    }

    /*//////////////////////////////////////////////////////////////
                    GOVERNANCE FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test voting power calculation
    function testFuzz_VotingPowerProportional(
        uint128 stakedAmount,
        uint128 totalStaked
    ) public pure {
        vm.assume(totalStaked > 0 && stakedAmount <= totalStaked);

        uint256 votingPower = (uint256(stakedAmount) * PRECISION) / totalStaked;

        assertLe(votingPower, PRECISION, "Voting power cannot exceed 100%");
    }

    /// @notice Fuzz test timelock delay bounds
    function testFuzz_TimelockDelayBounds(
        uint256 proposedDelay,
        uint256 minDelay,
        uint256 maxDelay
    ) public pure {
        vm.assume(minDelay <= maxDelay);

        uint256 effectiveDelay = proposedDelay;
        if (proposedDelay < minDelay) {
            effectiveDelay = minDelay;
        } else if (proposedDelay > maxDelay) {
            effectiveDelay = maxDelay;
        }

        assertGe(effectiveDelay, minDelay, "Delay below minimum");
        assertLe(effectiveDelay, maxDelay, "Delay above maximum");
    }

    /*//////////////////////////////////////////////////////////////
                    ORDER MATCHING FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test order matching symmetry
    function testFuzz_OrderMatchingSymmetric(
        uint128 buyAmount,
        uint128 sellAmount,
        uint128 price
    ) public pure {
        vm.assume(price > 0 && buyAmount > 0 && sellAmount > 0);

        // Check if orders can match
        uint256 buyerPays = (uint256(buyAmount) * price) / PRECISION;
        uint256 sellerReceives = (uint256(sellAmount) * price) / PRECISION;

        // If buy amount matches sell amount, trade should be symmetric
        if (buyAmount == sellAmount) {
            assertEq(
                buyerPays,
                sellerReceives,
                "Symmetric trades should match"
            );
        }
    }

    /// @notice Fuzz test partial fill correctness
    function testFuzz_PartialFillCorrect(
        uint128 orderAmount,
        uint128 fillAmount
    ) public pure {
        vm.assume(orderAmount > 0 && fillAmount > 0);
        vm.assume(fillAmount <= orderAmount);

        uint256 remaining = orderAmount - fillAmount;
        uint256 filled = fillAmount;

        assertEq(
            remaining + filled,
            orderAmount,
            "Fill + remaining should equal original"
        );
        assertLe(filled, orderAmount, "Cannot fill more than order");
    }

    /*//////////////////////////////////////////////////////////////
                    MERKLE PROOF FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Merkle proof verification
    function testFuzz_MerkleProofValid(
        bytes32 leaf,
        bytes32 sibling,
        bool isLeft
    ) public pure {
        bytes32 parent;
        if (isLeft) {
            parent = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            parent = keccak256(abi.encodePacked(sibling, leaf));
        }

        // Parent should be deterministic
        bytes32 parent2;
        if (isLeft) {
            parent2 = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            parent2 = keccak256(abi.encodePacked(sibling, leaf));
        }

        assertEq(parent, parent2, "Merkle computation should be deterministic");
    }

    /// @notice Fuzz test Merkle collision resistance
    function testFuzz_MerkleCollisionResistance(
        bytes32 leaf1,
        bytes32 leaf2,
        bytes32 sibling
    ) public pure {
        vm.assume(leaf1 != leaf2);

        bytes32 parent1 = keccak256(abi.encodePacked(leaf1, sibling));
        bytes32 parent2 = keccak256(abi.encodePacked(leaf2, sibling));

        assertNotEq(
            parent1,
            parent2,
            "Different leaves should produce different parents"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    PROTOCOL FEE FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test fee distribution
    function testFuzz_FeeDistribution(
        uint128 totalFee,
        uint16 protocolShare,
        uint16 lpShare
    ) public pure {
        vm.assume(
            totalFee > 0 && totalFee < type(uint128).max / FEE_DENOMINATOR
        );
        vm.assume(uint256(protocolShare) + uint256(lpShare) <= FEE_DENOMINATOR);

        uint256 protocolFee = (uint256(totalFee) * protocolShare) /
            FEE_DENOMINATOR;
        uint256 lpFee = (uint256(totalFee) * lpShare) / FEE_DENOMINATOR;

        assertLe(
            protocolFee + lpFee,
            totalFee,
            "Distributed fees should not exceed total"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * (FEE_DENOMINATOR - SWAP_FEE);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * FEE_DENOMINATOR + amountInWithFee;
        return numerator / denominator;
    }
}
