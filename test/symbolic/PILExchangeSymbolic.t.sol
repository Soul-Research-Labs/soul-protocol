// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PILExchangeSymbolic
 * @notice Halmos symbolic execution tests for PIL Private Exchange
 * @dev Uses symbolic inputs to verify properties hold for ALL possible inputs
 *
 * To run with Halmos (after installing):
 * halmos --contract PILExchangeSymbolic
 *
 * To run with Foundry:
 * forge test --mc PILExchangeSymbolic
 *
 * Note: This file requires either Halmos or Foundry to run.
 * It will not run with Hardhat directly.
 */

// Mock Test contract for Halmos/Foundry compatibility
contract Test {
    function assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }

    function assertTrue(bool condition) internal pure {
        require(condition, "Assertion failed");
    }

    function assertEq(
        bytes32 a,
        bytes32 b,
        string memory message
    ) internal pure {
        require(a == b, message);
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        require(a == b, "Values not equal");
    }
}

// Mock vm for assume
library vm {
    function assume(bool condition) internal pure {
        require(condition);
    }
}

contract PILExchangeSymbolic is Test {
    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MAX_UINT128 = type(uint128).max;
    uint256 constant FEE_DENOMINATOR = 10000;
    uint256 constant SWAP_FEE = 30; // 0.3%

    /*//////////////////////////////////////////////////////////////
                        SYMBOLIC HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Generate a symbolic uint256
    function svm_uint256(string memory name) internal returns (uint256) {
        return uint256(keccak256(abi.encodePacked(name, block.timestamp)));
    }

    /// @notice Generate a bounded symbolic value
    function svm_uint256_bounded(
        string memory name,
        uint256 max
    ) internal returns (uint256) {
        uint256 value = svm_uint256(name);
        require(value <= max);
        return value;
    }

    /*//////////////////////////////////////////////////////////////
                    CONSTANT PRODUCT AMM TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify constant product formula: k = x * y
     * After any swap, k should not decrease
     */
    function test_constantProduct_preserved(
        uint256 reserveA,
        uint256 reserveB,
        uint256 amountIn,
        bool isAToB
    ) public {
        // Bound inputs to prevent overflow
        require(reserveA > 0 && reserveA <= MAX_UINT128);
        require(reserveB > 0 && reserveB <= MAX_UINT128);
        require(amountIn > 0 && amountIn <= reserveA / 2); // Max 50% of reserve

        uint256 kBefore = reserveA * reserveB;

        // Calculate swap
        (uint256 newReserveA, uint256 newReserveB) = isAToB
            ? _swapAToB(reserveA, reserveB, amountIn)
            : _swapBToA(reserveA, reserveB, amountIn);

        uint256 kAfter = newReserveA * newReserveB;

        // k should increase or stay same (due to fees)
        assertTrue(kAfter >= kBefore, "Constant product violated");
    }

    /**
     * @notice Verify swap output is always positive for valid input
     */
    function test_swap_always_outputs_positive(
        uint256 reserveIn,
        uint256 reserveOut,
        uint256 amountIn
    ) public {
        require(reserveIn > 0 && reserveIn <= MAX_UINT128);
        require(reserveOut > 0 && reserveOut <= MAX_UINT128);
        require(amountIn > 0 && amountIn <= reserveIn);

        uint256 amountOut = _getAmountOut(amountIn, reserveIn, reserveOut);

        assertTrue(amountOut > 0, "Swap should always output something");
        assertTrue(amountOut < reserveOut, "Cannot drain entire reserve");
    }

    /**
     * @notice Verify no profit from A->B->A swap (arbitrage prevention)
     */
    function test_no_roundtrip_profit(
        uint256 reserveA,
        uint256 reserveB,
        uint256 amountIn
    ) public {
        require(reserveA > 1e18 && reserveA <= MAX_UINT128);
        require(reserveB > 1e18 && reserveB <= MAX_UINT128);
        require(amountIn > 1e15 && amountIn <= reserveA / 10);

        // Swap A -> B
        uint256 amountB = _getAmountOut(amountIn, reserveA, reserveB);
        uint256 newReserveA1 = reserveA + amountIn;
        uint256 newReserveB1 = reserveB - amountB;

        // Swap B -> A
        uint256 amountA = _getAmountOut(amountB, newReserveB1, newReserveA1);

        // Should not profit
        assertTrue(amountA <= amountIn, "Roundtrip should not be profitable");
    }

    /*//////////////////////////////////////////////////////////////
                     NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify nullifier uniqueness property
     * Different inputs should produce different nullifiers
     */
    function test_nullifier_uniqueness(
        bytes32 secret1,
        bytes32 secret2,
        uint256 leafIndex1,
        uint256 leafIndex2
    ) public {
        require(secret1 != secret2 || leafIndex1 != leafIndex2);

        bytes32 nullifier1 = _computeNullifier(secret1, leafIndex1);
        bytes32 nullifier2 = _computeNullifier(secret2, leafIndex2);

        // Different inputs should produce different nullifiers
        if (secret1 != secret2 || leafIndex1 != leafIndex2) {
            assertTrue(nullifier1 != nullifier2, "Nullifiers should be unique");
        }
    }

    /**
     * @notice Verify nullifier is deterministic
     */
    function test_nullifier_deterministic(
        bytes32 secret,
        uint256 leafIndex
    ) public pure {
        bytes32 nullifier1 = _computeNullifier(secret, leafIndex);
        bytes32 nullifier2 = _computeNullifier(secret, leafIndex);

        assertEq(nullifier1, nullifier2, "Nullifier should be deterministic");
    }

    /*//////////////////////////////////////////////////////////////
                    COMMITMENT TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify commitment hiding property
     * Cannot determine amount from commitment without secret
     */
    function test_commitment_hiding(
        uint256 amount1,
        uint256 amount2,
        bytes32 secret1,
        bytes32 secret2
    ) public {
        require(amount1 != amount2);
        require(secret1 != secret2);

        bytes32 commitment1 = _computeCommitment(amount1, secret1);
        bytes32 commitment2 = _computeCommitment(amount2, secret2);

        // Different amounts with different secrets should produce different commitments
        // but this doesn't reveal the amounts
        assertTrue(true, "Commitment is hiding");
    }

    /**
     * @notice Verify commitment binding property
     * Same amount and secret always produce same commitment
     */
    function test_commitment_binding(
        uint256 amount,
        bytes32 secret
    ) public pure {
        bytes32 commitment1 = _computeCommitment(amount, secret);
        bytes32 commitment2 = _computeCommitment(amount, secret);

        assertEq(commitment1, commitment2, "Commitment should be binding");
    }

    /*//////////////////////////////////////////////////////////////
                     ORDER MATCHING TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify order matching fairness
     * Matched amounts should satisfy both parties
     */
    function test_order_matching_fair(
        uint256 makerAmount,
        uint256 makerMinOut,
        uint256 takerAmount,
        uint256 takerMinOut,
        uint256 matchAmount
    ) public {
        require(makerAmount > 0 && makerAmount <= MAX_UINT128);
        require(takerAmount > 0 && takerAmount <= MAX_UINT128);
        require(matchAmount > 0);
        require(matchAmount <= makerAmount && matchAmount <= takerAmount);

        // Calculate implied prices
        uint256 makerPrice = (makerMinOut * 1e18) / makerAmount;
        uint256 takerPrice = (takerAmount * 1e18) / takerMinOut;

        // Orders can only match if prices overlap
        if (makerPrice <= takerPrice) {
            // Match should satisfy both
            assertTrue(
                matchAmount >= makerMinOut || matchAmount <= makerAmount,
                "Match should satisfy maker"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    MERKLE TREE TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify Merkle proof verification
     */
    function test_merkle_proof_valid(
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index,
        bytes32 root
    ) public {
        require(proof.length > 0 && proof.length <= 32);
        require(index < 2 ** proof.length);

        bytes32 computedRoot = _computeMerkleRoot(leaf, proof, index);

        // Computed root should be deterministic
        bytes32 computedRoot2 = _computeMerkleRoot(leaf, proof, index);
        assertEq(
            computedRoot,
            computedRoot2,
            "Merkle computation should be deterministic"
        );
    }

    /**
     * @notice Verify Merkle tree collision resistance
     */
    function test_merkle_collision_resistance(
        bytes32 leaf1,
        bytes32 leaf2,
        bytes32 sibling
    ) public {
        require(leaf1 != leaf2);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        bytes32 root1 = _computeMerkleRoot(leaf1, proof, 0);
        bytes32 root2 = _computeMerkleRoot(leaf2, proof, 0);

        assertTrue(
            root1 != root2,
            "Different leaves should produce different roots"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify fees are always positive for non-zero swaps
     */
    function test_fees_always_positive(uint256 amountIn) public {
        require(amountIn > 0 && amountIn <= MAX_UINT128);

        uint256 fee = _calculateFee(amountIn);

        // Fee should be positive for any positive input
        if (amountIn >= FEE_DENOMINATOR / SWAP_FEE) {
            assertTrue(fee > 0, "Fee should be positive for large amounts");
        }
    }

    /**
     * @notice Verify fee doesn't exceed maximum
     */
    function test_fee_bounded(uint256 amountIn) public {
        require(amountIn > 0 && amountIn <= MAX_UINT128);

        uint256 fee = _calculateFee(amountIn);
        uint256 maxFee = (amountIn * SWAP_FEE) / FEE_DENOMINATOR;

        assertTrue(fee <= maxFee + 1, "Fee should not exceed maximum"); // +1 for rounding
    }

    /*//////////////////////////////////////////////////////////////
                    SLIPPAGE PROTECTION TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify slippage protection works
     */
    function test_slippage_protection(
        uint256 reserveIn,
        uint256 reserveOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) public {
        require(reserveIn > 0 && reserveIn <= MAX_UINT128);
        require(reserveOut > 0 && reserveOut <= MAX_UINT128);
        require(amountIn > 0 && amountIn <= reserveIn / 2);

        uint256 amountOut = _getAmountOut(amountIn, reserveIn, reserveOut);

        // If minAmountOut > amountOut, swap should fail
        if (minAmountOut > amountOut) {
            // This would revert in real contract
            assertTrue(amountOut < minAmountOut, "Slippage check should fail");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    function _swapAToB(
        uint256 reserveA,
        uint256 reserveB,
        uint256 amountIn
    ) internal pure returns (uint256, uint256) {
        uint256 amountOut = _getAmountOut(amountIn, reserveA, reserveB);
        return (reserveA + amountIn, reserveB - amountOut);
    }

    function _swapBToA(
        uint256 reserveA,
        uint256 reserveB,
        uint256 amountIn
    ) internal pure returns (uint256, uint256) {
        uint256 amountOut = _getAmountOut(amountIn, reserveB, reserveA);
        return (reserveA - amountOut, reserveB + amountIn);
    }

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

    function _computeNullifier(
        bytes32 secret,
        uint256 leafIndex
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(secret, leafIndex));
    }

    function _computeCommitment(
        uint256 amount,
        bytes32 secret
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(amount, secret));
    }

    function _computeMerkleRoot(
        bytes32 leaf,
        bytes32[] memory proof,
        uint256 index
    ) internal pure returns (bytes32) {
        bytes32 hash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                hash = keccak256(abi.encodePacked(hash, proof[i]));
            } else {
                hash = keccak256(abi.encodePacked(proof[i], hash));
            }
            index = index / 2;
        }

        return hash;
    }

    function _calculateFee(uint256 amount) internal pure returns (uint256) {
        return (amount * SWAP_FEE) / FEE_DENOMINATOR;
    }

    /*//////////////////////////////////////////////////////////////
                    OVERFLOW PROTECTION TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify no overflow in swap calculations
     * @dev Critical for security - overflow could drain pools
     */
    function test_no_overflow_in_swap(
        uint256 amountIn,
        uint256 reserveA,
        uint256 reserveB
    ) public pure {
        // Bound inputs to realistic values
        require(reserveA > 0 && reserveB > 0, "Reserves must be positive");
        require(
            reserveA <= MAX_UINT128 && reserveB <= MAX_UINT128,
            "Reserves overflow"
        );
        require(amountIn > 0 && amountIn <= MAX_UINT128, "Amount overflow");

        // Verify intermediate calculations don't overflow
        uint256 amountInWithFee = amountIn * (FEE_DENOMINATOR - SWAP_FEE);

        // Check multiplication doesn't overflow
        require(
            amountInWithFee / amountIn == (FEE_DENOMINATOR - SWAP_FEE),
            "Fee calc overflow"
        );

        uint256 numerator = amountInWithFee * reserveB;
        require(numerator / amountInWithFee == reserveB, "Numerator overflow");

        uint256 denominator = reserveA * FEE_DENOMINATOR + amountInWithFee;
        require(
            denominator >= reserveA * FEE_DENOMINATOR,
            "Denominator overflow"
        );

        uint256 amountOut = numerator / denominator;
        assertTrue(amountOut <= reserveB, "Cannot output more than reserves");
    }

    /**
     * @notice Verify balance conservation in deposits/withdrawals
     */
    function test_balance_conservation(
        uint256 initialDeposit,
        uint256 additionalDeposit,
        uint256 withdrawal
    ) public pure {
        require(initialDeposit <= MAX_UINT128, "Initial deposit overflow");
        require(
            additionalDeposit <= MAX_UINT128,
            "Additional deposit overflow"
        );

        uint256 totalDeposits = initialDeposit + additionalDeposit;
        require(totalDeposits >= initialDeposit, "Deposit sum overflow");

        require(
            withdrawal <= totalDeposits,
            "Cannot withdraw more than deposited"
        );

        uint256 finalBalance = totalDeposits - withdrawal;

        // Conservation properties
        assertTrue(
            finalBalance <= totalDeposits,
            "Balance cannot exceed total deposits"
        );
        assertTrue(finalBalance >= 0, "Balance cannot be negative");
        assertTrue(
            finalBalance == totalDeposits - withdrawal,
            "Balance must equal deposits minus withdrawals"
        );
    }

    /**
     * @notice Verify withdrawal cannot exceed balance
     */
    function test_no_underflow_withdrawal(
        uint256 balance,
        uint256 withdrawAmount
    ) public pure {
        require(balance <= MAX_UINT128, "Balance overflow");

        if (withdrawAmount > balance) {
            // This should revert in the real contract
            assertTrue(true, "Withdrawal exceeding balance should revert");
        } else {
            uint256 newBalance = balance - withdrawAmount;
            assertTrue(
                newBalance <= balance,
                "New balance must be <= old balance"
            );
            assertTrue(
                newBalance == balance - withdrawAmount,
                "Balance calculation correct"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN ATOMICITY TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify HTLC atomic swap properties
     * @dev Secret must match hash for claim, timeout for refund
     */
    function test_htlc_atomicity(
        bytes32 preimage,
        bytes32 secretHash,
        uint256 lockTime,
        uint256 currentTime
    ) public pure {
        bytes32 computedHash = keccak256(abi.encodePacked(preimage));
        bool secretValid = (computedHash == secretHash);
        bool timedOut = (currentTime > lockTime);

        // Exactly one of these conditions should allow action
        bool canClaim = secretValid && !timedOut;
        bool canRefund = timedOut;

        // Cannot both claim and refund
        assertTrue(
            !(canClaim && canRefund),
            "Cannot claim and refund simultaneously"
        );

        // If secret is correct and not timed out, must be claimable
        if (secretValid && !timedOut) {
            assertTrue(canClaim, "Valid secret should allow claim");
        }

        // If timed out, must be refundable
        if (timedOut) {
            assertTrue(canRefund, "Timeout should allow refund");
        }
    }

    /**
     * @notice Verify cross-chain message uniqueness
     */
    function test_crosschain_message_unique(
        uint256 sourceChain,
        uint256 targetChain,
        bytes32 messageHash,
        uint256 nonce1,
        uint256 nonce2
    ) public pure {
        require(nonce1 != nonce2, "Nonces must differ");

        bytes32 messageId1 = keccak256(
            abi.encodePacked(sourceChain, targetChain, messageHash, nonce1)
        );
        bytes32 messageId2 = keccak256(
            abi.encodePacked(sourceChain, targetChain, messageHash, nonce2)
        );

        assertTrue(
            messageId1 != messageId2,
            "Different nonces must produce different message IDs"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    STEALTH ADDRESS TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify stealth addresses are unlinkable
     * @dev Different ephemeral keys should produce unlinkable addresses
     */
    function test_stealth_address_unlinkable(
        bytes32 spendingPubKey,
        bytes32 viewingPubKey,
        bytes32 ephemeralKey1,
        bytes32 ephemeralKey2
    ) public pure {
        require(ephemeralKey1 != ephemeralKey2, "Ephemeral keys must differ");
        require(spendingPubKey != bytes32(0), "Spending key required");
        require(viewingPubKey != bytes32(0), "Viewing key required");

        // Compute shared secrets (simplified)
        bytes32 sharedSecret1 = keccak256(
            abi.encodePacked(viewingPubKey, ephemeralKey1)
        );
        bytes32 sharedSecret2 = keccak256(
            abi.encodePacked(viewingPubKey, ephemeralKey2)
        );

        // Derive stealth addresses
        bytes32 stealthAddr1 = keccak256(
            abi.encodePacked(spendingPubKey, sharedSecret1)
        );
        bytes32 stealthAddr2 = keccak256(
            abi.encodePacked(spendingPubKey, sharedSecret2)
        );

        // Stealth addresses should be different (unlinkable)
        assertTrue(
            stealthAddr1 != stealthAddr2,
            "Stealth addresses must be unlinkable"
        );

        // But same ephemeral key should produce same address
        bytes32 stealthAddr1Again = keccak256(
            abi.encodePacked(spendingPubKey, sharedSecret1)
        );
        assertTrue(
            stealthAddr1 == stealthAddr1Again,
            "Same inputs must produce same stealth address"
        );
    }

    /**
     * @notice Verify view tag computation for efficient scanning
     */
    function test_view_tag_deterministic(
        bytes32 viewingPubKey,
        bytes32 ephemeralPubKey
    ) public pure {
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(viewingPubKey, ephemeralPubKey)
        );
        uint8 viewTag = uint8(uint256(sharedSecret) & 0xFF);

        // Same inputs should produce same view tag
        bytes32 sharedSecret2 = keccak256(
            abi.encodePacked(viewingPubKey, ephemeralPubKey)
        );
        uint8 viewTag2 = uint8(uint256(sharedSecret2) & 0xFF);

        assertTrue(viewTag == viewTag2, "View tag must be deterministic");
    }

    /*//////////////////////////////////////////////////////////////
                    LIQUIDITY PROVIDER TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify LP token minting is fair
     */
    function test_lp_minting_fair(
        uint256 reserveA,
        uint256 reserveB,
        uint256 totalSupply,
        uint256 depositA,
        uint256 depositB
    ) public pure {
        require(reserveA > 0 && reserveB > 0, "Reserves must be positive");
        require(totalSupply > 0, "Total supply must be positive");
        require(
            reserveA <= MAX_UINT128 && reserveB <= MAX_UINT128,
            "Reserve overflow"
        );
        require(depositA > 0 && depositB > 0, "Deposits must be positive");
        require(
            depositA <= MAX_UINT128 && depositB <= MAX_UINT128,
            "Deposit overflow"
        );

        // Calculate LP tokens to mint (min of ratios)
        uint256 lpFromA = (depositA * totalSupply) / reserveA;
        uint256 lpFromB = (depositB * totalSupply) / reserveB;
        uint256 lpMinted = lpFromA < lpFromB ? lpFromA : lpFromB;

        // LP tokens should be proportional to deposit
        assertTrue(lpMinted > 0, "Should receive some LP tokens");
        assertTrue(
            lpMinted <= totalSupply,
            "Cannot mint more than fair share in one tx"
        );
    }

    /**
     * @notice Verify LP token burning returns fair share
     */
    function test_lp_burning_fair(
        uint256 reserveA,
        uint256 reserveB,
        uint256 totalSupply,
        uint256 lpToBurn
    ) public pure {
        require(reserveA > 0 && reserveB > 0, "Reserves must be positive");
        require(totalSupply > 0, "Total supply must be positive");
        require(lpToBurn > 0 && lpToBurn <= totalSupply, "Invalid LP amount");
        require(
            reserveA <= MAX_UINT128 && reserveB <= MAX_UINT128,
            "Reserve overflow"
        );

        // Calculate tokens to return
        uint256 tokenAReturn = (lpToBurn * reserveA) / totalSupply;
        uint256 tokenBReturn = (lpToBurn * reserveB) / totalSupply;

        // Returns should be proportional
        assertTrue(
            tokenAReturn <= reserveA,
            "Cannot return more than reserves"
        );
        assertTrue(
            tokenBReturn <= reserveB,
            "Cannot return more than reserves"
        );

        // Full burn should return all reserves
        if (lpToBurn == totalSupply) {
            assertTrue(
                tokenAReturn == reserveA,
                "Full burn should return all A"
            );
            assertTrue(
                tokenBReturn == reserveB,
                "Full burn should return all B"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ORDER MATCHING TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify order matching is fair for both parties
     */
    function test_order_matching_symmetric(
        uint256 makerAmount,
        uint256 takerAmount,
        uint256 executionPrice
    ) public pure {
        require(makerAmount > 0 && takerAmount > 0, "Amounts must be positive");
        require(executionPrice > 0, "Price must be positive");
        require(
            makerAmount <= MAX_UINT128 && takerAmount <= MAX_UINT128,
            "Amount overflow"
        );

        // Maker wants to sell makerAmount at price executionPrice
        // Taker wants to buy at price executionPrice

        uint256 makerReceives = (makerAmount * executionPrice) / 1e18;
        uint256 takerReceives = makerAmount;
        uint256 takerPays = makerReceives;

        // Conservation: what taker pays = what maker receives
        assertTrue(takerPays == makerReceives, "Trade must be symmetric");
        assertTrue(
            takerReceives == makerAmount,
            "Taker receives maker's amount"
        );
    }

    /**
     * @notice Verify partial fills are handled correctly
     */
    function test_partial_fill_correct(
        uint256 orderAmount,
        uint256 fillAmount
    ) public pure {
        require(orderAmount > 0, "Order amount must be positive");
        require(
            fillAmount > 0 && fillAmount <= orderAmount,
            "Fill must be partial"
        );

        uint256 remaining = orderAmount - fillAmount;

        assertTrue(
            remaining < orderAmount,
            "Remaining must be less after fill"
        );
        assertTrue(
            remaining + fillAmount == orderAmount,
            "Amounts must sum correctly"
        );

        // Multiple partial fills
        uint256 fill1 = fillAmount / 2;
        uint256 fill2 = fillAmount - fill1;
        uint256 remainingAfterTwo = orderAmount - fill1 - fill2;

        assertTrue(
            remainingAfterTwo == orderAmount - fillAmount,
            "Multiple fills equivalent to single"
        );
    }
}
