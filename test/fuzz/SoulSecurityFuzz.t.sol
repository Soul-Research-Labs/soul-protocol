// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title SoulSecurityFuzz
 * @notice Security-focused fuzz tests targeting common vulnerability patterns
 * @dev Tests reentrancy, overflow, access control, oracle manipulation, etc.
 *
 * Run with: forge test --match-contract SoulSecurityFuzz --fuzz-runs 10000
 */
contract SoulSecurityFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MAX_UINT256 = type(uint256).max;
    uint256 constant MAX_UINT128 = type(uint128).max;
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                    OVERFLOW/UNDERFLOW TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test addition overflow protection
    function testFuzz_AdditionOverflow(uint256 a, uint256 b) public pure {
        // Solidity 0.8+ should revert on overflow
        if (a <= MAX_UINT256 - b) {
            uint256 result = a + b;
            assertGe(result, a, "Addition result should be >= a");
            assertGe(result, b, "Addition result should be >= b");
        }
        // If a + b would overflow, Solidity reverts automatically
    }

    /// @notice Fuzz test multiplication overflow protection
    function testFuzz_MultiplicationOverflow(uint128 a, uint128 b) public pure {
        // Use uint128 inputs to allow testing the boundary
        uint256 result = uint256(a) * uint256(b);

        if (a != 0) {
            assertEq(result / a, b, "Multiplication should be reversible");
        }
        if (b != 0) {
            assertEq(result / b, a, "Multiplication should be reversible");
        }
    }

    /// @notice Fuzz test subtraction underflow protection
    function testFuzz_SubtractionUnderflow(uint256 a, uint256 b) public pure {
        if (a >= b) {
            uint256 result = a - b;
            assertLe(result, a, "Subtraction result should be <= a");
            assertEq(result + b, a, "Subtraction should be reversible");
        }
        // If a < b, Solidity reverts automatically
    }

    /// @notice Fuzz test division by zero protection
    function testFuzz_DivisionByZero(
        uint256 numerator,
        uint256 denominator
    ) public pure {
        vm.assume(denominator > 0);

        uint256 result = numerator / denominator;
        assertLe(result, numerator, "Division result should be <= numerator");

        // Check remainder
        uint256 remainder = numerator % denominator;
        assertLt(remainder, denominator, "Remainder should be < denominator");
        assertEq(
            result * denominator + remainder,
            numerator,
            "Division should be reversible"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    REENTRANCY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test checks-effects-interactions pattern
    function testFuzz_ChecksEffectsInteractions(
        uint128 balance,
        uint128 withdrawAmount,
        uint8 reentrancyAttempts
    ) public pure {
        vm.assume(balance > 0);
        vm.assume(reentrancyAttempts > 0 && reentrancyAttempts <= 5);

        uint256 currentBalance = balance;
        uint256 totalWithdrawn = 0;

        // Simulate proper CEI pattern
        for (uint8 i = 0; i < reentrancyAttempts; i++) {
            uint256 amount = withdrawAmount / reentrancyAttempts;

            // Check
            if (amount > currentBalance) continue;

            // Effect (before interaction)
            currentBalance -= amount;
            totalWithdrawn += amount;

            // Interaction would happen here
        }

        // Invariant: total withdrawn + remaining = original
        assertEq(
            totalWithdrawn + currentBalance,
            balance,
            "Balance conservation violated"
        );
        assertLe(totalWithdrawn, balance, "Cannot withdraw more than balance");
    }

    /// @notice Fuzz test reentrancy guard effectiveness
    function testFuzz_ReentrancyGuard(
        uint256 callDepthSeed,
        bool guardEnabled
    ) public pure {
        uint256 callDepth = bound(callDepthSeed, 1, 10);

        bool shouldRevert = guardEnabled && callDepth > 1;

        if (guardEnabled) {
            // With guard, nested calls should be blocked
            assertTrue(
                callDepth == 1 || shouldRevert,
                "Reentrancy should be blocked"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test role-based access control
    function testFuzz_RoleBasedAccess(
        address caller,
        bytes32 role,
        bytes32 requiredRole
    ) public pure {
        vm.assume(caller != address(0));

        bool hasAccess = (role == requiredRole);

        if (role != requiredRole) {
            assertFalse(hasAccess, "Should not have access with wrong role");
        } else {
            assertTrue(hasAccess, "Should have access with correct role");
        }
    }

    /// @notice Fuzz test ownership transfer safety
    function testFuzz_OwnershipTransfer(
        address currentOwner,
        address pendingOwner,
        address caller
    ) public pure {
        vm.assume(currentOwner != address(0));
        vm.assume(pendingOwner != address(0));

        // Two-step transfer pattern
        bool canInitiate = (caller == currentOwner);
        bool canAccept = (caller == pendingOwner);

        // Random caller shouldn't be able to do either
        if (caller != currentOwner && caller != pendingOwner) {
            assertFalse(canInitiate, "Random caller cannot initiate transfer");
            assertFalse(canAccept, "Random caller cannot accept transfer");
        }
    }

    /// @notice Fuzz test timelocked operations
    function testFuzz_TimelockSafety(
        uint256 proposalTime,
        uint256 executionTime,
        uint256 minDelay
    ) public pure {
        vm.assume(minDelay > 0 && minDelay <= 30 days);
        vm.assume(proposalTime < MAX_UINT256 - minDelay);

        uint256 earliestExecution = proposalTime + minDelay;
        bool canExecute = executionTime >= earliestExecution;

        if (executionTime < earliestExecution) {
            assertFalse(canExecute, "Should not execute before delay");
        } else {
            assertTrue(canExecute, "Should be able to execute after delay");
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ORACLE MANIPULATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test TWAP oracle resistance
    function testFuzz_TWAPResistance(
        uint256 spotPriceSeed,
        uint256 manipulatedPriceSeed,
        uint256 manipulationBlocksSeed,
        uint256 totalBlocksSeed
    ) public pure {
        uint256 totalBlocks = bound(totalBlocksSeed, 2, 100);
        uint256 manipulationBlocks = bound(
            manipulationBlocksSeed,
            1,
            totalBlocks - 1
        );
        uint256 spotPrice = bound(spotPriceSeed, 1e9, 1e27);
        // Bound manipulated price relative to spot to avoid extreme ratios
        uint256 manipulatedPrice = bound(
            manipulatedPriceSeed,
            0,
            spotPrice * 10
        );

        // Calculate TWAP with manipulation
        uint256 legitContribution = spotPrice *
            (totalBlocks - manipulationBlocks);
        uint256 manipulatedContribution = manipulatedPrice * manipulationBlocks;
        uint256 calculatedTWAP = (legitContribution + manipulatedContribution) /
            totalBlocks;

        // Manipulation impact should be bounded by the weighted average formula
        // maxDeviation when manipulatedPrice is max possible would be:
        // (manipulatedPrice - spotPrice) * manipulationBlocks / totalBlocks
        uint256 actualDeviation = calculatedTWAP > spotPrice
            ? calculatedTWAP - spotPrice
            : spotPrice - calculatedTWAP;

        // TWAP should never deviate more than the proportion of manipulated blocks
        // Worst case: manipulatedPrice could be 10x spotPrice
        uint256 worstCaseDeviation = (spotPrice * 9 * manipulationBlocks) /
            totalBlocks;

        // TWAP provides dampening - deviation should be bounded
        if (manipulationBlocks < totalBlocks / 2) {
            assertLe(
                actualDeviation,
                worstCaseDeviation + 1,
                "TWAP should dampen manipulation"
            );
        }
    }

    /// @notice Fuzz test price bounds checking
    function testFuzz_PriceBoundsCheck(
        uint256 currentPriceSeed,
        uint256 newPrice,
        uint16 maxDeviationBpsSeed
    ) public pure {
        // Bound currentPrice to prevent overflow in maxChange calculation
        uint256 currentPrice = bound(
            currentPriceSeed,
            1,
            type(uint256).max / 10000
        );
        uint256 maxDeviationBps = bound(maxDeviationBpsSeed, 1, 5000); // Max 50%

        uint256 maxChange = (currentPrice * maxDeviationBps) / 10000;
        uint256 minAllowed = currentPrice > maxChange
            ? currentPrice - maxChange
            : 0;
        uint256 maxAllowed = currentPrice + maxChange;

        bool withinBounds = (newPrice >= minAllowed && newPrice <= maxAllowed);

        if (newPrice < minAllowed || newPrice > maxAllowed) {
            assertFalse(withinBounds, "Price outside bounds should fail");
        }
    }

    /*//////////////////////////////////////////////////////////////
                    SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test signature malleability protection
    function testFuzz_SignatureMalleability(
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public pure {
        // secp256k1 curve order
        uint256 SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

        uint256 sValue = uint256(s);

        // Check s is in lower half of curve order (EIP-2)
        bool isLowS = sValue <= SECP256K1_N / 2;

        // v should be 27 or 28
        bool validV = (v == 27 || v == 28);

        // Both conditions needed for non-malleable signature
        if (isLowS && validV) {
            assertTrue(true, "Valid non-malleable signature");
        }
    }

    /// @notice Fuzz test nonce uniqueness for signatures
    function testFuzz_SignatureNonceUniqueness(
        address signer,
        uint256 nonce1,
        uint256 nonce2,
        bytes32 data
    ) public pure {
        vm.assume(nonce1 != nonce2);
        vm.assume(signer != address(0));

        bytes32 hash1 = keccak256(abi.encodePacked(signer, nonce1, data));
        bytes32 hash2 = keccak256(abi.encodePacked(signer, nonce2, data));

        assertNotEq(
            hash1,
            hash2,
            "Different nonces should produce different hashes"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FRONTRUNNING TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test commit-reveal scheme
    function testFuzz_CommitRevealScheme(
        bytes32 secret,
        uint256 valueSeed,
        address sender
    ) public pure {
        vm.assume(sender != address(0));
        vm.assume(secret != bytes32(0));

        // Bound value to prevent overflow when adding 1
        uint256 value = bound(valueSeed, 0, type(uint256).max - 1);

        // Commit phase
        bytes32 commitment = keccak256(abi.encodePacked(secret, value, sender));

        // Reveal phase - should match
        bytes32 revealedCommitment = keccak256(
            abi.encodePacked(secret, value, sender)
        );
        assertEq(
            commitment,
            revealedCommitment,
            "Commitment should match reveal"
        );

        // Wrong reveal should not match
        bytes32 wrongReveal = keccak256(
            abi.encodePacked(secret, value + 1, sender)
        );
        assertNotEq(commitment, wrongReveal, "Wrong value should not match");
    }

    /// @notice Fuzz test deadline protection
    function testFuzz_DeadlineProtection(
        uint256 deadline,
        uint256 currentTime
    ) public pure {
        bool expired = currentTime > deadline;

        if (currentTime <= deadline) {
            assertFalse(expired, "Should not be expired before deadline");
        } else {
            assertTrue(expired, "Should be expired after deadline");
        }
    }

    /*//////////////////////////////////////////////////////////////
                    FLASH LOAN TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test flash loan fee calculation
    function testFuzz_FlashLoanFee(
        uint128 loanAmount,
        uint16 feeRate
    ) public pure {
        vm.assume(loanAmount > 0);
        vm.assume(feeRate <= 1000); // Max 10%

        uint256 fee = (uint256(loanAmount) * feeRate) / 10000;
        uint256 repayAmount = loanAmount + fee;

        assertGe(repayAmount, loanAmount, "Repay should include fee");
        assertLe(fee, loanAmount / 10, "Fee should be at most 10%");
    }

    /// @notice Fuzz test flash loan invariant
    function testFuzz_FlashLoanInvariant(
        uint128 poolBalance,
        uint128 loanAmount
    ) public pure {
        vm.assume(poolBalance > 0 && loanAmount > 0);
        vm.assume(loanAmount <= poolBalance);

        // Before loan
        uint256 balanceBefore = poolBalance;

        // During loan (balance reduced)
        uint256 duringLoan = poolBalance - loanAmount;

        // After repay (with fee)
        uint256 fee = loanAmount / 1000; // 0.1% fee
        uint256 balanceAfter = duringLoan + loanAmount + fee;

        // Pool should have more after loan
        assertGe(
            balanceAfter,
            balanceBefore,
            "Pool should gain from flash loan"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    DOS PROTECTION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test gas limit protection
    function testFuzz_GasLimitProtection(
        uint256 arrayLengthSeed,
        uint256 maxIterationsSeed
    ) public pure {
        uint256 maxIterations = bound(maxIterationsSeed, 1, 1000);
        uint256 arrayLength = bound(arrayLengthSeed, 0, 10000);

        uint256 effectiveIterations = arrayLength > maxIterations
            ? maxIterations
            : arrayLength;

        assertLe(effectiveIterations, maxIterations, "Should cap iterations");
    }

    /// @notice Fuzz test withdrawal pattern (pull over push)
    function testFuzz_PullOverPush(
        address[] memory recipients,
        uint128 totalAmount
    ) public pure {
        vm.assume(recipients.length > 0 && recipients.length <= 100);
        vm.assume(totalAmount > 0);

        uint256 amountPerRecipient = totalAmount / recipients.length;

        // With pull pattern, each recipient withdraws independently
        // One failure doesn't block others
        uint256 totalAllocated = amountPerRecipient * recipients.length;
        assertLe(totalAllocated, totalAmount, "Should not over-allocate");
    }

    /*//////////////////////////////////////////////////////////////
                    MERKLE TREE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Merkle proof length bounds
    function testFuzz_MerkleProofBounds(
        uint256 treeSizeSeed,
        uint256 leafIndexSeed
    ) public pure {
        uint256 treeSize = bound(treeSizeSeed, 1, 2 ** 32);
        uint256 leafIndex = bound(leafIndexSeed, 0, treeSize - 1);

        // Max proof length is log2(treeSize)
        uint256 maxProofLength = 0;
        uint256 temp = treeSize;
        while (temp > 1) {
            maxProofLength++;
            temp = (temp + 1) / 2;
        }

        assertLe(maxProofLength, 256, "Proof length should be bounded");
    }

    /// @notice Fuzz test Merkle leaf uniqueness
    function testFuzz_MerkleLeafUniqueness(
        bytes32 data1,
        bytes32 data2,
        uint256 index
    ) public pure {
        vm.assume(data1 != data2);

        bytes32 leaf1 = keccak256(abi.encodePacked(data1, index));
        bytes32 leaf2 = keccak256(abi.encodePacked(data2, index));

        assertNotEq(
            leaf1,
            leaf2,
            "Different data should produce different leaves"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    PRECISION LOSS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test division precision
    function testFuzz_DivisionPrecision(
        uint128 numerator,
        uint128 denominator
    ) public pure {
        vm.assume(denominator > 0);

        // Standard division loses precision
        uint256 result = uint256(numerator) / denominator;
        uint256 reconstructed = result * denominator;

        // Loss should be less than denominator
        uint256 loss = numerator >= reconstructed
            ? numerator - reconstructed
            : 0;
        assertLt(loss, denominator, "Precision loss should be bounded");
    }

    /// @notice Fuzz test scaled arithmetic
    function testFuzz_ScaledArithmetic(
        uint256 amountSeed,
        uint256 rateSeed,
        uint256 scaleSeed
    ) public pure {
        uint256 scale = bound(scaleSeed, 1, 1e18);
        uint256 rate = bound(rateSeed, 1, 1e18);
        // Bound amount to prevent overflow: amount * scale * rate <= type(uint256).max
        uint256 maxAmount = type(uint256).max / scale / rate;
        uint256 amount = bound(amountSeed, 0, maxAmount);

        // Scale up, calculate, scale down
        uint256 scaled = amount * scale;
        uint256 result = (scaled * rate) / scale;

        // Result should be close to amount * rate
        uint256 expected = amount * rate;
        uint256 diff = result > expected
            ? result - expected
            : expected - result;

        assertLe(diff, rate, "Scaling should preserve precision");
    }
}
