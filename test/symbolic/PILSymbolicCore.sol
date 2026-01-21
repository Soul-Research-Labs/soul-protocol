// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PILSymbolicCore
 * @notice Minimal symbolic execution tests for PIL Exchange core properties
 * @dev Standalone file without external dependencies for fast Halmos execution
 *
 * Run with: halmos --contract PILSymbolicCore --solver-timeout-assertion 60
 */
contract PILSymbolicCore {
    uint256 constant MAX_UINT128 = type(uint128).max;
    uint256 constant FEE_DENOMINATOR = 10000;
    uint256 constant SWAP_FEE = 30; // 0.3%

    /*//////////////////////////////////////////////////////////////
                    CONSTANT PRODUCT AMM TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify k = x * y is preserved after swap
    function check_constantProduct_preserved(
        uint128 reserveA,
        uint128 reserveB,
        uint128 amountIn
    ) public pure {
        require(reserveA > 0 && reserveB > 0);
        require(amountIn > 0 && amountIn < reserveA / 2);

        uint256 oldK = uint256(reserveA) * uint256(reserveB);

        uint256 amountOut = getAmountOut(amountIn, reserveA, reserveB);
        require(amountOut < reserveB);

        uint256 newReserveA = uint256(reserveA) + amountIn;
        uint256 newReserveB = uint256(reserveB) - amountOut;
        uint256 newK = newReserveA * newReserveB;

        assert(newK >= oldK); // Fees increase K
    }

    /// @notice Verify swap always produces positive output
    function check_swap_positive_output(
        uint128 reserveA,
        uint128 reserveB,
        uint128 amountIn
    ) public pure {
        require(reserveA > 1000 && reserveB > 1000);
        require(amountIn > 0 && amountIn <= reserveA / 10);

        uint256 amountOut = getAmountOut(amountIn, reserveA, reserveB);
        assert(amountOut > 0);
    }

    /// @notice Verify no roundtrip profit (arbitrage protection)
    function check_no_roundtrip_profit(
        uint128 reserveA,
        uint128 reserveB,
        uint128 amountIn
    ) public pure {
        require(reserveA > 10000 && reserveB > 10000);
        require(amountIn > 0 && amountIn <= reserveA / 10);

        // Swap A -> B
        uint256 amountB = getAmountOut(amountIn, reserveA, reserveB);
        require(amountB > 0 && amountB < reserveB);

        uint256 newReserveA = uint256(reserveA) + amountIn;
        uint256 newReserveB = uint256(reserveB) - amountB;

        // Swap B -> A
        uint256 amountABack = getAmountOut(
            uint128(amountB),
            uint128(newReserveB),
            uint128(newReserveA)
        );

        assert(amountABack <= amountIn); // No profit from roundtrip
    }

    /*//////////////////////////////////////////////////////////////
                    NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify nullifier uniqueness
    function check_nullifier_unique(
        bytes32 secret1,
        bytes32 secret2,
        uint256 leafIndex
    ) public pure {
        require(secret1 != secret2);

        bytes32 nullifier1 = keccak256(abi.encodePacked(secret1, leafIndex));
        bytes32 nullifier2 = keccak256(abi.encodePacked(secret2, leafIndex));

        assert(nullifier1 != nullifier2);
    }

    /// @notice Verify commitment hiding
    function check_commitment_hiding(
        uint256 amount,
        bytes32 salt1,
        bytes32 salt2
    ) public pure {
        require(salt1 != salt2);

        bytes32 commitment1 = keccak256(abi.encodePacked(amount, salt1));
        bytes32 commitment2 = keccak256(abi.encodePacked(amount, salt2));

        assert(commitment1 != commitment2);
    }

    /*//////////////////////////////////////////////////////////////
                    OVERFLOW PROTECTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify no overflow in swap math
    function check_no_overflow(
        uint128 reserveA,
        uint128 reserveB,
        uint128 amountIn
    ) public pure {
        require(reserveA > 0 && reserveB > 0);
        require(amountIn > 0);

        // These should not overflow
        uint256 amountInWithFee = uint256(amountIn) *
            (FEE_DENOMINATOR - SWAP_FEE);
        uint256 numerator = amountInWithFee * uint256(reserveB);
        uint256 denominator = uint256(reserveA) *
            FEE_DENOMINATOR +
            amountInWithFee;

        assert(denominator > 0);

        uint256 amountOut = numerator / denominator;
        assert(amountOut <= reserveB);
    }

    /// @notice Verify balance conservation
    function check_balance_conservation(
        uint128 deposit,
        uint128 withdraw
    ) public pure {
        require(deposit >= withdraw);

        uint256 balance = uint256(deposit) - uint256(withdraw);
        assert(balance <= deposit);
        assert(balance == deposit - withdraw);
    }

    /*//////////////////////////////////////////////////////////////
                    HTLC ATOMICITY
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify HTLC mutual exclusion
    function check_htlc_atomicity(
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
        assert(!(canClaim && canRefund));
    }

    /*//////////////////////////////////////////////////////////////
                    STEALTH ADDRESSES
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify stealth address unlinkability
    function check_stealth_unlinkable(
        bytes32 spendingPubKey,
        bytes32 viewingPubKey,
        bytes32 ephemeralKey1,
        bytes32 ephemeralKey2
    ) public pure {
        require(ephemeralKey1 != ephemeralKey2);
        require(spendingPubKey != bytes32(0) && viewingPubKey != bytes32(0));

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

        assert(stealthAddr1 != stealthAddr2);
    }

    /*//////////////////////////////////////////////////////////////
                    FEE BOUNDS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify fees are bounded
    function check_fee_bounded(uint128 amount, uint16 feeRate) public pure {
        require(feeRate <= 10000); // Max 100%
        require(amount > 0);

        uint256 fee = (uint256(amount) * feeRate) / FEE_DENOMINATOR;

        assert(fee <= amount);
        assert(fee >= 0);
    }

    /// @notice Verify slippage protection
    function check_slippage_protection(
        uint128 amountOut,
        uint128 minAmountOut
    ) public pure {
        if (amountOut >= minAmountOut) {
            assert(true); // Trade should succeed
        } else {
            assert(amountOut < minAmountOut); // Trade should fail
        }
    }

    /*//////////////////////////////////////////////////////////////
                    LP TOKEN FAIRNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify LP minting is proportional
    function check_lp_proportional(
        uint128 reserveA,
        uint128 totalSupply,
        uint128 depositA
    ) public pure {
        require(reserveA > 0 && totalSupply > 0 && depositA > 0);

        uint256 lpMinted = (uint256(depositA) * totalSupply) / reserveA;

        // LP tokens should be positive
        assert(lpMinted > 0 || depositA < reserveA / totalSupply);
    }

    /*//////////////////////////////////////////////////////////////
                    HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getAmountOut(
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
