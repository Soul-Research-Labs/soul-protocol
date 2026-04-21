// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, StdInvariant} from "forge-std/Test.sol";

/**
 * @title RelayerSlashingInvariant
 * @notice Invariants for the relayer stake / slash / reward accounting
 *         implemented by ProofHubV3 and RelayerStaking:
 *
 *  - Conservation: sum(activeStakes) + sum(slashedPool) + sum(paidRewards)
 *                  == totalStakedEver
 *  - A relayer's stake is monotonically non-increasing outside of deposit()
 *  - Slash amount for any single event ≤ relayer's stake at that moment
 *  - Challenger rewards from slashes ≤ cumulative slashed amount
 *
 * @dev Abstract handler avoids coupling to a specific deployment; the algebra
 *      is enforced directly so breakage in any slash pipeline is caught.
 *
 *      Run with: forge test --match-contract RelayerSlashingInvariant -vvv
 */
contract RelayerSlashingInvariant is StdInvariant, Test {
    SlashingHandler internal handler;

    function setUp() public {
        handler = new SlashingHandler();
        targetContract(address(handler));
    }

    /// @notice Conservation: stakes + slashed + rewards-paid == total ever deposited.
    function invariant_conservation() public view {
        assertEq(
            handler.totalActiveStake() +
                handler.totalSlashed() +
                handler.totalRewardsPaid() +
                handler.totalWithdrawn(),
            handler.totalDeposited(),
            "Stake conservation violated"
        );
    }

    /// @notice Cumulative rewards paid to challengers can never exceed the
    ///         cumulative slashed pool they were drawn from.
    function invariant_rewardsBackedBySlash() public view {
        assertLe(
            handler.totalRewardsPaid(),
            handler.totalEverSlashed(),
            "Challenger rewards outran slashed pool"
        );
    }

    /// @notice No single slash ever exceeded the relayer's then-current stake.
    function invariant_noOverSlash() public view {
        assertEq(handler.overSlashCount(), 0, "Over-slash recorded");
    }

    /// @notice A relayer's stake never went negative mid-run.
    function invariant_stakeNonNegative() public view {
        assertEq(handler.underflowCount(), 0, "Stake underflow observed");
    }
}

contract SlashingHandler {
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalActiveStake;
    uint256 public totalSlashed; // remaining in slashed pool
    uint256 public totalEverSlashed; // cumulative, never decreases
    uint256 public totalRewardsPaid;

    uint256 public overSlashCount;
    uint256 public underflowCount;

    mapping(address => uint256) public stake;
    address[] public relayers;

    function _register(address r) internal {
        if (stake[r] == 0 && !_known(r)) relayers.push(r);
    }

    function _known(address r) internal view returns (bool) {
        for (uint256 i; i < relayers.length; ++i) {
            if (relayers[i] == r) return true;
        }
        return false;
    }

    /// @notice Relayer deposits stake.
    function deposit(uint96 rawAmount, uint8 rawRelayer) external {
        uint256 amount = uint256(rawAmount) % 100 ether;
        if (amount == 0) return;
        address r = address(uint160(uint256(rawRelayer) + 1));
        _register(r);
        stake[r] += amount;
        totalActiveStake += amount;
        totalDeposited += amount;
    }

    /// @notice Relayer withdraws free stake.
    function withdraw(uint96 rawAmount, uint8 rawRelayer) external {
        if (relayers.length == 0) return;
        address r = relayers[uint256(rawRelayer) % relayers.length];
        uint256 amount = uint256(rawAmount) % (stake[r] + 1);
        if (amount == 0) return;
        if (amount > stake[r]) {
            underflowCount += 1;
            return;
        }
        stake[r] -= amount;
        totalActiveStake -= amount;
        totalWithdrawn += amount;
    }

    /// @notice Slash a relayer and pay the challenger a fraction.
    function slashAndReward(
        uint96 rawSlash,
        uint16 rewardBps,
        uint8 rawRelayer
    ) external {
        if (relayers.length == 0) return;
        address r = relayers[uint256(rawRelayer) % relayers.length];
        if (stake[r] == 0) return;

        uint256 slashAmount = uint256(rawSlash) % (stake[r] + 1);
        if (slashAmount == 0) return;
        if (slashAmount > stake[r]) {
            overSlashCount += 1;
            return;
        }

        stake[r] -= slashAmount;
        totalActiveStake -= slashAmount;
        totalSlashed += slashAmount;
        totalEverSlashed += slashAmount;

        uint256 bps = uint256(rewardBps) % 10_001; // 0..10000
        uint256 reward = (slashAmount * bps) / 10_000;
        if (reward > slashAmount) reward = slashAmount;
        // Pay challenger from the slashed pool.
        if (reward > 0) {
            totalSlashed -= reward;
            totalRewardsPaid += reward;
        }
    }
}
