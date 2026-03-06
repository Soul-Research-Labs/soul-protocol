// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CrossChainLiquidityVault} from "../../contracts/bridge/CrossChainLiquidityVault.sol";
import {ICrossChainLiquidityVault} from "../../contracts/interfaces/ICrossChainLiquidityVault.sol";

contract CrossChainLiquidityVaultFuzzTest is Test {
    CrossChainLiquidityVault vault;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address guardian = makeAddr("guardian");
    address privacyHub = makeAddr("privacyHub");
    address lp = makeAddr("lp");

    uint256 constant LP_FEE_BPS = 5000;
    uint256 constant MIN_DEPOSIT = 0.01 ether;
    uint256 constant WITHDRAWAL_COOLDOWN = 1 hours;
    uint256 constant LOCK_DURATION = 7 days;

    function setUp() public {
        vault = new CrossChainLiquidityVault(
            admin,
            operator,
            guardian,
            privacyHub,
            LP_FEE_BPS
        );
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _depositAs(address who, uint256 amt) internal {
        vm.deal(who, amt);
        vm.prank(who);
        vault.depositETH{value: amt}();
    }

    function _lockAs(bytes32 reqId, uint256 amt, uint256 destChain) internal {
        vm.prank(privacyHub);
        vault.lockLiquidity(reqId, address(0), amt, destChain);
    }

    // -------------------------------------------------------------------------
    // testFuzz_depositWithdraw_accounting
    // -------------------------------------------------------------------------

    function testFuzz_depositWithdraw_accounting(
        uint96 depositAmt,
        uint96 withdrawAmt
    ) public {
        // Bound deposit to valid range
        uint256 dep = bound(uint256(depositAmt), MIN_DEPOSIT, type(uint96).max);
        uint256 wit = bound(uint256(withdrawAmt), 1, dep);

        // Deposit
        _depositAs(lp, dep);
        assertEq(vault.totalETH(), dep, "totalETH after deposit");
        assertEq(vault.lpEthDeposited(lp), dep, "lp balance after deposit");

        // Advance past cooldown
        vm.warp(block.timestamp + WITHDRAWAL_COOLDOWN + 1);

        // Withdraw
        vm.prank(lp);
        vault.withdrawETH(wit);

        assertEq(vault.totalETH(), dep - wit, "totalETH after withdraw");
        assertEq(
            vault.lpEthDeposited(lp),
            dep - wit,
            "lp balance after withdraw"
        );
    }

    // -------------------------------------------------------------------------
    // testFuzz_lockRelease_invariant
    // -------------------------------------------------------------------------

    function testFuzz_lockRelease_invariant(uint96 lockAmt) public {
        uint256 amt = bound(uint256(lockAmt), MIN_DEPOSIT, type(uint96).max);

        // Seed vault with enough liquidity
        _depositAs(lp, amt);

        bytes32 reqId = keccak256(abi.encodePacked("lock", amt));

        // Lock
        _lockAs(reqId, amt, 42161);
        assertEq(vault.totalETHLocked(), amt, "locked after lock");

        // Unlock via unlockAfterCompletion (simulates successful relay)
        vm.prank(privacyHub);
        vault.unlockAfterCompletion(reqId);

        assertEq(vault.totalETHLocked(), 0, "locked should return to 0");
        // totalETH unchanged because lock/unlock doesn't move tokens out
        assertEq(vault.totalETH(), amt, "totalETH unchanged after lock cycle");
    }

    // -------------------------------------------------------------------------
    // testFuzz_refundExpiredLock_timing
    // -------------------------------------------------------------------------

    function testFuzz_refundExpiredLock_timing(uint32 timeDelta) public {
        uint256 amt = 1 ether;
        _depositAs(lp, amt);

        bytes32 reqId = keccak256("refund-timing");
        _lockAs(reqId, amt, 10);

        uint256 lockTime = block.timestamp;
        uint256 expiry = lockTime + LOCK_DURATION;

        // Warp by fuzzed delta
        uint256 warpTo = lockTime + uint256(timeDelta);
        vm.warp(warpTo);

        if (warpTo < expiry) {
            // Should revert — lock not expired yet
            vm.expectRevert(
                abi.encodeWithSelector(
                    ICrossChainLiquidityVault.LockNotExpired.selector,
                    reqId
                )
            );
            vault.refundExpiredLock(reqId);

            // totalETHLocked still held
            assertEq(vault.totalETHLocked(), amt, "still locked before expiry");
        } else {
            // Should succeed — lock expired
            vault.refundExpiredLock(reqId);

            assertEq(vault.totalETHLocked(), 0, "unlocked after refund");
        }
    }

    // -------------------------------------------------------------------------
    // testFuzz_withdrawCooldown_enforcement
    // -------------------------------------------------------------------------

    function testFuzz_withdrawCooldown_enforcement(uint32 timeDelta) public {
        uint256 dep = 1 ether;
        _depositAs(lp, dep);

        uint256 depositTime = block.timestamp;
        uint256 cooldownEnd = depositTime + WITHDRAWAL_COOLDOWN;

        // Warp by fuzzed delta
        uint256 warpTo = depositTime + uint256(timeDelta);
        vm.warp(warpTo);

        vm.prank(lp);

        if (warpTo < cooldownEnd) {
            // Should revert with cooldown error
            vm.expectRevert(
                abi.encodeWithSelector(
                    ICrossChainLiquidityVault.WithdrawalCooldownActive.selector,
                    cooldownEnd
                )
            );
            vault.withdrawETH(dep);
        } else {
            // Should succeed
            vault.withdrawETH(dep);
            assertEq(vault.totalETH(), 0, "fully withdrawn");
        }
    }

    // -------------------------------------------------------------------------
    // testFuzz_netFlows_consistency
    // -------------------------------------------------------------------------

    function testFuzz_netFlows_consistency(uint96 amt1, uint96 amt2) public {
        uint256 a1 = bound(uint256(amt1), MIN_DEPOSIT, type(uint96).max);
        uint256 a2 = bound(uint256(amt2), MIN_DEPOSIT, type(uint96).max);

        uint256 totalDeposit = a1 + a2; // safe — both are uint96
        _depositAs(lp, totalDeposit);

        uint256 remoteChain = 42161;

        // Lock a1 for remoteChain (source-side lock)
        bytes32 req1 = keccak256(abi.encodePacked("flow1", a1));
        _lockAs(req1, a1, remoteChain);

        // Release a2 on behalf of remoteChain (destination-side release)
        address recipient = makeAddr("recipient");
        vm.deal(address(vault), address(vault).balance); // ensure balance
        vm.prank(privacyHub);
        vault.releaseLiquidity(
            keccak256(abi.encodePacked("release1", a2)),
            address(0),
            recipient,
            a2,
            remoteChain
        );

        // Net flow for remoteChain should be +a2 (we released a2 on their behalf)
        // lockLiquidity does NOT update netFlows; releaseLiquidity adds +amount
        (uint256 netAmt, bool isOutflow) = vault.getNetSettlement(
            remoteChain,
            address(0)
        );
        assertEq(netAmt, a2, "net amount = released amount");
        assertFalse(isOutflow, "remote chain owes us (inflow)");

        // Unlock the lock (simulates completion on dest side)
        vm.prank(privacyHub);
        vault.unlockAfterCompletion(req1);

        // unlockAfterCompletion adjusts netFlows by -lockAmount for destChain
        (uint256 netAfter, bool isOutflowAfter) = vault.getNetSettlement(
            remoteChain,
            address(0)
        );

        // netFlows = +a2 (release) - a1 (unlock) = a2 - a1
        if (a2 >= a1) {
            assertEq(netAfter, a2 - a1, "net = a2 - a1");
            assertFalse(isOutflowAfter, "still inflow or zero");
        } else {
            assertEq(netAfter, a1 - a2, "net = a1 - a2");
            assertTrue(isOutflowAfter, "we owe remote chain");
        }

        // Verify totalETHLocked is back to 0
        assertEq(vault.totalETHLocked(), 0, "all locks released");
    }
}
