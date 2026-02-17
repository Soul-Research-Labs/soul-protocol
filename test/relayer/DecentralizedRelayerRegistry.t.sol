// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";

contract DecentralizedRelayerRegistryTest is Test {
    DecentralizedRelayerRegistry public registry;
    address public admin = address(this);
    address public relayer = makeAddr("relayer");
    address public slasher = makeAddr("slasher");

    function setUp() public {
        registry = new DecentralizedRelayerRegistry(admin);
        
        // Grant slasher role
        registry.grantRole(registry.SLASHER_ROLE(), slasher);
        
        // Fund relayer
        vm.deal(relayer, 100 ether);
    }

    function test_RegisterWithStake() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();
        vm.stopPrank();

        (uint256 stake, , , bool isRegistered) = registry.relayers(relayer);
        assertEq(stake, 10 ether);
        assertTrue(isRegistered);
    }

    function test_UnstakeWaitPeriod() public {
        vm.startPrank(relayer);
        registry.register{value: 10 ether}();
        
        registry.initiateUnstake();
        
        (,, uint256 unlockTime, ) = registry.relayers(relayer);
        assertEq(unlockTime, block.timestamp + 7 days);
        
        // Try withdraw too early
        vm.expectRevert("Still locked");
        registry.withdrawStake();
        
        // Wait
        vm.warp(unlockTime + 1);
        
        uint256 balanceBefore = relayer.balance;
        registry.withdrawStake();
        uint256 balanceAfter = relayer.balance;
        
        assertEq(balanceAfter - balanceBefore, 10 ether);
        
        (uint256 stake,,, bool isRegistered) = registry.relayers(relayer);
        assertEq(stake, 0);
        assertFalse(isRegistered);
        vm.stopPrank();
    }

    function test_Slash() public {
        vm.prank(relayer);
        registry.register{value: 20 ether}();
        
        address insuranceFund = makeAddr("insurance");
        
        vm.prank(slasher);
        registry.slash(relayer, 5 ether, insuranceFund);
        
        (uint256 stake,,,) = registry.relayers(relayer);
        assertEq(stake, 15 ether);
        assertEq(insuranceFund.balance, 5 ether);
    }
}
