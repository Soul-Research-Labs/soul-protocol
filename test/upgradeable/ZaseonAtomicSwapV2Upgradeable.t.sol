// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ZaseonAtomicSwapV2Upgradeable} from "../../contracts/upgradeable/ZaseonAtomicSwapV2Upgradeable.sol";

contract ZaseonAtomicSwapV2UpgradeableTest is Test {
    ZaseonAtomicSwapV2Upgradeable public impl;
    ZaseonAtomicSwapV2Upgradeable public swap;
    address owner = address(this);
    address feeRecipient = address(0xFEE);

    // Accept ETH refunds
    receive() external payable {}

    function setUp() public {
        impl = new ZaseonAtomicSwapV2Upgradeable();
        bytes memory data = abi.encodeCall(
            impl.initialize,
            (owner, feeRecipient)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
        swap = ZaseonAtomicSwapV2Upgradeable(payable(address(proxy)));
    }

    function test_InitializerSetsAdmin() public view {
        assertTrue(swap.hasRole(swap.DEFAULT_ADMIN_ROLE(), owner));
        assertTrue(swap.hasRole(swap.UPGRADER_ROLE(), owner));
        assertTrue(swap.hasRole(swap.OPERATOR_ROLE(), owner));
        assertTrue(swap.hasRole(swap.EMERGENCY_ROLE(), owner));
    }

    function test_InitializerSetsFeeRecipient() public view {
        assertEq(swap.feeRecipient(), feeRecipient);
    }

    function test_DefaultProtocolFee() public view {
        assertEq(swap.protocolFeeBps(), 10); // 0.1%
    }

    function test_ContractVersion() public view {
        assertEq(swap.contractVersion(), 1);
    }

    function test_CannotDoubleInitialize() public {
        vm.expectRevert();
        swap.initialize(owner, feeRecipient);
    }

    function test_SetProtocolFee() public {
        swap.setProtocolFee(50); // 0.5%
        assertEq(swap.protocolFeeBps(), 50);
    }

    function test_SetFeeRecipient() public {
        address newRecipient = address(0xBEEF);
        swap.setFeeRecipient(newRecipient);
        assertEq(swap.feeRecipient(), newRecipient);
    }

    function test_PauseUnpause() public {
        swap.pause();
        assertTrue(swap.paused());
        swap.unpause();
        assertFalse(swap.paused());
    }

    function test_CreateSwapETH() public {
        address recipient = address(0x1234);
        bytes32 hashLock = keccak256("secret");
        uint256 timelock = block.timestamp + 1 hours;
        bytes32 stealthPubKey = bytes32(0);

        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            recipient,
            hashLock,
            timelock,
            stealthPubKey
        );
        assertTrue(swapId != bytes32(0));
    }

    function test_OnlyOperatorCanSetFee() public {
        address attacker = address(0xDEAD);
        vm.prank(attacker);
        vm.expectRevert();
        swap.setProtocolFee(100);
    }

    function test_RefundAfterTimelock() public {
        address recipient = address(0x1234);
        bytes32 hashLock = keccak256("secret");
        uint256 timelock = block.timestamp + 1 hours;

        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            recipient,
            hashLock,
            timelock,
            bytes32(0)
        );

        // Warp past timelock
        vm.warp(block.timestamp + 2 hours);

        swap.refund(swapId);
    }
}
