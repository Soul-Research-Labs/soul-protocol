// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BitcoinBridgeAdapter.sol";

contract BitcoinBridgeFuzz is Test {
    BitcoinBridgeAdapter public bridge;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public relayer = address(0xD);
    address public user1 = address(0xE);

    function setUp() public {
        bridge = new BitcoinBridgeAdapter(admin);
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        vm.stopPrank();
    }

    // --- HTLC Creation ---
    function testFuzz_createHTLC(bytes32 hashlock, uint256 timelock) public {
        vm.assume(hashlock != bytes32(0));
        timelock = bound(timelock, 1 hours, 7 days);
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        bytes32 htlcId = bridge.createHTLC{value: 0.5 ether}(hashlock, timelock, admin);
        assertTrue(htlcId != bytes32(0));
    }

    function testFuzz_createHTLCTimelockTooShort(uint256 timelock) public {
        vm.assume(timelock < 1 hours && timelock > 0);
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        bridge.createHTLC{value: 0.5 ether}(bytes32(uint256(1)), timelock, admin);
    }

    function testFuzz_createHTLCTimelockTooLong(uint256 timelock) public {
        vm.assume(timelock > 7 days);
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        bridge.createHTLC{value: 0.5 ether}(bytes32(uint256(1)), timelock, admin);
    }

    // --- HTLC Redeem ---
    function testFuzz_redeemHTLCRequiresCorrectPreimage(bytes32 preimage) public {
        bytes32 hashlock = keccak256(abi.encodePacked(preimage));
        vm.deal(user1, 1 ether);
        address payable recipient = payable(address(0xBEEF));

        vm.prank(user1);
        bytes32 htlcId = bridge.createHTLC{value: 0.5 ether}(hashlock, 24 hours, recipient);

        vm.prank(recipient);
        bridge.redeemHTLC(htlcId, preimage);
        assertEq(recipient.balance, 0.5 ether);
    }

    function testFuzz_redeemHTLCWrongPreimage(bytes32 preimage, bytes32 wrongPreimage) public {
        vm.assume(preimage != wrongPreimage);
        bytes32 hashlock = keccak256(abi.encodePacked(preimage));
        vm.deal(user1, 1 ether);

        vm.prank(user1);
        bytes32 htlcId = bridge.createHTLC{value: 0.5 ether}(hashlock, 24 hours, admin);

        vm.prank(admin);
        vm.expectRevert();
        bridge.redeemHTLC(htlcId, wrongPreimage);
    }

    // --- HTLC Refund ---
    function testFuzz_refundHTLCBeforeTimelock(bytes32 preimage) public {
        bytes32 hashlock = keccak256(abi.encodePacked(preimage));
        vm.deal(user1, 1 ether);

        vm.prank(user1);
        bytes32 htlcId = bridge.createHTLC{value: 0.5 ether}(hashlock, 24 hours, admin);

        vm.prank(user1);
        vm.expectRevert();
        bridge.refundHTLC(htlcId);
    }

    function test_refundHTLCAfterTimelock() public {
        bytes32 hashlock = keccak256(abi.encodePacked(bytes32(uint256(42))));
        vm.deal(user1, 1 ether);

        vm.prank(user1);
        bytes32 htlcId = bridge.createHTLC{value: 0.5 ether}(hashlock, 1 hours, admin);

        vm.warp(block.timestamp + 2 hours);
        vm.prank(user1);
        bridge.refundHTLC(htlcId);
    }

    // --- Withdrawal ---
    function testFuzz_initiateWithdrawalAmountValidation(uint256 satoshis) public {
        satoshis = bound(satoshis, 1, 99999); // below min
        bytes32 hashlock = keccak256(abi.encodePacked(bytes32(satoshis)));
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        (bool success,) = address(bridge).call{value: 0.5 ether}(
            abi.encodeWithSelector(
                bridge.initiateWithdrawal.selector,
                bytes20(uint160(admin)), satoshis, hashlock, 24 hours
            )
        );
        assertFalse(success);
    }

    // --- Pause ---
    function test_pauseAndUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
        vm.prank(guardian);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function testFuzz_pauseBlocksHTLC(bytes32 hashlock) public {
        vm.assume(hashlock != bytes32(0));
        vm.prank(guardian);
        bridge.pause();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        bridge.createHTLC{value: 0.5 ether}(hashlock, 24 hours, admin);
    }

    // --- Access Control ---
    function testFuzz_onlyRelayerInitiatesDeposit(address caller) public {
        vm.assume(caller != admin && caller != relayer);
        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateBTCDeposit(bytes32(uint256(1)), hex"01", new bytes32[](0), hex"02", user1);
    }

    // --- Stats ---
    function test_initialStats() public view {
        (uint256 d, uint256 w, uint256 ht, uint256 hr, uint256 hrf, uint256 f) = bridge.getBridgeStats();
        assertEq(d, 0);
        assertEq(w, 0);
        assertEq(ht, 0);
        assertEq(hr, 0);
        assertEq(hrf, 0);
        assertEq(f, 0);
    }

    // --- HTLC Not Found ---
    function testFuzz_getHTLCNotFound(bytes32 id) public view {
        IBitcoinBridgeAdapter.HTLC memory htlc = bridge.getHTLC(id);
        assertEq(htlc.amount, 0);
    }

    // --- Receive ---
    function testFuzz_receiveETH(uint256 amount) public {
        amount = bound(amount, 1, 10 ether);
        vm.deal(user1, amount);
        vm.prank(user1);
        (bool ok,) = address(bridge).call{value: amount}("");
        assertTrue(ok);
    }
}
