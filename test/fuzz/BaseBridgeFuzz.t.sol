// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BaseBridgeAdapter.sol";

contract BaseBridgeFuzz is Test {
    BaseBridgeAdapter public bridge;

    address public admin = address(0xA);
    address public l1Messenger = address(0xB1);
    address public l2Messenger = address(0xB2);
    address public portal = address(0xB3);

    address public operator;
    address public guardian = address(0xC);
    address public relayer = address(0xD);
    address public user1 = address(0xE);

    function setUp() public {
        operator = admin;
        bridge = new BaseBridgeAdapter(admin, l1Messenger, l2Messenger, portal, true);
        vm.startPrank(admin);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), admin);
        vm.stopPrank();
    }

    // --- Proof Relay ---
    function testFuzz_sendProofRequiresOperator(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.sendProofToL2(bytes32(uint256(1)), hex"01", hex"02", 500000);
    }

    function testFuzz_receiveProofRequiresRelayer(address caller) public {
        vm.assume(caller != admin && caller != relayer);
        vm.prank(caller);
        vm.expectRevert();
        bridge.receiveProofFromL1(bytes32(uint256(1)), hex"01", hex"02", 1);
    }

    // --- Proof Relay Tracking ---
    function testFuzz_proofRelayTracksCorrectly(bytes32 proofHash) public {
        assertFalse(bridge.isProofRelayed(proofHash));
        vm.prank(relayer);
        bridge.receiveProofFromL1(proofHash, hex"01", hex"02", 1);
        assertTrue(bridge.isProofRelayed(proofHash));
    }

    function testFuzz_duplicateProofRelayReverts(bytes32 proofHash) public {
        vm.prank(relayer);
        bridge.receiveProofFromL1(proofHash, hex"01", hex"02", 1);
        vm.prank(relayer);
        vm.expectRevert(BaseBridgeAdapter.ProofAlreadyRelayed.selector);
        bridge.receiveProofFromL1(proofHash, hex"01", hex"02", 1);
    }

    // --- State Sync ---
    function testFuzz_stateRootSync(bytes32 stateRoot, uint256 blockNum) public {
        vm.prank(relayer);
        bridge.receiveStateFromL1(stateRoot, blockNum);
        assertEq(bridge.confirmedStateRoots(stateRoot), blockNum);
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

    function testFuzz_pauseBlocksOperations(bytes32 proofHash) public {
        vm.prank(guardian);
        bridge.pause();
        vm.prank(relayer);
        vm.expectRevert();
        bridge.receiveProofFromL1(proofHash, hex"01", hex"02", 1);
    }

    // --- L2 Target ---
    function testFuzz_setL2Target(address target) public {
        vm.assume(target != address(0));
        vm.prank(admin);
        bridge.setL2Target(target);
        assertEq(bridge.l2Target(), target);
    }

    function testFuzz_onlyAdminSetsL2Target(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setL2Target(address(0x123));
    }

    // --- Stats ---
    function test_initialStats() public view {
        (uint256 sent, uint256 recv, uint256 val, uint256 usdc, uint256 nonce) = bridge.getStats();
        assertEq(sent, 0);
        assertEq(recv, 0);
        assertEq(val, 0);
        assertEq(usdc, 0);
        assertEq(nonce, 0);
    }

    // --- Emergency Withdraw ---
    function testFuzz_emergencyWithdrawOnlyAdmin(address caller) public {
        vm.assume(caller != admin);
        vm.deal(address(bridge), 1 ether);
        vm.prank(caller);
        vm.expectRevert();
        bridge.emergencyWithdraw(caller, 1 ether);
    }

    function test_emergencyWithdraw() public {
        vm.deal(address(bridge), 5 ether);
        address payable recipient = payable(address(0xBEEF));
        uint256 balBefore = recipient.balance;
        vm.prank(admin);
        bridge.emergencyWithdraw(recipient, 5 ether);
        assertEq(recipient.balance, balBefore + 5 ether);
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
