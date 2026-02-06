// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BitVMBridge.sol";

contract BitVMBridgeFuzz is Test {
    BitVMBridge public bridge;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public prover = address(0xD);
    address public user1 = address(0xE);

    function setUp() public {
        bridge = new BitVMBridge(admin);
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.PROVER_ROLE(), prover);
        vm.stopPrank();
    }

    // --- Deposit Initiation ---
    function testFuzz_initiateDeposit(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 100 ether);
        vm.deal(user1, amount + 1 ether);
        vm.prank(user1);
        bytes32 depositId = bridge.initiateDeposit{value: amount}(amount, bytes32(uint256(1)), prover);
        assertTrue(depositId != bytes32(0));
    }

    function testFuzz_initiateDepositZeroReverts() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateDeposit{value: 0}(0, bytes32(uint256(1)), prover);
    }

    // --- Challenge ---
    function testFuzz_openChallengeRequiresStake(uint256 stake) public {
        vm.assume(stake < 0.1 ether);
        // First create a deposit
        vm.deal(user1, 10 ether);
        vm.prank(user1);
        bytes32 depositId = bridge.initiateDeposit{value: 2 ether}(2 ether, bytes32(uint256(1)), prover);

        // Commit as prover
        vm.deal(prover, 2 ether);
        vm.prank(prover);
        bridge.commitDeposit{value: 1 ether}(depositId, bytes32(uint256(2)), bytes32(uint256(3)));

        // Challenge with insufficient stake
        vm.deal(user1, stake);
        vm.prank(user1);
        (bool success,) = address(bridge).call{value: stake}(
            abi.encodeWithSelector(
                bridge.openChallenge.selector,
                depositId, bytes32(uint256(5)), bytes32(uint256(6))
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

    function testFuzz_onlyGuardianPauses(address caller) public {
        vm.assume(caller != admin && caller != guardian);
        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    // --- Circuit Registration ---
    function testFuzz_registerCircuit(bytes32 circuitId, uint256 numGates, uint256 numInputs, uint256 numOutputs) public {
        vm.assume(circuitId != bytes32(0));
        numGates = bound(numGates, 1, 1000);
        numInputs = bound(numInputs, 1, 100);
        numOutputs = bound(numOutputs, 1, 100);
        vm.prank(operator);
        bridge.registerCircuit(circuitId, numGates, numInputs, numOutputs, bytes32(uint256(1)));
    }

    // --- Gate Commitment ---
    function testFuzz_commitGate(bytes32 gateId) public {
        vm.prank(prover);
        bridge.commitGate(gateId, IBitVMBridge.GateType.NAND, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)));
    }

    // --- Stats ---
    function test_initialStats() public view {
        (uint256 dc, uint256 cc, uint256 sc, uint256 fc) = bridge.getBridgeStats();
        assertEq(dc, 0);
        assertEq(cc, 0);
        assertEq(sc, 0);
        assertEq(fc, 0);
    }

    // --- Access Control ---
    function testFuzz_onlyOperatorConfigures(address caller) public {
        vm.assume(caller != admin && caller != operator);
        vm.prank(caller);
        vm.expectRevert();
        bridge.configure(address(1), address(2));
    }

    // --- Deposit Not Found ---
    function testFuzz_getDepositNotFound(bytes32 id) public view {
        IBitVMBridge.BitVMDeposit memory dep = bridge.getDeposit(id);
        assertEq(dep.amount, 0);
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
