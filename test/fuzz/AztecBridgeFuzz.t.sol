// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/AztecBridgeAdapter.sol";

contract AztecBridgeFuzz is Test {
    AztecBridgeAdapter public bridge;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public relayer = address(0xD);
    address public user1 = address(0xE);

    function setUp() public {
        bridge = new AztecBridgeAdapter(admin);
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        vm.stopPrank();
    }

    // --- Bridge Amount Validation ---
    function testFuzz_bridgeSoulToAztecAmountTooLow(uint256 amount) public {
        vm.assume(amount < 0.01 ether && amount > 0);
        uint256 fee = (amount * 10) / 10000;
        vm.deal(user1, amount + fee);
        vm.prank(user1);
        (bool success,) = address(bridge).call{value: amount + fee}(
            abi.encodeWithSelector(
                bridge.bridgeSoulToAztec.selector,
                bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)),
                amount, uint8(0), bytes32(0), hex"0000"
            )
        );
        assertFalse(success);
    }

    function testFuzz_bridgeSoulToAztecAmountTooHigh(uint256 amount) public {
        amount = bound(amount, 1001 ether, 10000 ether);
        uint256 fee = (amount * 10) / 10000;
        vm.deal(user1, amount + fee);
        vm.prank(user1);
        (bool success,) = address(bridge).call{value: amount + fee}(
            abi.encodeWithSelector(
                bridge.bridgeSoulToAztec.selector,
                bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)),
                amount, uint8(0), bytes32(0), hex"0000"
            )
        );
        assertFalse(success);
    }

    // --- Nullifier Protection ---
    function testFuzz_nullifierNotUsedByDefault(bytes32 nullifier) public view {
        assertFalse(bridge.isNullifierUsed(nullifier));
    }

    // --- Access Control ---
    function testFuzz_onlyOperatorConfiguresAztec(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.configureAztecContracts(address(1), address(2), address(3));
    }

    function testFuzz_onlyAdminSetsTreasury(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setTreasury(address(0x999));
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

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != guardian);
        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    // --- Stats ---
    function test_initialStats() public view {
        (uint256 pending, uint256 toAztec, uint256 fromAztec, uint256 fees, uint256 rollup) = bridge.getBridgeStats();
        assertEq(pending, 0);
        assertEq(toAztec, 0);
        assertEq(fromAztec, 0);
        assertEq(fees, 0);
        assertEq(rollup, 0);
    }

    // --- Request Not Found ---
    function testFuzz_getSoulToAztecRequestNotFound(bytes32 id) public view {
        IAztecBridgeAdapter.SoulToAztecRequest memory req = bridge.getSoulToAztecRequest(id);
        assertEq(req.amount, 0);
    }

    function testFuzz_getAztecToSoulRequestNotFound(bytes32 id) public view {
        IAztecBridgeAdapter.AztecToSoulRequest memory req = bridge.getAztecToSoulRequest(id);
        assertEq(req.amount, 0);
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
