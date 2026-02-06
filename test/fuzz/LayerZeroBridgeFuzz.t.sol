// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/LayerZeroBridgeAdapter.sol";

contract LayerZeroBridgeFuzz is Test {
    LayerZeroBridgeAdapter public bridge;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public executor = address(0xD);
    address public configAdmin = address(0xE);
    address public user1 = address(0xF);

    function setUp() public {
        vm.prank(admin);
        bridge = new LayerZeroBridgeAdapter();
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.EXECUTOR_ROLE(), executor);
        bridge.grantRole(bridge.CONFIG_ROLE(), configAdmin);
        bridge.setEndpoint(address(0x1234), 30101);
        vm.stopPrank();
    }

    // --- Endpoint Configuration ---
    function testFuzz_setEndpoint(address endpoint, uint32 eid) public {
        vm.assume(endpoint != address(0) && eid != 0);
        vm.prank(admin);
        bridge.setEndpoint(endpoint, eid);
        assertEq(bridge.lzEndpoint(), endpoint);
        assertEq(bridge.localEid(), eid);
    }

    function testFuzz_setEndpointZeroAddressReverts(uint32 eid) public {
        vm.assume(eid != 0);
        vm.prank(admin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEndpoint.selector);
        bridge.setEndpoint(address(0), eid);
    }

    function testFuzz_setEndpointZeroEidReverts(address endpoint) public {
        vm.assume(endpoint != address(0));
        vm.prank(admin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        bridge.setEndpoint(endpoint, 0);
    }

    // --- Bridge Fee ---
    function testFuzz_setBridgeFee(uint256 fee) public {
        fee = bound(fee, 0, 100);
        vm.prank(admin);
        bridge.setBridgeFee(fee);
        assertEq(bridge.bridgeFee(), fee);
    }

    function testFuzz_setBridgeFeeTooHighReverts(uint256 fee) public {
        fee = bound(fee, 101, type(uint256).max);
        vm.prank(admin);
        vm.expectRevert(LayerZeroBridgeAdapter.FeeTooHigh.selector);
        bridge.setBridgeFee(fee);
    }

    // --- Peer Management ---
    function testFuzz_setPeer(uint32 eid, bytes32 peerAddr, uint256 minGas) public {
        vm.assume(eid != 0 && peerAddr != bytes32(0));
        minGas = bound(minGas, 0, 10_000_000);
        vm.prank(configAdmin);
        bridge.setPeer(
            eid,
            peerAddr,
            LayerZeroBridgeAdapter.ChainType.EVM,
            minGas,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );
        (uint32 storedEid, bytes32 storedPeer,,bool active,,,) = bridge.peers(eid);
        assertEq(storedEid, eid);
        assertEq(storedPeer, peerAddr);
        assertTrue(active);
    }

    function testFuzz_setPeerDuplicateReverts(uint32 eid, bytes32 peerAddr) public {
        vm.assume(eid != 0 && peerAddr != bytes32(0));
        vm.startPrank(configAdmin);
        bridge.setPeer(eid, peerAddr, LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerAlreadySet.selector);
        bridge.setPeer(eid, peerAddr, LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.stopPrank();
    }

    function testFuzz_deactivatePeer(uint32 eid, bytes32 peerAddr) public {
        vm.assume(eid != 0 && peerAddr != bytes32(0));
        vm.prank(configAdmin);
        bridge.setPeer(eid, peerAddr, LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(guardian);
        bridge.deactivatePeer(eid);
        (,,, bool active,,,) = bridge.peers(eid);
        assertFalse(active);
    }

    // --- Security Level ---
    function testFuzz_updatePeerSecurity(uint32 eid, bytes32 peerAddr) public {
        vm.assume(eid != 0 && peerAddr != bytes32(0));
        vm.prank(configAdmin);
        bridge.setPeer(eid, peerAddr, LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(guardian);
        bridge.updatePeerSecurity(eid, LayerZeroBridgeAdapter.SecurityLevel.MAXIMUM);
        (,,,,, LayerZeroBridgeAdapter.SecurityLevel level,) = bridge.peers(eid);
        assertEq(uint8(level), uint8(LayerZeroBridgeAdapter.SecurityLevel.MAXIMUM));
    }

    // --- Pause ---
    function test_pauseAndUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
        vm.prank(admin);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function testFuzz_onlyGuardianPauses(address caller) public {
        vm.assume(caller != admin && caller != guardian);
        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    // --- Access Control ---
    function testFuzz_onlyAdminSetsEndpoint(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setEndpoint(address(0x99), 1);
    }

    function testFuzz_onlyConfigSetsPeer(address caller) public {
        vm.assume(caller != admin && caller != configAdmin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setPeer(1, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
    }

    // --- Stats ---
    function test_initialStats() public view {
        assertEq(bridge.totalMessagesSent(), 0);
        assertEq(bridge.totalMessagesReceived(), 0);
        assertEq(bridge.messageNonce(), 0);
    }

    // --- Receive ETH ---
    function testFuzz_lzSendRequiresPeer(uint32 dstEid) public {
        vm.assume(dstEid != 0);
        // Sending to a destination without a peer should revert
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        bridge.lzSend{value: 0.01 ether}(
            dstEid,
            bytes32(uint256(uint160(user1))),
            "hello",
            LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            })
        );
    }
}
