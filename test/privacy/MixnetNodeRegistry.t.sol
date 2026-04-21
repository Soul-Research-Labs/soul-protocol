// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MixnetNodeRegistry} from "../../contracts/privacy/MixnetNodeRegistry.sol";
import {IMixnetNodeRegistry} from "../../contracts/interfaces/IMixnetNodeRegistry.sol";

/// @title MixnetNodeRegistry targeted unit tests
/// @notice Closes the coverage gap flagged by the Phase 0 survey: the registry
///         previously had no dedicated test file.
contract MixnetNodeRegistryTest is Test {
    MixnetNodeRegistry internal reg;

    address internal admin = address(0xA11CE);
    address internal op1 = address(0xB0B);
    address internal op2 = address(0xC0DE);

    bytes internal pubKey = new bytes(32);

    function setUp() public {
        vm.prank(admin);
        reg = new MixnetNodeRegistry(admin);
        // Deterministic X25519-shaped key material.
        for (uint8 i; i < 32; ++i) pubKey[i] = bytes1(i + 1);

        vm.deal(op1, 10 ether);
        vm.deal(op2, 10 ether);
    }

    // -------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------

    function test_register_success() public {
        uint32[] memory chains = new uint32[](2);
        chains[0] = 1;
        chains[1] = 10;

        vm.prank(op1);
        reg.registerNode{value: 1 ether}(bytes32("n1"), pubKey, chains);

        assertEq(reg.totalActiveNodes(), 1);
        assertEq(reg.allNodeIds(0), bytes32("n1"));
    }

    function test_register_revertsOnLowStake() public {
        uint32[] memory chains = new uint32[](1);
        chains[0] = 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                IMixnetNodeRegistry.InsufficientStake.selector,
                0.5 ether,
                1 ether
            )
        );
        vm.prank(op1);
        reg.registerNode{value: 0.5 ether}(bytes32("n1"), pubKey, chains);
    }

    function test_register_revertsOnBadKey() public {
        uint32[] memory chains = new uint32[](1);
        chains[0] = 1;

        bytes memory badKey = new bytes(16); // wrong length

        vm.expectRevert(IMixnetNodeRegistry.InvalidEncryptionKey.selector);
        vm.prank(op1);
        reg.registerNode{value: 1 ether}(bytes32("n1"), badKey, chains);
    }

    // -------------------------------------------------------------------
    // Deactivation + withdrawal delay
    // -------------------------------------------------------------------

    function test_deactivate_onlyByOperator() public {
        _register(op1, bytes32("n1"));

        vm.prank(op2);
        vm.expectRevert();
        reg.deactivateNode(bytes32("n1"));
    }

    function test_deactivate_decrementsActive() public {
        _register(op1, bytes32("n1"));
        assertEq(reg.totalActiveNodes(), 1);

        vm.prank(op1);
        reg.deactivateNode(bytes32("n1"));
        assertEq(reg.totalActiveNodes(), 0);
    }

    function test_withdraw_revertsBeforeDelay() public {
        _register(op1, bytes32("n1"));
        vm.prank(op1);
        reg.deactivateNode(bytes32("n1"));

        vm.prank(op1);
        vm.expectRevert();
        reg.withdrawStake(bytes32("n1"));
    }

    function test_withdraw_succeedsAfterDelay() public {
        _register(op1, bytes32("n1"));
        vm.prank(op1);
        reg.deactivateNode(bytes32("n1"));

        vm.warp(block.timestamp + 7 days + 1);
        uint256 balBefore = op1.balance;

        vm.prank(op1);
        reg.withdrawStake(bytes32("n1"));

        assertEq(op1.balance, balBefore + 1 ether);
    }

    // -------------------------------------------------------------------
    // Path selection
    // -------------------------------------------------------------------

    function test_selectPath_revertsOnInsufficientNodes() public {
        _register(op1, bytes32("n1"));

        vm.expectRevert(); // InsufficientActiveNodes
        reg.selectRelayPath(1, 10, 2);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _register(address op, bytes32 id) internal {
        uint32[] memory chains = new uint32[](2);
        chains[0] = 1;
        chains[1] = 10;
        vm.prank(op);
        reg.registerNode{value: 1 ether}(id, pubKey, chains);
    }
}
