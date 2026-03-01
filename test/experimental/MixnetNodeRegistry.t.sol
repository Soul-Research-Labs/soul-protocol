// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MixnetNodeRegistry} from "../../contracts/experimental/privacy/MixnetNodeRegistry.sol";
import {ExperimentalFeatureRegistry} from "../../contracts/security/ExperimentalFeatureRegistry.sol";

/**
 * @title MixnetNodeRegistryTest
 * @notice Tests for the experimental mixnet node registry
 */
contract MixnetNodeRegistryTest is Test {
    MixnetNodeRegistry public registry;
    ExperimentalFeatureRegistry public featureReg;

    address admin = makeAddr("admin");
    address operator1 = makeAddr("operator1");
    address operator2 = makeAddr("operator2");

    bytes32 constant PUB_KEY_1 = keccak256("pubkey1");
    bytes32 constant PUB_KEY_2 = keccak256("pubkey2");
    bytes constant ENC_KEY_1 = hex"aabbccdd";
    bytes constant ENC_KEY_2 = hex"11223344";

    function setUp() public {
        vm.startPrank(admin);
        featureReg = new ExperimentalFeatureRegistry(admin);

        // Feature is already registered as EXPERIMENTAL by the registry constructor

        registry = new MixnetNodeRegistry(admin, address(featureReg));
        vm.stopPrank();
    }

    // =========================================================================
    // DEPLOYMENT
    // =========================================================================

    function test_deployment() public view {
        assertEq(registry.totalActiveNodes(), 0);
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.OPERATOR_ROLE(), admin));
        assertTrue(registry.hasRole(registry.SLASHER_ROLE(), admin));
    }

    function test_constructor_zeroAdmin_reverts() public {
        vm.expectRevert();
        new MixnetNodeRegistry(address(0), address(featureReg));
    }

    // =========================================================================
    // REGISTER NODE
    // =========================================================================

    function test_registerNode() public {
        vm.deal(operator1, 1 ether);
        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);

        assertEq(registry.totalActiveNodes(), 1);
        // nodeId uses block.timestamp, so retrieve via operatorNode mapping
        bytes32 nodeId = registry.operatorNode(operator1);
        assertTrue(nodeId != bytes32(0));
        assertTrue(registry.isNodeActive(nodeId));
    }

    function test_registerNode_insufficientStake_reverts() public {
        vm.deal(operator1, 1 ether);
        vm.prank(operator1);
        vm.expectRevert();
        registry.registerNode{value: 0.01 ether}(PUB_KEY_1, ENC_KEY_1, 0);
    }

    function test_registerNode_invalidLayer_reverts() public {
        vm.deal(operator1, 1 ether);
        vm.prank(operator1);
        vm.expectRevert();
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 6); // MAX_LAYERS = 5
    }

    function test_registerNode_duplicateOperator_reverts() public {
        vm.deal(operator1, 2 ether);
        vm.startPrank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        vm.expectRevert();
        registry.registerNode{value: 0.1 ether}(PUB_KEY_2, ENC_KEY_2, 1);
        vm.stopPrank();
    }

    // =========================================================================
    // DEREGISTER / EXIT
    // =========================================================================

    function test_deregisterAndFinalizeExit() public {
        vm.deal(operator1, 1 ether);

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        assertEq(registry.totalActiveNodes(), 1);
        bytes32 nodeId = registry.operatorNode(operator1);

        // Deregister
        vm.prank(operator1);
        registry.deregisterNode(nodeId);

        // Can't exit before delay
        vm.prank(operator1);
        vm.expectRevert();
        registry.finalizeExit(nodeId);

        // Warp past EXIT_DELAY
        vm.warp(block.timestamp + 7 days + 1);
        uint256 balanceBefore = operator1.balance;
        vm.prank(operator1);
        registry.finalizeExit(nodeId);

        // Stake returned
        assertTrue(operator1.balance > balanceBefore);
        assertEq(registry.totalActiveNodes(), 0);
    }

    // =========================================================================
    // KEY ROTATION
    // =========================================================================

    function test_rotateKeys() public {
        vm.deal(operator1, 1 ether);

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        // Warp past MIN_ROTATION_INTERVAL
        vm.warp(block.timestamp + 1 hours + 1);

        bytes32 newPubKey = keccak256("newPubKey");
        bytes memory newEncKey = hex"55667788";
        vm.prank(operator1);
        registry.rotateKeys(nodeId, newPubKey, newEncKey);
    }

    function test_rotateKeys_tooSoon_reverts() public {
        vm.deal(operator1, 1 ether);

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        // Try to rotate immediately
        vm.prank(operator1);
        vm.expectRevert();
        registry.rotateKeys(nodeId, keccak256("newKey"), hex"aabb");
    }

    // =========================================================================
    // SLASHING
    // =========================================================================

    function test_slashNode() public {
        vm.deal(operator1, 1 ether);

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        bytes memory evidence = abi.encodePacked("misbehavior");
        vm.prank(admin);
        registry.slashNode(nodeId, evidence);

        // Node should be deactivated and stake partially slashed
        assertFalse(registry.isNodeActive(nodeId));
        assertTrue(registry.slashingPool() > 0);
    }

    // =========================================================================
    // REPUTATION
    // =========================================================================

    function test_updateReputation() public {
        vm.deal(operator1, 1 ether);

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        vm.prank(admin); // admin has OPERATOR_ROLE
        registry.updateReputation(nodeId, 9000);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_getActiveNodes_byLayer() public {
        vm.deal(operator1, 1 ether);
        vm.deal(operator2, 1 ether);

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);

        vm.prank(operator2);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_2, ENC_KEY_2, 0);

        bytes32[] memory nodesLayer0 = registry.getActiveNodes(0);
        assertEq(nodesLayer0.length, 2);
    }

    function test_minimumStake() public view {
        assertEq(registry.minimumStake(), 0.1 ether);
    }

    // =========================================================================
    // PAUSE
    // =========================================================================

    function test_pause_unpause() public {
        vm.prank(admin);
        registry.pause();

        vm.deal(operator1, 1 ether);
        vm.prank(operator1);
        vm.expectRevert();
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);

        vm.prank(admin);
        registry.unpause();

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY_1, 0);
        assertEq(registry.totalActiveNodes(), 1);
    }
}
