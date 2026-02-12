// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MixnetNodeRegistry, IMixnetNodeRegistry} from "../../contracts/experimental/privacy/MixnetNodeRegistry.sol";

/**
 * @title MixnetNodeRegistryTest
 * @notice Tests for MixnetNodeRegistry — node registration, rotation, slashing, exit
 */
contract MixnetNodeRegistryTest is Test {
    MixnetNodeRegistry public registry;
    address public admin = address(0xA);
    address public operator1 = address(0xB);
    address public operator2 = address(0xC);
    address public slasher = address(0xD);

    bytes32 constant PUB_KEY_1 = keccak256("pubkey1");
    bytes32 constant PUB_KEY_2 = keccak256("pubkey2");
    bytes constant ENC_KEY = hex"deadbeef";

    function setUp() public {
        registry = new MixnetNodeRegistry(admin);
        bytes32 slasherRole = keccak256("SLASHER_ROLE");
        vm.prank(admin);
        registry.grantRole(slasherRole, slasher);

        // Fund operators
        vm.deal(operator1, 10 ether);
        vm.deal(operator2, 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RegisterNode() public {
        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);

        assertEq(registry.totalActiveNodes(), 1);
    }

    function test_RegisterNode_InsufficientStake() public {
        vm.prank(operator1);
        vm.expectRevert(
            abi.encodeWithSelector(
                MixnetNodeRegistry.InsufficientStake.selector,
                0.01 ether,
                0.1 ether
            )
        );
        registry.registerNode{value: 0.01 ether}(PUB_KEY_1, ENC_KEY, 0);
    }

    function test_RegisterNode_InvalidLayer() public {
        vm.prank(operator1);
        vm.expectRevert(
            abi.encodeWithSelector(MixnetNodeRegistry.InvalidLayer.selector, 5)
        );
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 5);
    }

    function test_RegisterNode_InvalidPublicKey() public {
        vm.prank(operator1);
        vm.expectRevert(MixnetNodeRegistry.InvalidPublicKey.selector);
        registry.registerNode{value: 0.1 ether}(bytes32(0), ENC_KEY, 0);
    }

    function test_RegisterNode_OperatorAlreadyRegistered() public {
        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);

        vm.prank(operator1);
        vm.expectRevert(
            abi.encodeWithSelector(
                MixnetNodeRegistry.OperatorAlreadyRegistered.selector,
                operator1
            )
        );
        registry.registerNode{value: 0.1 ether}(PUB_KEY_2, ENC_KEY, 1);
    }

    function test_MultipleNodes() public {
        vm.prank(operator1);
        registry.registerNode{value: 0.5 ether}(PUB_KEY_1, ENC_KEY, 0);

        vm.prank(operator2);
        registry.registerNode{value: 0.5 ether}(PUB_KEY_2, ENC_KEY, 1);

        assertEq(registry.totalActiveNodes(), 2);

        bytes32[] memory layer0 = registry.getActiveNodes(0);
        bytes32[] memory layer1 = registry.getActiveNodes(1);
        assertEq(layer0.length, 1);
        assertEq(layer1.length, 1);
    }

    /*//////////////////////////////////////////////////////////////
                          KEY ROTATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RotateKeys() public {
        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);

        bytes32 nodeId = registry.operatorNode(operator1);

        // Advance time past rotation interval
        vm.warp(block.timestamp + 1 hours + 1);

        bytes32 newKey = keccak256("newkey");
        vm.prank(operator1);
        registry.rotateKeys(nodeId, newKey, hex"cafe");

        IMixnetNodeRegistry.MixnetNode memory node = registry.getNode(nodeId);
        assertEq(node.publicKey, newKey);
    }

    function test_RotateKeys_TooSoon() public {
        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        bytes32 newKey = keccak256("newkey");
        vm.prank(operator1);
        vm.expectRevert(); // RotationTooSoon
        registry.rotateKeys(nodeId, newKey, hex"cafe");
    }

    /*//////////////////////////////////////////////////////////////
                         DEREGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_DeregisterAndExit() public {
        vm.prank(operator1);
        registry.registerNode{value: 1 ether}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        // Deregister
        vm.prank(operator1);
        registry.deregisterNode(nodeId);
        assertEq(registry.totalActiveNodes(), 0);

        // Cannot exit before delay
        vm.prank(operator1);
        vm.expectRevert(); // ExitNotReady
        registry.finalizeExit(nodeId);

        // Advance past exit delay
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balBefore = operator1.balance;
        vm.prank(operator1);
        registry.finalizeExit(nodeId);

        assertEq(operator1.balance, balBefore + 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                           SLASHING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SlashNode() public {
        vm.prank(operator1);
        registry.registerNode{value: 2 ether}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        vm.prank(slasher);
        registry.slashNode(nodeId, hex"badbad");

        IMixnetNodeRegistry.MixnetNode memory node = registry.getNode(nodeId);
        assertEq(
            uint8(node.status),
            uint8(IMixnetNodeRegistry.NodeStatus.Slashed)
        );
        assertEq(node.stakedAmount, 1 ether); // 50% slashed
        assertEq(node.reputationScore, 0);
        assertEq(registry.slashingPool(), 1 ether);
        assertEq(registry.totalActiveNodes(), 0);
    }

    function test_SlashNode_OnlySlasherRole() public {
        vm.prank(operator1);
        registry.registerNode{value: 1 ether}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        vm.prank(operator2);
        vm.expectRevert(); // AccessControl
        registry.slashNode(nodeId, hex"badace");
    }

    /*//////////////////////////////////////////////////////////////
                          ROUTING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetRouteNodes() public {
        // Register nodes on layers 0, 1, 2
        address[3] memory ops = [
            address(0x100),
            address(0x200),
            address(0x300)
        ];
        for (uint16 i = 0; i < 3; i++) {
            vm.deal(ops[i], 1 ether);
            vm.prank(ops[i]);
            registry.registerNode{value: 0.1 ether}(
                keccak256(abi.encode("key", i)),
                ENC_KEY,
                i
            );
        }

        bytes32[] memory route = registry.getRouteNodes(3);
        assertEq(route.length, 3);
        // Each should be a valid node
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(registry.isNodeActive(route[i]));
        }
    }

    /*//////////////////////////////////////////////////////////////
                        REPUTATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UpdateReputation() public {
        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        vm.prank(admin);
        registry.updateReputation(nodeId, 9000);

        IMixnetNodeRegistry.MixnetNode memory node = registry.getNode(nodeId);
        assertEq(node.reputationScore, 9000);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PauseUnpause() public {
        vm.prank(admin);
        registry.pause();

        vm.prank(operator1);
        vm.expectRevert(); // Paused
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);

        vm.prank(admin);
        registry.unpause();

        vm.prank(operator1);
        registry.registerNode{value: 0.1 ether}(PUB_KEY_1, ENC_KEY, 0);
        assertEq(registry.totalActiveNodes(), 1);
    }

    function test_WithdrawSlashingPool() public {
        vm.prank(operator1);
        registry.registerNode{value: 2 ether}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        vm.prank(slasher);
        registry.slashNode(nodeId, hex"badbad");

        address treasury = address(0xFEED);
        uint256 poolAmount = registry.slashingPool();

        vm.prank(admin);
        registry.withdrawSlashingPool(treasury);

        assertEq(treasury.balance, poolAmount);
        assertEq(registry.slashingPool(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterNodeStakeRange(uint256 stake) public {
        stake = bound(stake, 0.1 ether, 100 ether);
        vm.deal(operator1, stake);
        vm.prank(operator1);
        registry.registerNode{value: stake}(PUB_KEY_1, ENC_KEY, 0);

        bytes32 nodeId = registry.operatorNode(operator1);
        IMixnetNodeRegistry.MixnetNode memory node = registry.getNode(nodeId);
        assertEq(node.stakedAmount, stake);
    }

    function testFuzz_SlashPenaltyCalculation(uint256 stake) public {
        stake = bound(stake, 0.1 ether, 100 ether);
        vm.deal(operator1, stake);
        vm.prank(operator1);
        registry.registerNode{value: stake}(PUB_KEY_1, ENC_KEY, 0);
        bytes32 nodeId = registry.operatorNode(operator1);

        uint256 expectedPenalty = (stake * 5000) / 10000;
        vm.prank(slasher);
        registry.slashNode(nodeId, hex"bada");

        IMixnetNodeRegistry.MixnetNode memory node = registry.getNode(nodeId);
        assertEq(node.stakedAmount, stake - expectedPenalty);
        assertEq(registry.slashingPool(), expectedPenalty);
    }
}
