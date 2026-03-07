// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/PrivacyTierRouter.sol";
import "../../contracts/interfaces/IMixnetNodeRegistry.sol";

/// @dev Minimal mock MixnetNodeRegistry for testing
contract MockMixnetRegistry is IMixnetNodeRegistry {
    mapping(bytes32 => MixnetNode) private _nodes;
    bytes32[] private _nodeIds;

    function addNode(
        bytes32 nodeId,
        address op,
        uint32[] memory chains
    ) external {
        _nodes[nodeId] = MixnetNode({
            operator: op,
            encryptionPubKey: hex"01",
            stakeAmount: 1 ether,
            registeredAt: block.timestamp,
            lastActiveAt: block.timestamp,
            status: NodeStatus.ACTIVE,
            supportedChainIds: chains,
            totalRelaysHandled: 0
        });
        _nodeIds.push(nodeId);
    }

    function registerNode(
        bytes32,
        bytes calldata,
        uint32[] calldata
    ) external payable override {}

    function deactivateNode(bytes32) external override {}

    function selectRelayPath(
        uint32,
        uint32,
        uint8 hopCount
    ) external view override returns (bytes32[] memory path) {
        path = new bytes32[](hopCount);
        for (uint8 i = 0; i < hopCount && i < _nodeIds.length; i++) {
            path[i] = _nodeIds[i];
        }
    }

    function getNode(
        bytes32 nodeId
    ) external view override returns (MixnetNode memory) {
        return _nodes[nodeId];
    }

    function activeNodeCount(uint32) external pure override returns (uint256) {
        return 5;
    }

    function minimumStake() external pure override returns (uint256) {
        return 1 ether;
    }
}

contract PrivacyTierRouterTest is Test {
    PrivacyTierRouter public router;
    MockMixnetRegistry public mockMixnet;
    address public admin = address(this);
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public operator = makeAddr("operator");

    address public relayerA = makeAddr("relayerA");
    address public relayerB = makeAddr("relayerB");

    uint32 constant SRC_CHAIN = 1;
    uint32 constant DST_CHAIN = 42161;

    function setUp() public {
        router = new PrivacyTierRouter(admin);
        router.grantRole(router.OPERATOR_ROLE(), operator);

        // Set up mock mixnet with 5 nodes
        mockMixnet = new MockMixnetRegistry();
        uint32[] memory chains = new uint32[](2);
        chains[0] = SRC_CHAIN;
        chains[1] = DST_CHAIN;
        for (uint256 i = 0; i < 5; i++) {
            address nodeOp = i == 0
                ? relayerA
                : (
                    i == 1
                        ? relayerB
                        : makeAddr(string(abi.encodePacked("node", i)))
                );
            mockMixnet.addNode(bytes32(i + 1), nodeOp, chains);
        }

        // Configure router with mixnet
        router.setMixnetRegistry(address(mockMixnet));
    }

    /*//////////////////////////////////////////////////////////////
                       SUBMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SubmitOperation_Standard() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(op.sender, user1);
        assertEq(
            uint8(op.tier),
            uint8(IPrivacyTierRouter.PrivacyTier.STANDARD)
        );
        assertEq(op.value, 1 ether);
        assertFalse(op.completed);
        assertEq(router.totalOperations(), 1);
    }

    function test_SubmitOperation_AutoEscalateEnhanced() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            15 ether // above 10 ETH threshold
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(
            uint8(op.tier),
            uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED)
        );
    }

    function test_SubmitOperation_AutoEscalateMaximum() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            200 ether // above 100 ETH threshold
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(uint8(op.tier), uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM));
    }

    function test_SubmitOperation_UserDefaultFloor() public {
        vm.prank(user1);
        router.setUserDefaultTier(IPrivacyTierRouter.PrivacyTier.ENHANCED);

        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD, // request standard
            1 ether // below threshold
        );

        // Should be enhanced (user default floor)
        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(
            uint8(op.tier),
            uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED)
        );
    }

    function test_SubmitOperation_ExplicitHigherTierRespected() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.MAXIMUM, // explicit maximum
            1 ether // low value
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(uint8(op.tier), uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM));
    }

    /*//////////////////////////////////////////////////////////////
                       LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AssignCluster() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        bytes32 clusterId = keccak256("cluster1");
        vm.prank(operator);
        router.assignCluster(opId, clusterId);

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(op.assignedCluster, clusterId);
    }

    function test_CompleteOperation() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        vm.prank(operator);
        router.completeOperation(opId, true);

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertTrue(op.completed);
        assertEq(router.completedOperations(), 1);
    }

    function test_CompleteOperation_DoubleCompleteReverts() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        vm.prank(operator);
        router.completeOperation(opId, true);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPrivacyTierRouter.OperationAlreadyCompleted.selector,
                opId
            )
        );
        router.completeOperation(opId, true);
    }

    /*//////////////////////////////////////////////////////////////
                       TIER CONFIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureTier() public {
        IPrivacyTierRouter.TierConfig memory config = IPrivacyTierRouter
            .TierConfig({
                minRelayers: 7,
                requireRingSig: true,
                requireConstantTime: true,
                requireMixnet: true,
                requireRecursiveProof: true,
                escalationThreshold: 50 ether
            });

        router.configureTier(IPrivacyTierRouter.PrivacyTier.ENHANCED, config);

        IPrivacyTierRouter.TierConfig memory stored = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.ENHANCED
        );
        assertEq(stored.minRelayers, 7);
        assertTrue(stored.requireMixnet);
        assertEq(stored.escalationThreshold, 50 ether);
    }

    function test_ConfigureTier_ZeroRelayersReverts() public {
        IPrivacyTierRouter.TierConfig memory config = IPrivacyTierRouter
            .TierConfig({
                minRelayers: 0,
                requireRingSig: false,
                requireConstantTime: false,
                requireMixnet: false,
                requireRecursiveProof: false,
                escalationThreshold: 0
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                IPrivacyTierRouter.InvalidTierConfig.selector,
                IPrivacyTierRouter.PrivacyTier.STANDARD
            )
        );
        router.configureTier(IPrivacyTierRouter.PrivacyTier.STANDARD, config);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetEffectiveTier() public {
        IPrivacyTierRouter.PrivacyTier tier = router.getEffectiveTier(
            user1,
            1 ether
        );
        assertEq(uint8(tier), uint8(IPrivacyTierRouter.PrivacyTier.STANDARD));

        tier = router.getEffectiveTier(user1, 50 ether);
        assertEq(uint8(tier), uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED));

        tier = router.getEffectiveTier(user1, 200 ether);
        assertEq(uint8(tier), uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM));
    }

    function test_GetDefaultTierConfig() public {
        IPrivacyTierRouter.TierConfig memory std = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.STANDARD
        );
        assertEq(std.minRelayers, 1);
        assertFalse(std.requireRingSig);

        IPrivacyTierRouter.TierConfig memory enh = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.ENHANCED
        );
        assertEq(enh.minRelayers, 3);
        assertTrue(enh.requireRingSig);

        IPrivacyTierRouter.TierConfig memory max = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.MAXIMUM
        );
        assertEq(max.minRelayers, 5);
        assertTrue(max.requireRecursiveProof);
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_TierEscalationMonotonicity(uint256 value) public {
        vm.assume(value <= 1000 ether);

        vm.prank(user1);
        IPrivacyTierRouter.PrivacyTier tier = router.getEffectiveTier(
            user1,
            value
        );

        if (value >= 100 ether) {
            assertEq(
                uint8(tier),
                uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM)
            );
        } else if (value >= 10 ether) {
            assertEq(
                uint8(tier),
                uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED)
            );
        } else {
            assertEq(
                uint8(tier),
                uint8(IPrivacyTierRouter.PrivacyTier.STANDARD)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                       MIXNET ENFORCEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_MaximumTier_assignsMixnetPath() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.MAXIMUM,
            1 ether
        );

        bytes32[] memory path = router.getMixnetPath(opId);
        assertEq(path.length, 5, "MAXIMUM tier should assign 5-node path");
    }

    function test_StandardTier_noMixnetPath() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        bytes32[] memory path = router.getMixnetPath(opId);
        assertEq(path.length, 0, "STANDARD tier should not assign mixnet path");
    }

    function test_isRelayerOnPath_validRelayer() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.MAXIMUM,
            1 ether
        );

        // relayerA is node operator for node 1, which is always in the path
        assertTrue(
            router.isRelayerOnPath(opId, relayerA),
            "relayerA should be on path"
        );
    }

    function test_isRelayerOnPath_invalidRelayer() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.MAXIMUM,
            1 ether
        );

        address rogue = makeAddr("rogue");
        assertFalse(
            router.isRelayerOnPath(opId, rogue),
            "Rogue relayer should not be on path"
        );
    }

    function test_isRelayerOnPath_standardTier_alwaysTrue() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        // For standard tier (no mixnet required), any relayer is valid
        address anyone = makeAddr("anyone");
        assertTrue(
            router.isRelayerOnPath(opId, anyone),
            "Standard tier should accept any relayer"
        );
    }

    function test_MaximumTier_revertsWithoutMixnetRegistry() public {
        // Create a router without mixnet
        PrivacyTierRouter noMixnetRouter = new PrivacyTierRouter(admin);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivacyTierRouter.MixnetRegistryNotSet.selector
            )
        );
        noMixnetRouter.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.MAXIMUM,
            1 ether
        );
    }

    function test_setMixnetRegistry_onlyGovernance() public {
        vm.prank(user1);
        vm.expectRevert();
        router.setMixnetRegistry(address(mockMixnet));
    }

    function test_autoEscalatedMaximum_alsoAssignsPath() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            200 ether // auto-escalates to MAXIMUM
        );

        bytes32[] memory path = router.getMixnetPath(opId);
        assertGt(
            path.length,
            0,
            "Auto-escalated MAXIMUM should have mixnet path"
        );
    }
}
