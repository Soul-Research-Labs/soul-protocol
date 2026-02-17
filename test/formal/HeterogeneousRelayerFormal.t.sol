// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/relayer/HeterogeneousRelayerRegistry.sol";

/**
 * @title HeterogeneousRelayerRegistry Formal Property Tests
 * @notice Fuzz-based invariant checks for slash accounting solvency,
 *         role-based stake minimums, and task completion lifecycle
 */
contract HeterogeneousRelayerFormalTest is Test {
    HeterogeneousRelayerRegistry public registry;

    bytes32 public constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant TASK_ASSIGNER_ROLE = keccak256("TASK_ASSIGNER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    function setUp() public {
        registry = new HeterogeneousRelayerRegistry(address(this));
    }

    receive() external payable {}

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    /**
     * @notice Property: ProofGenerator registration requires >= 1 ETH
     * @dev Fuzz random stake amounts — registration below 1 ETH must revert
     */
    function test_ProofGeneratorMinStake(uint256 stakeAmount) public {
        stakeAmount = bound(stakeAmount, 0, 5 ether);
        address relayer = address(uint160(uint256(keccak256("PG_relayer"))));

        vm.deal(relayer, stakeAmount);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(relayer);
        if (stakeAmount < 1 ether) {
            vm.expectRevert();
            registry.registerProofGenerator{value: stakeAmount}(chains, bytes32(0));
        } else {
            registry.registerProofGenerator{value: stakeAmount}(chains, bytes32(0));
        }
    }

    /**
     * @notice Property: LightRelayer registration requires >= 0.1 ETH
     */
    function test_LightRelayerMinStake(uint256 stakeAmount) public {
        stakeAmount = bound(stakeAmount, 0, 2 ether);
        address relayer = address(uint160(uint256(keccak256("LR_relayer"))));

        vm.deal(relayer, stakeAmount);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(relayer);
        if (stakeAmount < 0.1 ether) {
            vm.expectRevert();
            registry.registerLightRelayer{value: stakeAmount}(chains);
        } else {
            registry.registerLightRelayer{value: stakeAmount}(chains);
        }
    }

    /**
     * @notice Property: Watchtower registration requires >= 0.5 ETH
     */
    function test_WatchtowerMinStake(uint256 stakeAmount) public {
        stakeAmount = bound(stakeAmount, 0, 3 ether);
        address relayer = address(uint160(uint256(keccak256("WT_relayer"))));

        vm.deal(relayer, stakeAmount);

        vm.prank(relayer);
        if (stakeAmount < 0.5 ether) {
            vm.expectRevert();
            registry.registerWatchtower{value: stakeAmount}();
        } else {
            registry.registerWatchtower{value: stakeAmount}();
        }
    }

    /**
     * @notice Property: Slash accounting never exceeds stake
     * @dev Slash amount is capped at relayer's current stake
     */
    function test_SlashAccountingSolvency(
        uint256 stakeAmount,
        uint256 slashAmount
    ) public {
        stakeAmount = bound(stakeAmount, 1 ether, 10 ether);
        slashAmount = bound(slashAmount, 0, 20 ether);

        address relayer = address(0xBEEF);
        vm.deal(relayer, stakeAmount);

        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(relayer);
        registry.registerProofGenerator{value: stakeAmount}(chains, bytes32(0));

        uint256 slashedBefore = registry.slashedFunds();

        // Slash the relayer
        registry.slashRelayer(relayer, slashAmount, "test-slash");

        uint256 slashedAfter = registry.slashedFunds();

        // The actual slash amount is min(slashAmount, stake)
        uint256 expectedSlash = slashAmount > stakeAmount ? stakeAmount : slashAmount;
        assertEq(slashedAfter - slashedBefore, expectedSlash,
            "Slashed funds must increase by min(slashAmount, stake)");
    }

    /**
     * @notice Property: No double registration
     * @dev Registering the same address twice must revert
     */
    function test_NoDoubleRegistration() public {
        address relayer = address(0xCAFE);
        vm.deal(relayer, 3 ether);

        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(relayer);
        registry.registerProofGenerator{value: 1 ether}(chains, bytes32(0));

        // Second registration must revert
        vm.prank(relayer);
        vm.expectRevert();
        registry.registerProofGenerator{value: 1 ether}(chains, bytes32(0));

        // Also cannot register as different role
        vm.prank(relayer);
        vm.expectRevert();
        registry.registerLightRelayer{value: 0.1 ether}(chains);
    }

    /**
     * @notice Property: Task counter monotonicity
     * @dev Assigning tasks always increases the counter
     */
    function test_TaskCounterMonotonicity(uint8 numTasks) public {
        numTasks = uint8(bound(numTasks, 1, 5));

        // Register a proof generator to be assigned tasks
        address relayer = address(0xFACE);
        vm.deal(relayer, 10 ether);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;
        vm.prank(relayer);
        registry.registerProofGenerator{value: 1 ether}(chains, bytes32(0));

        uint256 prevCount = registry.totalTasks();
        vm.deal(address(this), 10 ether);

        for (uint8 i = 0; i < numTasks; i++) {
            registry.assignTask{value: 0.01 ether}(
                IHeterogeneousRelayerRegistry.TaskType.ProofGeneration,
                keccak256(abi.encodePacked("task", i)),
                1,
                10,
                uint64(block.timestamp + 1 hours)
            );

            uint256 newCount = registry.totalTasks();
            assertGt(newCount, prevCount, "Task counter must monotonically increase");
            prevCount = newCount;
        }
    }

    /**
     * @notice Property: Task completion lifecycle
     * @dev A completed task stays completed and cannot be completed again
     */
    function test_TaskCompletionPermanence() public {
        // Register relayer
        address relayer = address(0xDEAD);
        vm.deal(relayer, 2 ether);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;
        vm.prank(relayer);
        registry.registerProofGenerator{value: 1 ether}(chains, bytes32(0));

        // Assign task
        vm.deal(address(this), 1 ether);
        bytes32 taskId = registry.assignTask{value: 0.01 ether}(
            IHeterogeneousRelayerRegistry.TaskType.ProofGeneration,
            keccak256("task-data"),
            1,
            10,
            uint64(block.timestamp + 1 hours)
        );

        // Complete the task
        vm.prank(relayer);
        registry.completeTask(taskId, new bytes(32));

        // Trying to complete again must revert
        vm.prank(relayer);
        vm.expectRevert();
        registry.completeTask(taskId, new bytes(32));

        // Trying to report failure must also revert
        vm.expectRevert();
        registry.reportTaskFailure(taskId, "late");
    }

    /**
     * @notice Property: Default reputation is set correctly
     */
    function test_DefaultReputationOnRegistration() public {
        address relayer = address(0xABCD);
        vm.deal(relayer, 2 ether);

        vm.prank(relayer);
        registry.registerWatchtower{value: 0.5 ether}();

        IHeterogeneousRelayerRegistry.Relayer memory r = registry.getRelayer(relayer);
        assertEq(r.reputationScore, 5000, "Default reputation must be 5000");
    }
}
