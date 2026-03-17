// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DynamicRoutingOrchestrator} from "../../contracts/core/DynamicRoutingOrchestrator.sol";
import {IDynamicRoutingOrchestrator} from "../../contracts/interfaces/IDynamicRoutingOrchestrator.sol";

contract DynamicRoutingOrchestratorBitVMTest is Test {
    DynamicRoutingOrchestrator internal orchestrator;

    address internal admin = address(0x1A);
    address internal oracle = address(0x1B);
    address internal bridgeAdmin = address(0x1C);

    address internal bitvmAdapter = address(0xB17);

    uint256 internal constant CHAIN_ETH = 1;
    uint256 internal constant CHAIN_ARB = 42161;

    function setUp() public {
        orchestrator = new DynamicRoutingOrchestrator(
            admin,
            oracle,
            bridgeAdmin
        );

        vm.startPrank(bridgeAdmin);
        orchestrator.registerPool(CHAIN_ETH, 1_000 ether, 0.01 ether);
        orchestrator.registerPool(CHAIN_ARB, 1_000 ether, 0.01 ether);

        uint256[] memory chains = new uint256[](2);
        chains[0] = CHAIN_ETH;
        chains[1] = CHAIN_ARB;
        orchestrator.registerAdapter(bitvmAdapter, chains, 8800);
        vm.stopPrank();

        // Seed positive bridge reliability/latency history.
        vm.startPrank(admin);
        for (uint256 i = 0; i < 8; i++) {
            orchestrator.recordAdapterOutcome(bitvmAdapter, true, 40, 1 ether);
        }
        vm.stopPrank();
    }

    function test_BitVMRegistration_MetricsAndSupport() public view {
        IDynamicRoutingOrchestrator.AdapterMetrics memory metrics = orchestrator
            .getAdapterMetrics(bitvmAdapter);

        assertEq(metrics.adapter, bitvmAdapter);
        assertEq(metrics.securityScoreBps, 8800);
        assertTrue(metrics.isActive);

        assertTrue(orchestrator.adapterSupportsChain(bitvmAdapter, CHAIN_ETH));
        assertTrue(orchestrator.adapterSupportsChain(bitvmAdapter, CHAIN_ARB));
    }

    function test_BitVMCanBeSelectedAsOptimalRoute() public view {
        IDynamicRoutingOrchestrator.RouteRequest
            memory request = IDynamicRoutingOrchestrator.RouteRequest({
                sourceChainId: CHAIN_ETH,
                destChainId: CHAIN_ARB,
                amount: 1 ether,
                urgency: IDynamicRoutingOrchestrator.Urgency.STANDARD,
                maxCost: 0,
                maxTime: 0,
                minSuccessBps: 0,
                requirePrivacy: false
            });

        IDynamicRoutingOrchestrator.Route memory route = orchestrator
            .findOptimalRoute(request);

        assertTrue(route.routeId != bytes32(0));
        assertTrue(route.relayAdapters.length > 0);
        assertEq(route.relayAdapters[0], bitvmAdapter);
    }

    function test_DeactivatedBitVM_NoViableRoute() public {
        vm.prank(bridgeAdmin);
        orchestrator.setAdapterActive(bitvmAdapter, false);

        IDynamicRoutingOrchestrator.RouteRequest
            memory request = IDynamicRoutingOrchestrator.RouteRequest({
                sourceChainId: CHAIN_ETH,
                destChainId: CHAIN_ARB,
                amount: 1 ether,
                urgency: IDynamicRoutingOrchestrator.Urgency.STANDARD,
                maxCost: 0,
                maxTime: 0,
                minSuccessBps: 0,
                requirePrivacy: false
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                IDynamicRoutingOrchestrator.NoViableRoute.selector,
                CHAIN_ETH,
                CHAIN_ARB
            )
        );
        orchestrator.findOptimalRoute(request);
    }
}
