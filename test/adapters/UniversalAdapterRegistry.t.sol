// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/adapters/UniversalAdapterRegistry.sol";
import "../../contracts/interfaces/IUniversalChainAdapter.sol";

contract UniversalAdapterRegistryTest is Test {
    UniversalAdapterRegistry public registry;

    address admin = address(0xA);
    address operator = address(0xB);
    address emergency = address(0xC);
    address nobody = address(0xDEAD);

    bytes32 ethChainId = keccak256("ethereum");
    bytes32 arbChainId = keccak256("arbitrum");
    bytes32 solChainId = keccak256("solana");
    bytes32 starkChainId = keccak256("starknet");

    address ethAdapter = address(0x1111);
    address arbAdapter = address(0x2222);

    function setUp() public {
        vm.prank(admin);
        registry = new UniversalAdapterRegistry(admin);

        vm.startPrank(admin);
        registry.grantRole(registry.OPERATOR_ROLE(), operator);
        registry.grantRole(registry.EMERGENCY_ROLE(), emergency);
        vm.stopPrank();
    }

    /* ── Constructor ────────────────────────────────── */

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(UniversalAdapterRegistry.ZeroAddress.selector);
        new UniversalAdapterRegistry(address(0));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.OPERATOR_ROLE(), admin));
    }

    /* ── EVM Adapter Registration ───────────────────── */

    function test_registerEVMAdapter_happyPath() public {
        vm.prank(operator);
        registry.registerEVMAdapter(
            ethChainId,
            ethAdapter,
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Ethereum"
        );

        assertTrue(registry.isChainRegistered(ethChainId));
        assertEq(registry.totalChains(), 1);
        assertEq(registry.getEVMAdapterAddress(ethChainId), ethAdapter);
        assertTrue(registry.isAdapterActive(ethChainId));
    }

    function test_registerEVMAdapter_revertsZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(UniversalAdapterRegistry.ZeroAddress.selector);
        registry.registerEVMAdapter(
            ethChainId,
            address(0),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Ethereum"
        );
    }

    function test_registerEVMAdapter_revertsDuplicate() public {
        vm.startPrank(operator);
        registry.registerEVMAdapter(
            ethChainId,
            ethAdapter,
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Ethereum"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.ChainAlreadyRegistered.selector,
                ethChainId
            )
        );
        registry.registerEVMAdapter(
            ethChainId,
            address(0x9999),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Ethereum-2"
        );
        vm.stopPrank();
    }

    function test_registerEVMAdapter_unauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        registry.registerEVMAdapter(
            ethChainId,
            ethAdapter,
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Ethereum"
        );
    }

    /* ── External Adapter Registration ──────────────── */

    function test_registerExternalAdapter_happyPath() public {
        bytes memory solProgramId = abi.encodePacked(bytes32(uint256(0xBEEF)));

        vm.prank(operator);
        registry.registerExternalAdapter(
            solChainId,
            solProgramId,
            IUniversalChainAdapter.ChainVM.SVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Solana"
        );

        assertTrue(registry.isChainRegistered(solChainId));
        assertEq(
            registry.getExternalAdapterIdentifier(solChainId),
            solProgramId
        );
    }

    function test_registerExternalAdapter_revertsEmptyIdentifier() public {
        vm.prank(operator);
        vm.expectRevert(UniversalAdapterRegistry.EmptyIdentifier.selector);
        registry.registerExternalAdapter(
            solChainId,
            "",
            IUniversalChainAdapter.ChainVM.SVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Solana"
        );
    }

    /* ── Route Management ───────────────────────────── */

    function _registerTwoChains() internal {
        vm.startPrank(operator);
        registry.registerEVMAdapter(
            ethChainId,
            ethAdapter,
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Ethereum"
        );
        registry.registerEVMAdapter(
            arbChainId,
            arbAdapter,
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.PLONK,
            "Arbitrum"
        );
        vm.stopPrank();
    }

    function test_createRoute_happyPath() public {
        _registerTwoChains();

        vm.prank(operator);
        registry.createRoute(ethChainId, arbChainId);

        assertTrue(registry.isRouteActive(ethChainId, arbChainId));
        assertEq(registry.totalActiveRoutes(), 1);
    }

    function test_createRoute_revertsUnknownChain() public {
        _registerTwoChains();

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.ChainNotRegistered.selector,
                solChainId
            )
        );
        registry.createRoute(ethChainId, solChainId);
    }

    function test_createRoute_revertsSelfRoute() public {
        _registerTwoChains();

        vm.prank(operator);
        vm.expectRevert(UniversalAdapterRegistry.SelfRoute.selector);
        registry.createRoute(ethChainId, ethChainId);
    }

    function test_createRoute_revertsDuplicate() public {
        _registerTwoChains();

        vm.startPrank(operator);
        registry.createRoute(ethChainId, arbChainId);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.RouteAlreadyExists.selector,
                ethChainId,
                arbChainId
            )
        );
        registry.createRoute(ethChainId, arbChainId);
        vm.stopPrank();
    }

    function test_createBidirectionalRoute() public {
        _registerTwoChains();

        vm.prank(operator);
        registry.createBidirectionalRoute(ethChainId, arbChainId);

        assertTrue(registry.isRouteActive(ethChainId, arbChainId));
        assertTrue(registry.isRouteActive(arbChainId, ethChainId));
        assertEq(registry.totalActiveRoutes(), 2);
    }

    function test_deactivateRoute() public {
        _registerTwoChains();

        vm.startPrank(operator);
        registry.createRoute(ethChainId, arbChainId);
        registry.deactivateRoute(ethChainId, arbChainId);
        vm.stopPrank();

        assertFalse(registry.isRouteActive(ethChainId, arbChainId));
        assertEq(registry.totalActiveRoutes(), 0);
    }

    function test_deactivateRoute_revertsNotActive() public {
        _registerTwoChains();

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.RouteNotActive.selector,
                ethChainId,
                arbChainId
            )
        );
        registry.deactivateRoute(ethChainId, arbChainId);
    }

    /* ── Adapter Management ─────────────────────────── */

    function test_deactivateAdapter() public {
        _registerTwoChains();

        vm.prank(operator);
        registry.deactivateAdapter(ethChainId);
        assertFalse(registry.isAdapterActive(ethChainId));
    }

    function test_activateAdapter() public {
        _registerTwoChains();

        vm.startPrank(operator);
        registry.deactivateAdapter(ethChainId);
        registry.activateAdapter(ethChainId);
        vm.stopPrank();

        assertTrue(registry.isAdapterActive(ethChainId));
    }

    function test_deactivateAdapter_revertsNotRegistered() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.ChainNotRegistered.selector,
                solChainId
            )
        );
        registry.deactivateAdapter(solChainId);
    }

    /* ── Proof Relay ────────────────────────────────── */

    function test_recordProofRelay() public {
        _registerTwoChains();

        vm.startPrank(operator);
        registry.createRoute(ethChainId, arbChainId);
        registry.recordProofRelay(ethChainId, arbChainId, bytes32(uint256(1)));
        vm.stopPrank();

        (uint256 total, uint256 lastAt) = registry.getRouteStats(
            ethChainId,
            arbChainId
        );
        assertEq(total, 1);
        assertTrue(lastAt > 0);
    }

    function test_recordProofRelay_revertsInactiveRoute() public {
        _registerTwoChains();

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.RouteNotActive.selector,
                ethChainId,
                arbChainId
            )
        );
        registry.recordProofRelay(ethChainId, arbChainId, bytes32(uint256(1)));
    }

    /* ── View Functions ─────────────────────────────── */

    function test_getRegisteredChains() public {
        _registerTwoChains();
        bytes32[] memory chains = registry.getRegisteredChains();
        assertEq(chains.length, 2);
    }

    function test_getChainVM() public {
        _registerTwoChains();
        IUniversalChainAdapter.ChainVM vm_ = registry.getChainVM(ethChainId);
        assertEq(uint256(vm_), uint256(IUniversalChainAdapter.ChainVM.EVM));
    }

    /* ── Emergency ──────────────────────────────────── */

    function test_pause_unpause() public {
        vm.prank(emergency);
        registry.pause();
        assertTrue(registry.paused());

        vm.prank(emergency);
        registry.unpause();
        assertFalse(registry.paused());
    }

    /* ── Fuzz ────────────────────────────────────────── */

    function testFuzz_registerEVMAdapter(
        bytes32 chainId,
        address adapter_
    ) public {
        vm.assume(chainId != bytes32(0));
        vm.assume(adapter_ != address(0));

        vm.prank(operator);
        registry.registerEVMAdapter(
            chainId,
            adapter_,
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "TestChain"
        );

        assertTrue(registry.isChainRegistered(chainId));
    }
}
