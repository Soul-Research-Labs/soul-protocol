// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PrivacyRouterUpgradeable} from "../../contracts/upgradeable/PrivacyRouterUpgradeable.sol";
import {ProofCarryingContainerUpgradeable} from "../../contracts/upgradeable/ProofCarryingContainerUpgradeable.sol";
import {Zaseonv2OrchestratorUpgradeable} from "../../contracts/upgradeable/Zaseonv2OrchestratorUpgradeable.sol";
import {UniversalShieldedPoolUpgradeable} from "../../contracts/upgradeable/UniversalShieldedPoolUpgradeable.sol";
import {StorageSlots} from "../../contracts/upgradeable/StorageLayout.sol";

/**
 * @title UpgradeableContractsTest
 * @notice Comprehensive tests for all UUPS upgradeable contracts
 * @dev Covers initialization, double-init guard, upgrade auth, storage gaps, role checks
 */
contract UpgradeableContractsTest is Test {
    address public admin = makeAddr("admin");
    address public unauthorized = makeAddr("unauthorized");

    /*//////////////////////////////////////////////////////////////
                     PRIVACY ROUTER UPGRADEABLE
    //////////////////////////////////////////////////////////////*/

    function _deployRouter() internal returns (PrivacyRouterUpgradeable) {
        PrivacyRouterUpgradeable impl = new PrivacyRouterUpgradeable();
        bytes memory initData = abi.encodeCall(
            PrivacyRouterUpgradeable.initialize,
            (
                admin,
                makeAddr("pool"),
                makeAddr("hub"),
                makeAddr("stealth"),
                makeAddr("nullifier"),
                makeAddr("compliance"),
                makeAddr("translator")
            )
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        return PrivacyRouterUpgradeable(payable(address(proxy)));
    }

    function test_RouterInitialize() public {
        PrivacyRouterUpgradeable router = _deployRouter();
        assertEq(router.contractVersion(), 1);
        assertEq(router.shieldedPool(), makeAddr("pool"));
        assertTrue(router.complianceEnabled());
    }

    function test_RouterDoubleInitReverts() public {
        PrivacyRouterUpgradeable router = _deployRouter();
        vm.expectRevert();
        router.initialize(
            admin,
            makeAddr("pool"),
            makeAddr("hub"),
            makeAddr("stealth"),
            makeAddr("nullifier"),
            makeAddr("compliance"),
            makeAddr("translator")
        );
    }

    function test_RouterImplCannotBeInitialized() public {
        PrivacyRouterUpgradeable impl = new PrivacyRouterUpgradeable();
        vm.expectRevert();
        impl.initialize(
            admin,
            makeAddr("pool"),
            makeAddr("hub"),
            makeAddr("stealth"),
            makeAddr("nullifier"),
            makeAddr("compliance"),
            makeAddr("translator")
        );
    }

    function test_RouterZeroAddressInInitialize() public {
        PrivacyRouterUpgradeable impl = new PrivacyRouterUpgradeable();
        bytes memory initData = abi.encodeCall(
            PrivacyRouterUpgradeable.initialize,
            (
                address(0),
                makeAddr("pool"),
                makeAddr("hub"),
                makeAddr("stealth"),
                makeAddr("nullifier"),
                makeAddr("compliance"),
                makeAddr("translator")
            )
        );
        vm.expectRevert();
        new ERC1967Proxy(address(impl), initData);
    }

    function test_RouterAdminRoles() public {
        PrivacyRouterUpgradeable router = _deployRouter();
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(router.hasRole(router.OPERATOR_ROLE(), admin));
        assertTrue(router.hasRole(router.EMERGENCY_ROLE(), admin));
    }

    /*//////////////////////////////////////////////////////////////
                 PROOF CARRYING CONTAINER UPGRADEABLE
    //////////////////////////////////////////////////////////////*/

    function _deployPC3() internal returns (ProofCarryingContainerUpgradeable) {
        ProofCarryingContainerUpgradeable impl = new ProofCarryingContainerUpgradeable();
        bytes memory initData = abi.encodeCall(
            ProofCarryingContainerUpgradeable.initialize,
            (admin)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        return ProofCarryingContainerUpgradeable(address(proxy));
    }

    function test_PC3Initialize() public {
        ProofCarryingContainerUpgradeable pc3 = _deployPC3();
        assertEq(pc3.contractVersion(), 1);
        assertEq(pc3.totalContainers(), 0);
    }

    function test_PC3DoubleInitReverts() public {
        ProofCarryingContainerUpgradeable pc3 = _deployPC3();
        vm.expectRevert();
        pc3.initialize(admin);
    }

    function test_PC3AdminRoles() public {
        ProofCarryingContainerUpgradeable pc3 = _deployPC3();
        assertTrue(pc3.hasRole(pc3.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pc3.hasRole(pc3.CONTAINER_ADMIN_ROLE(), admin));
    }

    /*//////////////////////////////////////////////////////////////
                  ZASEONV2 ORCHESTRATOR UPGRADEABLE
    //////////////////////////////////////////////////////////////*/

    function _deployOrchestrator()
        internal
        returns (Zaseonv2OrchestratorUpgradeable)
    {
        Zaseonv2OrchestratorUpgradeable impl = new Zaseonv2OrchestratorUpgradeable();
        bytes memory initData = abi.encodeCall(
            Zaseonv2OrchestratorUpgradeable.initialize,
            (
                admin,
                makeAddr("pc3"),
                makeAddr("pbp"),
                makeAddr("easc"),
                makeAddr("cdna")
            )
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        return Zaseonv2OrchestratorUpgradeable(address(proxy));
    }

    function test_OrchestratorInitialize() public {
        Zaseonv2OrchestratorUpgradeable orch = _deployOrchestrator();
        assertEq(orch.contractVersion(), 1);
        assertEq(orch.totalOperations(), 0);
    }

    function test_OrchestratorDoubleInitReverts() public {
        Zaseonv2OrchestratorUpgradeable orch = _deployOrchestrator();
        vm.expectRevert();
        orch.initialize(
            admin,
            makeAddr("pc3"),
            makeAddr("pbp"),
            makeAddr("easc"),
            makeAddr("cdna")
        );
    }

    function test_OrchestratorAdminRoles() public {
        Zaseonv2OrchestratorUpgradeable orch = _deployOrchestrator();
        assertTrue(orch.hasRole(orch.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(orch.hasRole(orch.ORCHESTRATOR_ADMIN_ROLE(), admin));
        assertTrue(orch.hasRole(orch.OPERATOR_ROLE(), admin));
    }

    /*//////////////////////////////////////////////////////////////
                UNIVERSAL SHIELDED POOL UPGRADEABLE
    //////////////////////////////////////////////////////////////*/

    function _deployPool() internal returns (UniversalShieldedPoolUpgradeable) {
        UniversalShieldedPoolUpgradeable impl = new UniversalShieldedPoolUpgradeable();
        bytes memory initData = abi.encodeCall(
            UniversalShieldedPoolUpgradeable.initialize,
            (admin, address(0), true)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        return UniversalShieldedPoolUpgradeable(payable(address(proxy)));
    }

    function test_PoolInitialize() public {
        UniversalShieldedPoolUpgradeable p = _deployPool();
        assertEq(p.contractVersion(), 1);
        assertTrue(p.testMode());
    }

    function test_PoolDoubleInitReverts() public {
        UniversalShieldedPoolUpgradeable p = _deployPool();
        vm.expectRevert();
        p.initialize(admin, address(0), true);
    }

    function test_PoolAdminRoles() public {
        UniversalShieldedPoolUpgradeable p = _deployPool();
        assertTrue(p.hasRole(p.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(p.hasRole(p.OPERATOR_ROLE(), admin));
    }

    function test_PoolZeroAdminReverts() public {
        UniversalShieldedPoolUpgradeable impl = new UniversalShieldedPoolUpgradeable();
        bytes memory initData = abi.encodeCall(
            UniversalShieldedPoolUpgradeable.initialize,
            (address(0), address(0), true)
        );
        vm.expectRevert();
        new ERC1967Proxy(address(impl), initData);
    }

    /*//////////////////////////////////////////////////////////////
                          STORAGE LAYOUT
    //////////////////////////////////////////////////////////////*/

    function test_StorageSlotsNonZero() public pure {
        assert(StorageSlots.PC3_CONTAINERS_SLOT != bytes32(0));
        assert(StorageSlots.PC3_NULLIFIERS_SLOT != bytes32(0));
        assert(StorageSlots.PBP_POLICIES_SLOT != bytes32(0));
        assert(StorageSlots.EASC_COMMITMENTS_SLOT != bytes32(0));
        assert(StorageSlots.CDNA_DOMAINS_SLOT != bytes32(0));
    }

    function test_StorageSlotsUnique() public pure {
        assert(
            StorageSlots.PC3_CONTAINERS_SLOT != StorageSlots.PBP_POLICIES_SLOT
        );
        assert(
            StorageSlots.PC3_CONTAINERS_SLOT !=
                StorageSlots.EASC_COMMITMENTS_SLOT
        );
        assert(
            StorageSlots.PC3_CONTAINERS_SLOT != StorageSlots.CDNA_DOMAINS_SLOT
        );
        assert(
            StorageSlots.PBP_POLICIES_SLOT != StorageSlots.EASC_COMMITMENTS_SLOT
        );
        assert(
            StorageSlots.PBP_POLICIES_SLOT != StorageSlots.CDNA_DOMAINS_SLOT
        );
        assert(
            StorageSlots.EASC_COMMITMENTS_SLOT != StorageSlots.CDNA_DOMAINS_SLOT
        );
    }

    function test_StorageSlotsMatchKeccak() public pure {
        assertEq(
            StorageSlots.PC3_CONTAINERS_SLOT,
            keccak256("zaseon.storage.pc3.containers")
        );
        assertEq(
            StorageSlots.PC3_NULLIFIERS_SLOT,
            keccak256("zaseon.storage.pc3.nullifiers")
        );
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-1967 SLOTS
    //////////////////////////////////////////////////////////////*/

    function test_EIP1967ImplementationSlot() public pure {
        bytes32 implSlot = bytes32(
            uint256(keccak256("eip1967.proxy.implementation")) - 1
        );
        assertEq(
            implSlot,
            0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        );
    }
}
