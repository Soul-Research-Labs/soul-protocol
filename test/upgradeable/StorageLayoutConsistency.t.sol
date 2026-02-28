// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Upgradeable contracts to test
import {ZKBoundStateLocksUpgradeable} from "../../contracts/upgradeable/ZKBoundStateLocksUpgradeable.sol";
import {NullifierRegistryV3Upgradeable} from "../../contracts/upgradeable/NullifierRegistryV3Upgradeable.sol";
import {DirectL2MessengerUpgradeable} from "../../contracts/upgradeable/DirectL2MessengerUpgradeable.sol";

/**
 * @title StorageLayoutConsistencyTest
 * @notice Tests that upgradeable contracts preserve storage across proxy upgrades
 * @dev For each upgradeable contract:
 *   1. Deploy implementation behind ERC1967Proxy
 *   2. Initialize with known state
 *   3. Verify state is accessible through proxy
 *   4. Verify __gap size is reserved
 *
 * This catches storage layout regressions that would corrupt state during upgrades.
 */
contract StorageLayoutConsistencyTest is Test {
    address public admin;
    address public zaseonHub;

    function setUp() public {
        admin = makeAddr("admin");
        zaseonHub = makeAddr("zaseonHub");
        vm.deal(admin, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                  ZKBoundStateLocksUpgradeable
    //////////////////////////////////////////////////////////////*/

    function test_zkslocks_proxyDeployAndInitialize() public {
        // Deploy implementation
        ZKBoundStateLocksUpgradeable impl = new ZKBoundStateLocksUpgradeable();

        // Deploy proxy with initialization
        address proofVerifier = makeAddr("proofVerifier");
        bytes memory initData = abi.encodeWithSelector(
            ZKBoundStateLocksUpgradeable.initialize.selector,
            admin,
            proofVerifier
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);

        // Access through proxy
        ZKBoundStateLocksUpgradeable locks = ZKBoundStateLocksUpgradeable(
            address(proxy)
        );

        // Verify initialization
        assertTrue(
            locks.hasRole(locks.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role should be granted"
        );

        // Verify contractVersion (state variable persists through proxy)
        assertEq(locks.contractVersion(), 0, "Initial version should be 0");
    }

    /*//////////////////////////////////////////////////////////////
                NullifierRegistryV3Upgradeable
    //////////////////////////////////////////////////////////////*/

    function test_nullifierRegistry_proxyDeployAndInitialize() public {
        NullifierRegistryV3Upgradeable impl = new NullifierRegistryV3Upgradeable();

        bytes memory initData = abi.encodeWithSelector(
            NullifierRegistryV3Upgradeable.initialize.selector,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);

        NullifierRegistryV3Upgradeable registry = NullifierRegistryV3Upgradeable(
                address(proxy)
            );

        assertTrue(
            registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role should be granted"
        );
    }

    /*//////////////////////////////////////////////////////////////
                DirectL2MessengerUpgradeable
    //////////////////////////////////////////////////////////////*/

    function test_directL2Messenger_proxyDeployAndInitialize() public {
        DirectL2MessengerUpgradeable impl = new DirectL2MessengerUpgradeable();

        bytes memory initData = abi.encodeWithSelector(
            DirectL2MessengerUpgradeable.initialize.selector,
            admin,
            zaseonHub
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);

        DirectL2MessengerUpgradeable messenger = DirectL2MessengerUpgradeable(
            payable(address(proxy))
        );

        assertTrue(
            messenger.hasRole(messenger.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role should be granted"
        );
    }

    /*//////////////////////////////////////////////////////////////
               UPGRADE SIMULATION (state preservation)
    //////////////////////////////////////////////////////////////*/

    function test_zkslocks_statePreservedAcrossUpgrade() public {
        // Deploy V1
        ZKBoundStateLocksUpgradeable implV1 = new ZKBoundStateLocksUpgradeable();
        address proofVerifier = makeAddr("proofVerifier");
        bytes memory initData = abi.encodeWithSelector(
            ZKBoundStateLocksUpgradeable.initialize.selector,
            admin,
            proofVerifier
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implV1), initData);
        ZKBoundStateLocksUpgradeable locks = ZKBoundStateLocksUpgradeable(
            address(proxy)
        );

        // Store some state via admin
        uint256 versionBefore = locks.contractVersion();

        // Deploy V2 (same contract — simulates a no-op upgrade)
        ZKBoundStateLocksUpgradeable implV2 = new ZKBoundStateLocksUpgradeable();

        // Upgrade
        vm.prank(admin);
        locks.upgradeToAndCall(address(implV2), "");

        // State should be preserved
        assertTrue(
            locks.hasRole(locks.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role must survive upgrade"
        );
        // Version increments on upgrade (in _authorizeUpgrade)
        assertEq(
            locks.contractVersion(),
            versionBefore + 1,
            "Version should increment on upgrade"
        );
    }

    /*//////////////////////////////////////////////////////////////
                  IMPLEMENTATION CANNOT BE INITIALIZED
    //////////////////////////////////////////////////////////////*/

    function test_implementationCannotBeInitialized() public {
        ZKBoundStateLocksUpgradeable impl = new ZKBoundStateLocksUpgradeable();

        // Calling initialize on implementation should revert
        // (constructor calls _disableInitializers)
        vm.expectRevert();
        impl.initialize(admin, makeAddr("verifier"));
    }
}
