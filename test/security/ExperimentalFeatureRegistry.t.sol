// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

// Import from security/ — the canonical version (core/ is deprecated)
import {ExperimentalFeatureRegistry} from "../../contracts/security/ExperimentalFeatureRegistry.sol";

contract ExperimentalFeatureRegistryTest is Test {
    ExperimentalFeatureRegistry public registry;
    address public admin;
    address public featureAdmin;
    address public emergencyAdmin;
    address public attacker;

    bytes32 public constant FEATURE_ADMIN = keccak256("FEATURE_ADMIN");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // Cached feature IDs — avoids vm.prank/vm.expectRevert being consumed
    // by the FHE_OPERATIONS() static call when used inline as a parameter.
    bytes32 public fheId;
    bytes32 public pqcId;

    function setUp() public {
        admin = makeAddr("admin");
        featureAdmin = makeAddr("featureAdmin");
        emergencyAdmin = makeAddr("emergencyAdmin");
        attacker = makeAddr("attacker");

        vm.startPrank(admin);
        registry = new ExperimentalFeatureRegistry(admin);
        registry.grantRole(FEATURE_ADMIN, featureAdmin);
        registry.grantRole(EMERGENCY_ROLE, emergencyAdmin);
        vm.stopPrank();

        // Cache feature IDs so tests don't make external calls in param position
        fheId = registry.FHE_OPERATIONS();
        pqcId = registry.PQC_SIGNATURES();
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_grantsAllRoles() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(FEATURE_ADMIN, admin));
        assertTrue(registry.hasRole(EMERGENCY_ROLE, admin));
    }

    function test_constructor_registersDefaultFeatures() public view {
        bytes32[] memory ids = registry.getAllFeatureIds();
        assertEq(ids.length, 5, "Should have 5 pre-registered features");
    }

    function test_constructor_defaultFeaturesAreDisabled() public view {
        assertFalse(registry.isFeatureEnabled(fheId));
        assertFalse(registry.isFeatureEnabled(registry.PQC_SIGNATURES()));
        assertFalse(registry.isFeatureEnabled(registry.MPC_THRESHOLD()));
        assertFalse(registry.isFeatureEnabled(registry.SERAPHIM_PRIVACY()));
        assertFalse(registry.isFeatureEnabled(registry.TRIPTYCH_SIGNATURES()));
    }

    /*//////////////////////////////////////////////////////////////
                       FEATURE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_registerFeature_success() public {
        bytes32 featureId = keccak256("NEW_FEATURE");
        address impl = makeAddr("impl");

        vm.prank(admin);
        registry.registerFeature(
            featureId,
            "New Feature",
            ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
            impl,
            1000 ether,
            true,
            "https://docs.soul.io/new-feature"
        );

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            featureId
        );
        assertEq(f.name, "New Feature");
        assertEq(f.implementation, impl);
        assertEq(f.maxValueLocked, 1000 ether);
        assertTrue(f.requiresWarning);
    }

    function test_registerFeature_emitsEvent() public {
        bytes32 featureId = keccak256("EVT_FEATURE");

        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit ExperimentalFeatureRegistry.FeatureRegistered(
            featureId,
            "Event Feature",
            ExperimentalFeatureRegistry.FeatureStatus.DISABLED
        );
        registry.registerFeature(
            featureId,
            "Event Feature",
            ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
            address(0),
            0,
            false,
            ""
        );
    }

    function test_registerFeature_revertsIfAlreadyExists() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.FeatureAlreadyExists.selector,
                fheId
            )
        );
        registry.registerFeature(
            fheId,
            "Duplicate",
            ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
            address(0),
            0,
            false,
            ""
        );
    }

    function test_registerFeature_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.registerFeature(
            keccak256("UNAUTH"),
            "Unauthorized",
            ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
            address(0),
            0,
            false,
            ""
        );
    }

    /*//////////////////////////////////////////////////////////////
                     STATUS TRANSITION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_updateStatus_disabledToExperimental() public {
        vm.prank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        assertTrue(registry.isFeatureEnabled(fheId));
    }

    function test_updateStatus_experimentalToBeta() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        vm.stopPrank();

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        assertEq(
            uint8(f.status),
            uint8(ExperimentalFeatureRegistry.FeatureStatus.BETA)
        );
    }

    function test_updateStatus_betaToProduction() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
        vm.stopPrank();
    }

    function test_updateStatus_productionCanRegressToBeta() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        vm.stopPrank();
    }

    function test_updateStatus_revertsInvalidTransition_disabledToBeta()
        public
    {
        vm.prank(featureAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.InvalidStatusTransition.selector,
                ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
                ExperimentalFeatureRegistry.FeatureStatus.BETA
            )
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
    }

    function test_updateStatus_revertsInvalidTransition_disabledToProduction()
        public
    {
        vm.prank(featureAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.InvalidStatusTransition.selector,
                ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
                ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
            )
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
    }

    function test_updateStatus_revertsForUnregisteredFeature() public {
        vm.prank(featureAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.FeatureNotFound.selector,
                keccak256("NONEXISTENT")
            )
        );
        registry.updateFeatureStatus(
            keccak256("NONEXISTENT"),
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
    }

    function test_updateStatus_emitsEvent() public {
        vm.prank(featureAdmin);
        vm.expectEmit(true, false, false, true);
        emit ExperimentalFeatureRegistry.FeatureStatusUpdated(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.DISABLED,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
    }

    /*//////////////////////////////////////////////////////////////
                    EMERGENCY DISABLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_emergencyDisable_disablesActiveFeature() public {
        vm.prank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );

        vm.prank(emergencyAdmin);
        registry.emergencyDisable(fheId);

        assertFalse(registry.isFeatureEnabled(fheId));
    }

    function test_emergencyDisable_bypassesTransitionRules() public {
        // Move to PRODUCTION
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
        vm.stopPrank();

        // Emergency disable skips from PRODUCTION → DISABLED directly
        vm.prank(emergencyAdmin);
        registry.emergencyDisable(fheId);
        assertFalse(registry.isFeatureEnabled(fheId));
    }

    function test_emergencyDisable_revertsForNonEmergency() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.emergencyDisable(fheId);
    }

    /*//////////////////////////////////////////////////////////////
                      VALUE LOCK/UNLOCK TESTS
    //////////////////////////////////////////////////////////////*/

    function test_lockValue_success() public {
        vm.prank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );

        vm.prank(featureAdmin);
        registry.lockValue(fheId, 0.5 ether);

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        assertEq(f.currentValueLocked, 0.5 ether);
    }

    function test_lockValue_revertsWhenDisabled() public {
        vm.prank(featureAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.FeatureDisabled.selector,
                fheId
            )
        );
        registry.lockValue(fheId, 0.5 ether);
    }

    function test_lockValue_revertsWhenExceedsRiskLimit() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        uint256 maxValue = f.maxValueLocked;

        vm.expectRevert(); // ExceedsRiskLimit
        registry.lockValue(fheId, maxValue + 1);
        vm.stopPrank();
    }

    function test_unlockValue_success() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.lockValue(fheId, 0.5 ether);
        registry.unlockValue(fheId, 0.2 ether);
        vm.stopPrank();

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        assertEq(f.currentValueLocked, 0.3 ether);
    }

    /*//////////////////////////////////////////////////////////////
                     REQUIRE HELPERS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_requireFeatureEnabled_revertsWhenDisabled() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.FeatureDisabled.selector,
                fheId
            )
        );
        registry.requireFeatureEnabled(fheId);
    }

    function test_requireFeatureEnabled_passesWhenEnabled() public {
        vm.prank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        // Should not revert
        registry.requireFeatureEnabled(fheId);
    }

    function test_requireProductionReady_revertsWhenNotProduction() public {
        vm.prank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.FeatureDisabled.selector,
                fheId
            )
        );
        registry.requireProductionReady(fheId);
    }

    function test_requireProductionReady_passesWhenProduction() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
        vm.stopPrank();

        registry.requireProductionReady(fheId);
    }

    /*//////////////////////////////////////////////////////////////
                     VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getAllFeatureIds_returnsCorrectCount() public view {
        bytes32[] memory ids = registry.getAllFeatureIds();
        assertEq(ids.length, 5);
    }

    function test_getRemainingCapacity() public {
        vm.startPrank(featureAdmin);
        registry.updateFeatureStatus(
            fheId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        uint256 maxVal = f.maxValueLocked;
        uint256 lockAmount = 0.5 ether;

        if (maxVal >= lockAmount) {
            registry.lockValue(fheId, lockAmount);
            uint256 remaining = registry.getRemainingCapacity(
                fheId
            );
            assertEq(remaining, maxVal - lockAmount);
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       RISK LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_updateRiskLimit_success() public {
        vm.prank(admin);
        registry.updateRiskLimit(fheId, 5000 ether);

        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        assertEq(f.maxValueLocked, 5000 ether);
    }

    function test_updateRiskLimit_emitsEvent() public {
        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            fheId
        );
        uint256 oldLimit = f.maxValueLocked;

        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit ExperimentalFeatureRegistry.RiskLimitUpdated(
            fheId,
            oldLimit,
            5000 ether
        );
        registry.updateRiskLimit(fheId, 5000 ether);
    }

    function test_updateRiskLimit_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.updateRiskLimit(fheId, 5000 ether);
    }
}
