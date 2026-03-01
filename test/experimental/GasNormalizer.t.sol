// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GasNormalizer} from "../../contracts/experimental/privacy/GasNormalizer.sol";
import {ExperimentalFeatureRegistry} from "../../contracts/security/ExperimentalFeatureRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Simple target contract for normalized execution
contract GasTarget {
    uint256 public counter;

    function increment() external {
        counter++;
    }

    function heavyWork(uint256 iterations) external {
        for (uint256 i; i < iterations; i++) {
            counter++;
        }
    }
}

/**
 * @title GasNormalizerTest
 * @notice Tests for the experimental gas normalization contract
 */
contract GasNormalizerTest is Test {
    GasNormalizer public normalizer;
    ExperimentalFeatureRegistry public featureReg;
    GasTarget public target;

    address admin = makeAddr("admin");
    address user = makeAddr("user");

    function setUp() public {
        vm.startPrank(admin);

        // Deploy feature registry (features pre-registered as EXPERIMENTAL by constructor)
        featureReg = new ExperimentalFeatureRegistry(admin);

        // Deploy behind proxy (UUPS)
        GasNormalizer impl = new GasNormalizer();
        bytes memory initData = abi.encodeWithSelector(
            GasNormalizer.initialize.selector,
            admin,
            address(featureReg)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        normalizer = GasNormalizer(address(proxy));

        // Deploy target
        target = new GasTarget();

        // Authorize user as caller
        normalizer.authorizeCaller(user, true);

        vm.stopPrank();
    }

    // =========================================================================
    // DEPLOYMENT
    // =========================================================================

    function test_initialize() public view {
        assertTrue(normalizer.normalizationEnabled());
        assertTrue(normalizer.hasRole(normalizer.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(normalizer.hasRole(normalizer.OPERATOR_ROLE(), admin));
    }

    function test_defaultProfiles() public view {
        GasNormalizer.GasProfile memory transferProfile = normalizer
            .getGasProfile(GasNormalizer.OperationType.TRANSFER);
        assertTrue(transferProfile.isActive);
        assertGt(transferProfile.targetGas, 0);
    }

    // =========================================================================
    // NORMALIZED EXECUTION
    // =========================================================================

    function test_executeNormalized() public {
        bytes memory data = abi.encodeWithSelector(
            GasTarget.increment.selector
        );

        vm.prank(user);
        (bool success, ) = normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );
        assertTrue(success);
        assertEq(target.counter(), 1);
    }

    function test_executeNormalized_unauthorized_reverts() public {
        address rando = makeAddr("rando");
        bytes memory data = abi.encodeWithSelector(
            GasTarget.increment.selector
        );

        vm.prank(rando);
        vm.expectRevert();
        normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );
    }

    // =========================================================================
    // CALLER AUTHORIZATION
    // =========================================================================

    function test_authorizeCaller() public {
        address newCaller = makeAddr("newCaller");

        vm.prank(admin);
        normalizer.authorizeCaller(newCaller, true);

        bytes memory data = abi.encodeWithSelector(
            GasTarget.increment.selector
        );
        vm.prank(newCaller);
        (bool success, ) = normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );
        assertTrue(success);
    }

    function test_authorizeCaller_onlyOperator() public {
        vm.prank(user);
        vm.expectRevert();
        normalizer.authorizeCaller(makeAddr("other"), true);
    }

    // =========================================================================
    // GAS PROFILE MANAGEMENT
    // =========================================================================

    function test_setGasProfile() public {
        vm.prank(admin);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.COMPLEX,
            3_000_000,
            500_000,
            100_000
        );

        GasNormalizer.GasProfile memory profile = normalizer.getGasProfile(
            GasNormalizer.OperationType.COMPLEX
        );
        assertEq(profile.targetGas, 3_000_000);
        assertEq(profile.minGas, 500_000);
        assertEq(profile.variance, 100_000);
        assertTrue(profile.isActive);
    }

    function test_deactivateProfile() public {
        vm.prank(admin);
        normalizer.deactivateProfile(GasNormalizer.OperationType.TRANSFER);

        GasNormalizer.GasProfile memory profile = normalizer.getGasProfile(
            GasNormalizer.OperationType.TRANSFER
        );
        assertFalse(profile.isActive);
    }

    // =========================================================================
    // NORMALIZATION TOGGLE
    // =========================================================================

    function test_setNormalizationEnabled() public {
        vm.prank(admin);
        normalizer.setNormalizationEnabled(false);
        assertFalse(normalizer.normalizationEnabled());

        vm.prank(admin);
        normalizer.setNormalizationEnabled(true);
        assertTrue(normalizer.normalizationEnabled());
    }

    // =========================================================================
    // METRICS
    // =========================================================================

    function test_metricsTrack() public {
        bytes memory data = abi.encodeWithSelector(
            GasTarget.increment.selector
        );

        vm.prank(user);
        normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );

        GasNormalizer.ExecutionMetrics memory m = normalizer.getMetrics();
        assertEq(m.totalExecutions, 1);
        assertGt(m.totalGasUsed, 0);
    }

    function test_callerMetrics() public {
        bytes memory data = abi.encodeWithSelector(
            GasTarget.increment.selector
        );

        vm.prank(user);
        normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );

        GasNormalizer.ExecutionMetrics memory m = normalizer.getCallerMetrics(
            user
        );
        assertEq(m.totalExecutions, 1);
    }

    // =========================================================================
    // VIEW HELPERS
    // =========================================================================

    function test_getTargetGas() public view {
        uint256 targetGas = normalizer.getTargetGas(
            GasNormalizer.OperationType.TRANSFER
        );
        assertGt(targetGas, 0);
    }

    function test_wouldNormalize() public view {
        (bool would, uint256 burn) = normalizer.wouldNormalize(
            GasNormalizer.OperationType.TRANSFER,
            100_000
        );
        assertTrue(would);
        assertGt(burn, 0);
    }

    function test_estimateGasToBurn() public view {
        uint256 estimate = normalizer.estimateGasToBurn(
            GasNormalizer.OperationType.TRANSFER,
            100_000
        );
        assertGt(estimate, 0);
    }
}
