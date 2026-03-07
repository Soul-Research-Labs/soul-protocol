// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/GasNormalizer.sol";
import "../../contracts/interfaces/IGasNormalizer.sol";

contract GasNormalizerTest is Test {
    GasNormalizer public normalizer;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public nobody = makeAddr("nobody");

    event GasCeilingConfigured(
        IGasNormalizer.OperationType indexed opType,
        uint256 targetGas
    );
    event GasNormalized(
        IGasNormalizer.OperationType indexed opType,
        uint256 actualGas,
        uint256 paddedGas
    );

    function setUp() public {
        normalizer = new GasNormalizer(admin);

        vm.startPrank(admin);
        normalizer.grantRole(normalizer.OPERATOR_ROLE(), operator);
        vm.stopPrank();
    }

    // ════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ════════════════════════════════════════════════════════════════

    function test_constructor_setsRoles() public view {
        assertTrue(normalizer.hasRole(normalizer.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(normalizer.hasRole(normalizer.OPERATOR_ROLE(), admin));
    }

    function test_constructor_enabledByDefault() public view {
        assertTrue(normalizer.enabled());
    }

    function test_constructor_setsDefaultCeilings() public view {
        IGasNormalizer.GasCeiling memory deposit = normalizer.getGasCeiling(
            IGasNormalizer.OperationType.DEPOSIT
        );
        assertEq(deposit.targetGas, 300_000);
        assertTrue(deposit.isActive);

        IGasNormalizer.GasCeiling memory bridge = normalizer.getGasCeiling(
            IGasNormalizer.OperationType.BRIDGE
        );
        assertEq(bridge.targetGas, 800_000);
        assertTrue(bridge.isActive);
    }

    // ════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ════════════════════════════════════════════════════════════════

    function test_setGasCeiling_operatorCanSet() public {
        vm.prank(operator);
        vm.expectEmit(true, false, false, true);
        emit GasCeilingConfigured(
            IGasNormalizer.OperationType.TRANSFER,
            600_000
        );
        normalizer.setGasCeiling(
            IGasNormalizer.OperationType.TRANSFER,
            600_000
        );

        IGasNormalizer.GasCeiling memory c = normalizer.getGasCeiling(
            IGasNormalizer.OperationType.TRANSFER
        );
        assertEq(c.targetGas, 600_000);
        assertTrue(c.isActive);
    }

    function test_setGasCeiling_revertsBelowMin() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IGasNormalizer.InvalidGasCeiling.selector,
                IGasNormalizer.OperationType.DEPOSIT,
                10_000
            )
        );
        normalizer.setGasCeiling(IGasNormalizer.OperationType.DEPOSIT, 10_000);
    }

    function test_setGasCeiling_revertsAboveMax() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IGasNormalizer.InvalidGasCeiling.selector,
                IGasNormalizer.OperationType.DEPOSIT,
                20_000_000
            )
        );
        normalizer.setGasCeiling(
            IGasNormalizer.OperationType.DEPOSIT,
            20_000_000
        );
    }

    function test_setGasCeiling_revertsForNonOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        normalizer.setGasCeiling(IGasNormalizer.OperationType.DEPOSIT, 500_000);
    }

    function test_deactivateCeiling() public {
        vm.prank(operator);
        normalizer.deactivateCeiling(IGasNormalizer.OperationType.DEPOSIT);

        assertFalse(normalizer.isActive(IGasNormalizer.OperationType.DEPOSIT));
    }

    function test_setEnabled_toggle() public {
        vm.prank(operator);
        normalizer.setEnabled(false);
        assertFalse(normalizer.enabled());

        vm.prank(operator);
        normalizer.setEnabled(true);
        assertTrue(normalizer.enabled());
    }

    // ════════════════════════════════════════════════════════════════
    // GAS BURN
    // ════════════════════════════════════════════════════════════════

    function test_burnToTarget_emitsEvent() public {
        uint256 gasStart = gasleft();

        vm.expectEmit(true, false, false, false);
        emit GasNormalized(IGasNormalizer.OperationType.DEPOSIT, 0, 0);
        normalizer.burnToTarget(IGasNormalizer.OperationType.DEPOSIT, gasStart);
    }

    function test_burnToTarget_noopWhenDisabled() public {
        vm.prank(operator);
        normalizer.setEnabled(false);

        uint256 gasBefore = gasleft();
        normalizer.burnToTarget(
            IGasNormalizer.OperationType.DEPOSIT,
            gasBefore
        );
        uint256 gasAfter = gasleft();

        // Should use very little gas when disabled (just the function call overhead)
        assertLt(gasBefore - gasAfter, 10_000);
    }

    function test_burnToTarget_noopWhenCeilingInactive() public {
        vm.prank(operator);
        normalizer.deactivateCeiling(IGasNormalizer.OperationType.DEPOSIT);

        uint256 gasBefore = gasleft();
        normalizer.burnToTarget(
            IGasNormalizer.OperationType.DEPOSIT,
            gasBefore
        );
        uint256 gasAfter = gasleft();

        assertLt(gasBefore - gasAfter, 10_000);
    }

    function test_burnToTarget_consumesGasTowardsCeiling() public {
        // Set a small ceiling for testing
        vm.prank(operator);
        normalizer.setGasCeiling(IGasNormalizer.OperationType.DEPOSIT, 100_000);

        // Measure gas WITHOUT normalization (disabled)
        vm.prank(operator);
        normalizer.setEnabled(false);
        uint256 gasA = gasleft();
        normalizer.burnToTarget(IGasNormalizer.OperationType.DEPOSIT, gasA);
        uint256 gasUsedDisabled = gasA - gasleft();

        // Measure gas WITH normalization (enabled)
        vm.prank(operator);
        normalizer.setEnabled(true);
        uint256 gasB = gasleft();
        normalizer.burnToTarget(IGasNormalizer.OperationType.DEPOSIT, gasB);
        uint256 gasUsedEnabled = gasB - gasleft();

        // Enabled burn should consume more gas than disabled (no-op) path
        assertGt(
            gasUsedEnabled,
            gasUsedDisabled,
            "burn loop should consume extra gas"
        );
    }

    function test_isActive_returnsFalseWhenGloballyDisabled() public {
        vm.prank(operator);
        normalizer.setEnabled(false);

        assertFalse(normalizer.isActive(IGasNormalizer.OperationType.DEPOSIT));
    }

    function test_calculateBurn_returnsCorrectAmount() public view {
        uint256 burn = normalizer.calculateBurn(
            IGasNormalizer.OperationType.DEPOSIT,
            100_000
        );
        assertEq(burn, 200_000); // 300_000 ceiling - 100_000 used
    }

    function test_calculateBurn_returnsZeroWhenExceeded() public view {
        uint256 burn = normalizer.calculateBurn(
            IGasNormalizer.OperationType.DEPOSIT,
            400_000
        );
        assertEq(burn, 0);
    }

    function test_calculateBurn_returnsZeroWhenDisabled() public {
        vm.prank(operator);
        normalizer.setEnabled(false);

        uint256 burn = normalizer.calculateBurn(
            IGasNormalizer.OperationType.DEPOSIT,
            100_000
        );
        assertEq(burn, 0);
    }

    // ════════════════════════════════════════════════════════════════
    // RECORDSTART
    // ════════════════════════════════════════════════════════════════

    function test_recordStart_returnsGasLeft() public view {
        uint256 gasBefore = gasleft();
        uint256 recorded = normalizer.recordStart();
        // recordStart should return a value close to gasleft() at call time
        assertGt(recorded, 0);
        assertLt(recorded, gasBefore);
    }

    // ════════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ════════════════════════════════════════════════════════════════

    function testFuzz_setGasCeiling_validRange(uint256 gas) public {
        gas = bound(
            gas,
            normalizer.MIN_GAS_CEILING(),
            normalizer.MAX_GAS_CEILING()
        );

        vm.prank(operator);
        normalizer.setGasCeiling(IGasNormalizer.OperationType.TRANSFER, gas);

        IGasNormalizer.GasCeiling memory c = normalizer.getGasCeiling(
            IGasNormalizer.OperationType.TRANSFER
        );
        assertEq(c.targetGas, gas);
    }

    function testFuzz_setGasCeiling_revertsOutOfRange(uint256 gas) public {
        vm.assume(
            gas < normalizer.MIN_GAS_CEILING() ||
                gas > normalizer.MAX_GAS_CEILING()
        );

        vm.prank(operator);
        vm.expectRevert();
        normalizer.setGasCeiling(IGasNormalizer.OperationType.DEPOSIT, gas);
    }

    function testFuzz_calculateBurn_neverReverts(uint256 gasUsed) public view {
        // Should never revert regardless of input
        normalizer.calculateBurn(IGasNormalizer.OperationType.DEPOSIT, gasUsed);
    }
}
