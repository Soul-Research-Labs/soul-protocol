// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/experimental/privacy/GasNormalizer.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract GasTarget {
    uint256 public value;

    function setVal(uint256 v) external {
        value = v;
    }

    function expensiveOp(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            value = uint256(keccak256(abi.encodePacked(value, i)));
        }
    }

    function revertOp() external pure {
        revert("intentional");
    }
}

contract GasNormalizerTest is Test {
    GasNormalizer public normalizer;
    GasTarget public target;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public caller1 = makeAddr("caller1");

    function setUp() public {
        // Deploy UUPS proxy
        GasNormalizer impl = new GasNormalizer();
        bytes memory initData = abi.encodeCall(
            GasNormalizer.initialize,
            (admin)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        normalizer = GasNormalizer(address(proxy));

        normalizer.grantRole(normalizer.OPERATOR_ROLE(), operator);
        target = new GasTarget();
    }

    // ======== Initialization ========

    function test_initialize() public view {
        assertTrue(normalizer.hasRole(normalizer.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(normalizer.hasRole(normalizer.OPERATOR_ROLE(), admin));
    }

    function test_initialize_revert_doubleInit() public {
        vm.expectRevert();
        normalizer.initialize(admin);
    }

    // ======== Gas Profile Management ========

    function test_setGasProfile() public {
        vm.prank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            100_000,
            10_000
        );
    }

    function test_setGasProfile_revert_notOperator() public {
        vm.prank(caller1);
        vm.expectRevert();
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            100_000,
            10_000
        );
    }

    function test_getGasProfile() public {
        vm.prank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.SWAP,
            2_000_000,
            200_000,
            50_000
        );

        GasNormalizer.GasProfile memory profile = normalizer.getGasProfile(
            GasNormalizer.OperationType.SWAP
        );
        assertEq(profile.targetGas, 2_000_000);
        assertEq(profile.minGas, 200_000);
    }

    function test_deactivateProfile() public {
        vm.startPrank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            100_000,
            10_000
        );
        normalizer.deactivateProfile(GasNormalizer.OperationType.TRANSFER);
        vm.stopPrank();
    }

    // ======== Caller Authorization ========

    function test_authorizeCaller() public {
        vm.prank(operator);
        normalizer.authorizeCaller(caller1, true);
    }

    function test_authorizeCaller_deauthorize() public {
        vm.startPrank(operator);
        normalizer.authorizeCaller(caller1, true);
        normalizer.authorizeCaller(caller1, false);
        vm.stopPrank();
    }

    // ======== Normalization Toggle ========

    function test_setNormalizationEnabled() public {
        vm.prank(operator);
        normalizer.setNormalizationEnabled(false);
    }

    // ======== Execute Normalized ========

    function test_executeNormalized() public {
        vm.startPrank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            50_000,
            10_000
        );
        normalizer.authorizeCaller(caller1, true);
        normalizer.setNormalizationEnabled(true);
        vm.stopPrank();

        bytes memory data = abi.encodeCall(GasTarget.setVal, (42));

        vm.prank(caller1);
        (bool success, ) = normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );
        assertTrue(success);
        assertEq(target.value(), 42);
    }

    function test_executeNormalized_revertingTarget() public {
        vm.startPrank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            50_000,
            10_000
        );
        normalizer.authorizeCaller(caller1, true);
        normalizer.setNormalizationEnabled(true);
        vm.stopPrank();

        bytes memory data = abi.encodeCall(GasTarget.revertOp, ());

        // executeNormalized may propagate the revert from the target
        vm.prank(caller1);
        vm.expectRevert("intentional");
        normalizer.executeNormalized(
            address(target),
            GasNormalizer.OperationType.TRANSFER,
            data
        );
    }

    // ======== Batch Execute ========

    function test_executeBatchNormalized() public {
        vm.startPrank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            50_000,
            10_000
        );
        normalizer.authorizeCaller(caller1, true);
        normalizer.setNormalizationEnabled(true);
        vm.stopPrank();

        address[] memory targets = new address[](2);
        targets[0] = address(target);
        targets[1] = address(target);

        GasNormalizer.OperationType[]
            memory opTypes = new GasNormalizer.OperationType[](2);
        opTypes[0] = GasNormalizer.OperationType.TRANSFER;
        opTypes[1] = GasNormalizer.OperationType.TRANSFER;

        bytes[] memory dataArray = new bytes[](2);
        dataArray[0] = abi.encodeCall(GasTarget.setVal, (10));
        dataArray[1] = abi.encodeCall(GasTarget.setVal, (20));

        vm.prank(caller1);
        bool[] memory successes = normalizer.executeBatchNormalized(
            targets,
            opTypes,
            dataArray
        );
        assertEq(successes.length, 2);
        assertTrue(successes[0]);
        assertTrue(successes[1]);
        assertEq(target.value(), 20);
    }

    // ======== Gas Burn ========

    function test_burnGas() public {
        uint256 gasBefore = gasleft();
        normalizer.burnGas(1000);
        uint256 gasAfter = gasleft();
        assertGt(gasBefore - gasAfter, 1000);
    }

    // ======== View Functions ========

    function test_getTargetGas() public {
        vm.prank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.DEPOSIT,
            3_000_000,
            100_000,
            10_000
        );

        uint256 targetGas = normalizer.getTargetGas(
            GasNormalizer.OperationType.DEPOSIT
        );
        assertEq(targetGas, 3_000_000);
    }

    function test_getMetrics() public view {
        GasNormalizer.ExecutionMetrics memory m = normalizer.getMetrics();
        assertEq(m.totalExecutions, 0);
    }

    function test_estimateGasToBurn() public {
        vm.prank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            50_000,
            10_000
        );

        uint256 estimate = normalizer.estimateGasToBurn(
            GasNormalizer.OperationType.TRANSFER,
            200_000
        );
        assertGt(estimate, 0);
    }

    function test_wouldNormalize() public {
        vm.prank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.TRANSFER,
            1_000_000,
            50_000,
            10_000
        );

        (bool would, uint256 gasToBurn) = normalizer.wouldNormalize(
            GasNormalizer.OperationType.TRANSFER,
            200_000
        );
        assertTrue(would);
        assertGt(gasToBurn, 0);
    }

    // ======== Fuzz ========

    function testFuzz_setGasProfile(
        uint256 targetGas,
        uint256 minGas,
        uint256 variance
    ) public {
        targetGas = bound(targetGas, 100_000, 5_000_000);
        minGas = bound(minGas, 10_000, targetGas);
        variance = bound(variance, 0, targetGas / 2);

        vm.prank(operator);
        normalizer.setGasProfile(
            GasNormalizer.OperationType.COMPLEX,
            targetGas,
            minGas,
            variance
        );

        GasNormalizer.GasProfile memory p = normalizer.getGasProfile(
            GasNormalizer.OperationType.COMPLEX
        );
        assertEq(p.targetGas, targetGas);
    }
}
