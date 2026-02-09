// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";

/**
 * @title ArbitrumBridgeAdapterTest
 * @notice Unit tests for the Arbitrum bridge adapter
 */
contract ArbitrumBridgeAdapterTest is Test {
    ArbitrumBridgeAdapter adapter;
    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address executor = address(0xEC1);
    address user = address(0xBEEF);
    address treasury = address(0x7EA5);

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    function setUp() public {
        adapter = new ArbitrumBridgeAdapter(admin);
        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(EXECUTOR_ROLE, executor);
        adapter.grantRole(GUARDIAN_ROLE, admin);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
        assertEq(adapter.ARB_ONE_CHAIN_ID(), 42161);
        assertEq(adapter.ARB_NOVA_CHAIN_ID(), 42170);
        assertEq(adapter.CHALLENGE_PERIOD(), 604800);
    }

    function test_BridgeStatsInitiallyZero() public view {
        (
            uint256 totalDeps,
            uint256 totalWith,
            uint256 totalValDep,
            uint256 totalValWith,
            uint256 totalFast,
            uint256 totalFees
        ) = adapter.getBridgeStats();
        assertEq(totalDeps, 0);
        assertEq(totalWith, 0);
        assertEq(totalValDep, 0);
        assertEq(totalValWith, 0);
        assertEq(totalFast, 0);
        assertEq(totalFees, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureRollup() public {
        vm.prank(operator);
        adapter.configureRollup(
            42161,
            address(0x1),
            address(0x2),
            address(0x3),
            address(0x4),
            ArbitrumBridgeAdapter.RollupType.ARB_ONE
        );
    }

    function test_ConfigureRollup_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.configureRollup(
            42161,
            address(0x1),
            address(0x2),
            address(0x3),
            address(0x4),
            ArbitrumBridgeAdapter.RollupType.ARB_ONE
        );
    }

    function test_SetBridgeFee() public {
        vm.prank(operator);
        adapter.setBridgeFee(25); // 0.25%
    }

    function test_SetBridgeFee_RevertTooHigh() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setBridgeFee(10001);
    }

    function test_SetDepositLimits() public {
        vm.prank(operator);
        adapter.setDepositLimits(1e16, 1e25);
    }

    function test_SetTreasury() public {
        vm.prank(admin);
        adapter.setTreasury(treasury);
    }

    function test_SetTreasury_RevertNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setTreasury(treasury);
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Deposit_RevertUnconfiguredRollup() public {
        vm.deal(user, 2 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.deposit{value: 1 ether}(
            42161,
            user,
            address(0),
            1 ether,
            1000000,
            1 gwei
        );
    }

    /*//////////////////////////////////////////////////////////////
                         PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(admin);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_Unpause() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_Pause_RevertNonGuardian() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    /*//////////////////////////////////////////////////////////////
                       FAST EXIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetFastExitEnabled() public {
        vm.prank(admin);
        adapter.setFastExitEnabled(false);
    }

    /*//////////////////////////////////////////////////////////////
                       TOKEN MAPPING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_MapToken() public {
        vm.prank(operator);
        adapter.mapToken(address(0xDA1), address(0xDA12), 42161, 18);
    }

    function test_MapToken_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.mapToken(address(0xDA1), address(0xDA12), 42161, 18);
    }

    /*//////////////////////////////////////////////////////////////
                       LIQUIDITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ProvideLiquidity() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        adapter.provideLiquidity{value: 5 ether}();
    }

    function test_ReceiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
    }
}
