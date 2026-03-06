// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/LineaBridgeAdapter.sol";

contract LineaBridgeAdapterTest is Test {
    LineaBridgeAdapter adapter;
    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address executor = address(0xEC1);
    address guardian = address(0x6A1);
    address user = address(0xBEEF);
    address treasury = address(0x7EA5);

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    function setUp() public {
        adapter = new LineaBridgeAdapter(admin);
        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(EXECUTOR_ROLE, executor);
        adapter.grantRole(GUARDIAN_ROLE, guardian);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, operator));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, guardian));
        assertTrue(adapter.hasRole(EXECUTOR_ROLE, executor));
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureLinea() public {
        vm.prank(operator);
        adapter.configureLinea(
            59144, // Linea chain ID
            address(0x1), // messageService
            address(0x2) // tokenBridge
        );
    }

    function test_ConfigureLinea_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.configureLinea(59144, address(0x1), address(0x2));
    }

    function test_MapToken() public {
        vm.prank(operator);
        adapter.mapToken(address(0xDA1), address(0xDA2), 59144, 18);
    }

    function test_MapToken_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.mapToken(address(0xDA1), address(0xDA2), 59144, 18);
    }

    function test_SetFee() public {
        vm.prank(operator);
        adapter.setFee(25);
    }

    function test_SetFee_RevertTooHigh() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setFee(10001);
    }

    function test_SetTreasury() public {
        vm.prank(operator);
        adapter.setTreasury(treasury);
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Deposit_RevertUnconfiguredBridge() public {
        vm.deal(user, 2 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.deposit{value: 1 ether}(
            59144,
            user,
            address(0),
            1 ether,
            0.01 ether
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RegisterWithdrawal_RevertNonExecutor() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.registerWithdrawal(
            user,
            user,
            address(0),
            1 ether,
            100,
            bytes32(0)
        );
    }

    function test_ClaimWithdrawal_RevertInvalidId() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.claimWithdrawal(bytes32(uint256(999)));
    }

    /*//////////////////////////////////////////////////////////////
                       PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(guardian);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_Unpause() public {
        vm.prank(guardian);
        adapter.pause();
        vm.prank(guardian);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_Pause_RevertNonGuardian() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    /*//////////////////////////////////////////////////////////////
                   IBridgeAdapter COMPATIBILITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_BridgeMessage_Reverts() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert("Use deposit() with explicit parameters");
        adapter.bridgeMessage{value: 0.5 ether}(address(0x1), "", address(0));
    }

    function test_EstimateFee_Reverts() public {
        vm.expectRevert("Use Linea-specific fee estimation");
        adapter.estimateFee(address(0x1), "");
    }

    function test_IsMessageVerified_DefaultFalse() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(1))));
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetUserDeposits_Empty() public view {
        bytes32[] memory deposits = adapter.getUserDeposits(user);
        assertEq(deposits.length, 0);
    }

    function test_GetUserWithdrawals_Empty() public view {
        bytes32[] memory withdrawals = adapter.getUserWithdrawals(user);
        assertEq(withdrawals.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetFee(uint256 feeBps) public {
        vm.prank(operator);
        if (feeBps > 100) {
            vm.expectRevert();
        }
        adapter.setFee(feeBps);
    }
}
