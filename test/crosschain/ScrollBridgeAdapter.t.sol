// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/experimental/adapters/ScrollBridgeAdapter.sol";

/**
 * @title ScrollBridgeAdapterTest
 * @notice Unit tests for the Scroll bridge adapter
 */
contract ScrollBridgeAdapterTest is Test {
    ScrollBridgeAdapter adapter;
    address admin = address(0xAD1);
    address user = address(0xBEEF);
    address scrollMessenger = address(0x5C10);
    address gatewayRouter = address(0x6A7E);
    address rollupContract = address(0x10CC);

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    function setUp() public {
        adapter = new ScrollBridgeAdapter(
            scrollMessenger,
            gatewayRouter,
            rollupContract,
            admin
        );
        vm.startPrank(admin);
        adapter.grantRole(PAUSER_ROLE, admin);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ChainId() public view {
        assertEq(adapter.chainId(), 534352);
    }

    function test_ChainName() public view {
        assertEq(adapter.chainName(), "Scroll");
    }

    function test_IsConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_FinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    function test_Roles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetSoulHubL2() public {
        vm.prank(admin);
        adapter.setSoulHubL2(address(0x1234));
    }

    function test_SetSoulHubL2_RevertNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setSoulHubL2(address(0x1234));
    }

    function test_SetProofRegistry() public {
        vm.prank(admin);
        adapter.setProofRegistry(address(0x5678));
    }

    function test_SetProofRegistry_RevertNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setProofRegistry(address(0x5678));
    }

    /*//////////////////////////////////////////////////////////////
                         MESSAGE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SendMessage_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage(address(0x1), hex"", 200000);
    }

    function test_VerifyMessage_EmptyProof() public view {
        assertFalse(adapter.verifyMessage(bytes32(0), hex""));
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

    function test_Pause_RevertNonPauser() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EmergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(admin);
        adapter.emergencyWithdrawETH(payable(admin), 2 ether);
        assertEq(address(admin).balance, 2 ether);
    }

    function test_EmergencyWithdrawETH_RevertNonAdmin() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(user), 1 ether);
    }
}
