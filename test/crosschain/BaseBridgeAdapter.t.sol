// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BaseBridgeAdapter.sol";

/**
 * @title BaseBridgeAdapterTest
 * @notice Unit tests for the Base bridge adapter
 */
contract BaseBridgeAdapterTest is Test {
    BaseBridgeAdapter adapter;
    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address relayer = address(0x1E1);
    address guardian = address(0x6A1);
    address user = address(0xBEEF);

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant CCTP_ROLE = keccak256("CCTP_ROLE");

    function setUp() public {
        adapter = new BaseBridgeAdapter(
            admin,
            address(0xCD1), // l1CrossDomainMessenger
            address(0xCD2), // l2CrossDomainMessenger
            address(0xBA5), // basePortal
            true // isL1
        );
        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(GUARDIAN_ROLE, guardian);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
        assertEq(adapter.BASE_MAINNET_CHAIN_ID(), 8453);
        assertEq(adapter.ETH_MAINNET_CHAIN_ID(), 1);
    }

    function test_StatsInitiallyZero() public view {
        (
            uint256 msgSent,
            uint256 msgRecv,
            uint256 valBridged,
            uint256 usdcBridged,
            uint256 currentNonce
        ) = adapter.getStats();
        assertEq(msgSent, 0);
        assertEq(msgRecv, 0);
        assertEq(valBridged, 0);
        assertEq(usdcBridged, 0);
        assertEq(currentNonce, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetL2Target() public {
        vm.prank(admin);
        adapter.setL2Target(address(0x1234));
    }

    function test_SetL2Target_RevertNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setL2Target(address(0x1234));
    }

    function test_ConfigureCCTP() public {
        vm.prank(admin);
        adapter.configureCCTP(address(0x1), address(0x2));
    }

    function test_SetMessenger() public {
        vm.prank(admin);
        adapter.setMessenger(address(0x1), true);
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF RELAY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IsProofRelayed_InitiallyFalse() public view {
        assertFalse(adapter.isProofRelayed(bytes32(uint256(42))));
    }

    function test_ReceiveProofFromL1() public {
        vm.prank(relayer);
        adapter.receiveProofFromL1(
            bytes32(uint256(42)),
            hex"abcd",
            hex"1234",
            1
        );
        assertTrue(adapter.isProofRelayed(bytes32(uint256(42))));
    }

    function test_ReceiveProofFromL1_RevertNonRelayer() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.receiveProofFromL1(
            bytes32(uint256(42)),
            hex"abcd",
            hex"1234",
            1
        );
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitiateWithdrawal_RevertInvalidChain() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.initiateWithdrawal{value: 1 ether}(bytes32(uint256(123)));
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
                      EMERGENCY WITHDRAW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EmergencyWithdraw() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(admin);
        adapter.emergencyWithdraw(admin, 2 ether);
        assertEq(admin.balance, 2 ether);
    }

    function test_EmergencyWithdraw_RevertNonAdmin() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.emergencyWithdraw(user, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE ETH
    //////////////////////////////////////////////////////////////*/

    function test_ReceiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
    }
}
