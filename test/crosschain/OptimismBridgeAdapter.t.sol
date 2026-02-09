// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/OptimismBridgeAdapter.sol";

/**
 * @title OptimismBridgeAdapterTest
 * @notice Unit tests for the Optimism bridge adapter
 */
contract OptimismBridgeAdapterTest is Test {
    OptimismBridgeAdapter adapter;
    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address relayer = address(0x1E1);
    address guardian = address(0x6A1);
    address user = address(0xBEEF);

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    function setUp() public {
        adapter = new OptimismBridgeAdapter(admin);
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
        assertTrue(adapter.hasRole(RELAYER_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
        assertTrue(adapter.hasRole(TREASURY_ROLE, admin));
        assertEq(adapter.OPTIMISM_CHAIN_ID(), 10);
    }

    function test_RevertZeroAdmin() public {
        vm.expectRevert();
        new OptimismBridgeAdapter(address(0));
    }

    function test_BridgeStatsInitiallyZero() public view {
        (
            uint256 totalDep,
            uint256 totalWith,
            uint256 totalEsc,
            uint256 totalEscFin,
            uint256 totalEscCan,
            uint256 accFees,
            uint256 latestBlock
        ) = adapter.getBridgeStats();
        assertEq(totalDep, 0);
        assertEq(totalWith, 0);
        assertEq(totalEsc, 0);
        assertEq(totalEscFin, 0);
        assertEq(totalEscCan, 0);
        assertEq(accFees, 0);
        assertEq(latestBlock, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Configure() public {
        vm.prank(operator);
        adapter.configure(
            address(0x1), // optimism bridge contract
            address(0x2), // wrapped OP
            address(0x3), // L1 output oracle
            1, // min validator signatures
            12 // required block confirmations
        );
    }

    function test_Configure_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.configure(address(0x1), address(0x2), address(0x3), 1, 12);
    }

    function test_SetTreasury() public {
        vm.prank(admin);
        adapter.setTreasury(address(0x7EA5));
    }

    function test_SetTreasury_RevertNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setTreasury(address(0x7EA5));
    }

    function test_SetZKProofVerifier() public {
        vm.prank(admin);
        adapter.setZKProofVerifier(address(0xBEEF));
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitiateWithdrawal_RevertBridgeNotConfigured() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.initiateWithdrawal(user, 0.0001 ether);
    }

    function test_InitiateWithdrawal_RevertZeroRecipient() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.initiateWithdrawal(address(0), 1 ether);
    }

    function test_GetWithdrawal_NonExistent() public view {
        // Non-existent withdrawal returns default struct (no revert)
        IOptimismBridgeAdapter.OPWithdrawal memory w = adapter.getWithdrawal(
            bytes32(uint256(999))
        );
        assertEq(w.evmSender, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         ESCROW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreateEscrow_RevertNotConfigured() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.createEscrow{value: 1 ether}(
            address(0xABC), // l2Party
            keccak256("secret"), // hashlock
            uint256(block.timestamp + 2 hours), // finishAfter
            uint256(block.timestamp + 25 hours) // cancelAfter
        );
    }

    function test_CreateEscrow_RevertInvalidTimelock() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.createEscrow{value: 1 ether}(
            address(0xABC),
            keccak256("secret"),
            uint256(block.timestamp + 30 minutes), // too short
            uint256(block.timestamp + 31 days) // too long
        );
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
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WithdrawFees_RevertNonTreasury() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.withdrawFees();
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
