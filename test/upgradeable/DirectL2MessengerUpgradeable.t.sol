// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DirectL2MessengerUpgradeable} from "../../contracts/upgradeable/DirectL2MessengerUpgradeable.sol";

/// @dev Minimal mock L1 bridge adapter for sendMessage tests
contract MockL1Adapter {
    event MessageSent(uint256 destChainId, address recipient, bytes data);

    function sendMessage(
        uint256 destChainId,
        address recipient_,
        bytes calldata data
    ) external payable {
        emit MessageSent(destChainId, recipient_, data);
    }
}

/**
 * @title DirectL2MessengerUpgradeable Tests
 * @notice Tests initialization, messaging, relayer operations, access control,
 *         and upgrade safety for the UUPS-upgradeable DirectL2Messenger.
 */
contract DirectL2MessengerUpgradeableTest is Test {
    DirectL2MessengerUpgradeable public impl;
    DirectL2MessengerUpgradeable public messenger;

    address admin = address(this);
    address zaseonHub = makeAddr("zaseonHub");
    address operator = makeAddr("operator");
    address relayer1 = makeAddr("relayer1");
    address relayer2 = makeAddr("relayer2");
    address user = makeAddr("user");
    address recipient = makeAddr("recipient");

    uint256 constant DEST_CHAIN = 42161; // Arbitrum
    uint256 constant MIN_RELAYER_BOND = 1 ether;

    function setUp() public {
        impl = new DirectL2MessengerUpgradeable();
        bytes memory data = abi.encodeCall(impl.initialize, (admin, zaseonHub));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
        messenger = DirectL2MessengerUpgradeable(payable(address(proxy)));
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializerSetsAdmin() public view {
        assertTrue(messenger.hasRole(messenger.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_InitializerSetsOperator() public view {
        assertTrue(messenger.hasRole(messenger.OPERATOR_ROLE(), admin));
    }

    function test_InitializerSetsUpgrader() public view {
        assertTrue(messenger.hasRole(messenger.UPGRADER_ROLE(), admin));
    }

    function test_InitializerSetsZaseonHub() public view {
        assertEq(messenger.zaseonHub(), zaseonHub);
    }

    function test_InitializerSetsChainId() public view {
        assertEq(messenger.currentChainId(), block.chainid);
    }

    function test_ContractVersion() public view {
        assertEq(messenger.contractVersion(), 1);
    }

    function test_InitializerSetsChallengerReward() public view {
        assertEq(messenger.challengerReward(), 0.1 ether);
    }

    function test_InitializerSetsRequiredConfirmations() public view {
        assertEq(messenger.requiredConfirmations(), 3);
    }

    function test_CannotDoubleInitialize() public {
        vm.expectRevert();
        messenger.initialize(admin, zaseonHub);
    }

    function test_CannotInitializeWithZeroAdmin() public {
        DirectL2MessengerUpgradeable newImpl = new DirectL2MessengerUpgradeable();
        vm.expectRevert(DirectL2MessengerUpgradeable.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(newImpl.initialize, (address(0), zaseonHub))
        );
    }

    function test_CannotInitializeWithZeroHub() public {
        DirectL2MessengerUpgradeable newImpl = new DirectL2MessengerUpgradeable();
        vm.expectRevert(DirectL2MessengerUpgradeable.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(newImpl.initialize, (admin, address(0)))
        );
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE SENDING
    //////////////////////////////////////////////////////////////*/

    function test_SendMessage_RevertsForSameChain() public {
        vm.expectRevert(
            DirectL2MessengerUpgradeable.InvalidDestinationChain.selector
        );
        messenger.sendMessage(
            block.chainid,
            recipient,
            "hello",
            DirectL2MessengerUpgradeable.MessagePath.SLOW_L1,
            bytes32(0)
        );
    }

    function test_SendMessage_RevertsForZeroRecipient() public {
        vm.expectRevert(DirectL2MessengerUpgradeable.InvalidMessage.selector);
        messenger.sendMessage(
            DEST_CHAIN,
            address(0),
            "hello",
            DirectL2MessengerUpgradeable.MessagePath.SLOW_L1,
            bytes32(0)
        );
    }

    function test_SendMessage_ViaL1Path() public {
        // Deploy a mock L1 bridge adapter
        MockL1Adapter adapter = new MockL1Adapter();

        // Configure a SLOW_L1 route with the adapter
        messenger.configureRoute(
            block.chainid,
            DEST_CHAIN,
            DirectL2MessengerUpgradeable.MessagePath.SLOW_L1,
            address(adapter),
            1,
            3600
        );

        bytes32 messageId = messenger.sendMessage(
            DEST_CHAIN,
            recipient,
            "test payload",
            DirectL2MessengerUpgradeable.MessagePath.SLOW_L1,
            bytes32(0)
        );
        assertTrue(messageId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterRelayer() public {
        vm.deal(relayer1, 2 ether);
        vm.prank(relayer1);
        messenger.registerRelayer{value: MIN_RELAYER_BOND}();
    }

    function test_RegisterRelayer_InsufficientBond() public {
        vm.deal(relayer1, 2 ether);
        vm.prank(relayer1);
        vm.expectRevert(DirectL2MessengerUpgradeable.InsufficientBond.selector);
        messenger.registerRelayer{value: 0.5 ether}();
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN CONTROLS
    //////////////////////////////////////////////////////////////*/

    function test_SetRequiredConfirmations() public {
        messenger.setRequiredConfirmations(5);
        assertEq(messenger.requiredConfirmations(), 5);
    }

    function test_SetRequiredConfirmations_OnlyOperator() public {
        vm.prank(user);
        vm.expectRevert();
        messenger.setRequiredConfirmations(5);
    }

    function test_SetChallengerReward() public {
        messenger.setChallengerReward(0.5 ether);
        assertEq(messenger.challengerReward(), 0.5 ether);
    }

    function test_ConfigureRoute() public {
        messenger.configureRoute(
            block.chainid,
            DEST_CHAIN,
            DirectL2MessengerUpgradeable.MessagePath.FAST_RELAYER,
            address(0),
            3,
            7200
        );
    }

    function test_ConfigureRoute_OnlyOperator() public {
        vm.prank(user);
        vm.expectRevert();
        messenger.configureRoute(
            block.chainid,
            DEST_CHAIN,
            DirectL2MessengerUpgradeable.MessagePath.FAST_RELAYER,
            address(0),
            3,
            7200
        );
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        messenger.pause();
        assertTrue(messenger.paused());
    }

    function test_Unpause() public {
        messenger.pause();
        messenger.unpause();
        assertFalse(messenger.paused());
    }

    function test_SendMessage_RevertWhenPaused() public {
        messenger.pause();
        vm.expectRevert();
        messenger.sendMessage(
            DEST_CHAIN,
            recipient,
            "hello",
            DirectL2MessengerUpgradeable.MessagePath.SLOW_L1,
            bytes32(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          UPGRADE SAFETY
    //////////////////////////////////////////////////////////////*/

    function test_UpgradeOnlyUpgrader() public {
        DirectL2MessengerUpgradeable newImpl = new DirectL2MessengerUpgradeable();
        // Admin has UPGRADER_ROLE
        messenger.upgradeToAndCall(address(newImpl), "");
        assertEq(messenger.contractVersion(), 2);
    }

    function test_UpgradeRevertsWithoutRole() public {
        DirectL2MessengerUpgradeable newImpl = new DirectL2MessengerUpgradeable();
        vm.prank(user);
        vm.expectRevert();
        messenger.upgradeToAndCall(address(newImpl), "");
    }

    function test_UpgradePreservesState() public {
        // Set some state
        messenger.setRequiredConfirmations(7);
        messenger.setChallengerReward(0.5 ether);

        // Upgrade
        DirectL2MessengerUpgradeable newImpl = new DirectL2MessengerUpgradeable();
        messenger.upgradeToAndCall(address(newImpl), "");

        // State preserved
        assertEq(messenger.requiredConfirmations(), 7);
        assertEq(messenger.challengerReward(), 0.5 ether);
        assertEq(messenger.zaseonHub(), zaseonHub);
        assertEq(messenger.currentChainId(), block.chainid);
        assertEq(messenger.contractVersion(), 2);
    }
}
