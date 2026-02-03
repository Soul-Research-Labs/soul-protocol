// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/adapters/MidnightL2BridgeAdapter.sol";

/**
 * @title MidnightL2BridgeAdapterTest
 * @notice Comprehensive tests for MidnightL2BridgeAdapter
 */
contract MidnightL2BridgeAdapterTest is Test {
    MidnightL2BridgeAdapter public adapter;

    address public admin = address(0xAD);
    address public operator = address(0xBB);
    address public relayer = address(0xCC);
    address public user = address(0xDD);
    address public bridgeHub = address(0x1111);
    address public proofVerifier = address(0x2222);

    // Chain IDs
    uint256 constant ARBITRUM = 42161;
    uint256 constant OPTIMISM = 10;
    uint256 constant BASE = 8453;
    uint256 constant ZKSYNC = 324;
    uint256 constant SCROLL = 534352;
    uint256 constant LINEA = 59144;
    uint256 constant POLYGON_ZKEVM = 1101;

    function setUp() public {
        adapter = new MidnightL2BridgeAdapter(bridgeHub, proofVerifier, admin);

        vm.deal(user, 100 ether);
        vm.deal(admin, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertEq(adapter.bridgeHub(), bridgeHub);
        assertEq(adapter.proofVerifier(), proofVerifier);
        assertEq(adapter.totalMessagesSent(), 0);
        assertEq(adapter.totalMessagesReceived(), 0);
    }

    function test_InitialL2Configs() public view {
        // Arbitrum
        (, , uint256 arbGasLimit, , , ) = adapter.l2Configs(ARBITRUM);
        assertEq(arbGasLimit, 1_000_000);

        // zkSync has higher gas limit
        (, , uint256 zkGasLimit, , , ) = adapter.l2Configs(ZKSYNC);
        assertEq(zkGasLimit, 2_000_000);
    }

    function test_AdminHasRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.EMERGENCY_ROLE(), admin));
    }

    function test_RevertOnZeroAddresses() public {
        vm.expectRevert("Invalid bridge hub");
        new MidnightL2BridgeAdapter(address(0), proofVerifier, admin);

        vm.expectRevert("Invalid verifier");
        new MidnightL2BridgeAdapter(bridgeHub, address(0), admin);

        vm.expectRevert("Invalid admin");
        new MidnightL2BridgeAdapter(bridgeHub, proofVerifier, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       SEND TO MIDNIGHT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SendToMidnight() public {
        bytes32 commitment = keccak256("commitment");
        bytes32 midnightRecipient = keccak256("midnight_addr");
        uint256 amount = 1 ether;

        vm.prank(user);
        bytes32 messageId = adapter.sendToMidnight{value: 0.01 ether}(
            commitment,
            midnightRecipient,
            amount,
            address(0) // ETH
        );

        assertNotEq(messageId, bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);

        // Check message stored - 11 fields in CrossChainMessage
        (
            bytes32 storedId, // sourceChainId // destChainId // midnightCommitment // nullifier // sender // recipient // amount // token // timestamp
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            MidnightL2BridgeAdapter.MessageStatus status
        ) = adapter.messages(messageId);
        assertEq(storedId, messageId);
        assertTrue(status == MidnightL2BridgeAdapter.MessageStatus.Pending);
    }

    function test_SendToMidnight_RevertOnZeroAmount() public {
        bytes32 commitment = keccak256("commitment");
        bytes32 midnightRecipient = keccak256("midnight_addr");

        vm.prank(user);
        vm.expectRevert(MidnightL2BridgeAdapter.InvalidMessage.selector);
        adapter.sendToMidnight{value: 0.01 ether}(
            commitment,
            midnightRecipient,
            0, // Zero amount
            address(0)
        );
    }

    function test_SendToMidnight_RevertOnInsufficientFee() public {
        bytes32 commitment = keccak256("commitment");
        bytes32 midnightRecipient = keccak256("midnight_addr");
        uint256 amount = 1 ether;

        vm.prank(user);
        vm.expectRevert(MidnightL2BridgeAdapter.InsufficientFee.selector);
        adapter.sendToMidnight{value: 0.0001 ether}( // Less than messageFee
            commitment,
            midnightRecipient,
            amount,
            address(0)
        );
    }

    function test_SendToMidnight_UniqueMessageIds() public {
        bytes32 commitment = keccak256("commitment");
        bytes32 midnightRecipient = keccak256("midnight_addr");
        uint256 amount = 1 ether;

        vm.startPrank(user);
        bytes32 messageId1 = adapter.sendToMidnight{value: 0.01 ether}(
            commitment,
            midnightRecipient,
            amount,
            address(0)
        );

        bytes32 messageId2 = adapter.sendToMidnight{value: 0.01 ether}(
            commitment,
            midnightRecipient,
            amount,
            address(0)
        );
        vm.stopPrank();

        assertNotEq(messageId1, messageId2, "Message IDs should be unique");
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PauseBlocksSend() public {
        vm.prank(admin);
        adapter.pause();

        bytes32 commitment = keccak256("commitment");
        bytes32 midnightRecipient = keccak256("midnight_addr");

        vm.prank(user);
        vm.expectRevert();
        adapter.sendToMidnight{value: 0.01 ether}(
            commitment,
            midnightRecipient,
            1 ether,
            address(0)
        );
    }

    function test_OnlyEmergencyCanPause() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    /*//////////////////////////////////////////////////////////////
                     L2 CONFIG MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetL2Config() public {
        address newMessenger = address(0x9999);

        vm.prank(admin);
        adapter.setL2Config(
            ARBITRUM,
            newMessenger,
            2_000_000, // increased gas limit
            2, // increased confirmations
            true, // active
            MidnightL2BridgeAdapter.L2ChainType.Arbitrum
        );

        (
            address messenger,
            ,
            uint256 gasLimit,
            uint64 confirmations,
            bool isActive,

        ) = adapter.l2Configs(ARBITRUM);
        assertEq(messenger, newMessenger);
        assertEq(gasLimit, 2_000_000);
        assertEq(confirmations, 2);
        assertTrue(isActive);
    }

    function test_OnlyAdminCanSetConfig() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setL2Config(
            ARBITRUM,
            address(0x9999),
            2_000_000,
            2,
            true,
            MidnightL2BridgeAdapter.L2ChainType.Arbitrum
        );
    }

    function test_ActivateL2() public {
        vm.prank(admin);
        adapter.setL2Config(
            ARBITRUM,
            address(0x9999),
            1_000_000,
            1,
            true,
            MidnightL2BridgeAdapter.L2ChainType.Arbitrum
        );

        (, , , , bool isActive, ) = adapter.l2Configs(ARBITRUM);
        assertTrue(isActive);
    }

    function test_DeactivateL2() public {
        vm.startPrank(admin);
        adapter.setL2Config(
            ARBITRUM,
            address(0x9999),
            1_000_000,
            1,
            true,
            MidnightL2BridgeAdapter.L2ChainType.Arbitrum
        );
        adapter.setL2Config(
            ARBITRUM,
            address(0x9999),
            1_000_000,
            1,
            false,
            MidnightL2BridgeAdapter.L2ChainType.Arbitrum
        );
        vm.stopPrank();

        (, , , , bool isActive, ) = adapter.l2Configs(ARBITRUM);
        assertFalse(isActive);
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_NullifierNotUsedInitially() public view {
        bytes32 nullifier = keccak256("test_nullifier");
        assertFalse(adapter.nullifierUsed(nullifier));
    }

    /*//////////////////////////////////////////////////////////////
                         FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SendToMidnight(
        bytes32 commitment,
        bytes32 midnightRecipient,
        uint256 amount
    ) public {
        vm.assume(amount > 0 && amount < 1000 ether);

        vm.prank(user);
        bytes32 messageId = adapter.sendToMidnight{value: 0.01 ether}(
            commitment,
            midnightRecipient,
            amount,
            address(0)
        );

        assertNotEq(messageId, bytes32(0));
    }

    function testFuzz_MessageIdUniqueness(
        bytes32 commitment1,
        bytes32 commitment2,
        uint256 amount
    ) public {
        vm.assume(amount > 0 && amount < 100 ether);
        vm.assume(commitment1 != commitment2);

        vm.startPrank(user);
        bytes32 messageId1 = adapter.sendToMidnight{value: 0.01 ether}(
            commitment1,
            keccak256("recipient"),
            amount,
            address(0)
        );

        bytes32 messageId2 = adapter.sendToMidnight{value: 0.01 ether}(
            commitment2,
            keccak256("recipient"),
            amount,
            address(0)
        );
        vm.stopPrank();

        assertNotEq(messageId1, messageId2);
    }

    /*//////////////////////////////////////////////////////////////
                   CHAIN TYPE SPECIFIC TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AllSupportedChainsInitialized() public view {
        // All major L2s should have configs
        uint256[7] memory chainIds = [
            ARBITRUM,
            OPTIMISM,
            BASE,
            ZKSYNC,
            SCROLL,
            LINEA,
            POLYGON_ZKEVM
        ];

        for (uint i = 0; i < chainIds.length; i++) {
            (, , uint256 gasLimit, , , ) = adapter.l2Configs(chainIds[i]);
            assertGt(gasLimit, 0, "Chain should have gas limit configured");
        }
    }

    function test_OptimismUsesCorrectMessenger() public view {
        (address messenger, , , , , ) = adapter.l2Configs(OPTIMISM);
        assertEq(messenger, 0x4200000000000000000000000000000000000007);
    }

    function test_BaseUsesCorrectMessenger() public view {
        (address messenger, , , , , ) = adapter.l2Configs(BASE);
        assertEq(messenger, 0x4200000000000000000000000000000000000007);
    }
}
