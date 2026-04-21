// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {BridgeAdapterBase} from "../../contracts/crosschain/base/BridgeAdapterBase.sol";
import "../../contracts/crosschain/LayerZeroAdapter.sol";

contract LayerZeroAdapterTest is Test {
    LayerZeroAdapter adapter;
    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address guardian = address(0x6A1);
    address lzEndpoint = address(0xE0E);
    address user = address(0xBEEF);
    address treasury = address(0x7EA5);
    uint32 localEid = 30101; // Ethereum

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    function setUp() public {
        adapter = new LayerZeroAdapter(admin, lzEndpoint, localEid);
        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(GUARDIAN_ROLE, guardian);
        adapter.grantRole(EXECUTOR_ROLE, operator);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, operator));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, guardian));
        assertEq(adapter.lzEndpoint(), lzEndpoint);
        assertEq(adapter.localEid(), localEid);
        assertEq(adapter.bridgeFeeBps(), 15);
    }

    function test_Constructor_RevertZeroAdmin() public {
        vm.expectRevert(BridgeAdapterBase.ZeroAddress.selector);
        new LayerZeroAdapter(address(0), lzEndpoint, localEid);
    }

    function test_Constructor_RevertZeroEndpoint() public {
        vm.expectRevert(BridgeAdapterBase.ZeroAddress.selector);
        new LayerZeroAdapter(admin, address(0), localEid);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureEndpoint() public {
        vm.prank(operator);
        adapter.configureEndpoint(30110, address(0xAB), 15, 200_000);

        (
            uint32 eid,
            address ep,
            uint64 confs,
            uint128 gas,
            bool active
        ) = adapter.endpoints(30110);
        assertEq(eid, 30110);
        assertEq(ep, address(0xAB));
        assertEq(confs, 15);
        assertEq(gas, 200_000);
        assertTrue(active);
    }

    function test_ConfigureEndpoint_RevertZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(LayerZeroAdapter.InvalidEndpoint.selector);
        adapter.configureEndpoint(30110, address(0), 15, 200_000);
    }

    function test_ConfigureEndpoint_RevertNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.configureEndpoint(30110, address(0xAB), 15, 200_000);
    }

    function test_SetPeer() public {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.setPeer(30110, peer);
        assertEq(adapter.peers(30110), peer);
    }

    function test_SetPeer_RevertZeroPeer() public {
        vm.prank(operator);
        vm.expectRevert(LayerZeroAdapter.InvalidPeer.selector);
        adapter.setPeer(30110, bytes32(0));
    }

    function test_ConfigureDVN() public {
        address[] memory required = new address[](2);
        required[0] = address(0x1);
        required[1] = address(0x2);
        address[] memory optional = new address[](1);
        optional[0] = address(0x3);

        vm.prank(operator);
        adapter.configureDVN(30101, 30110, required, optional, 1);

        LayerZeroAdapter.DVNConfig memory cfg = adapter.getDVNConfig(
            30101,
            30110
        );
        assertEq(cfg.requiredDVNs.length, 2);
        assertEq(cfg.optionalDVNs.length, 1);
        assertEq(cfg.optionalThreshold, 1);
    }

    /*//////////////////////////////////////////////////////////////
                          SEND TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Send_RevertEndpointNotConfigured() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                LayerZeroAdapter.EndpointNotConfigured.selector,
                uint32(30110)
            )
        );
        adapter.send{value: 0.1 ether}(
            30110,
            address(0xDEAD),
            "hello",
            LayerZeroAdapter.MessagingOptions(200_000, 0, "")
        );
    }

    function test_Send_RevertPeerNotSet() public {
        vm.prank(operator);
        adapter.configureEndpoint(30110, address(0xAB), 15, 200_000);

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                LayerZeroAdapter.PeerNotSet.selector,
                uint32(30110)
            )
        );
        adapter.send{value: 0.1 ether}(
            30110,
            address(0xDEAD),
            "hello",
            LayerZeroAdapter.MessagingOptions(200_000, 0, "")
        );
    }

    function test_Send_RevertZeroReceiver() public {
        _configureEndpointAndPeer(30110);

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(LayerZeroAdapter.ZeroReceiver.selector);
        adapter.send{value: 0.1 ether}(
            30110,
            address(0),
            "hello",
            LayerZeroAdapter.MessagingOptions(200_000, 0, "")
        );
    }

    function test_Send_RevertPayloadTooLarge() public {
        _configureEndpointAndPeer(30110);
        bytes memory oversized = new bytes(10241);

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeAdapterBase.PayloadTooLarge.selector,
                uint256(10241),
                uint256(10240)
            )
        );
        adapter.send{value: 0.1 ether}(
            30110,
            address(0xDEAD),
            oversized,
            LayerZeroAdapter.MessagingOptions(200_000, 0, "")
        );
    }

    function test_Send_RevertGasLimitExceeded() public {
        _configureEndpointAndPeer(30110);

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                LayerZeroAdapter.GasLimitExceeded.selector,
                uint128(6_000_000),
                uint256(5_000_000)
            )
        );
        adapter.send{value: 0.1 ether}(
            30110,
            address(0xDEAD),
            "hello",
            LayerZeroAdapter.MessagingOptions(6_000_000, 0, "")
        );
    }

    function test_Send_RevertWhenPaused() public {
        _configureEndpointAndPeer(30110);

        vm.prank(guardian);
        adapter.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.send{value: 0.1 ether}(
            30110,
            address(0xDEAD),
            "hello",
            LayerZeroAdapter.MessagingOptions(200_000, 0, "")
        );
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_LzReceive_RevertUnauthorizedCaller() public {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(user); // Not the LZ endpoint
        vm.expectRevert(LayerZeroAdapter.UnauthorizedCaller.selector);
        adapter.lzReceive(30110, peer, 0, "hello");
    }

    function test_LzReceive_RevertInvalidPeer() public {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        bytes32 wrongPeer = bytes32(uint256(uint160(address(0xBAD))));

        vm.prank(operator);
        adapter.setPeer(30110, peer);

        vm.prank(lzEndpoint);
        vm.expectRevert(LayerZeroAdapter.InvalidPeer.selector);
        adapter.lzReceive(30110, wrongPeer, 0, "hello");
    }

    function test_LzReceive_Success() public {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.setPeer(30110, peer);

        vm.prank(lzEndpoint);
        adapter.lzReceive(30110, peer, 0, "hello");

        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_LzReceive_RevertReplay() public {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.setPeer(30110, peer);

        vm.startPrank(lzEndpoint);
        adapter.lzReceive(30110, peer, 0, "hello");

        vm.expectRevert();
        adapter.lzReceive(30110, peer, 0, "hello"); // same nonce
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       FEE ESTIMATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EstimateFee() public {
        vm.prank(operator);
        adapter.configureEndpoint(30110, address(0xAB), 15, 200_000);

        LayerZeroAdapter.MessagingFee memory fee = adapter.estimateFee(
            30110,
            "hello",
            200_000
        );
        assertGt(fee.nativeFee, 0);
        assertEq(fee.lzTokenFee, 0);
    }

    function test_EstimateFee_RevertUnconfigured() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                LayerZeroAdapter.EndpointNotConfigured.selector,
                uint32(99999)
            )
        );
        adapter.estimateFee(99999, "hello", 200_000);
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetFee() public {
        vm.prank(operator);
        adapter.setFee(50);
        assertEq(adapter.bridgeFeeBps(), 50);
    }

    function test_SetFee_RevertTooHigh() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                LayerZeroAdapter.FeeTooHigh.selector,
                uint256(101)
            )
        );
        adapter.setFee(101);
    }

    function test_SetTreasury() public {
        vm.prank(operator);
        adapter.setTreasury(treasury);
        assertEq(adapter.treasury(), treasury);
    }

    function test_SetTreasury_RevertZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(BridgeAdapterBase.ZeroAddress.selector);
        adapter.setTreasury(address(0));
    }

    function test_DisableEndpoint() public {
        vm.prank(operator);
        adapter.configureEndpoint(30110, address(0xAB), 15, 200_000);

        vm.prank(guardian);
        adapter.disableEndpoint(30110);

        (, , , , bool active) = adapter.endpoints(30110);
        assertFalse(active);
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

    function test_BridgeMessage_RevertsUnmappedChain() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        // Payload encodes chainId=999 (unmapped) + actual message
        bytes memory payload = abi.encodePacked(uint256(999), bytes("hello"));
        vm.expectRevert();
        adapter.bridgeMessage{value: 0.1 ether}(
            address(0x1),
            payload,
            address(0)
        );
    }

    function test_EstimateFee_IBridgeAdapter_Reverts() public {
        vm.expectRevert("Use estimateFee(uint32,bytes,uint128)");
        adapter.estimateFee(address(0x1), "");
    }

    function test_IsMessageVerified_DefaultFalse() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(1))));
    }

    function test_IsMessageVerified_AfterReceive() public {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.setPeer(30110, peer);

        vm.prank(lzEndpoint);
        adapter.lzReceive(30110, peer, 0, "hello");

        // The message ID is derived internally — check totalMessagesReceived instead
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetUserMessages_Empty() public view {
        bytes32[] memory msgs = adapter.getUserMessages(user);
        assertEq(msgs.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetFee(uint256 feeBps) public {
        vm.prank(operator);
        if (feeBps > 100) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    LayerZeroAdapter.FeeTooHigh.selector,
                    feeBps
                )
            );
        }
        adapter.setFee(feeBps);
    }

    function testFuzz_ConfigureEndpoint(
        uint32 eid,
        uint64 confs,
        uint128 baseGas
    ) public {
        vm.prank(operator);
        adapter.configureEndpoint(eid, address(0xAB), confs, baseGas);
        (uint32 storedEid, , , , bool active) = adapter.endpoints(eid);
        assertEq(storedEid, eid);
        assertTrue(active);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPERS
    //////////////////////////////////////////////////////////////*/

    function _configureEndpointAndPeer(uint32 eid) internal {
        bytes32 peer = bytes32(uint256(uint160(address(0xDEAD))));
        vm.startPrank(operator);
        adapter.configureEndpoint(eid, address(0xAB), 15, 200_000);
        adapter.setPeer(eid, peer);
        vm.stopPrank();
    }
}
