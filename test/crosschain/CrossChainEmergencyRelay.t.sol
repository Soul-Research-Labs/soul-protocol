// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CrossChainEmergencyRelay} from "../../contracts/crosschain/CrossChainEmergencyRelay.sol";
import {ICrossChainEmergencyRelay} from "../../contracts/interfaces/ICrossChainEmergencyRelay.sol";
import {IProtocolEmergencyCoordinator} from "../../contracts/interfaces/IProtocolEmergencyCoordinator.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK MESSENGER
//////////////////////////////////////////////////////////////*/

contract MockMessenger {
    bool public shouldRevert;
    uint256 public sendCallCount;
    address public lastTo;
    bytes public lastData;

    function sendMessage(address to, bytes calldata data) external {
        require(!shouldRevert, "MockMessenger: revert");
        sendCallCount++;
        lastTo = to;
        lastData = data;
    }

    function setShouldRevert(bool _v) external {
        shouldRevert = _v;
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: CONSTRUCTOR
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayConstructorTest is Test {
    function test_Constructor_Success() public {
        address admin = address(0xAD);
        CrossChainEmergencyRelay relay = new CrossChainEmergencyRelay(admin);

        assertEq(relay.deployChainId(), block.chainid);
        assertTrue(relay.hasRole(relay.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(relay.hasRole(relay.BROADCASTER_ROLE(), admin));
        assertTrue(relay.hasRole(relay.RECEIVER_ROLE(), admin));
        assertTrue(relay.hasRole(relay.HEARTBEAT_ROLE(), admin));

        (uint48 lastHeartbeat, uint48 interval, bool triggered) = relay
            .heartbeat();
        assertEq(interval, 1 hours);
        assertEq(lastHeartbeat, uint48(block.timestamp));
        assertFalse(triggered);
    }

    function test_Constructor_RevertsZeroAdmin() public {
        vm.expectRevert(ICrossChainEmergencyRelay.ZeroAddress.selector);
        new CrossChainEmergencyRelay(address(0));
    }

    function test_Constants() public {
        CrossChainEmergencyRelay relay = new CrossChainEmergencyRelay(
            address(1)
        );
        assertEq(relay.MAX_CHAINS(), 20);
        assertEq(relay.DEFAULT_HEARTBEAT_INTERVAL(), 1 hours);
        assertEq(relay.MIN_HEARTBEAT_INTERVAL(), 10 minutes);
        assertEq(relay.MAX_HEARTBEAT_INTERVAL(), 24 hours);
        assertEq(relay.EMERGENCY_PREFIX(), bytes4(0x454D5247));
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: CHAIN REGISTRATION
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayChainTest is Test {
    CrossChainEmergencyRelay relay;
    MockMessenger messenger1;
    MockMessenger messenger2;
    address admin = address(0xAD);
    address remote1 = address(0xBB);
    address remote2 = address(0xCC);
    uint256 chainId1 = 42161; // Arbitrum
    uint256 chainId2 = 10; // Optimism

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
        messenger1 = new MockMessenger();
        messenger2 = new MockMessenger();
    }

    function test_RegisterChain_Success() public {
        vm.prank(admin);
        relay.registerChain(chainId1, address(messenger1), remote1);

        (
            uint256 cid,
            address msgr,
            address receiver,
            bool active,
            uint48 lastBcast
        ) = relay.chains(chainId1);

        assertEq(cid, chainId1);
        assertEq(msgr, address(messenger1));
        assertEq(receiver, remote1);
        assertTrue(active);
        assertEq(lastBcast, 0);

        uint256[] memory ids = relay.getRegisteredChainIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], chainId1);
    }

    function test_RegisterChain_Multiple() public {
        vm.startPrank(admin);
        relay.registerChain(chainId1, address(messenger1), remote1);
        relay.registerChain(chainId2, address(messenger2), remote2);
        vm.stopPrank();

        assertEq(relay.activeChainCount(), 2);
    }

    function test_RegisterChain_RevertsZeroChainId() public {
        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.InvalidChainId.selector);
        relay.registerChain(0, address(messenger1), remote1);
    }

    function test_RegisterChain_RevertsSameChain() public {
        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.InvalidChainId.selector);
        relay.registerChain(block.chainid, address(messenger1), remote1);
    }

    function test_RegisterChain_RevertsAlreadyRegistered() public {
        vm.prank(admin);
        relay.registerChain(chainId1, address(messenger1), remote1);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.ChainAlreadyRegistered.selector,
                chainId1
            )
        );
        relay.registerChain(chainId1, address(messenger2), remote2);
    }

    function test_RegisterChain_RevertsZeroMessenger() public {
        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.ZeroAddress.selector);
        relay.registerChain(chainId1, address(0), remote1);
    }

    function test_RegisterChain_RevertsZeroReceiver() public {
        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.ZeroAddress.selector);
        relay.registerChain(chainId1, address(messenger1), address(0));
    }

    function test_RegisterChain_RevertsMaxChains() public {
        vm.startPrank(admin);
        for (uint256 i = 1; i <= relay.MAX_CHAINS(); i++) {
            // Use unique chain IDs that aren't the deploy chain
            uint256 cid = 1000 + i;
            relay.registerChain(cid, address(messenger1), remote1);
        }

        vm.expectRevert(ICrossChainEmergencyRelay.MaxChainsReached.selector);
        relay.registerChain(9999, address(messenger1), remote1);
        vm.stopPrank();
    }

    function test_DeactivateChain() public {
        vm.prank(admin);
        relay.registerChain(chainId1, address(messenger1), remote1);

        assertEq(relay.activeChainCount(), 1);

        vm.prank(admin);
        relay.deactivateChain(chainId1);

        assertEq(relay.activeChainCount(), 0);
        (, , , bool active, ) = relay.chains(chainId1);
        assertFalse(active);
    }

    function test_DeactivateChain_RevertsNotRegistered() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.ChainNotRegistered.selector,
                999
            )
        );
        relay.deactivateChain(999);
    }

    function test_ReactivateChain() public {
        vm.startPrank(admin);
        relay.registerChain(chainId1, address(messenger1), remote1);
        relay.deactivateChain(chainId1);
        relay.reactivateChain(chainId1);
        vm.stopPrank();

        assertEq(relay.activeChainCount(), 1);
    }

    function test_ReactivateChain_RevertsNotRegistered() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.ChainNotRegistered.selector,
                999
            )
        );
        relay.reactivateChain(999);
    }

    function test_RegisterChain_RevertsUnauthorized() public {
        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        relay.registerChain(chainId1, address(messenger1), remote1);
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: BROADCASTING
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayBroadcastTest is Test {
    CrossChainEmergencyRelay relay;
    MockMessenger messenger1;
    MockMessenger messenger2;
    address admin = address(0xAD);
    address remote1 = address(0xBB);
    address remote2 = address(0xCC);
    uint256 chainId1 = 42161;
    uint256 chainId2 = 10;

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
        messenger1 = new MockMessenger();
        messenger2 = new MockMessenger();

        vm.startPrank(admin);
        relay.registerChain(chainId1, address(messenger1), remote1);
        relay.registerChain(chainId2, address(messenger2), remote2);
        vm.stopPrank();
    }

    function test_BroadcastEmergency_Success() public {
        vm.prank(admin);
        relay.broadcastEmergency(IProtocolEmergencyCoordinator.Severity.RED, 1);

        assertEq(relay.globalNonce(), 1);
        assertEq(messenger1.sendCallCount(), 1);
        assertEq(messenger2.sendCallCount(), 1);
        assertEq(messenger1.lastTo(), remote1);
        assertEq(messenger2.lastTo(), remote2);
    }

    function test_BroadcastEmergency_IncrementsNonce() public {
        vm.startPrank(admin);
        relay.broadcastEmergency(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            1
        );
        relay.broadcastEmergency(IProtocolEmergencyCoordinator.Severity.RED, 1);
        vm.stopPrank();

        assertEq(relay.globalNonce(), 2);
    }

    function test_BroadcastEmergency_SkipsInactiveChains() public {
        vm.prank(admin);
        relay.deactivateChain(chainId2);

        vm.prank(admin);
        relay.broadcastEmergency(IProtocolEmergencyCoordinator.Severity.RED, 1);

        assertEq(messenger1.sendCallCount(), 1);
        assertEq(messenger2.sendCallCount(), 0);
    }

    function test_BroadcastEmergency_FailOpenOnSendFailure() public {
        messenger1.setShouldRevert(true);

        vm.prank(admin);
        // Should not revert even though messenger1 fails
        relay.broadcastEmergency(IProtocolEmergencyCoordinator.Severity.RED, 1);

        // Messenger2 still got the message
        assertEq(messenger2.sendCallCount(), 1);
    }

    function test_BroadcastEmergency_RevertsUnauthorized() public {
        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        relay.broadcastEmergency(IProtocolEmergencyCoordinator.Severity.RED, 1);
    }

    function test_BroadcastEmergency_RevertsWhenPaused() public {
        vm.prank(admin);
        relay.pause();

        vm.prank(admin);
        vm.expectRevert();
        relay.broadcastEmergency(IProtocolEmergencyCoordinator.Severity.RED, 1);
    }

    function test_BroadcastRecovery_Success() public {
        vm.prank(admin);
        relay.broadcastRecovery(1);

        assertEq(relay.globalNonce(), 1);
        assertEq(messenger1.sendCallCount(), 1);
        assertEq(messenger2.sendCallCount(), 1);
    }

    function test_BroadcastRecovery_SkipsInactive() public {
        vm.prank(admin);
        relay.deactivateChain(chainId1);

        vm.prank(admin);
        relay.broadcastRecovery(1);

        assertEq(messenger1.sendCallCount(), 0);
        assertEq(messenger2.sendCallCount(), 1);
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: RECEIVING
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayReceiveTest is Test {
    CrossChainEmergencyRelay relay;
    address admin = address(0xAD);
    uint256 sourceChainId = 1; // mainnet

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
    }

    function _makeMessage(
        IProtocolEmergencyCoordinator.Severity severity,
        uint256 nonce,
        uint256 incidentId
    ) internal view returns (bytes memory) {
        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg_ = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: nonce,
                sourceChainId: sourceChainId,
                targetChainId: block.chainid,
                severity: severity,
                incidentId: incidentId,
                timestamp: uint48(block.timestamp)
            });
        return abi.encode(msg_);
    }

    function test_ReceiveEmergency_Success() public {
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            1,
            100
        );

        vm.prank(admin);
        relay.receiveEmergency(encoded);

        assertEq(
            uint8(relay.receivedSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.YELLOW)
        );
        assertEq(relay.lastReceivedNonce(sourceChainId), 1);
    }

    function test_ReceiveEmergency_RED_AutoPauses() public {
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.RED,
            1,
            100
        );

        vm.prank(admin);
        relay.receiveEmergency(encoded);

        assertTrue(relay.paused());
    }

    function test_ReceiveEmergency_YELLOW_DoesNotPause() public {
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            1,
            100
        );

        vm.prank(admin);
        relay.receiveEmergency(encoded);

        assertFalse(relay.paused());
    }

    function test_ReceiveEmergency_ReplayRejected() public {
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            1,
            100
        );

        vm.prank(admin);
        relay.receiveEmergency(encoded);

        // Same nonce should revert
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.ReplayDetected.selector,
                sourceChainId,
                1
            )
        );
        relay.receiveEmergency(encoded);
    }

    function test_ReceiveEmergency_LowerNonceRejected() public {
        bytes memory encoded2 = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            2,
            100
        );
        vm.prank(admin);
        relay.receiveEmergency(encoded2);

        bytes memory encoded1 = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            1,
            100
        );
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.ReplayDetected.selector,
                sourceChainId,
                1
            )
        );
        relay.receiveEmergency(encoded1);
    }

    function test_ReceiveEmergency_WrongPrefix() public {
        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg_ = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: bytes4(0xDEADBEEF),
                nonce: 1,
                sourceChainId: sourceChainId,
                targetChainId: block.chainid,
                severity: IProtocolEmergencyCoordinator.Severity.RED,
                incidentId: 1,
                timestamp: uint48(block.timestamp)
            });

        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.InvalidMessage.selector);
        relay.receiveEmergency(abi.encode(msg_));
    }

    function test_ReceiveEmergency_WrongTargetChain() public {
        ICrossChainEmergencyRelay.EmergencyMessage memory msg_ = ICrossChainEmergencyRelay
            .EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: 1,
                sourceChainId: sourceChainId,
                targetChainId: 9999, // Wrong target
                severity: IProtocolEmergencyCoordinator.Severity.RED,
                incidentId: 1,
                timestamp: uint48(block.timestamp)
            });

        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.InvalidChainId.selector);
        relay.receiveEmergency(abi.encode(msg_));
    }

    function test_ReceiveEmergency_StaleMessage() public {
        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg_ = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: 1,
                sourceChainId: sourceChainId,
                targetChainId: block.chainid,
                severity: IProtocolEmergencyCoordinator.Severity.RED,
                incidentId: 1,
                timestamp: uint48(block.timestamp)
            });

        // Advance time past maxMessageAge (1 hour)
        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(admin);
        vm.expectRevert();
        relay.receiveEmergency(abi.encode(msg_));
    }

    function test_ReceiveEmergency_RevertsUnauthorized() public {
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.RED,
            1,
            100
        );

        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        relay.receiveEmergency(encoded);
    }

    function test_ReceiveEmergency_GREENRecovery() public {
        // First, trigger heartbeat auto-pause
        vm.warp(block.timestamp + 2 hours);
        relay.checkHeartbeatLiveness();
        assertTrue(relay.paused());

        // Now receive GREEN recovery — should unpause since autoPauseTriggered
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.GREEN,
            1,
            100
        );

        vm.prank(admin);
        relay.receiveEmergency(encoded);

        assertFalse(relay.paused());
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: HEARTBEAT
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayHeartbeatTest is Test {
    CrossChainEmergencyRelay relay;
    MockMessenger messenger;
    address admin = address(0xAD);
    address remote = address(0xBB);
    uint256 chainId1 = 42161;

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
        messenger = new MockMessenger();

        vm.prank(admin);
        relay.registerChain(chainId1, address(messenger), remote);
    }

    function test_SendHeartbeat_Success() public {
        vm.prank(admin);
        relay.sendHeartbeat(chainId1);

        assertEq(messenger.sendCallCount(), 1);
        assertEq(messenger.lastTo(), remote);
    }

    function test_SendHeartbeat_RevertsInactiveChain() public {
        vm.prank(admin);
        relay.deactivateChain(chainId1);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.ChainNotRegistered.selector,
                chainId1
            )
        );
        relay.sendHeartbeat(chainId1);
    }

    function test_SendHeartbeat_RevertsOnSendFailure() public {
        messenger.setShouldRevert(true);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainEmergencyRelay.SendFailed.selector,
                chainId1
            )
        );
        relay.sendHeartbeat(chainId1);
    }

    function test_ReceiveHeartbeat_ResetsTimer() public {
        vm.warp(block.timestamp + 30 minutes);

        vm.prank(admin);
        relay.receiveHeartbeat(1);

        (uint48 lastHeartbeat, , ) = relay.heartbeat();
        assertEq(lastHeartbeat, uint48(block.timestamp));
    }

    function test_CheckHeartbeatLiveness_TriggersAutoPause() public {
        // Advance past heartbeat interval (1 hour)
        vm.warp(block.timestamp + 1 hours + 1);

        relay.checkHeartbeatLiveness();

        assertTrue(relay.paused());
        (, , bool triggered) = relay.heartbeat();
        assertTrue(triggered);
    }

    function test_CheckHeartbeatLiveness_NoopIfRecent() public {
        relay.checkHeartbeatLiveness();

        assertFalse(relay.paused());
    }

    function test_CheckHeartbeatLiveness_NoopIfAlreadyTriggered() public {
        vm.warp(block.timestamp + 2 hours);
        relay.checkHeartbeatLiveness();
        assertTrue(relay.paused());

        // Call again — should be a no-op (already triggered)
        relay.checkHeartbeatLiveness();
        assertTrue(relay.paused());
    }

    function test_ReceiveHeartbeat_RecoversFromAutoPause() public {
        // Trigger auto-pause
        vm.warp(block.timestamp + 2 hours);
        relay.checkHeartbeatLiveness();
        assertTrue(relay.paused());

        // Receive heartbeat — should unpause
        vm.prank(admin);
        relay.receiveHeartbeat(1);

        assertFalse(relay.paused());
        (, , bool triggered) = relay.heartbeat();
        assertFalse(triggered);
    }

    function test_ReceiveHeartbeat_DoesNotRecoverIfEmergency() public {
        // Set received severity to YELLOW (emergency)
        bytes memory encoded = _makeMessage(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            1,
            100
        );
        vm.prank(admin);
        relay.receiveEmergency(encoded);

        // Trigger auto-pause via heartbeat
        vm.warp(block.timestamp + 2 hours);
        relay.checkHeartbeatLiveness();
        assertTrue(relay.paused());

        // Receive heartbeat — should NOT unpause because _isEmergency() is true
        vm.prank(admin);
        relay.receiveHeartbeat(1);

        assertTrue(relay.paused());
    }

    function test_IsHeartbeatOverdue() public {
        assertFalse(relay.isHeartbeatOverdue());

        vm.warp(block.timestamp + 1 hours + 1);
        assertTrue(relay.isHeartbeatOverdue());
    }

    function _makeMessage(
        IProtocolEmergencyCoordinator.Severity severity,
        uint256 nonce,
        uint256 incidentId
    ) internal view returns (bytes memory) {
        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg_ = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: nonce,
                sourceChainId: 1,
                targetChainId: block.chainid,
                severity: severity,
                incidentId: incidentId,
                timestamp: uint48(block.timestamp)
            });
        return abi.encode(msg_);
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: ADMIN FUNCTIONS
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayAdminTest is Test {
    CrossChainEmergencyRelay relay;
    address admin = address(0xAD);

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
    }

    function test_SetHeartbeatInterval_Success() public {
        vm.prank(admin);
        relay.setHeartbeatInterval(2 hours);

        (, uint48 interval, ) = relay.heartbeat();
        assertEq(interval, 2 hours);
    }

    function test_SetHeartbeatInterval_RevertsTooShort() public {
        vm.prank(admin);
        vm.expectRevert(
            ICrossChainEmergencyRelay.InvalidHeartbeatInterval.selector
        );
        relay.setHeartbeatInterval(5 minutes);
    }

    function test_SetHeartbeatInterval_RevertsTooLong() public {
        vm.prank(admin);
        vm.expectRevert(
            ICrossChainEmergencyRelay.InvalidHeartbeatInterval.selector
        );
        relay.setHeartbeatInterval(25 hours);
    }

    function test_SetHeartbeatInterval_BoundaryMin() public {
        vm.prank(admin);
        relay.setHeartbeatInterval(10 minutes);
        (, uint48 interval, ) = relay.heartbeat();
        assertEq(interval, 10 minutes);
    }

    function test_SetHeartbeatInterval_BoundaryMax() public {
        vm.prank(admin);
        relay.setHeartbeatInterval(24 hours);
        (, uint48 interval, ) = relay.heartbeat();
        assertEq(interval, 24 hours);
    }

    function test_SetMaxMessageAge_Success() public {
        vm.prank(admin);
        relay.setMaxMessageAge(2 hours);

        assertEq(relay.maxMessageAge(), 2 hours);
    }

    function test_SetMaxMessageAge_RevertsZero() public {
        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.InvalidMessage.selector);
        relay.setMaxMessageAge(0);
    }

    function test_SetMaxMessageAge_RevertsTooLong() public {
        vm.prank(admin);
        vm.expectRevert(ICrossChainEmergencyRelay.InvalidMessage.selector);
        relay.setMaxMessageAge(uint48(24 hours + 1));
    }

    function test_Pause_Unpause() public {
        vm.prank(admin);
        relay.pause();
        assertTrue(relay.paused());

        vm.prank(admin);
        relay.unpause();
        assertFalse(relay.paused());
    }

    function test_Unpause_ClearsAutoPauseTrigger() public {
        // Trigger auto-pause
        vm.warp(block.timestamp + 2 hours);
        relay.checkHeartbeatLiveness();
        assertTrue(relay.paused());

        vm.prank(admin);
        relay.unpause();

        (, , bool triggered) = relay.heartbeat();
        assertFalse(triggered);
    }

    function test_Pause_RevertsUnauthorized() public {
        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        relay.pause();
    }

    function test_Unpause_RevertsUnauthorized() public {
        vm.prank(admin);
        relay.pause();

        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        relay.unpause();
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: VIEW FUNCTIONS
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayViewTest is Test {
    CrossChainEmergencyRelay relay;
    MockMessenger messenger;
    address admin = address(0xAD);

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
        messenger = new MockMessenger();
    }

    function test_ActiveChainCount_Empty() public view {
        assertEq(relay.activeChainCount(), 0);
    }

    function test_ActiveChainCount_WithDeactivated() public {
        vm.startPrank(admin);
        relay.registerChain(100, address(messenger), address(0xBB));
        relay.registerChain(200, address(messenger), address(0xCC));
        relay.registerChain(300, address(messenger), address(0xDD));
        relay.deactivateChain(200);
        vm.stopPrank();

        assertEq(relay.activeChainCount(), 2);
    }

    function test_GetRegisteredChainIds() public {
        vm.startPrank(admin);
        relay.registerChain(100, address(messenger), address(0xBB));
        relay.registerChain(200, address(messenger), address(0xCC));
        vm.stopPrank();

        uint256[] memory ids = relay.getRegisteredChainIds();
        assertEq(ids.length, 2);
        assertEq(ids[0], 100);
        assertEq(ids[1], 200);
    }

    function test_IsInEmergency_False() public view {
        assertFalse(relay.isInEmergency());
    }

    function test_IsInEmergency_True() public {
        // Receive an emergency message to set receivedSeverity
        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg_ = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: 1,
                sourceChainId: 1,
                targetChainId: block.chainid,
                severity: IProtocolEmergencyCoordinator.Severity.YELLOW,
                incidentId: 1,
                timestamp: uint48(block.timestamp)
            });

        vm.prank(admin);
        relay.receiveEmergency(abi.encode(msg_));

        assertTrue(relay.isInEmergency());
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: FUZZ
//////////////////////////////////////////////////////////////*/

contract CrossChainEmergencyRelayFuzzTest is Test {
    CrossChainEmergencyRelay relay;
    MockMessenger messenger;
    address admin = address(0xAD);

    function setUp() public {
        relay = new CrossChainEmergencyRelay(admin);
        messenger = new MockMessenger();
    }

    function testFuzz_RegisterChain_ValidChainId(uint256 chainId) public {
        // Must not be 0 or deployChainId
        vm.assume(chainId != 0 && chainId != block.chainid);
        // Only register one chain to avoid MaxChainsReached
        vm.prank(admin);
        relay.registerChain(chainId, address(messenger), address(0xBB));

        (uint256 cid, , , , ) = relay.chains(chainId);
        assertEq(cid, chainId);
    }

    function testFuzz_HeartbeatInterval(uint48 interval) public {
        interval = uint48(bound(interval, 10 minutes, 24 hours));

        vm.prank(admin);
        relay.setHeartbeatInterval(interval);

        (, uint48 stored, ) = relay.heartbeat();
        assertEq(stored, interval);
    }

    function testFuzz_MessageAge(uint48 age) public {
        age = uint48(bound(age, 1, 24 hours));

        vm.prank(admin);
        relay.setMaxMessageAge(age);

        assertEq(relay.maxMessageAge(), age);
    }

    function testFuzz_ReceiveEmergency_NonceMonotonic(
        uint256 nonce1,
        uint256 nonce2
    ) public {
        nonce1 = bound(nonce1, 1, type(uint128).max - 1);
        nonce2 = bound(nonce2, nonce1 + 1, type(uint128).max);

        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg1 = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: nonce1,
                sourceChainId: 1,
                targetChainId: block.chainid,
                severity: IProtocolEmergencyCoordinator.Severity.YELLOW,
                incidentId: 1,
                timestamp: uint48(block.timestamp)
            });

        vm.prank(admin);
        relay.receiveEmergency(abi.encode(msg1));

        assertEq(relay.lastReceivedNonce(1), nonce1);

        ICrossChainEmergencyRelay.EmergencyMessage
            memory msg2 = ICrossChainEmergencyRelay.EmergencyMessage({
                prefix: relay.EMERGENCY_PREFIX(),
                nonce: nonce2,
                sourceChainId: 1,
                targetChainId: block.chainid,
                severity: IProtocolEmergencyCoordinator.Severity.ORANGE,
                incidentId: 2,
                timestamp: uint48(block.timestamp)
            });

        vm.prank(admin);
        relay.receiveEmergency(abi.encode(msg2));

        assertEq(relay.lastReceivedNonce(1), nonce2);
    }
}
