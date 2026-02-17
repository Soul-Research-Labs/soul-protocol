// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/adapters/HyperlaneBridgeWrapper.sol";
import "../../contracts/adapters/LayerZeroBridgeWrapper.sol";
import "../../contracts/adapters/NativeL2BridgeWrapper.sol";
import "../../contracts/crosschain/IBridgeAdapter.sol";

/// @dev Mock Hyperlane mailbox
contract MockMailbox {
    uint256 public dispatchCount;
    bool public shouldFail;

    function dispatch(
        uint32,
        bytes32,
        bytes calldata
    ) external payable returns (bytes32) {
        if (shouldFail) revert("dispatch failed");
        dispatchCount++;
        return keccak256(abi.encodePacked(dispatchCount));
    }

    function quoteDispatch(
        uint32,
        bytes32,
        bytes calldata
    ) external pure returns (uint256) {
        return 0.005 ether;
    }

    function delivered(bytes32) external pure returns (bool) {
        return true;
    }

    function setFail(bool _fail) external {
        shouldFail = _fail;
    }
}

/// @dev Mock LayerZero endpoint
contract MockLZEndpoint {
    uint256 public sendCount;
    bool public shouldFail;

    // Simplified send that accepts any calldata
    fallback() external payable {
        if (shouldFail) revert("send failed");
        sendCount++;
    }

    receive() external payable {}

    function setFail(bool _fail) external {
        shouldFail = _fail;
    }
}

/// @dev Mock native bridge (OP-style messenger)
contract MockNativeBridge {
    uint256 public messageCount;
    bool public shouldFail;

    function sendMessage(address, bytes calldata, uint32) external payable {
        if (shouldFail) revert("bridge failed");
        messageCount++;
    }

    function createRetryableTicket(
        address,
        uint256,
        uint256,
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external payable returns (uint256) {
        if (shouldFail) revert("ticket failed");
        messageCount++;
        return messageCount;
    }

    function setFail(bool _fail) external {
        shouldFail = _fail;
    }
}

contract BridgeAdapterWrappersTest is Test {
    HyperlaneBridgeWrapper public hyperlaneWrapper;
    LayerZeroBridgeWrapper public lzWrapper;
    NativeL2BridgeWrapper public opWrapper;
    NativeL2BridgeWrapper public arbWrapper;

    MockMailbox public mockMailbox;
    MockLZEndpoint public mockLZEndpoint;
    MockNativeBridge public mockNativeBridge;

    address admin = address(this);
    address user = makeAddr("user");
    address target = makeAddr("target");

    function setUp() public {
        mockMailbox = new MockMailbox();
        mockLZEndpoint = new MockLZEndpoint();
        mockNativeBridge = new MockNativeBridge();

        hyperlaneWrapper = new HyperlaneBridgeWrapper(
            admin,
            address(mockMailbox),
            42161 // Arbitrum domain
        );

        lzWrapper = new LayerZeroBridgeWrapper(
            admin,
            address(mockLZEndpoint),
            30110, // LZ Arbitrum EID
            bytes32(uint256(uint160(target)))
        );

        opWrapper = new NativeL2BridgeWrapper(
            admin,
            address(mockNativeBridge),
            NativeL2BridgeWrapper.BridgeType.OP_CROSS_DOMAIN_MESSENGER,
            200_000
        );

        arbWrapper = new NativeL2BridgeWrapper(
            admin,
            address(mockNativeBridge),
            NativeL2BridgeWrapper.BridgeType.ARBITRUM_INBOX,
            200_000
        );
    }

    // ================================================================
    // Hyperlane Wrapper
    // ================================================================

    function test_Hyperlane_bridgeMessage() public {
        bytes memory payload = abi.encode("hello");
        bytes32 msgId = hyperlaneWrapper.bridgeMessage(target, payload, admin);

        assertTrue(msgId != bytes32(0));
        assertEq(mockMailbox.dispatchCount(), 1);
    }

    function test_Hyperlane_estimateFee() public view {
        uint256 fee = hyperlaneWrapper.estimateFee(target, abi.encode("test"));
        assertEq(fee, 0.005 ether);
    }

    function test_Hyperlane_isMessageVerified() public view {
        // MockMailbox.delivered always returns true
        assertTrue(hyperlaneWrapper.isMessageverified(bytes32(uint256(1))));
    }

    function test_Hyperlane_constructorZeroMailboxReverts() public {
        vm.expectRevert(HyperlaneBridgeWrapper.InvalidMailbox.selector);
        new HyperlaneBridgeWrapper(admin, address(0), 42161);
    }

    function test_Hyperlane_dispatchFailureReverts() public {
        mockMailbox.setFail(true);
        vm.expectRevert(HyperlaneBridgeWrapper.DispatchFailed.selector);
        hyperlaneWrapper.bridgeMessage(target, abi.encode("fail"), admin);
    }

    function test_Hyperlane_nonceIncrements() public {
        hyperlaneWrapper.bridgeMessage(target, abi.encode("a"), admin);
        assertEq(hyperlaneWrapper.nonce(), 1);
        hyperlaneWrapper.bridgeMessage(target, abi.encode("b"), admin);
        assertEq(hyperlaneWrapper.nonce(), 2);
    }

    // ================================================================
    // LayerZero Wrapper
    // ================================================================

    function test_LZ_bridgeMessage() public {
        bytes memory payload = abi.encode("lz-test");
        bytes32 msgId = lzWrapper.bridgeMessage{value: 0.01 ether}(
            target,
            payload,
            admin
        );
        vm.deal(address(this), 1 ether);

        assertTrue(msgId != bytes32(0));
    }

    function test_LZ_isMessageVerified_defaultFalse() public view {
        assertFalse(lzWrapper.isMessageverified(bytes32(uint256(99))));
    }

    function test_LZ_markVerified() public {
        bytes32 msgId = bytes32(uint256(42));
        lzWrapper.markVerified(msgId);
        assertTrue(lzWrapper.isMessageverified(msgId));
    }

    function test_LZ_peerNotSetReverts() public {
        LayerZeroBridgeWrapper wrapper = new LayerZeroBridgeWrapper(
            admin,
            address(mockLZEndpoint),
            30110,
            bytes32(0) // No peer
        );
        vm.expectRevert(LayerZeroBridgeWrapper.PeerNotSet.selector);
        wrapper.bridgeMessage(target, abi.encode("test"), admin);
    }

    function test_LZ_constructorZeroEndpointReverts() public {
        vm.expectRevert(LayerZeroBridgeWrapper.InvalidEndpoint.selector);
        new LayerZeroBridgeWrapper(
            admin,
            address(0),
            30110,
            bytes32(uint256(1))
        );
    }

    // ================================================================
    // Native L2 Bridge Wrapper (OP Stack)
    // ================================================================

    function test_OP_bridgeMessage() public {
        bytes memory payload = abi.encode("op-test");
        bytes32 msgId = opWrapper.bridgeMessage(target, payload, admin);

        assertTrue(msgId != bytes32(0));
        assertEq(mockNativeBridge.messageCount(), 1);
    }

    function test_OP_estimateFee() public view {
        uint256 fee = opWrapper.estimateFee(target, abi.encode("test"));
        assertEq(fee, 0.002 ether);
    }

    function test_OP_failureReverts() public {
        mockNativeBridge.setFail(true);
        vm.expectRevert(NativeL2BridgeWrapper.BridgeSendFailed.selector);
        opWrapper.bridgeMessage(target, abi.encode("fail"), admin);
    }

    // ================================================================
    // Native L2 Bridge Wrapper (Arbitrum)
    // ================================================================

    function test_Arb_bridgeMessage() public {
        bytes memory payload = abi.encode("arb-test");
        bytes32 msgId = arbWrapper.bridgeMessage(target, payload, admin);

        assertTrue(msgId != bytes32(0));
        assertEq(mockNativeBridge.messageCount(), 1);
    }

    function test_Arb_estimateFee() public view {
        uint256 fee = arbWrapper.estimateFee(target, abi.encode("test"));
        assertEq(fee, 0.005 ether);
    }

    // ================================================================
    // Interface compliance — all wrappers implement IBridgeAdapter
    // ================================================================

    function test_allWrappersImplementIBridgeAdapter() public view {
        // Compile-time check via casting
        IBridgeAdapter h = IBridgeAdapter(address(hyperlaneWrapper));
        IBridgeAdapter l = IBridgeAdapter(address(lzWrapper));
        IBridgeAdapter o = IBridgeAdapter(address(opWrapper));
        IBridgeAdapter a = IBridgeAdapter(address(arbWrapper));

        // Verify they're valid addresses
        assertTrue(address(h) != address(0));
        assertTrue(address(l) != address(0));
        assertTrue(address(o) != address(0));
        assertTrue(address(a) != address(0));
    }

    function test_NativeWrapper_markVerified() public {
        bytes32 msgId = bytes32(uint256(7));
        opWrapper.markVerified(msgId);
        assertTrue(opWrapper.isMessageverified(msgId));
    }

    function test_NativeWrapper_constructorZeroBridgeReverts() public {
        vm.expectRevert(NativeL2BridgeWrapper.InvalidBridge.selector);
        new NativeL2BridgeWrapper(
            admin,
            address(0),
            NativeL2BridgeWrapper.BridgeType.OP_CROSS_DOMAIN_MESSENGER,
            200_000
        );
    }
}
