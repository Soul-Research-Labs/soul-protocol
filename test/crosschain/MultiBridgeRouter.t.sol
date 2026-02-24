// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/MultiBridgeRouter.sol";
import "../../contracts/crosschain/IBridgeAdapter.sol";

contract MockBridgeAdapter is IBridgeAdapter {
    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        return keccak256("mock");
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256) {
        return 0;
    }

    function isMessageverified(bytes32) external pure override returns (bool) {
        return true;
    }
}

contract MockTarget {
    bool public executed;
    bytes public receivedData;

    function execute(bytes calldata data) external {
        executed = true;
        receivedData = data;
    }

    function revertFunc() external pure {
        revert("Target Reverted");
    }
}

contract MultiBridgeRouterTest is Test {
    SimpleMultiBridgeRouter public router;
    MockBridgeAdapter public adapter1;
    MockBridgeAdapter public adapter2;
    MockBridgeAdapter public adapter3;
    MockTarget public target;

    function setUp() public {
        router = new SimpleMultiBridgeRouter(address(this), 2); // 2 confirmations required

        adapter1 = new MockBridgeAdapter();
        adapter2 = new MockBridgeAdapter();
        adapter3 = new MockBridgeAdapter();

        target = new MockTarget();

        // Register adapters
        router.addAdapter(address(adapter1));
        router.addAdapter(address(adapter2));
        router.addAdapter(address(adapter3));
    }

    function test_sendMultiBridgeMessage_IncrementsNonce() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"1234")
        );

        uint256 nonceBefore = router.nonce();
        router.sendMultiBridgeMessage{value: 0}(
            address(target),
            payload,
            address(this)
        );
        uint256 nonceAfter = router.nonce();

        assertEq(nonceAfter, nonceBefore + 1);
    }

    function test_receiveConfirmation_Execute() public {
        bytes memory data = hex"1234";
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", data)
        );

        // 1. Send message to get ID
        bytes32 messageId = router.sendMultiBridgeMessage(
            address(target),
            payload,
            address(this)
        );

        // 2. Construct wrapped payload for receiving side
        bytes memory wrappedPayload = abi.encode(messageId, payload);

        // 3. Adapter 1 confirms
        vm.prank(address(adapter1));
        router.receiveBridgeMessage(wrappedPayload);

        (uint256 confirmations, bool executed) = router.messages(messageId);
        assertEq(confirmations, 1);
        assertFalse(executed);
        assertFalse(target.executed());

        // 4. Adapter 2 confirms (Trigger execution)
        vm.prank(address(adapter2));
        router.receiveBridgeMessage(wrappedPayload);

        (confirmations, executed) = router.messages(messageId);
        assertEq(confirmations, 2);
        assertTrue(executed);
        assertTrue(target.executed());
        assertEq(target.receivedData(), data);
    }

    function test_receiveConfirmation_ReplayProtection() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"")
        );
        bytes32 messageId = router.sendMultiBridgeMessage(
            address(target),
            payload,
            address(this)
        );
        bytes memory wrappedPayload = abi.encode(messageId, payload);

        vm.startPrank(address(adapter1));
        router.receiveBridgeMessage(wrappedPayload);

        // Try confirming again
        vm.expectRevert("Already confirmed");
        router.receiveBridgeMessage(wrappedPayload);
        vm.stopPrank();
    }

    function test_ExecutionFailure_Reverts() public {
        // Prepare payload calling revertFunc
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("revertFunc()")
        );
        bytes32 messageId = router.sendMultiBridgeMessage(
            address(target),
            payload,
            address(this)
        );
        bytes memory wrappedPayload = abi.encode(messageId, payload);

        vm.prank(address(adapter1));
        router.receiveBridgeMessage(wrappedPayload);

        // Adapter 2 triggers execution which reverts
        vm.prank(address(adapter2));
        vm.expectRevert("Execution failed");
        router.receiveBridgeMessage(wrappedPayload);
    }
}
