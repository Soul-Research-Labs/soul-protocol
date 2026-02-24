// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/MultiBridgeRouter.sol";
import "../../contracts/crosschain/IBridgeAdapter.sol";

/// @dev Bridge adapter that always reverts on bridgeMessage (simulates down bridge)
contract FailingBridgeAdapter is IBridgeAdapter {
    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        revert("Bridge unavailable");
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256) {
        return 0;
    }

    function isMessageverified(bytes32) external pure override returns (bool) {
        return false;
    }
}

/// @dev Bridge adapter that succeeds normally
contract SucceedingBridgeAdapter is IBridgeAdapter {
    uint256 public callCount;
    uint256 public lastValue;

    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        callCount++;
        lastValue = msg.value;
        return keccak256(abi.encodePacked("msg", callCount));
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256) {
        return 0.01 ether;
    }

    function isMessageverified(bytes32) external pure override returns (bool) {
        return true;
    }
}

/// @dev Reentrant adapter that tries to call receiveBridgeMessage during confirmation
contract ReentrantAdapter is IBridgeAdapter {
    SimpleMultiBridgeRouter public router;
    bytes public storedPayload;
    bool public shouldReenter;

    constructor(address _router) {
        router = SimpleMultiBridgeRouter(_router);
    }

    function setPayload(bytes memory p) external {
        storedPayload = p;
    }

    function setReenter(bool r) external {
        shouldReenter = r;
    }

    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        return keccak256("reentrant");
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

    /// @dev Called externally; this contract can also be pranked into calling receiveBridgeMessage
    function triggerReceive(bytes calldata payload) external {
        if (shouldReenter) {
            // Attempt reentrancy
            router.receiveBridgeMessage(payload);
        }
    }
}

/// @dev Target that receives ETH
contract ETHReceiver {
    bool public received;

    function execute(bytes calldata) external {
        received = true;
    }

    receive() external payable {}
}

/**
 * @title MultiBridgeRouterExtended
 * @notice Extended test coverage for SimpleMultiBridgeRouter: failover gaps, access control,
 *         edge cases, and configuration management.
 */
contract MultiBridgeRouterExtended is Test {
    SimpleMultiBridgeRouter public router;
    SucceedingBridgeAdapter public adapter1;
    SucceedingBridgeAdapter public adapter2;
    SucceedingBridgeAdapter public adapter3;
    ETHReceiver public target;
    address admin;
    address attacker;

    function setUp() public {
        admin = address(this);
        attacker = makeAddr("attacker");

        router = new SimpleMultiBridgeRouter(admin, 2);

        adapter1 = new SucceedingBridgeAdapter();
        adapter2 = new SucceedingBridgeAdapter();
        adapter3 = new SucceedingBridgeAdapter();
        target = new ETHReceiver();

        router.addAdapter(address(adapter1));
        router.addAdapter(address(adapter2));
        router.addAdapter(address(adapter3));
    }

    // ====================================================================
    // Failover — try/catch ensures graceful degradation
    // ====================================================================

    function test_failover_singleAdapterFailureDoesNotKillSend() public {
        // Deploy a new router with a failing adapter mixed in
        SimpleMultiBridgeRouter router2 = new SimpleMultiBridgeRouter(admin, 2);
        SucceedingBridgeAdapter good1 = new SucceedingBridgeAdapter();
        FailingBridgeAdapter bad = new FailingBridgeAdapter();
        SucceedingBridgeAdapter good2 = new SucceedingBridgeAdapter();

        router2.addAdapter(address(good1));
        router2.addAdapter(address(bad)); // This adapter always reverts
        router2.addAdapter(address(good2));

        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"aa")
        );

        // With try/catch: bad adapter fails gracefully, 2 good adapters succeed
        // requiredConfirmations=2, successCount=2 → does NOT revert
        router2.sendMultiBridgeMessage{value: 0}(
            address(target),
            payload,
            admin
        );

        // Prove the 2 good adapters were called successfully
        assertEq(good1.callCount(), 1, "Good adapter 1 should succeed");
        assertEq(good2.callCount(), 1, "Good adapter 2 should succeed");
    }

    function test_failover_allAdaptersFailing() public {
        SimpleMultiBridgeRouter router2 = new SimpleMultiBridgeRouter(admin, 1);
        FailingBridgeAdapter bad1 = new FailingBridgeAdapter();
        FailingBridgeAdapter bad2 = new FailingBridgeAdapter();

        router2.addAdapter(address(bad1));
        router2.addAdapter(address(bad2));

        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"bb")
        );

        vm.expectRevert("Insufficient adapters succeeded");
        router2.sendMultiBridgeMessage(address(target), payload, admin);
    }

    // ====================================================================
    // Access Control
    // ====================================================================

    function test_acl_nonAdminCannotAddAdapter() public {
        vm.prank(attacker);
        vm.expectRevert();
        router.addAdapter(makeAddr("newAdapter"));
    }

    function test_acl_nonAdminCannotSetConfirmations() public {
        vm.prank(attacker);
        vm.expectRevert();
        router.setRequiredConfirmations(1);
    }

    function test_acl_nonAdapterCannotConfirm() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"cc")
        );
        bytes32 msgId = router.sendMultiBridgeMessage(
            address(target),
            payload,
            admin
        );
        bytes memory wrapped = abi.encode(msgId, payload);

        vm.prank(attacker);
        vm.expectRevert(); // AccessControl revert
        router.receiveBridgeMessage(wrapped);
    }

    // ====================================================================
    // setRequiredConfirmations edge cases
    // ====================================================================

    function test_setConfirmations_validRange() public {
        router.setRequiredConfirmations(1);
        assertEq(router.requiredConfirmations(), 1);

        router.setRequiredConfirmations(3);
        assertEq(router.requiredConfirmations(), 3);
    }

    function test_setConfirmations_zeroReverts() public {
        vm.expectRevert("Invalid N");
        router.setRequiredConfirmations(0);
    }

    function test_setConfirmations_exceedsAdaptersReverts() public {
        // We have 3 adapters
        vm.expectRevert("Invalid N");
        router.setRequiredConfirmations(4);
    }

    // ====================================================================
    // Send with zero adapters
    // ====================================================================

    function test_sendWithZeroAdapters_reverts() public {
        SimpleMultiBridgeRouter emptyRouter = new SimpleMultiBridgeRouter(admin, 1);
        // No adapters added

        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"dd")
        );

        vm.expectRevert("Not enough adapters");
        emptyRouter.sendMultiBridgeMessage(address(target), payload, admin);
    }

    // ====================================================================
    // ETH value distribution across adapters
    // ====================================================================

    function test_ethDistribution_splitEvenly() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"ee")
        );

        // Send 3 ETH across 3 adapters → 1 ETH each
        vm.deal(admin, 3 ether);
        router.sendMultiBridgeMessage{value: 3 ether}(
            address(target),
            payload,
            admin
        );

        assertEq(adapter1.lastValue(), 1 ether);
        assertEq(adapter2.lastValue(), 1 ether);
        assertEq(adapter3.lastValue(), 1 ether);
    }

    function test_ethDistribution_dustLoss() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"ff")
        );

        // Send 1 wei across 3 adapters → 0 per adapter, 1 wei dust lost
        vm.deal(admin, 1);
        router.sendMultiBridgeMessage{value: 1}(
            address(target),
            payload,
            admin
        );

        // 1 / 3 = 0 per adapter due to integer division
        assertEq(adapter1.lastValue(), 0);
        assertEq(adapter2.lastValue(), 0);
        assertEq(adapter3.lastValue(), 0);
        // Dust (1 wei) stays in the router contract
        assertEq(address(router).balance, 1);
    }

    // ====================================================================
    // Confirmation after execution (3rd adapter confirms late)
    // ====================================================================

    function test_lateConfirmation_silentlyIgnored() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"11")
        );
        bytes32 msgId = router.sendMultiBridgeMessage(
            address(target),
            payload,
            admin
        );
        bytes memory wrapped = abi.encode(msgId, payload);

        // Adapter 1 + 2 confirm → executes (N=2)
        vm.prank(address(adapter1));
        router.receiveBridgeMessage(wrapped);

        vm.prank(address(adapter2));
        router.receiveBridgeMessage(wrapped);

        // Verify executed
        (uint256 confs, bool exec) = router.messages(msgId);
        assertTrue(exec);
        assertEq(confs, 2);

        // Adapter 3 confirms late — should silently return (status.executed = true)
        vm.prank(address(adapter3));
        router.receiveBridgeMessage(wrapped);

        // Confirmations should NOT increase (early return before incrementing)
        (confs, exec) = router.messages(msgId);
        assertEq(confs, 2, "Late confirmation should not increment counter");
        assertTrue(exec);
    }

    // ====================================================================
    // Message ID uniqueness (fuzz)
    // ====================================================================

    function testFuzz_messageIdUniqueness(uint8 count) public {
        vm.assume(count > 0 && count <= 20);

        bytes32[] memory ids = new bytes32[](count);

        for (uint8 i = 0; i < count; i++) {
            bytes memory payload = abi.encode(
                address(target),
                abi.encodeWithSignature("execute(bytes)", abi.encodePacked(i))
            );
            ids[i] = router.sendMultiBridgeMessage(
                address(target),
                payload,
                admin
            );
        }

        // All IDs must be unique
        for (uint8 i = 0; i < count; i++) {
            for (uint8 j = i + 1; j < count; j++) {
                assertNotEq(ids[i], ids[j], "Message IDs must be unique");
            }
        }
    }

    // ====================================================================
    // Nonce monotonicity
    // ====================================================================

    function test_nonceMonotonicallyIncreases() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"22")
        );

        uint256 n0 = router.nonce();
        router.sendMultiBridgeMessage(address(target), payload, admin);
        uint256 n1 = router.nonce();
        router.sendMultiBridgeMessage(address(target), payload, admin);
        uint256 n2 = router.nonce();

        assertEq(n1, n0 + 1);
        assertEq(n2, n1 + 1);
    }

    // ====================================================================
    // 1-of-3 threshold (single confirmation triggers execution)
    // ====================================================================

    function test_singleConfirmationThreshold() public {
        router.setRequiredConfirmations(1);

        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"33")
        );
        bytes32 msgId = router.sendMultiBridgeMessage(
            address(target),
            payload,
            admin
        );
        bytes memory wrapped = abi.encode(msgId, payload);

        // First confirmation should immediately execute
        vm.prank(address(adapter1));
        router.receiveBridgeMessage(wrapped);

        (, bool exec) = router.messages(msgId);
        assertTrue(exec, "Should execute on first confirmation with N=1");
        assertTrue(target.received(), "Target should have received call");
    }

    // ====================================================================
    // estimateFee aggregation
    // ====================================================================

    function test_adapterEstimateFee() public view {
        // Each SucceedingBridgeAdapter returns 0.01 ether
        uint256 totalFee;
        for (uint256 i = 0; i < 3; i++) {
            totalFee += IBridgeAdapter(router.activeAdapters(i)).estimateFee(
                address(target),
                hex"00"
            );
        }
        assertEq(
            totalFee,
            0.03 ether,
            "Aggregate fee should be sum across adapters"
        );
    }

    // ====================================================================
    // Multiple adapters called in sequence (all adapters are called)
    // ====================================================================

    function test_allAdaptersCalledOnSend() public {
        bytes memory payload = abi.encode(
            address(target),
            abi.encodeWithSignature("execute(bytes)", hex"44")
        );
        router.sendMultiBridgeMessage(address(target), payload, admin);

        assertEq(adapter1.callCount(), 1, "Adapter 1 should be called");
        assertEq(adapter2.callCount(), 1, "Adapter 2 should be called");
        assertEq(adapter3.callCount(), 1, "Adapter 3 should be called");
    }
}
