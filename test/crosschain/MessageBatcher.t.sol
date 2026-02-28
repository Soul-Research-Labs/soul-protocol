// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MessageBatcher} from "../../contracts/crosschain/MessageBatcher.sol";
import {ZaseonCrossChainRelay} from "../../contracts/crosschain/ZaseonCrossChainRelay.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title MockZaseonRelay
/// @notice Minimal mock of ZaseonCrossChainRelay for MessageBatcher testing
contract MockZaseonRelay {
    uint8 public constant MSG_PROOF_RELAY = 1;
    uint256 public batchCount;
    uint64 public lastDestChainId;
    uint256 public lastPayloadCount;
    bool public shouldRevert;

    function relayBatch(
        uint64 destChainId,
        bytes[] calldata payloads
    ) external payable returns (bytes32) {
        require(!shouldRevert, "Relay: batch failed");
        batchCount++;
        lastDestChainId = destChainId;
        lastPayloadCount = payloads.length;
        return keccak256(abi.encode(batchCount, destChainId, block.timestamp));
    }

    function setShouldRevert(bool _revert) external {
        shouldRevert = _revert;
    }
}

/**
 * @title MessageBatcherTest
 * @notice Unit tests for MessageBatcher
 */
contract MessageBatcherTest is Test {
    MessageBatcher public batcher;
    MockZaseonRelay public relay;

    address public admin;
    address public user1;
    address public user2;

    uint64 constant DEST_CHAIN = 42161; // Arbitrum

    bytes32 constant PROOF_ID_1 = keccak256("proof_1");
    bytes32 constant PROOF_ID_2 = keccak256("proof_2");
    bytes constant PROOF_DATA = hex"aabbcc";
    bytes constant PUB_INPUTS = hex"112233";
    bytes32 constant COMMITMENT = keccak256("commitment");
    bytes32 constant PROOF_TYPE = keccak256("PRIVACY_PROOF");

    function setUp() public {
        admin = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        relay = new MockZaseonRelay();
        batcher = new MessageBatcher(address(relay), admin);

        // Fund test users
        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
    }

    // =========== queueProof ===========

    /// @notice Queue a single proof
    function test_queueProof_single() public {
        vm.prank(user1);
        batcher.queueProof{value: 0.01 ether}(
            PROOF_ID_1,
            PROOF_DATA,
            PUB_INPUTS,
            COMMITMENT,
            DEST_CHAIN,
            PROOF_TYPE
        );
        // Batch should not auto-send (default maxBatchSize = 10)
        assertEq(relay.batchCount(), 0, "Batch should not auto-send yet");
    }

    /// @notice Queue multiple proofs and trigger auto-send at maxBatchSize
    function test_queueProof_autoSendAtMaxBatch() public {
        batcher.setMaxBatchSize(3);

        for (uint256 i = 0; i < 3; i++) {
            vm.prank(user1);
            batcher.queueProof{value: 0.01 ether}(
                keccak256(abi.encode("proof", i)),
                PROOF_DATA,
                PUB_INPUTS,
                COMMITMENT,
                DEST_CHAIN,
                PROOF_TYPE
            );
        }

        // Should have auto-sent when 3rd proof filled the batch
        assertEq(relay.batchCount(), 1, "Batch should auto-send at max size");
        assertEq(relay.lastDestChainId(), DEST_CHAIN);
        assertEq(relay.lastPayloadCount(), 3);
    }

    // =========== sendBatch ===========

    /// @notice Manual batch send
    function test_sendBatch_manual() public {
        // Queue 2 proofs
        for (uint256 i = 0; i < 2; i++) {
            vm.prank(user1);
            batcher.queueProof{value: 0.01 ether}(
                keccak256(abi.encode("proof", i)),
                PROOF_DATA,
                PUB_INPUTS,
                COMMITMENT,
                DEST_CHAIN,
                PROOF_TYPE
            );
        }

        // Manual send
        batcher.sendBatch(DEST_CHAIN);
        assertEq(relay.batchCount(), 1);
        assertEq(relay.lastPayloadCount(), 2);
    }

    /// @notice sendBatch reverts on empty queue
    function test_sendBatch_revertsEmpty() public {
        vm.expectRevert("Queue empty");
        batcher.sendBatch(DEST_CHAIN);
    }

    /// @notice sendBatch clears the queue after sending
    function test_sendBatch_clearsQueue() public {
        vm.prank(user1);
        batcher.queueProof{value: 0.01 ether}(
            PROOF_ID_1,
            PROOF_DATA,
            PUB_INPUTS,
            COMMITMENT,
            DEST_CHAIN,
            PROOF_TYPE
        );

        batcher.sendBatch(DEST_CHAIN);

        // Queue should be empty — sending again should revert
        vm.expectRevert("Queue empty");
        batcher.sendBatch(DEST_CHAIN);
    }

    // =========== setMaxBatchSize ===========

    /// @notice Admin can update max batch size
    function test_setMaxBatchSize_adminOnly() public {
        batcher.setMaxBatchSize(5);
        assertEq(batcher.maxBatchSize(), 5);
    }

    /// @notice Non-admin cannot update max batch size
    function test_setMaxBatchSize_revertsNonAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        batcher.setMaxBatchSize(5);
    }

    // =========== rescueFunds ===========

    /// @notice Admin can rescue stuck native ETH
    function test_rescueFunds_nativeETH() public {
        // Send ETH directly to the batcher (stuck funds scenario)
        vm.deal(address(batcher), 1 ether);
        uint256 balBefore = admin.balance;

        batcher.rescueFunds(address(0), 1 ether);

        assertEq(admin.balance, balBefore + 1 ether);
    }

    /// @notice Non-admin cannot rescue funds
    function test_rescueFunds_revertsNonAdmin() public {
        vm.deal(address(batcher), 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        batcher.rescueFunds(address(0), 1 ether);
    }

    // =========== Multi-destination ===========

    /// @notice Queues are isolated per destination chain
    function test_multiDestination_isolatedQueues() public {
        uint64 chainA = 42161;
        uint64 chainB = 10; // Optimism

        vm.startPrank(user1);
        batcher.queueProof{value: 0.01 ether}(
            PROOF_ID_1,
            PROOF_DATA,
            PUB_INPUTS,
            COMMITMENT,
            chainA,
            PROOF_TYPE
        );
        batcher.queueProof{value: 0.01 ether}(
            PROOF_ID_2,
            PROOF_DATA,
            PUB_INPUTS,
            COMMITMENT,
            chainB,
            PROOF_TYPE
        );
        vm.stopPrank();

        // Send only chain A
        batcher.sendBatch(chainA);
        assertEq(
            relay.lastPayloadCount(),
            1,
            "Should send 1 proof for chain A"
        );

        // Chain B still has its proof
        batcher.sendBatch(chainB);
        assertEq(
            relay.lastPayloadCount(),
            1,
            "Should send 1 proof for chain B"
        );
        assertEq(relay.batchCount(), 2, "Two batches total");
    }

    // =========== Value forwarding ===========

    /// @notice Queued value is forwarded to relay
    function test_valueForwarding() public {
        uint256 proofValue = 0.05 ether;

        vm.prank(user1);
        batcher.queueProof{value: proofValue}(
            PROOF_ID_1,
            PROOF_DATA,
            PUB_INPUTS,
            COMMITMENT,
            DEST_CHAIN,
            PROOF_TYPE
        );

        // Check batcher holds the value
        assertEq(address(batcher).balance, proofValue);

        batcher.sendBatch(DEST_CHAIN);

        // Value should be forwarded to relay
        assertEq(address(relay).balance, proofValue);
        assertEq(address(batcher).balance, 0);
    }

    // Required to receive ETH for rescue test
    receive() external payable {}
}
