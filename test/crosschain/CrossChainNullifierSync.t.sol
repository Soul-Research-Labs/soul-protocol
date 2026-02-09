// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/CrossChainNullifierSync.sol";

/**
 * @title CrossChainNullifierSyncTest
 * @notice Unit tests for cross-chain nullifier synchronization
 */
contract CrossChainNullifierSyncTest is Test {
    CrossChainNullifierSync sync;
    address admin = address(this);
    address syncer = address(0x51C1);
    address bridge = address(0xB1D6);
    address nullifierRegistry = address(0xEC1);
    address user = address(0xBEEF);

    bytes32 constant SYNCER_ROLE = keccak256("SYNCER_ROLE");
    bytes32 constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        sync = new CrossChainNullifierSync(nullifierRegistry);
        sync.grantRole(SYNCER_ROLE, syncer);
        sync.grantRole(BRIDGE_ROLE, bridge);
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertTrue(sync.hasRole(sync.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(sync.hasRole(SYNCER_ROLE, admin));
        assertTrue(sync.hasRole(OPERATOR_ROLE, admin));
        assertEq(sync.getPendingCount(), 0);
        assertEq(sync.getBatchCount(), 0);
    }

    function test_RevertZeroRegistry() public {
        vm.expectRevert();
        new CrossChainNullifierSync(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       QUEUE NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_QueueNullifier() public {
        vm.prank(syncer);
        sync.queueNullifier(bytes32(uint256(1)), bytes32(uint256(100)));
        assertEq(sync.getPendingCount(), 1);
    }

    function test_QueueNullifier_RevertNonSyncer() public {
        vm.prank(user);
        vm.expectRevert();
        sync.queueNullifier(bytes32(uint256(1)), bytes32(uint256(100)));
    }

    function test_QueueNullifierBatch() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = bytes32(uint256(i + 1));
            commitments[i] = bytes32(uint256(i + 100));
        }

        vm.prank(syncer);
        sync.queueNullifierBatch(nullifiers, commitments);
        assertEq(sync.getPendingCount(), 3);
    }

    function test_QueueNullifierBatch_RevertMismatchedArrays() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        bytes32[] memory commitments = new bytes32[](3);
        nullifiers[0] = bytes32(uint256(1));
        nullifiers[1] = bytes32(uint256(2));

        vm.prank(syncer);
        vm.expectRevert();
        sync.queueNullifierBatch(nullifiers, commitments);
    }

    /*//////////////////////////////////////////////////////////////
                    SYNC TARGET CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureSyncTarget() public {
        CrossChainNullifierSync.SyncTarget
            memory target = CrossChainNullifierSync.SyncTarget({
                nullifierRegistry: address(0x1),
                relay: address(0x2),
                chainId: 42161,
                active: true
            });

        sync.configureSyncTarget(42161, target);
        uint256[] memory chains = sync.getTargetChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], 42161);
    }

    function test_ConfigureSyncTarget_RevertNonOperator() public {
        CrossChainNullifierSync.SyncTarget
            memory target = CrossChainNullifierSync.SyncTarget({
                nullifierRegistry: address(0x1),
                relay: address(0x2),
                chainId: 42161,
                active: true
            });

        vm.prank(user);
        vm.expectRevert();
        sync.configureSyncTarget(42161, target);
    }

    /*//////////////////////////////////////////////////////////////
                         FLUSH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Flush_RevertNoPending() public {
        CrossChainNullifierSync.SyncTarget
            memory target = CrossChainNullifierSync.SyncTarget({
                nullifierRegistry: address(0x1),
                relay: address(0x2),
                chainId: 42161,
                active: true
            });
        sync.configureSyncTarget(42161, target);

        vm.prank(syncer);
        vm.expectRevert();
        sync.flushToChain(42161);
    }

    function test_Flush_RevertUnconfiguredTarget() public {
        vm.prank(syncer);
        sync.queueNullifier(bytes32(uint256(1)), bytes32(uint256(100)));

        vm.prank(syncer);
        vm.expectRevert();
        sync.flushToChain(99999);
    }

    /*//////////////////////////////////////////////////////////////
                       RECEIVE BATCH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ReceiveBatch() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        bytes32[] memory commitments = new bytes32[](2);
        nullifiers[0] = bytes32(uint256(1));
        nullifiers[1] = bytes32(uint256(2));
        commitments[0] = bytes32(uint256(100));
        commitments[1] = bytes32(uint256(200));

        vm.prank(bridge);
        sync.receiveNullifierBatch(
            42161,
            nullifiers,
            commitments,
            bytes32(uint256(999))
        );
    }

    function test_ReceiveBatch_RevertNonBridge() public {
        bytes32[] memory nullifiers = new bytes32[](1);
        bytes32[] memory commitments = new bytes32[](1);
        nullifiers[0] = bytes32(uint256(1));
        commitments[0] = bytes32(uint256(100));

        vm.prank(user);
        vm.expectRevert();
        sync.receiveNullifierBatch(
            42161,
            nullifiers,
            commitments,
            bytes32(uint256(999))
        );
    }

    /*//////////////////////////////////////////////////////////////
                         PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        sync.pause();
        assertTrue(sync.paused());
    }

    function test_Unpause() public {
        sync.pause();
        sync.unpause();
        assertFalse(sync.paused());
    }

    function test_QueueNullifier_RevertWhenPaused() public {
        sync.pause();
        vm.prank(syncer);
        vm.expectRevert();
        sync.queueNullifier(bytes32(uint256(1)), bytes32(uint256(100)));
    }
}
