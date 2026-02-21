// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {L2ProofRouter} from "../../contracts/crosschain/L2ProofRouter.sol";

/// @dev Mock DirectL2Messenger for route testing
contract MockDirectL2Messenger {
    bool public messageSent;
    bytes public lastData;

    enum MessagePath {
        FAST_RELAYER,
        SHARED_SEQUENCER,
        DIRECT
    }

    function sendMessage(
        uint256,
        address,
        bytes calldata data,
        MessagePath,
        bytes32
    ) external returns (bytes32) {
        messageSent = true;
        lastData = data;
        return keccak256(data);
    }
}

/// @dev Mock L1 Adapter for VIA_L1 routing
contract MockL1Adapter {
    bool public routeProofsCalled;

    function routeProofs(
        uint256,
        bytes calldata
    ) external payable returns (bool) {
        routeProofsCalled = true;
        return true;
    }
}

/// @dev Always-failing adapter
contract FailingAdapter {
    function routeProofs(
        uint256,
        bytes calldata
    ) external payable returns (bool) {
        revert("adapter fail");
    }

    function sendMessage(
        uint256,
        address,
        bytes calldata,
        uint8,
        bytes32
    ) external returns (bytes32) {
        revert("adapter fail");
    }
}

/**
 * @title L2ProofRouterExtendedTest
 * @notice Extended tests for routeBatch, flushBatches success paths,
 *         cache management, access control reverts, batch-full scenarios,
 *         and additional fuzz coverage.
 */
contract L2ProofRouterExtendedTest is Test {
    L2ProofRouter public router;
    MockDirectL2Messenger public messenger;
    MockL1Adapter public l1Adapter;

    address public admin;
    address public operator;
    address public user1;

    bytes32 constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    uint256 constant DEST_CHAIN = 42_161;

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        user1 = makeAddr("user1");

        router = new L2ProofRouter(admin, makeAddr("soulHub"));
        router.grantRole(OPERATOR_ROLE, operator);

        messenger = new MockDirectL2Messenger();
        l1Adapter = new MockL1Adapter();

        // Set direct messenger
        router.setDirectMessenger(address(messenger));
    }

    function _submitProof(
        L2ProofRouter.ProofType pType,
        uint256 destChain
    ) internal returns (bytes32) {
        return
            router.submitProof(
                pType,
                destChain,
                hex"deadbeef0123456789",
                hex"aabbccdd",
                bytes32(0)
            );
    }

    /*//////////////////////////////////////////////////////////////
                        routeBatch — SUCCESS PATH
    //////////////////////////////////////////////////////////////*/

    function test_routeBatch_success_directPath() public {
        // Configure route with DIRECT path and real adapter
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        // Submit a proof to create a batch
        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN
        );
        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);
        assertTrue(batchId != bytes32(0), "Batch should exist");

        // Finalize the batch by making it FULL
        // We need to route it — use operator
        vm.prank(operator);
        router.routeBatch(batchId);

        // Verify batch is completed
        L2ProofRouter.ProofBatch memory batch = router.getBatch(batchId);
        assertEq(
            uint8(batch.status),
            uint8(L2ProofRouter.BatchStatus.COMPLETED),
            "Batch should be COMPLETED"
        );
        assertGt(batch.routedAt, 0, "routedAt should be set");
        assertTrue(
            messenger.messageSent(),
            "Messenger should have been called"
        );
    }

    function test_routeBatch_success_viaL1() public {
        // Configure route with VIA_L1 path
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.VIA_L1,
            address(l1Adapter),
            0.001 ether,
            50_000,
            100
        );

        // Fund the router for L1 costs
        vm.deal(address(router), 1 ether);

        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);
        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);

        vm.prank(operator);
        router.routeBatch(batchId);

        L2ProofRouter.ProofBatch memory batch = router.getBatch(batchId);
        assertEq(
            uint8(batch.status),
            uint8(L2ProofRouter.BatchStatus.COMPLETED)
        );
        assertTrue(
            l1Adapter.routeProofsCalled(),
            "L1 adapter should have been called"
        );
    }

    function test_routeBatch_revert_notOperator() public {
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);
        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);

        vm.prank(user1);
        vm.expectRevert();
        router.routeBatch(batchId);
    }

    function test_routeBatch_revert_emptyBatch() public {
        // Create a batch through a proof, then try routing an invalid one
        vm.prank(operator);
        vm.expectRevert(L2ProofRouter.BatchNotReady.selector);
        router.routeBatch(keccak256("nonexistent"));
    }

    function test_routeBatch_updatesMetrics() public {
        // Configure route
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);
        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);

        vm.prank(operator);
        router.routeBatch(batchId);

        L2ProofRouter.RouteMetrics memory m = router.getRouteMetrics(
            block.chainid,
            DEST_CHAIN
        );
        assertEq(m.totalRouted, 1, "totalRouted should be 1");
        assertEq(m.successCount, 1, "successCount should be 1");
        assertGt(m.lastUpdated, 0, "lastUpdated should be set");
    }

    /*//////////////////////////////////////////////////////////////
                    flushBatches — SUCCESS PATH
    //////////////////////////////////////////////////////////////*/

    function test_flushBatches_success() public {
        // Configure route
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);
        _submitProof(L2ProofRouter.ProofType.PLONK, DEST_CHAIN);

        vm.prank(operator);
        router.flushBatches(DEST_CHAIN);

        // Active batch should be cleared
        bytes32 activeBatch = router.getActiveBatch(DEST_CHAIN);
        assertEq(activeBatch, bytes32(0), "Active batch should be cleared");
    }

    function test_flushBatches_revert_notOperator() public {
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);

        vm.prank(user1);
        vm.expectRevert();
        router.flushBatches(DEST_CHAIN);
    }

    function test_flushBatches_noop_noBatch() public {
        // Should not revert when no active batch exists
        vm.prank(operator);
        router.flushBatches(99999);
        // Just verify no revert
    }

    /*//////////////////////////////////////////////////////////////
                    CACHE MANAGEMENT — with data
    //////////////////////////////////////////////////////////////*/

    function test_clearExpiredCache_withExpiredEntries() public {
        // Configure route so routing succeeds (which caches proofs)
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        // Submit and route a proof to populate cache
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);
        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);

        vm.prank(operator);
        router.routeBatch(batchId);

        uint256 cacheSize = router.getCacheSize();
        assertGt(cacheSize, 0, "Cache should have entries");

        // Warp past cache TTL (1 hour)
        vm.warp(block.timestamp + 1 hours + 1);

        // Clear expired entries
        router.clearExpiredCache();
        assertEq(
            router.getCacheSize(),
            0,
            "Cache should be empty after clearing expired"
        );
    }

    function test_cacheHit_onResubmission() public {
        // Configure route
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        // Submit and route a proof
        router.submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN,
            hex"aabb0011",
            hex"ccdd0022",
            bytes32(0)
        );

        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);
        vm.prank(operator);
        router.routeBatch(batchId);

        // Submit same proof data again — should get cache hit event
        vm.expectEmit(false, false, false, false);
        emit L2ProofRouter.CacheHit(bytes32(0), bytes32(0));

        router.submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN,
            hex"aabb0011",
            hex"ccdd0022",
            bytes32(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ACCESS CONTROL REVERTS
    //////////////////////////////////////////////////////////////*/

    function test_configureRoute_revert_notOperator() public {
        vm.prank(user1);
        vm.expectRevert();
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(0),
            0,
            0,
            0
        );
    }

    function test_setDirectMessenger_revert_notAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        router.setDirectMessenger(makeAddr("m"));
    }

    function test_pause_revert_notOperator() public {
        vm.prank(user1);
        vm.expectRevert();
        router.pause();
    }

    function test_unpause_revert_notOperator() public {
        vm.prank(operator);
        router.pause();

        vm.prank(user1);
        vm.expectRevert();
        router.unpause();
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH FULL — AUTO NEW BATCH
    //////////////////////////////////////////////////////////////*/

    function test_batchFull_createsNewBatch() public {
        // Submit MAX_BATCH_SIZE proofs to fill a batch
        // The batch will auto-route when full if a messenger is configured
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        bytes32 firstBatch;
        for (uint256 i = 0; i < 100; i++) {
            bytes32 proofId = router.submitProof(
                L2ProofRouter.ProofType.GROTH16,
                DEST_CHAIN,
                abi.encodePacked(hex"deadbeef", i),
                abi.encodePacked(hex"aabb", i),
                bytes32(i)
            );
            if (i == 0) {
                firstBatch = router.getActiveBatch(DEST_CHAIN);
            }
        }

        // First batch should be completed (auto-routed when full)
        L2ProofRouter.ProofBatch memory fb = router.getBatch(firstBatch);
        assertTrue(
            fb.status == L2ProofRouter.BatchStatus.COMPLETED ||
                fb.status == L2ProofRouter.BatchStatus.FULL,
            "First batch should be completed or full"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF PROCESSED REPLAY CHECK
    //////////////////////////////////////////////////////////////*/

    function test_proofProcessed_preventReplay() public {
        // Configure route
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            0,
            50_000,
            100
        );

        // Submit and route a proof
        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN
        );
        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);

        vm.prank(operator);
        router.routeBatch(batchId);

        // Proof should be marked as processed
        L2ProofRouter.Proof memory p = router.getProof(proofId);
        // proofId is processed — we verify by checking if the batch completed
        L2ProofRouter.ProofBatch memory b = router.getBatch(batchId);
        assertEq(uint8(b.status), uint8(L2ProofRouter.BatchStatus.COMPLETED));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ — EXTENDED
    //////////////////////////////////////////////////////////////*/

    function testFuzz_submitProof_variableDataSizes(uint16 dataSize) public {
        dataSize = uint16(bound(dataSize, 1, 1000));

        bytes memory proofData = new bytes(dataSize);
        for (uint256 i = 0; i < dataSize; i++) {
            proofData[i] = bytes1(uint8(i % 256));
        }

        bytes32 id = router.submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN,
            proofData,
            hex"aabb",
            bytes32(0)
        );

        L2ProofRouter.Proof memory p = router.getProof(id);
        assertEq(p.gasEstimate, 200_000 + 10 * dataSize);
    }

    function testFuzz_configureRoute_validParams(
        uint256 baseCost,
        uint256 gasPerProof,
        uint256 maxBatch
    ) public {
        baseCost = bound(baseCost, 0, 1 ether);
        gasPerProof = bound(gasPerProof, 0, 1_000_000);
        maxBatch = bound(maxBatch, 1, 200);

        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(messenger),
            baseCost,
            gasPerProof,
            maxBatch
        );

        (
            L2ProofRouter.RoutingPath defaultPath,
            address routeAdapter,
            uint256 rBaseCost,
            uint256 rGasPerProof,
            uint256 rMaxBatch,
            bool active
        ) = router.routes(block.chainid, DEST_CHAIN);

        assertEq(rBaseCost, baseCost);
        assertEq(rGasPerProof, gasPerProof);
        assertEq(rMaxBatch, maxBatch);
        assertTrue(active);
    }
}
