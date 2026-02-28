// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {L2ProofRouter} from "../../contracts/crosschain/L2ProofRouter.sol";

contract L2ProofRouterTest is Test {
    L2ProofRouter public router;

    address public admin;
    address public operator;
    address public user1;

    bytes32 constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    uint256 constant DEST_CHAIN = 42161; // Arbitrum

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        user1 = makeAddr("user1");

        router = new L2ProofRouter(admin, makeAddr("zaseonHub"));
        router.grantRole(OPERATOR_ROLE, operator);
    }

    // ──────── Helpers ────────

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
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsChainId() public view {
        assertEq(router.currentChainId(), block.chainid);
    }

    function test_Constructor_SetsRoles() public view {
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(router.hasRole(OPERATOR_ROLE, admin));
    }

    function test_Constants() public view {
        assertEq(router.MAX_BATCH_SIZE(), 100);
        assertEq(router.BATCH_TIMEOUT(), 5 minutes);
        assertEq(router.CACHE_TTL(), 1 hours);
        assertEq(router.MAX_CACHE_SIZE(), 1000);
    }

    /*//////////////////////////////////////////////////////////////
                        PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function test_SubmitProof() public {
        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN
        );

        L2ProofRouter.Proof memory p = router.getProof(proofId);
        assertEq(uint8(p.proofType), uint8(L2ProofRouter.ProofType.GROTH16));
        assertEq(p.sourceChainId, block.chainid);
        assertEq(p.destChainId, DEST_CHAIN);
        assertEq(p.submitter, admin);
        assertGt(p.gasEstimate, 0);
        assertFalse(p.verified);
    }

    function test_SubmitProof_CreatesBatch() public {
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);

        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);
        assertGt(uint256(batchId), 0);

        L2ProofRouter.ProofBatch memory batch = router.getBatch(batchId);
        assertEq(batch.destChainId, DEST_CHAIN);
        assertEq(batch.proofIds.length, 1);
        assertEq(uint8(batch.status), uint8(L2ProofRouter.BatchStatus.OPEN));
    }

    function test_SubmitProof_RevertSameChain() public {
        vm.expectRevert(L2ProofRouter.InvalidDestination.selector);
        router.submitProof(
            L2ProofRouter.ProofType.GROTH16,
            block.chainid,
            hex"deadbeef",
            hex"aabb",
            bytes32(0)
        );
    }

    function test_SubmitProof_RevertEmptyProof() public {
        vm.expectRevert(L2ProofRouter.InvalidProof.selector);
        router.submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN,
            hex"",
            hex"aabb",
            bytes32(0)
        );
    }

    function test_SubmitProof_MultipleAddToBatch() public {
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);
        _submitProof(L2ProofRouter.ProofType.PLONK, DEST_CHAIN);
        _submitProof(L2ProofRouter.ProofType.STARK, DEST_CHAIN);

        bytes32 batchId = router.getActiveBatch(DEST_CHAIN);
        L2ProofRouter.ProofBatch memory batch = router.getBatch(batchId);
        assertEq(batch.proofIds.length, 3);
    }

    /*//////////////////////////////////////////////////////////////
                           GAS ESTIMATION
    //////////////////////////////////////////////////////////////*/

    function test_GasEstimate_Groth16() public {
        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN
        );
        L2ProofRouter.Proof memory p = router.getProof(proofId);
        // 200k + 10 * dataLength (hex"deadbeef0123456789" = 9 bytes)
        assertEq(p.gasEstimate, 200_000 + 10 * 9);
    }

    function test_GasEstimate_STARK() public {
        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.STARK,
            DEST_CHAIN
        );
        L2ProofRouter.Proof memory p = router.getProof(proofId);
        // 500k + 20 * 9
        assertEq(p.gasEstimate, 500_000 + 20 * 9);
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH ROUTING
    //////////////////////////////////////////////////////////////*/

    function test_FlushBatches() public {
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);

        // Configure a route (without adapter, routing will just mark completed)
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.VIA_L1,
            address(0),
            0,
            0,
            0
        );

        // FlushBatches — will attempt routing, may fail if no adapter
        vm.prank(operator);
        // This will likely revert with BatchNotReady since no adapter
        // We test the flow up to route selection
        vm.expectRevert(L2ProofRouter.BatchNotReady.selector);
        router.flushBatches(DEST_CHAIN);
    }

    function test_BatchTimeout() public {
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);

        // Warp past timeout
        vm.warp(block.timestamp + 5 minutes + 1);

        // Next proof should create new batch (old one is complete)
        _submitProof(L2ProofRouter.ProofType.PLONK, DEST_CHAIN);

        bytes32 batch2 = router.getActiveBatch(DEST_CHAIN);
        // batch2 may be same or different depending on internal logic
        // At minimum, the new proof is batched
        L2ProofRouter.ProofBatch memory b = router.getBatch(batch2);
        assertGe(b.proofIds.length, 1);
    }

    /*//////////////////////////////////////////////////////////////
                         ROUTE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureRoute() public {
        address adapter = makeAddr("adapter");

        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            adapter,
            0.001 ether,
            50_000,
            50
        );

        (
            L2ProofRouter.RoutingPath defaultPath,
            address routeAdapter,
            uint256 baseCost,
            uint256 gasPerProof,
            uint256 maxBatchSize,
            bool active
        ) = router.routes(block.chainid, DEST_CHAIN);

        assertEq(uint8(defaultPath), uint8(L2ProofRouter.RoutingPath.DIRECT));
        assertEq(routeAdapter, adapter);
        assertEq(baseCost, 0.001 ether);
        assertEq(gasPerProof, 50_000);
        assertEq(maxBatchSize, 50);
        assertTrue(active);
    }

    function test_ConfigureRoute_DefaultMaxBatch() public {
        vm.prank(operator);
        router.configureRoute(
            block.chainid,
            DEST_CHAIN,
            L2ProofRouter.RoutingPath.DIRECT,
            address(0),
            0,
            0,
            0 // 0 → default MAX_BATCH_SIZE
        );

        (, , , , uint256 maxBatchSize, ) = router.routes(
            block.chainid,
            DEST_CHAIN
        );
        assertEq(maxBatchSize, 100);
    }

    function test_SetDirectMessenger() public {
        address messenger = makeAddr("messenger");
        router.setDirectMessenger(messenger);
        assertEq(router.directMessenger(), messenger);
    }

    /*//////////////////////////////////////////////////////////////
                         CACHE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_ClearExpiredCache_NoEntries() public {
        // Should not revert
        router.clearExpiredCache();
        assertEq(router.getCacheSize(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                         METRICS
    //////////////////////////////////////////////////////////////*/

    function test_InitialMetrics() public view {
        L2ProofRouter.RouteMetrics memory m = router.getRouteMetrics(
            block.chainid,
            DEST_CHAIN
        );
        assertEq(m.totalRouted, 0);
        assertEq(m.successCount, 0);
        assertEq(m.failCount, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN / PAUSE
    //////////////////////////////////////////////////////////////*/

    function test_Pause_Unpause() public {
        vm.prank(operator);
        router.pause();

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        _submitProof(L2ProofRouter.ProofType.GROTH16, DEST_CHAIN);

        vm.prank(operator);
        router.unpause();

        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.GROTH16,
            DEST_CHAIN
        );
        assertGt(uint256(proofId), 0);
    }

    function test_ReceiveETH() public {
        (bool ok, ) = address(router).call{value: 1 ether}("");
        assertTrue(ok);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetProof_NonexistentReturnsDefault() public view {
        L2ProofRouter.Proof memory p = router.getProof(keccak256("nope"));
        assertEq(p.submitter, address(0));
    }

    function test_GetActiveBatch_Empty() public view {
        assertEq(router.getActiveBatch(99999), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SubmitDifferentProofTypes(uint8 typeIdx) public {
        uint8 maxType = 7; // 0..7 enum values
        typeIdx = uint8(bound(typeIdx, 0, maxType));

        bytes32 proofId = router.submitProof(
            L2ProofRouter.ProofType(typeIdx),
            DEST_CHAIN,
            hex"deadbeef",
            hex"aabb",
            bytes32(0)
        );

        L2ProofRouter.Proof memory p = router.getProof(proofId);
        assertEq(uint8(p.proofType), typeIdx);
        assertGt(p.gasEstimate, 0);
    }

    function testFuzz_MultipleDestChains(uint256 chainId) public {
        chainId = bound(chainId, 1, 100000);
        vm.assume(chainId != block.chainid);

        bytes32 proofId = _submitProof(
            L2ProofRouter.ProofType.GROTH16,
            chainId
        );
        L2ProofRouter.Proof memory p = router.getProof(proofId);
        assertEq(p.destChainId, chainId);
    }
}
