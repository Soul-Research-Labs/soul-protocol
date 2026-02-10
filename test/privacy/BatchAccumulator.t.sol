// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/BatchAccumulator.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// ─── Mock Proof Verifier
// ────────────────────────────────────────────────────
contract MockProofVerifier {
    bool public shouldReturn;

    constructor(
        bool _shouldReturn
    ) {
        shouldReturn = _shouldReturn;
    }

    function setShouldReturn(
        bool _val
    ) external {
        shouldReturn = _val;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldReturn;
    }
}

// ─── Test Suite
// ─────────────────────────────────────────────────────────────
contract BatchAccumulatorTest is Test {
    BatchAccumulator public accumulator;
    MockProofVerifier public verifier;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public upgrader = makeAddr("upgrader");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public nobody = makeAddr("nobody");

    address public crossChainHub = makeAddr("crossChainHub");

    uint256 constant SOURCE_CHAIN = 31_337; // foundry default chainid
    uint256 constant TARGET_CHAIN = 42_161; // Arbitrum

    event BatchCreated(
        bytes32 indexed batchId,
        uint256 indexed sourceChainId,
        uint256 indexed targetChainId,
        uint256 minSize,
        uint256 maxWaitTime
    );

    event TransactionAdded(
        bytes32 indexed batchId, bytes32 indexed commitment, uint256 batchSize, uint256 remaining
    );

    event BatchReady(bytes32 indexed batchId, uint256 size, string reason);

    event BatchProcessing(bytes32 indexed batchId, address indexed relayer);

    event BatchCompleted(
        bytes32 indexed batchId, bytes32 aggregateProofHash, uint256 processedCount
    );

    event BatchFailed(bytes32 indexed batchId, string reason);

    event RouteConfigured(bytes32 indexed routeHash, uint256 minBatchSize, uint256 maxWaitTime);

    // ========================================================================
    // SETUP
    // ========================================================================

    function setUp() public {
        verifier = new MockProofVerifier(true);

        BatchAccumulator impl = new BatchAccumulator();
        bytes memory initData = abi.encodeCall(
            BatchAccumulator.initialize, (admin, address(verifier), crossChainHub)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        accumulator = BatchAccumulator(address(proxy));

        // Grant roles
        vm.startPrank(admin);
        accumulator.grantRole(accumulator.OPERATOR_ROLE(), operator);
        accumulator.grantRole(accumulator.RELAYER_ROLE(), relayer);
        accumulator.grantRole(accumulator.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    function _configureDefaultRoute() internal {
        vm.prank(operator);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 10 minutes);
    }

    function _submitTx(
        bytes32 commitment,
        bytes32 nullifier,
        address submitter
    ) internal returns (bytes32 batchId) {
        vm.prank(submitter);
        batchId = accumulator.submitToBatch(
            commitment, nullifier, abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );
    }

    function _fillBatch(
        uint256 count,
        uint256 startSeed
    ) internal returns (bytes32 batchId) {
        for (uint256 i = 0; i < count; i++) {
            bytes32 commitment = keccak256(abi.encodePacked("c", startSeed + i));
            bytes32 nullifier = keccak256(abi.encodePacked("n", startSeed + i));
            batchId = _submitTx(commitment, nullifier, user1);
        }
    }

    // ========================================================================
    // INITIALIZATION TESTS
    // ========================================================================

    function test_initialize_setsAdmin() public view {
        assertTrue(accumulator.hasRole(accumulator.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_initialize_setsOperatorRole() public view {
        assertTrue(accumulator.hasRole(accumulator.OPERATOR_ROLE(), admin));
    }

    function test_initialize_setsUpgraderRole() public view {
        assertTrue(accumulator.hasRole(accumulator.UPGRADER_ROLE(), admin));
    }

    function test_initialize_setsProofVerifier() public view {
        assertEq(accumulator.proofVerifier(), address(verifier));
    }

    function test_initialize_setsCrossChainHub() public view {
        assertEq(accumulator.crossChainHub(), crossChainHub);
    }

    function test_initialize_revertsZeroAdmin() public {
        BatchAccumulator impl2 = new BatchAccumulator();
        vm.expectRevert(BatchAccumulator.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl2),
            abi.encodeCall(
                BatchAccumulator.initialize, (address(0), address(verifier), crossChainHub)
            )
        );
    }

    function test_initialize_revertsZeroVerifier() public {
        BatchAccumulator impl2 = new BatchAccumulator();
        vm.expectRevert(BatchAccumulator.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl2),
            abi.encodeCall(BatchAccumulator.initialize, (admin, address(0), crossChainHub))
        );
    }

    function test_initialize_revertsZeroCrossChainHub() public {
        BatchAccumulator impl2 = new BatchAccumulator();
        vm.expectRevert(BatchAccumulator.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl2),
            abi.encodeCall(BatchAccumulator.initialize, (admin, address(verifier), address(0)))
        );
    }

    function test_initialize_cannotReinitialize() public {
        vm.expectRevert();
        accumulator.initialize(admin, address(verifier), crossChainHub);
    }

    // ========================================================================
    // ROUTE CONFIGURATION TESTS
    // ========================================================================

    function test_configureRoute_success() public {
        bytes32 routeHash = keccak256(abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN));

        vm.expectEmit(true, false, false, true);
        emit RouteConfigured(routeHash, 8, 10 minutes);

        vm.prank(operator);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 10 minutes);

        (uint256 minBatchSize, uint256 maxWaitTime, bool isActive) =
            accumulator.routeConfigs(routeHash);
        assertEq(minBatchSize, 8);
        assertEq(maxWaitTime, 10 minutes);
        assertTrue(isActive);
    }

    function test_configureRoute_revertsInvalidSourceChainId() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidChainId.selector);
        accumulator.configureRoute(0, TARGET_CHAIN, 8, 10 minutes);
    }

    function test_configureRoute_revertsInvalidTargetChainId() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidChainId.selector);
        accumulator.configureRoute(SOURCE_CHAIN, 0, 8, 10 minutes);
    }

    function test_configureRoute_revertsInvalidBatchSizeTooSmall() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidBatchSize.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 1, 10 minutes);
    }

    function test_configureRoute_revertsInvalidBatchSizeTooLarge() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidBatchSize.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 65, 10 minutes);
    }

    function test_configureRoute_revertsInvalidWaitTimeTooShort() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidWaitTime.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 30 seconds);
    }

    function test_configureRoute_revertsInvalidWaitTimeTooLong() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.InvalidWaitTime.selector);
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 2 hours);
    }

    function test_configureRoute_revertsUnauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, 10 minutes);
    }

    function test_deactivateRoute_success() public {
        _configureDefaultRoute();

        bytes32 routeHash = keccak256(abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN));

        vm.prank(operator);
        accumulator.deactivateRoute(SOURCE_CHAIN, TARGET_CHAIN);

        (,, bool isActive) = accumulator.routeConfigs(routeHash);
        assertFalse(isActive);
    }

    function test_deactivateRoute_revertsUnauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        accumulator.deactivateRoute(SOURCE_CHAIN, TARGET_CHAIN);
    }

    // ========================================================================
    // BATCH SUBMISSION TESTS
    // ========================================================================

    function test_submitToBatch_createsNewBatch() public {
        _configureDefaultRoute();

        bytes32 commitment = keccak256("commitment1");
        bytes32 nullifier = keccak256("nullifier1");

        vm.prank(user1);
        bytes32 batchId = accumulator.submitToBatch(
            commitment, nullifier, abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );

        assertNotEq(batchId, bytes32(0));
        assertEq(accumulator.totalBatches(), 1);
        assertEq(accumulator.totalTransactionsBatched(), 1);
    }

    function test_submitToBatch_emitsTransactionAdded() public {
        _configureDefaultRoute();

        bytes32 commitment = keccak256("commitment1");
        bytes32 nullifier = keccak256("nullifier1");

        vm.prank(user1);
        bytes32 batchId = accumulator.submitToBatch(
            commitment, nullifier, abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );

        // Second submission to verify event parameters
        bytes32 commitment2 = keccak256("commitment2");
        bytes32 nullifier2 = keccak256("nullifier2");

        vm.expectEmit(true, true, false, true);
        emit TransactionAdded(batchId, commitment2, 2, 6); // size=2, remaining=6

        vm.prank(user2);
        accumulator.submitToBatch(
            commitment2, nullifier2, abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );
    }

    function test_submitToBatch_addsToExistingBatch() public {
        _configureDefaultRoute();

        bytes32 batchId1 = _submitTx(keccak256("c1"), keccak256("n1"), user1);
        bytes32 batchId2 = _submitTx(keccak256("c2"), keccak256("n2"), user2);

        assertEq(batchId1, batchId2);
        assertEq(accumulator.totalTransactionsBatched(), 2);
    }

    function test_submitToBatch_revertsOnZeroTargetChain() public {
        vm.prank(user1);
        vm.expectRevert(BatchAccumulator.InvalidChainId.selector);
        accumulator.submitToBatch(keccak256("c"), keccak256("n"), abi.encodePacked(bytes32(0)), 0);
    }

    function test_submitToBatch_revertsOnDuplicateCommitment() public {
        _configureDefaultRoute();
        bytes32 commitment = keccak256("dup");

        _submitTx(commitment, keccak256("n1"), user1);

        vm.prank(user2);
        vm.expectRevert(BatchAccumulator.CommitmentAlreadyUsed.selector);
        accumulator.submitToBatch(
            commitment, keccak256("n2"), abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );
    }

    function test_submitToBatch_revertsOnDuplicateNullifier() public {
        _configureDefaultRoute();
        bytes32 nullifier = keccak256("dup_null");

        _submitTx(keccak256("c1"), nullifier, user1);

        vm.prank(user2);
        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(
            keccak256("c2"), nullifier, abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );
    }

    function test_submitToBatch_revertsWhenPaused() public {
        vm.prank(operator);
        accumulator.pause();

        vm.prank(user1);
        vm.expectRevert();
        accumulator.submitToBatch(
            keccak256("c"), keccak256("n"), abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );
    }

    function test_submitToBatch_usesDefaultConfigWhenRouteNotConfigured() public {
        // Submit without configuring route – contract auto-creates defaults
        bytes32 batchId = _submitTx(keccak256("c1"), keccak256("n1"), user1);
        assertNotEq(batchId, bytes32(0));
        assertEq(accumulator.totalBatches(), 1);
    }

    function test_submitToBatch_marksBatchReadyWhenSizeReached() public {
        _configureDefaultRoute(); // minBatchSize=8

        bytes32 batchId = _fillBatch(8, 100);

        (uint256 size,, BatchAccumulator.BatchStatus status, bool isReady,) =
            accumulator.getBatchInfo(batchId);

        assertEq(size, 8);
        assertTrue(isReady);
        assertEq(uint256(status), uint256(BatchAccumulator.BatchStatus.READY));
    }

    function test_submitToBatch_padsPayloadToFixedSize() public {
        _configureDefaultRoute();

        bytes32 commitment = keccak256("c1");
        bytes32 nullifier = keccak256("n1");
        bytes memory smallPayload = hex"aabbcc";

        vm.prank(user1);
        bytes32 batchId =
            accumulator.submitToBatch(commitment, nullifier, smallPayload, TARGET_CHAIN);

        (,, bytes memory paddedPayload,,,) = accumulator.batchTransactions(batchId, 0);

        assertEq(paddedPayload.length, accumulator.FIXED_PAYLOAD_SIZE());
    }

    // ========================================================================
    // BATCH RELEASE TESTS
    // ========================================================================

    function test_releaseBatch_readyByTime() public {
        _configureDefaultRoute();

        bytes32 batchId = _submitTx(keccak256("c1"), keccak256("n1"), user1);

        // Warp past maxWaitTime (10 minutes)
        vm.warp(block.timestamp + 11 minutes);

        vm.expectEmit(true, false, false, true);
        emit BatchReady(batchId, 1, "TIME_ELAPSED");

        accumulator.releaseBatch(batchId);

        (,, BatchAccumulator.BatchStatus status, bool isReady,) = accumulator.getBatchInfo(batchId);
        assertTrue(isReady);
        assertEq(uint256(status), uint256(BatchAccumulator.BatchStatus.READY));
    }

    function test_releaseBatch_revertsIfBatchNotFound() public {
        vm.expectRevert(BatchAccumulator.BatchNotFound.selector);
        accumulator.releaseBatch(keccak256("nonexistent"));
    }

    function test_releaseBatch_revertsIfAlreadyProcessing() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 200);

        // Start processing
        vm.prank(relayer);
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));

        vm.expectRevert(BatchAccumulator.BatchAlreadyProcessing.selector);
        accumulator.releaseBatch(batchId);
    }

    function test_forceReleaseBatch_success() public {
        _configureDefaultRoute();

        bytes32 batchId = _submitTx(keccak256("c1"), keccak256("n1"), user1);

        vm.expectEmit(true, false, false, true);
        emit BatchReady(batchId, 1, "FORCE_RELEASED");

        vm.prank(operator);
        accumulator.forceReleaseBatch(batchId);

        (,, BatchAccumulator.BatchStatus status,,) = accumulator.getBatchInfo(batchId);
        assertEq(uint256(status), uint256(BatchAccumulator.BatchStatus.READY));
    }

    function test_forceReleaseBatch_revertsIfNotOperator() public {
        _configureDefaultRoute();
        bytes32 batchId = _submitTx(keccak256("c1"), keccak256("n1"), user1);

        vm.prank(nobody);
        vm.expectRevert();
        accumulator.forceReleaseBatch(batchId);
    }

    function test_forceReleaseBatch_revertsIfBatchNotFound() public {
        vm.prank(operator);
        vm.expectRevert(BatchAccumulator.BatchNotFound.selector);
        accumulator.forceReleaseBatch(keccak256("nonexistent"));
    }

    // ========================================================================
    // BATCH PROCESSING TESTS
    // ========================================================================

    function test_processBatch_success() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 300);

        bytes memory proof = abi.encodePacked(bytes32(uint256(42)));

        vm.expectEmit(true, true, false, false);
        emit BatchProcessing(batchId, relayer);

        vm.prank(relayer);
        accumulator.processBatch(batchId, proof);

        (,, BatchAccumulator.BatchStatus status,,) = accumulator.getBatchInfo(batchId);
        assertEq(uint256(status), uint256(BatchAccumulator.BatchStatus.COMPLETED));
    }

    function test_processBatch_setsAggregateProofHash() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 400);

        bytes memory proof = abi.encodePacked(bytes32(uint256(99)));
        vm.prank(relayer);
        accumulator.processBatch(batchId, proof);

        // Auto-generated getter skips dynamic array (commitments), returns 8 fields
        (,,,,,, bytes32 aggregateProofHash,) = accumulator.batches(batchId);
        assertEq(aggregateProofHash, keccak256(proof));
    }

    function test_processBatch_marksTransactionsProcessed() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 500);

        vm.prank(relayer);
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));

        for (uint256 i = 0; i < 8; i++) {
            (,,,,, bool processed) = accumulator.batchTransactions(batchId, i);
            assertTrue(processed);
        }
    }

    function test_processBatch_clearsActiveBatch() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 600);

        vm.prank(relayer);
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));

        bytes32 routeHash = keccak256(abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN));
        assertEq(accumulator.activeBatches(routeHash), bytes32(0));
    }

    function test_processBatch_revertsIfNotRelayer() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 700);

        vm.prank(nobody);
        vm.expectRevert();
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));
    }

    function test_processBatch_revertsIfBatchNotFound() public {
        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.BatchNotFound.selector);
        accumulator.processBatch(keccak256("nonexistent"), abi.encodePacked(bytes32(uint256(1))));
    }

    function test_processBatch_revertsIfStillAccumulating() public {
        _configureDefaultRoute();
        bytes32 batchId = _submitTx(keccak256("c1"), keccak256("n1"), user1);

        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.BatchNotReady.selector);
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));
    }

    function test_processBatch_revertsIfAlreadyCompleted() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 800);

        vm.prank(relayer);
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));

        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.BatchAlreadyCompleted.selector);
        accumulator.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));
    }

    function test_processBatch_revertsOnInvalidProof() public {
        // Deploy accumulator with verifier that rejects
        MockProofVerifier rejectVerifier = new MockProofVerifier(false);
        BatchAccumulator impl2 = new BatchAccumulator();
        ERC1967Proxy proxy2 = new ERC1967Proxy(
            address(impl2),
            abi.encodeCall(
                BatchAccumulator.initialize, (admin, address(rejectVerifier), crossChainHub)
            )
        );
        BatchAccumulator acc2 = BatchAccumulator(address(proxy2));

        vm.startPrank(admin);
        acc2.grantRole(acc2.OPERATOR_ROLE(), operator);
        acc2.grantRole(acc2.RELAYER_ROLE(), relayer);
        vm.stopPrank();

        vm.prank(operator);
        acc2.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 2, 10 minutes);

        // Fill batch with 2 txns
        vm.prank(user1);
        acc2.submitToBatch(
            keccak256("c1"), keccak256("n1"), abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );
        vm.prank(user1);
        bytes32 batchId = acc2.submitToBatch(
            keccak256("c2"), keccak256("n2"), abi.encodePacked(bytes32(0)), TARGET_CHAIN
        );

        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.InvalidProof.selector);
        acc2.processBatch(batchId, abi.encodePacked(bytes32(uint256(1))));
    }

    function test_processBatch_emitsBatchCompleted() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(8, 900);

        bytes memory proof = abi.encodePacked(bytes32(uint256(77)));

        vm.expectEmit(true, false, false, true);
        emit BatchCompleted(batchId, keccak256(proof), 8);

        vm.prank(relayer);
        accumulator.processBatch(batchId, proof);
    }

    // ========================================================================
    // VIEW FUNCTION TESTS
    // ========================================================================

    function test_getBatchInfo_returnsCorrectData() public {
        _configureDefaultRoute();

        bytes32 batchId = _fillBatch(3, 1000);

        (
            uint256 size,
            uint256 age,
            BatchAccumulator.BatchStatus status,
            bool isReady,
            uint256 targetChain
        ) = accumulator.getBatchInfo(batchId);

        assertEq(size, 3);
        assertGe(age, 0);
        assertEq(uint256(status), uint256(BatchAccumulator.BatchStatus.ACCUMULATING));
        assertFalse(isReady);
        assertEq(targetChain, TARGET_CHAIN);
    }

    function test_getActiveBatch_returnsCorrectData() public {
        _configureDefaultRoute();
        bytes32 batchId = _fillBatch(3, 1100);

        (bytes32 activeBatchId, uint256 currentSize, uint256 minSize, uint256 timeRemaining) =
            accumulator.getActiveBatch(SOURCE_CHAIN, TARGET_CHAIN);

        assertEq(activeBatchId, batchId);
        assertEq(currentSize, 3);
        assertEq(minSize, 8);
        assertGt(timeRemaining, 0);
    }

    function test_getActiveBatch_returnsZeroForUnknownRoute() public view {
        (bytes32 batchId, uint256 currentSize,,) = accumulator.getActiveBatch(999, 888);

        assertEq(batchId, bytes32(0));
        assertEq(currentSize, 0);
    }

    function test_getTransactionByCommitment_returnsCorrectData() public {
        _configureDefaultRoute();
        bytes32 commitment = keccak256("findme");
        _submitTx(commitment, keccak256("n_findme"), user1);

        (
            bytes32 batchId,
            uint256 submittedAt,
            bool processed,
            BatchAccumulator.BatchStatus batchStatus
        ) = accumulator.getTransactionByCommitment(commitment);

        assertNotEq(batchId, bytes32(0));
        assertEq(submittedAt, block.timestamp);
        assertFalse(processed);
        assertEq(uint256(batchStatus), uint256(BatchAccumulator.BatchStatus.ACCUMULATING));
    }

    function test_getAnonymitySet_returnsCorrectSize() public {
        _configureDefaultRoute();
        bytes32 commitment = keccak256("c_anon");
        _submitTx(commitment, keccak256("n_anon"), user1);
        _submitTx(keccak256("c2_anon"), keccak256("n2_anon"), user2);

        uint256 anonSet = accumulator.getAnonymitySet(commitment);
        assertEq(anonSet, 2);
    }

    function test_getAnonymitySet_returnsZeroForUnknownCommitment() public view {
        uint256 anonSet = accumulator.getAnonymitySet(keccak256("unknown"));
        assertEq(anonSet, 0);
    }

    // ========================================================================
    // ADMIN FUNCTION TESTS
    // ========================================================================

    function test_pause_success() public {
        vm.prank(operator);
        accumulator.pause();
        assertTrue(accumulator.paused());
    }

    function test_unpause_success() public {
        vm.prank(operator);
        accumulator.pause();

        vm.prank(operator);
        accumulator.unpause();
        assertFalse(accumulator.paused());
    }

    function test_pause_revertsUnauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        accumulator.pause();
    }

    function test_setProofVerifier_success() public {
        address newVerifier = makeAddr("newVerifier");

        vm.prank(admin);
        accumulator.setProofVerifier(newVerifier);

        assertEq(accumulator.proofVerifier(), newVerifier);
    }

    function test_setProofVerifier_revertsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(BatchAccumulator.ZeroAddress.selector);
        accumulator.setProofVerifier(address(0));
    }

    function test_setProofVerifier_revertsUnauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        accumulator.setProofVerifier(makeAddr("x"));
    }

    function test_setCrossChainHub_success() public {
        address newHub = makeAddr("newHub");

        vm.prank(admin);
        accumulator.setCrossChainHub(newHub);

        assertEq(accumulator.crossChainHub(), newHub);
    }

    function test_setCrossChainHub_revertsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(BatchAccumulator.ZeroAddress.selector);
        accumulator.setCrossChainHub(address(0));
    }

    function test_setCrossChainHub_revertsUnauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        accumulator.setCrossChainHub(makeAddr("x"));
    }

    // ========================================================================
    // CONSTANTS TESTS
    // ========================================================================

    function test_constants() public view {
        assertEq(accumulator.DEFAULT_MIN_BATCH_SIZE(), 8);
        assertEq(accumulator.MAX_BATCH_SIZE(), 64);
        assertEq(accumulator.DEFAULT_MAX_WAIT_TIME(), 10 minutes);
        assertEq(accumulator.MIN_WAIT_TIME(), 1 minutes);
        assertEq(accumulator.MAX_WAIT_TIME(), 1 hours);
        assertEq(accumulator.FIXED_PAYLOAD_SIZE(), 2048);
    }

    // ========================================================================
    // FUZZ TESTS
    // ========================================================================

    function testFuzz_configureRoute_batchSize(
        uint256 batchSize
    ) public {
        // Valid range is [2, 64]
        if (batchSize >= 2 && batchSize <= 64) {
            vm.prank(operator);
            accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, batchSize, 10 minutes);

            bytes32 routeHash = keccak256(abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN));
            (uint256 minBatchSize,,) = accumulator.routeConfigs(routeHash);
            assertEq(minBatchSize, batchSize);
        } else {
            vm.prank(operator);
            vm.expectRevert(BatchAccumulator.InvalidBatchSize.selector);
            accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, batchSize, 10 minutes);
        }
    }

    function testFuzz_configureRoute_waitTime(
        uint256 waitTime
    ) public {
        // Valid range is [1 min, 1 hour]
        if (waitTime >= 1 minutes && waitTime <= 1 hours) {
            vm.prank(operator);
            accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, waitTime);

            bytes32 routeHash = keccak256(abi.encodePacked(SOURCE_CHAIN, TARGET_CHAIN));
            (, uint256 maxWaitTime,) = accumulator.routeConfigs(routeHash);
            assertEq(maxWaitTime, waitTime);
        } else {
            vm.prank(operator);
            vm.expectRevert(BatchAccumulator.InvalidWaitTime.selector);
            accumulator.configureRoute(SOURCE_CHAIN, TARGET_CHAIN, 8, waitTime);
        }
    }

    function testFuzz_submitToBatch_uniqueCommitmentsAndNullifiers(
        bytes32 seed
    ) public {
        _configureDefaultRoute();

        bytes32 commitment = keccak256(abi.encodePacked("fuzz_c_", seed));
        bytes32 nullifier = keccak256(abi.encodePacked("fuzz_n_", seed));

        vm.prank(user1);
        bytes32 batchId = accumulator.submitToBatch(
            commitment, nullifier, abi.encodePacked(seed), TARGET_CHAIN
        );

        assertNotEq(batchId, bytes32(0));
        assertEq(accumulator.commitmentToBatch(commitment), batchId);
        assertTrue(accumulator.nullifierUsed(nullifier));
    }

    // ========================================================================
    // EDGE CASE / INTEGRATION TESTS
    // ========================================================================

    function test_newBatchCreatedAfterPreviousBecameReady() public {
        _configureDefaultRoute();

        // Fill first batch
        bytes32 batch1 = _fillBatch(8, 2000);
        (,, BatchAccumulator.BatchStatus status1,,) = accumulator.getBatchInfo(batch1);
        assertEq(uint256(status1), uint256(BatchAccumulator.BatchStatus.READY));

        // Next submission should create a new batch
        bytes32 batch2 = _submitTx(keccak256("new_batch_c"), keccak256("new_batch_n"), user1);

        assertNotEq(batch1, batch2);
        assertEq(accumulator.totalBatches(), 2);
    }

    function test_nullifierTracking() public {
        _configureDefaultRoute();

        bytes32 nullifier = keccak256("tracked_nullifier");
        assertFalse(accumulator.nullifierUsed(nullifier));

        _submitTx(keccak256("c_track"), nullifier, user1);
        assertTrue(accumulator.nullifierUsed(nullifier));
    }

    function test_commitmentToBatchMapping() public {
        _configureDefaultRoute();

        bytes32 commitment = keccak256("mapped_commitment");
        bytes32 batchId = _submitTx(commitment, keccak256("n_mapped"), user1);

        assertEq(accumulator.commitmentToBatch(commitment), batchId);
    }
}
