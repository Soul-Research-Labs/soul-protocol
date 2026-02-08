// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/CrossL2Atomicity.sol";

/// @notice Mock target contract for atomic execution
contract MockTarget {
    uint256 public value;
    bool public shouldFail;

    function execute(uint256 val) external payable {
        require(!shouldFail, "MockTarget: execution failed");
        value = val;
    }

    function setFail(bool _fail) external {
        shouldFail = _fail;
    }
}

contract CrossL2AtomicityTest is Test {
    CrossL2Atomicity public atomicity;
    MockTarget public target;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public executor = makeAddr("executor");
    address public guardian = makeAddr("guardian");
    address public user = makeAddr("user");

    function setUp() public {
        atomicity = new CrossL2Atomicity(admin);
        target = new MockTarget();

        // Grant roles
        atomicity.grantRole(atomicity.OPERATOR_ROLE(), operator);
        atomicity.grantRole(atomicity.EXECUTOR_ROLE(), executor);
        atomicity.grantRole(atomicity.GUARDIAN_ROLE(), guardian);

        // Fund
        vm.deal(admin, 100 ether);
        vm.deal(executor, 100 ether);
        vm.deal(user, 100 ether);
    }

    // ============ Helpers ============

    function _createSimpleBundle() internal returns (bytes32) {
        uint256[] memory chainIds = new uint256[](2);
        chainIds[0] = block.chainid; // Current chain
        chainIds[1] = 10; // Optimism

        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](2);
        chainTypes[0] = CrossL2Atomicity.ChainType.OP_STACK;
        chainTypes[1] = CrossL2Atomicity.ChainType.OP_STACK;

        address[] memory targets = new address[](2);
        targets[0] = address(target);
        targets[1] = address(target);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeCall(MockTarget.execute, (42));
        datas[1] = abi.encodeCall(MockTarget.execute, (99));

        uint256[] memory values = new uint256[](2);
        values[0] = 0;
        values[1] = 0;

        return
            atomicity.createAtomicBundle(
                chainIds,
                chainTypes,
                targets,
                datas,
                values,
                0
            );
    }

    function _createBundleWithValue() internal returns (bytes32) {
        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = block.chainid;

        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        chainTypes[0] = CrossL2Atomicity.ChainType.OP_STACK;

        address[] memory targets = new address[](1);
        targets[0] = address(target);

        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeCall(MockTarget.execute, (42));

        uint256[] memory values = new uint256[](1);
        values[0] = 1 ether;

        return
            atomicity.createAtomicBundle{value: 1 ether}(
                chainIds,
                chainTypes,
                targets,
                datas,
                values,
                0
            );
    }

    // ============ Constructor Tests ============

    function test_constructor_setsRoles() public view {
        assertTrue(atomicity.hasRole(atomicity.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(atomicity.hasRole(atomicity.OPERATOR_ROLE(), admin));
        assertTrue(atomicity.hasRole(atomicity.EXECUTOR_ROLE(), admin));
        assertTrue(atomicity.hasRole(atomicity.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_setsChainId() public view {
        assertEq(atomicity.currentChainId(), block.chainid);
    }

    // ============ Create Bundle Tests ============

    function test_createBundle_success() public {
        bytes32 bundleId = _createSimpleBundle();
        assertTrue(bundleId != bytes32(0));

        (
            address initiator,
            CrossL2Atomicity.BundlePhase phase,
            uint256 chainCount,
            uint256 preparedCount,
            uint256 executedCount,
            uint256 timeout
        ) = atomicity.getBundle(bundleId);

        assertEq(initiator, admin);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.CREATED));
        assertEq(chainCount, 2);
        assertEq(preparedCount, 0);
        assertEq(executedCount, 0);
        assertEq(timeout, 1 hours); // DEFAULT_TIMEOUT
    }

    function test_createBundle_customTimeout() public {
        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = block.chainid;

        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        chainTypes[0] = CrossL2Atomicity.ChainType.OP_STACK;

        address[] memory targets = new address[](1);
        targets[0] = address(target);

        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeCall(MockTarget.execute, (42));

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes32 bundleId = atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            2 hours
        );

        (, , , , , uint256 timeout) = atomicity.getBundle(bundleId);
        assertEq(timeout, 2 hours);
    }

    function test_createBundle_revertsEmptyChains() public {
        uint256[] memory chainIds = new uint256[](0);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](0);
        address[] memory targets = new address[](0);
        bytes[] memory datas = new bytes[](0);
        uint256[] memory values = new uint256[](0);

        vm.expectRevert(CrossL2Atomicity.InvalidChainCount.selector);
        atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    function test_createBundle_revertsTooManyChains() public {
        uint256 count = 11; // > MAX_CHAINS_PER_BUNDLE
        uint256[] memory chainIds = new uint256[](count);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](count);
        address[] memory targets = new address[](count);
        bytes[] memory datas = new bytes[](count);
        uint256[] memory values = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            chainIds[i] = i + 1;
            targets[i] = address(target);
            datas[i] = "";
        }

        vm.expectRevert(CrossL2Atomicity.InvalidChainCount.selector);
        atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    function test_createBundle_revertsMismatchedArrays() public {
        uint256[] memory chainIds = new uint256[](2);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1); // Mismatch
        address[] memory targets = new address[](2);
        bytes[] memory datas = new bytes[](2);
        uint256[] memory values = new uint256[](2);

        chainIds[0] = 1;
        chainIds[1] = 2;
        targets[0] = address(target);
        targets[1] = address(target);

        vm.expectRevert(CrossL2Atomicity.InvalidOperationData.selector);
        atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    function test_createBundle_revertsDuplicateChainId() public {
        uint256[] memory chainIds = new uint256[](2);
        chainIds[0] = 10;
        chainIds[1] = 10; // Duplicate

        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](2);
        address[] memory targets = new address[](2);
        targets[0] = address(target);
        targets[1] = address(target);
        bytes[] memory datas = new bytes[](2);
        uint256[] memory values = new uint256[](2);

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossL2Atomicity.DuplicateChainId.selector,
                10
            )
        );
        atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    function test_createBundle_revertsInsufficientValue() public {
        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = block.chainid;

        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        targets[0] = address(target);
        bytes[] memory datas = new bytes[](1);
        datas[0] = "";

        uint256[] memory values = new uint256[](1);
        values[0] = 1 ether; // Requires 1 ether

        vm.expectRevert(CrossL2Atomicity.InsufficientValue.selector);
        atomicity.createAtomicBundle{value: 0.5 ether}(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    // ============ Prepare Phase Tests ============

    function test_markChainPrepared_success() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        vm.prank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);

        CrossL2Atomicity.ChainOperation memory op = atomicity.getChainOperation(
            bundleId,
            block.chainid
        );
        assertTrue(op.prepared);
        assertEq(op.proofHash, proofHash);

        (
            ,
            CrossL2Atomicity.BundlePhase phase,
            ,
            uint256 preparedCount,
            ,

        ) = atomicity.getBundle(bundleId);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.PREPARING));
        assertEq(preparedCount, 1);
    }

    function test_markChainPrepared_autoCommitsWhenAllPrepared() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        vm.startPrank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);
        atomicity.markChainPrepared(bundleId, 10, proofHash);
        vm.stopPrank();

        (
            ,
            CrossL2Atomicity.BundlePhase phase,
            ,
            uint256 preparedCount,
            ,

        ) = atomicity.getBundle(bundleId);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.COMMITTED));
        assertEq(preparedCount, 2);
    }

    function test_markChainPrepared_revertsNotExecutor() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.prank(user);
        vm.expectRevert();
        atomicity.markChainPrepared(
            bundleId,
            block.chainid,
            keccak256("proof")
        );
    }

    function test_markChainPrepared_revertsAfterTimeout() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.warp(block.timestamp + 2 hours); // Past DEFAULT_TIMEOUT

        vm.prank(executor);
        vm.expectRevert(CrossL2Atomicity.BundleExpired.selector);
        atomicity.markChainPrepared(
            bundleId,
            block.chainid,
            keccak256("proof")
        );
    }

    function test_markChainPrepared_idempotent() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        vm.startPrank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);
        // Second call is a no-op
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);
        vm.stopPrank();

        (, , , uint256 preparedCount, , ) = atomicity.getBundle(bundleId);
        assertEq(preparedCount, 1);
    }

    // ============ Commit Phase Tests ============

    function test_commitBundle_manual() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        // Prepare only first chain (no auto-commit)
        vm.prank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);

        // Prepare second chain
        vm.prank(executor);
        atomicity.markChainPrepared(bundleId, 10, proofHash);
        // Auto-commit happens, so check phase
        (, CrossL2Atomicity.BundlePhase phase, , , , ) = atomicity.getBundle(
            bundleId
        );
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.COMMITTED));
    }

    function test_commitBundle_revertsNotAllPrepared() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        vm.prank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);

        // Try to manually commit with only 1 of 2 prepared
        vm.prank(executor);
        vm.expectRevert(CrossL2Atomicity.AllChainsMustPrepare.selector);
        atomicity.commitBundle(bundleId);
    }

    // ============ Execute Phase Tests ============

    function test_executeOnCurrentChain_success() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        // Prepare all chains
        vm.startPrank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);
        atomicity.markChainPrepared(bundleId, 10, proofHash);

        // Execute on current chain
        atomicity.executeOnCurrentChain(bundleId);
        vm.stopPrank();

        // Verify target was called
        assertEq(target.value(), 42);

        // Check execution state
        CrossL2Atomicity.ChainOperation memory op = atomicity.getChainOperation(
            bundleId,
            block.chainid
        );
        assertTrue(op.executed);
    }

    function test_executeOnCurrentChain_revertsNotCommitted() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.prank(executor);
        vm.expectRevert(CrossL2Atomicity.InvalidPhase.selector);
        atomicity.executeOnCurrentChain(bundleId);
    }

    function test_executeOnCurrentChain_revertsAlreadyExecuted() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        vm.startPrank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);
        atomicity.markChainPrepared(bundleId, 10, proofHash);
        atomicity.executeOnCurrentChain(bundleId);

        vm.expectRevert(CrossL2Atomicity.AlreadyExecuted.selector);
        atomicity.executeOnCurrentChain(bundleId);
        vm.stopPrank();
    }

    function test_executeOnCurrentChain_revertsTargetFailure() public {
        bytes32 bundleId = _createSimpleBundle();
        bytes32 proofHash = keccak256("proof");

        target.setFail(true);

        vm.startPrank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, proofHash);
        atomicity.markChainPrepared(bundleId, 10, proofHash);

        vm.expectRevert(CrossL2Atomicity.ExecutionFailed.selector);
        atomicity.executeOnCurrentChain(bundleId);
        vm.stopPrank();
    }

    // ============ Rollback Tests ============

    function test_rollbackAfterTimeout() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.warp(block.timestamp + 2 hours); // Past DEFAULT_TIMEOUT

        atomicity.rollbackAfterTimeout(bundleId);

        (, CrossL2Atomicity.BundlePhase phase, , , , ) = atomicity.getBundle(
            bundleId
        );
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.ROLLEDBACK));
    }

    function test_rollbackAfterTimeout_revertsBeforeTimeout() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.expectRevert(CrossL2Atomicity.TimeoutNotReached.selector);
        atomicity.rollbackAfterTimeout(bundleId);
    }

    function test_rollbackAfterTimeout_revertsAlreadyCompleted() public {
        // Create single-chain bundle and execute it fully
        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = block.chainid;
        CrossL2Atomicity.ChainType[]
            memory types = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        targets[0] = address(target);
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeCall(MockTarget.execute, (42));
        uint256[] memory values = new uint256[](1);

        bytes32 bundleId = atomicity.createAtomicBundle(
            chainIds,
            types,
            targets,
            datas,
            values,
            0
        );

        vm.startPrank(executor);
        atomicity.markChainPrepared(bundleId, block.chainid, keccak256("p"));
        atomicity.executeOnCurrentChain(bundleId);
        vm.stopPrank();

        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(CrossL2Atomicity.InvalidPhase.selector);
        atomicity.rollbackAfterTimeout(bundleId);
    }

    // ============ View Tests ============

    function test_getChainOperation() public {
        bytes32 bundleId = _createSimpleBundle();
        CrossL2Atomicity.ChainOperation memory op = atomicity.getChainOperation(
            bundleId,
            block.chainid
        );
        assertEq(op.chainId, block.chainid);
        assertEq(op.target, address(target));
        assertFalse(op.prepared);
        assertFalse(op.executed);
    }

    function test_isBundleExpired() public {
        bytes32 bundleId = _createSimpleBundle();
        assertFalse(atomicity.isBundleExpired(bundleId));

        vm.warp(block.timestamp + 2 hours);
        assertTrue(atomicity.isBundleExpired(bundleId));
    }

    // ============ Configuration Tests ============

    function test_setChainAdapter() public {
        address adapter = makeAddr("adapter");
        vm.prank(operator);
        atomicity.setChainAdapter(10, adapter);
        assertEq(atomicity.chainAdapters(10), adapter);
    }

    function test_setSuperchainMessenger() public {
        address messenger = makeAddr("messenger");
        vm.prank(operator);
        atomicity.setSuperchainMessenger(messenger);
        assertEq(atomicity.superchainMessenger(), messenger);
    }

    function test_setArbitrumInbox() public {
        address inbox = makeAddr("inbox");
        vm.prank(operator);
        atomicity.setArbitrumInbox(inbox);
        assertEq(atomicity.arbitrumInbox(), inbox);
    }

    function test_pause_unpause() public {
        vm.prank(guardian);
        atomicity.pause();

        vm.expectRevert();
        _createSimpleBundle();

        vm.prank(guardian);
        atomicity.unpause();

        bytes32 bundleId = _createSimpleBundle();
        assertTrue(bundleId != bytes32(0));
    }

    // ============ Access Control Tests ============

    function test_onlyExecutorCanPrepare() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.prank(user);
        vm.expectRevert();
        atomicity.markChainPrepared(bundleId, block.chainid, keccak256("p"));
    }

    function test_onlyExecutorCanCommit() public {
        bytes32 bundleId = _createSimpleBundle();

        vm.prank(user);
        vm.expectRevert();
        atomicity.commitBundle(bundleId);
    }

    function test_onlyGuardianCanPause() public {
        vm.prank(user);
        vm.expectRevert();
        atomicity.pause();
    }

    // ============ Receive ETH Test ============

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool success, ) = address(atomicity).call{value: 1 ether}("");
        assertTrue(success);
    }

    // ============ Full Lifecycle Test ============

    function test_fullLifecycle_singleChain() public {
        // 1. Create bundle
        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = block.chainid;
        CrossL2Atomicity.ChainType[]
            memory types = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        targets[0] = address(target);
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeCall(MockTarget.execute, (777));
        uint256[] memory values = new uint256[](1);

        bytes32 bundleId = atomicity.createAtomicBundle(
            chainIds,
            types,
            targets,
            datas,
            values,
            0
        );

        // 2. Prepare → auto-commits
        vm.prank(executor);
        atomicity.markChainPrepared(
            bundleId,
            block.chainid,
            keccak256("prepared")
        );

        (, CrossL2Atomicity.BundlePhase phase, , , , ) = atomicity.getBundle(
            bundleId
        );
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.COMMITTED));

        // 3. Execute
        vm.prank(executor);
        atomicity.executeOnCurrentChain(bundleId);

        // 4. Verify completed
        uint256 executedCount;
        (, phase, , , executedCount, ) = atomicity.getBundle(bundleId);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.COMPLETED));
        assertEq(executedCount, 1);
        assertEq(target.value(), 777);
    }
}
