// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainCommitmentRelay} from "../../contracts/crosschain/CrossChainCommitmentRelay.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title MockShieldedPool — simulates the pool that receives commitments
contract MockShieldedPool {
    uint256 public insertCount;
    bool public shouldRevert;
    string public revertReason;

    function setRevert(bool _shouldRevert, string memory _reason) external {
        shouldRevert = _shouldRevert;
        revertReason = _reason;
    }

    // Relay uses abi.encodeWithSignature with a tuple-style selector, so we
    // need a fallback to catch the call regardless of selector encoding.
    fallback() external payable {
        if (shouldRevert) {
            // Use assembly to revert with the stored reason string
            bytes memory reason = bytes(revertReason);
            assembly {
                revert(add(reason, 32), mload(reason))
            }
        }
        insertCount++;
    }

    receive() external payable {}
}

/**
 * @title CrossChainCommitmentRelayTest
 * @notice Comprehensive tests for CrossChainCommitmentRelay
 */
contract CrossChainCommitmentRelayTest is Test {
    CrossChainCommitmentRelay public relay;
    MockShieldedPool public pool;

    address admin = address(0xA);
    address relayer = address(0xB);
    address operator = address(0xC);
    address unauthorized = address(0xD);

    bytes32 constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    function setUp() public {
        pool = new MockShieldedPool();
        relay = new CrossChainCommitmentRelay(
            admin,
            address(pool),
            address(0x123)
        );

        vm.startPrank(admin);
        relay.grantRole(RELAYER_ROLE, relayer);
        relay.grantRole(OPERATOR_ROLE, operator);
        vm.stopPrank();
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    function test_Constructor_SetsRoles() public view {
        assertTrue(relay.hasRole(relay.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(relay.hasRole(OPERATOR_ROLE, admin));
        assertTrue(relay.hasRole(RELAYER_ROLE, relayer));
    }

    function test_Constructor_SetsAddresses() public view {
        assertEq(relay.shieldedPool(), address(pool));
        assertEq(relay.privacyHub(), address(0x123));
    }

    function test_Constructor_ZeroAdmin_Reverts() public {
        vm.expectRevert(CrossChainCommitmentRelay.ZeroAddress.selector);
        new CrossChainCommitmentRelay(
            address(0),
            address(pool),
            address(0x123)
        );
    }

    function test_Constructor_ZeroPool_Allowed() public {
        // Zero pool is allowed at construction — can be set later
        CrossChainCommitmentRelay r = new CrossChainCommitmentRelay(
            admin,
            address(0),
            address(0)
        );
        assertEq(r.shieldedPool(), address(0));
    }

    // =========================================================================
    // RELAY SINGLE BATCH
    // =========================================================================

    function _createBatch(
        uint256 size
    ) internal pure returns (CrossChainCommitmentRelay.CommitmentBatch memory) {
        bytes32[] memory commitments = new bytes32[](size);
        bytes32[] memory assetIds = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            commitments[i] = keccak256(abi.encode("commitment", i));
            assetIds[i] = keccak256(abi.encode("asset", i));
        }
        return
            CrossChainCommitmentRelay.CommitmentBatch({
                sourceChainId: bytes32(uint256(42161)),
                commitments: commitments,
                assetIds: assetIds,
                batchRoot: keccak256(abi.encode("root", size)),
                proof: hex"deadbeef",
                sourceTreeSize: 1000
            });
    }

    function test_RelayBatch_Success() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            3
        );

        vm.prank(relayer);
        relay.relayCommitmentBatch(batch);

        assertEq(relay.totalBatchesRelayed(), 1);
        assertEq(relay.chainCommitmentCounts(bytes32(uint256(42161))), 3);
        assertTrue(relay.processedBatches(batch.batchRoot));
        assertEq(pool.insertCount(), 1);
    }

    function test_RelayBatch_EmitEvent() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            2
        );

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit CrossChainCommitmentRelay.BatchRelayed(
            bytes32(uint256(42161)),
            batch.batchRoot,
            2,
            relayer
        );
        relay.relayCommitmentBatch(batch);
    }

    function test_RelayBatch_Unauthorized_Reverts() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );

        vm.prank(unauthorized);
        vm.expectRevert();
        relay.relayCommitmentBatch(batch);
    }

    function test_RelayBatch_EmptyCommitments_Reverts() public {
        bytes32[] memory empty = new bytes32[](0);
        CrossChainCommitmentRelay.CommitmentBatch
            memory batch = CrossChainCommitmentRelay.CommitmentBatch({
                sourceChainId: bytes32(uint256(1)),
                commitments: empty,
                assetIds: empty,
                batchRoot: bytes32(uint256(99)),
                proof: hex"",
                sourceTreeSize: 0
            });

        vm.prank(relayer);
        vm.expectRevert(CrossChainCommitmentRelay.EmptyBatch.selector);
        relay.relayCommitmentBatch(batch);
    }

    function test_RelayBatch_LengthMismatch_Reverts() public {
        bytes32[] memory commitments = new bytes32[](2);
        bytes32[] memory assetIds = new bytes32[](3);
        CrossChainCommitmentRelay.CommitmentBatch
            memory batch = CrossChainCommitmentRelay.CommitmentBatch({
                sourceChainId: bytes32(uint256(1)),
                commitments: commitments,
                assetIds: assetIds,
                batchRoot: bytes32(uint256(1)),
                proof: hex"",
                sourceTreeSize: 0
            });

        vm.prank(relayer);
        vm.expectRevert(CrossChainCommitmentRelay.BatchLengthMismatch.selector);
        relay.relayCommitmentBatch(batch);
    }

    function test_RelayBatch_DuplicateRoot_Reverts() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );

        vm.startPrank(relayer);
        relay.relayCommitmentBatch(batch);

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainCommitmentRelay.BatchAlreadyRelayed.selector,
                batch.batchRoot
            )
        );
        relay.relayCommitmentBatch(batch);
        vm.stopPrank();
    }

    function test_RelayBatch_ZeroPool_Reverts() public {
        CrossChainCommitmentRelay r = new CrossChainCommitmentRelay(
            admin,
            address(0),
            address(0)
        );
        vm.prank(admin);
        r.grantRole(RELAYER_ROLE, relayer);

        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );
        vm.prank(relayer);
        vm.expectRevert(CrossChainCommitmentRelay.ZeroAddress.selector);
        r.relayCommitmentBatch(batch);
    }

    function test_RelayBatch_PoolReverts_BubblesUp() public {
        pool.setRevert(true, "pool error");
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );

        vm.prank(relayer);
        vm.expectRevert();
        relay.relayCommitmentBatch(batch);
    }

    // =========================================================================
    // RELAY MULTIPLE BATCHES
    // =========================================================================

    function test_RelayMultiple_Success() public {
        CrossChainCommitmentRelay.CommitmentBatch[]
            memory batches = new CrossChainCommitmentRelay.CommitmentBatch[](3);
        for (uint256 i = 0; i < 3; i++) {
            batches[i] = _createBatch(i + 1);
            batches[i].batchRoot = keccak256(abi.encode("multi", i));
        }

        vm.prank(relayer);
        relay.relayMultipleBatches(batches);

        // 1 + 2 + 3 = 6 commitments
        assertEq(relay.totalBatchesRelayed(), 3);
        assertEq(relay.chainCommitmentCounts(bytes32(uint256(42161))), 6);
    }

    function test_RelayMultiple_DuplicateInBatch_Reverts() public {
        CrossChainCommitmentRelay.CommitmentBatch[]
            memory batches = new CrossChainCommitmentRelay.CommitmentBatch[](2);
        batches[0] = _createBatch(1);
        batches[1] = _createBatch(1); // Same batchRoot!

        vm.prank(relayer);
        vm.expectRevert();
        relay.relayMultipleBatches(batches);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function test_SetShieldedPool() public {
        address newPool = address(0x999);
        vm.prank(operator);
        relay.setShieldedPool(newPool);
        assertEq(relay.shieldedPool(), newPool);
    }

    function test_SetShieldedPool_ZeroAddress_Reverts() public {
        vm.prank(operator);
        vm.expectRevert(CrossChainCommitmentRelay.ZeroAddress.selector);
        relay.setShieldedPool(address(0));
    }

    function test_SetShieldedPool_Unauthorized_Reverts() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        relay.setShieldedPool(address(0x999));
    }

    function test_SetPrivacyHub() public {
        address newHub = address(0x888);
        vm.prank(operator);
        relay.setPrivacyHub(newHub);
        assertEq(relay.privacyHub(), newHub);
    }

    function test_SetPrivacyHub_ZeroAddress_Reverts() public {
        vm.prank(operator);
        vm.expectRevert(CrossChainCommitmentRelay.ZeroAddress.selector);
        relay.setPrivacyHub(address(0));
    }

    // =========================================================================
    // PAUSE / UNPAUSE
    // =========================================================================

    function test_Pause_BlocksRelay() public {
        vm.prank(admin);
        relay.pause();

        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );
        vm.prank(relayer);
        vm.expectRevert();
        relay.relayCommitmentBatch(batch);
    }

    function test_Unpause_AllowsRelay() public {
        vm.startPrank(admin);
        relay.pause();
        relay.unpause();
        vm.stopPrank();

        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );
        vm.prank(relayer);
        relay.relayCommitmentBatch(batch);
        assertEq(relay.totalBatchesRelayed(), 1);
    }

    function test_Pause_Unauthorized_Reverts() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        relay.pause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_GetChainStats() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            5
        );
        vm.prank(relayer);
        relay.relayCommitmentBatch(batch);

        assertEq(relay.getChainStats(bytes32(uint256(42161))), 5);
        assertEq(relay.getChainStats(bytes32(uint256(99))), 0);
    }

    // =========================================================================
    // SELF-RELAY (permissionless fallback — prevents SPOF)
    // =========================================================================

    function test_SelfRelay_Success() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            3
        );
        batch.batchRoot = keccak256(abi.encode("selfRelay"));

        // Anyone can self-relay, no RELAYER_ROLE required
        vm.prank(unauthorized);
        relay.selfRelayCommitmentBatch(batch);

        assertEq(relay.totalBatchesRelayed(), 1);
        assertEq(relay.chainCommitmentCounts(bytes32(uint256(42161))), 3);
        assertTrue(relay.processedBatches(batch.batchRoot));
        assertEq(pool.insertCount(), 1);
    }

    function test_SelfRelay_DuplicateRoot_Reverts() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );
        batch.batchRoot = keccak256(abi.encode("selfDup"));

        vm.prank(unauthorized);
        relay.selfRelayCommitmentBatch(batch);

        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainCommitmentRelay.BatchAlreadyRelayed.selector,
                batch.batchRoot
            )
        );
        relay.selfRelayCommitmentBatch(batch);
    }

    function test_SelfRelay_PauseBlocks() public {
        vm.prank(admin);
        relay.pause();

        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );
        batch.batchRoot = keccak256(abi.encode("selfPause"));

        vm.prank(unauthorized);
        vm.expectRevert();
        relay.selfRelayCommitmentBatch(batch);
    }

    function test_SelfRelay_ZeroPool_Reverts() public {
        CrossChainCommitmentRelay r = new CrossChainCommitmentRelay(
            admin,
            address(0),
            address(0)
        );

        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            1
        );
        batch.batchRoot = keccak256(abi.encode("selfZero"));

        vm.prank(unauthorized);
        vm.expectRevert(CrossChainCommitmentRelay.ZeroAddress.selector);
        r.selfRelayCommitmentBatch(batch);
    }

    function test_SelfRelay_EmptyBatch_Reverts() public {
        bytes32[] memory empty = new bytes32[](0);
        CrossChainCommitmentRelay.CommitmentBatch
            memory batch = CrossChainCommitmentRelay.CommitmentBatch({
                sourceChainId: bytes32(uint256(1)),
                commitments: empty,
                assetIds: empty,
                batchRoot: bytes32(uint256(99)),
                proof: hex"",
                sourceTreeSize: 0
            });

        vm.prank(unauthorized);
        vm.expectRevert(CrossChainCommitmentRelay.EmptyBatch.selector);
        relay.selfRelayCommitmentBatch(batch);
    }

    function test_SelfRelay_EmitsEvent() public {
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            2
        );
        batch.batchRoot = keccak256(abi.encode("selfEvent"));

        vm.prank(unauthorized);
        vm.expectEmit(true, true, true, true);
        emit CrossChainCommitmentRelay.BatchRelayed(
            bytes32(uint256(42161)),
            batch.batchRoot,
            2,
            unauthorized
        );
        relay.selfRelayCommitmentBatch(batch);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_RelayBatch_VariableSizes(uint8 rawSize) public {
        uint256 size = bound(rawSize, 1, 50);
        CrossChainCommitmentRelay.CommitmentBatch memory batch = _createBatch(
            size
        );
        batch.batchRoot = keccak256(abi.encode("fuzz", rawSize));

        vm.prank(relayer);
        relay.relayCommitmentBatch(batch);
        assertEq(relay.chainCommitmentCounts(bytes32(uint256(42161))), size);
    }

    function testFuzz_RelayBatch_UniqueRoots(
        bytes32 root1,
        bytes32 root2
    ) public {
        vm.assume(root1 != root2);
        vm.assume(root1 != bytes32(0) && root2 != bytes32(0));

        CrossChainCommitmentRelay.CommitmentBatch memory b1 = _createBatch(1);
        b1.batchRoot = root1;
        CrossChainCommitmentRelay.CommitmentBatch memory b2 = _createBatch(1);
        b2.batchRoot = root2;

        vm.startPrank(relayer);
        relay.relayCommitmentBatch(b1);
        relay.relayCommitmentBatch(b2);
        vm.stopPrank();

        assertEq(relay.totalBatchesRelayed(), 2);
    }
}
