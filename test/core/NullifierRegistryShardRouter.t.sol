// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NullifierRegistryShardRouter, INullifierShard} from "../../contracts/core/NullifierRegistryShardRouter.sol";

contract MockShard is INullifierShard {
    mapping(bytes32 => bool) public consumed;
    uint256 public consumeCalls;

    function isConsumed(bytes32 n) external view returns (bool) {
        return consumed[n];
    }

    function consume(bytes32 n, uint64, uint64) external {
        consumed[n] = true;
        consumeCalls += 1;
    }
}

contract NullifierRegistryShardRouterTest is Test {
    NullifierRegistryShardRouter internal router;
    MockShard internal s0;
    MockShard internal s1;
    MockShard internal s2;
    MockShard internal s3;
    MockShard internal legacy;
    address internal admin = address(0xA11CE);

    function setUp() public {
        s0 = new MockShard();
        s1 = new MockShard();
        s2 = new MockShard();
        s3 = new MockShard();
        legacy = new MockShard();
        address[] memory shards = new address[](4);
        shards[0] = address(s0);
        shards[1] = address(s1);
        shards[2] = address(s2);
        shards[3] = address(s3);
        router = new NullifierRegistryShardRouter(
            admin,
            shards,
            address(legacy)
        );
    }

    function test_shardIndex_partitionsByFirstByte() public view {
        // First byte 0x00 -> 0 % 4 = 0
        assertEq(router.shardIndexOf(bytes32(uint256(0))), 0);
        // First byte 0x01 -> 1 % 4 = 1
        assertEq(router.shardIndexOf(bytes32(uint256(0x01) << 248)), 1);
        // First byte 0x03 -> 3 % 4 = 3
        assertEq(router.shardIndexOf(bytes32(uint256(0x03) << 248)), 3);
        // First byte 0x05 -> 5 % 4 = 1
        assertEq(router.shardIndexOf(bytes32(uint256(0x05) << 248)), 1);
    }

    function test_consume_routesToCorrectShard() public {
        bytes32 n = bytes32(uint256(0x03) << 248);
        vm.prank(admin);
        router.consume(n, 1, 10);
        assertEq(s3.consumeCalls(), 1);
        assertEq(s0.consumeCalls(), 0);
        assertTrue(router.isConsumed(n));
    }

    function test_consume_rejectsReplayInSameShard() public {
        bytes32 n = bytes32(uint256(0x03) << 248);
        vm.startPrank(admin);
        router.consume(n, 1, 10);
        vm.expectRevert();
        router.consume(n, 1, 10);
        vm.stopPrank();
    }

    function test_consume_rejectsWhenLegacyAlreadyHasIt() public {
        bytes32 n = bytes32(uint256(0x03) << 248);
        legacy.consume(n, 1, 10);
        vm.prank(admin);
        vm.expectRevert();
        router.consume(n, 1, 10);
    }

    function test_isConsumed_readsLegacyUntilDisabled() public {
        bytes32 n = bytes32(uint256(0x02) << 248);
        legacy.consume(n, 1, 10);
        assertTrue(router.isConsumed(n));
        vm.prank(admin);
        router.setLegacyRegistry(address(legacy), true);
        assertFalse(router.isConsumed(n));
    }

    function test_onlyAdminCanAddShard() public {
        MockShard s4 = new MockShard();
        vm.expectRevert();
        router.addShard(address(s4));
        vm.prank(admin);
        router.addShard(address(s4));
        assertEq(router.shardCount(), 5);
    }

    function test_addShard_doesNotRemapExistingNullifier() public {
        bytes32 n = bytes32(uint256(0x05) << 248);
        vm.prank(admin);
        router.consume(n, 1, 10);

        MockShard s4 = new MockShard();
        vm.prank(admin);
        router.addShard(address(s4));

        assertTrue(router.isConsumed(n));

        vm.prank(admin);
        vm.expectRevert();
        router.consume(n, 1, 10);

        assertEq(s1.consumeCalls(), 1);
        assertEq(s4.consumeCalls(), 0);
    }

    function test_assignPrefixRange_routesFutureWritesToNewShard() public {
        MockShard s4 = new MockShard();

        vm.startPrank(admin);
        router.addShard(address(s4));
        router.assignPrefixRange(0x08, 0x08, 4);
        vm.stopPrank();

        bytes32 n = bytes32(uint256(0x08) << 248);

        vm.prank(admin);
        router.consume(n, 1, 10);

        assertEq(router.shardIndexOf(n), 4);
        assertEq(s4.consumeCalls(), 1);
        assertEq(s0.consumeCalls(), 0);
        assertEq(s1.consumeCalls(), 0);
        assertEq(s2.consumeCalls(), 0);
        assertEq(s3.consumeCalls(), 0);
    }

    function testFuzz_consume_anyNullifierRoutesExactlyOnce(
        bytes32 n,
        uint64 src,
        uint64 dst
    ) public {
        vm.assume(n != bytes32(0));
        vm.prank(admin);
        router.consume(n, src, dst);
        uint256 total = s0.consumeCalls() +
            s1.consumeCalls() +
            s2.consumeCalls() +
            s3.consumeCalls();
        assertEq(total, 1);
    }
}
