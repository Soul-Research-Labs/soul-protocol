// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CapacityTelemetryReader, ICapacitySource} from "../../contracts/crosschain/CapacityTelemetryReader.sol";

contract MockSource is ICapacitySource {
    mapping(uint64 => mapping(address => uint256)) public cap;
    bool public shouldRevert;

    function setCap(uint64 c, address t, uint256 v) external {
        cap[c][t] = v;
    }

    function setRevert(bool v) external {
        shouldRevert = v;
    }

    function availableCapacity(
        uint64 c,
        address t
    ) external view returns (uint256) {
        if (shouldRevert) revert("boom");
        return cap[c][t];
    }

    function dailyCap(uint64, address) external pure returns (uint256) {
        return 0;
    }
}

contract CapacityTelemetryReaderTest is Test {
    CapacityTelemetryReader internal reader;
    MockSource internal a;
    MockSource internal b;
    MockSource internal c;
    address internal admin = address(0xA11CE);
    address internal token = address(0xB0B);

    function setUp() public {
        reader = new CapacityTelemetryReader(admin);
        a = new MockSource();
        b = new MockSource();
        c = new MockSource();
        vm.startPrank(admin);
        reader.registerSource(keccak256("A"), address(a));
        reader.registerSource(keccak256("B"), address(b));
        reader.registerSource(keccak256("C"), address(c));
        vm.stopPrank();
    }

    function test_pickBest_returnsHighest() public {
        a.setCap(10, token, 100 ether);
        b.setCap(10, token, 250 ether);
        c.setCap(10, token, 50 ether);
        (bytes32 id, uint256 cap) = reader.pickBest(10, token, 0);
        assertEq(id, keccak256("B"));
        assertEq(cap, 250 ether);
    }

    function test_pickBest_enforcesMinCapacity() public {
        a.setCap(10, token, 1 ether);
        b.setCap(10, token, 2 ether);
        (bytes32 id, uint256 cap) = reader.pickBest(10, token, 5 ether);
        assertEq(id, bytes32(0));
        assertEq(cap, 0);
    }

    function test_pickBest_skipsRevertingSource() public {
        a.setCap(10, token, 500 ether);
        a.setRevert(true);
        b.setCap(10, token, 250 ether);
        (bytes32 id, ) = reader.pickBest(10, token, 0);
        assertEq(id, keccak256("B"));
    }

    function test_pickBest_skipsDisabled() public {
        a.setCap(10, token, 500 ether);
        b.setCap(10, token, 100 ether);
        vm.prank(admin);
        reader.setEnabled(keccak256("A"), false);
        (bytes32 id, ) = reader.pickBest(10, token, 0);
        assertEq(id, keccak256("B"));
    }

    function test_snapshot_returnsParallelArrays() public {
        a.setCap(10, token, 3 ether);
        b.setCap(10, token, 5 ether);
        c.setCap(10, token, 0);
        (bytes32[] memory ids, uint256[] memory caps) = reader.snapshot(
            10,
            token
        );
        assertEq(ids.length, 3);
        assertEq(caps[0], 3 ether);
        assertEq(caps[1], 5 ether);
        assertEq(caps[2], 0);
    }
}
