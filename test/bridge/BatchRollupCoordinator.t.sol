// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchRollupCoordinator, IRollupBatchVerifier} from "../../contracts/bridge/BatchRollupCoordinator.sol";

contract MockBatchVerifier is IRollupBatchVerifier {
    bool public accept = true;

    function setAccept(bool v) external {
        accept = v;
    }

    function verifyBatch(
        bytes calldata,
        bytes32,
        bytes32[] calldata
    ) external view returns (bool) {
        return accept;
    }
}

contract BatchRollupCoordinatorTest is Test {
    BatchRollupCoordinator internal coord;
    MockBatchVerifier internal verifier;
    address internal admin = address(0xA11CE);

    function setUp() public {
        verifier = new MockBatchVerifier();
        coord = new BatchRollupCoordinator(admin, address(verifier));
    }

    function _batch(uint256 n) internal pure returns (bytes32[] memory b) {
        b = new bytes32[](n);
        for (uint256 i; i < n; ++i) b[i] = keccak256(abi.encode("batch", i));
    }

    function test_settle_advancesHead() public {
        bytes32[] memory b = _batch(3);
        vm.prank(admin);
        uint64 h = coord.settleBatch(hex"00", keccak256("root1"), b);
        assertEq(h, 1);
        (bytes32 root, uint64 height, ) = coord.latest();
        assertEq(root, keccak256("root1"));
        assertEq(height, 1);
    }

    function test_settle_rejectsInvalidProof() public {
        verifier.setAccept(false);
        bytes32[] memory b = _batch(2);
        vm.prank(admin);
        vm.expectRevert();
        coord.settleBatch(hex"00", keccak256("x"), b);
    }

    function test_settle_rejectsEmptyBatch() public {
        bytes32[] memory b = new bytes32[](0);
        vm.prank(admin);
        vm.expectRevert();
        coord.settleBatch(hex"00", keccak256("x"), b);
    }

    function test_settle_rejectsDuplicateCommitment() public {
        bytes32[] memory b = _batch(2);
        vm.prank(admin);
        coord.settleBatch(hex"00", keccak256("r"), b);
        vm.prank(admin);
        vm.expectRevert();
        coord.settleBatch(hex"01", keccak256("r2"), b);
    }

    function test_settle_rejectsDuplicateCommitmentWithinBatch() public {
        bytes32 dup = keccak256("dup");
        bytes32[] memory b = new bytes32[](3);
        b[0] = dup;
        b[1] = keccak256("unique");
        b[2] = dup;

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BatchRollupCoordinator.DuplicateBatchCommitment.selector,
                dup
            )
        );
        coord.settleBatch(hex"00", keccak256("r"), b);
    }

    function test_settle_requiresProposerRole() public {
        bytes32[] memory b = _batch(1);
        vm.expectRevert();
        coord.settleBatch(hex"00", keccak256("x"), b);
    }

    function test_rootAt_recordsHistory() public {
        bytes32[] memory b1 = _batch(2);
        bytes32[] memory b2 = _batch(2);
        // Force distinct commitments in b2
        b2[0] = keccak256("other-batch-0");
        b2[1] = keccak256("other-batch-1");

        vm.startPrank(admin);
        coord.settleBatch(hex"00", keccak256("r1"), b1);
        coord.settleBatch(hex"00", keccak256("r2"), b2);
        vm.stopPrank();

        assertEq(coord.rootAt(1), keccak256("r1"));
        assertEq(coord.rootAt(2), keccak256("r2"));
    }
}
