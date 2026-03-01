// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {INullifierRegistryV3} from "../../contracts/interfaces/INullifierRegistryV3.sol";

contract NullifierRegistryV3Test is Test {
    NullifierRegistryV3 public registry;
    address public admin = address(this);
    address public registrar = address(0xBEEF);
    address public bridge = address(0xBB);

    function setUp() public {
        registry = new NullifierRegistryV3();
        registry.addRegistrar(registrar);
        registry.grantRole(registry.RELAY_ROLE(), bridge);
        // Register cross-chain domain used in tests
        registry.registerDomain(bytes32(uint256(42)));
    }

    // ======= Core Registration =======

    function test_registerNullifier() public {
        bytes32 nullifier = keccak256("null1");
        bytes32 commitment = keccak256("commit1");

        vm.prank(registrar);
        uint256 index = registry.registerNullifier(nullifier, commitment);

        assertEq(index, 0);
        assertTrue(registry.isNullifierUsed(nullifier));
        assertEq(registry.totalNullifiers(), 1);
    }

    function test_registerNullifier_incrementsIndex() public {
        vm.startPrank(registrar);
        registry.registerNullifier(keccak256("n1"), bytes32(0));
        uint256 idx = registry.registerNullifier(keccak256("n2"), bytes32(0));
        vm.stopPrank();

        assertEq(idx, 1);
        assertEq(registry.totalNullifiers(), 2);
    }

    function test_registerNullifier_revertsDuplicate() public {
        bytes32 nullifier = keccak256("dup");
        vm.prank(registrar);
        registry.registerNullifier(nullifier, bytes32(0));

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.NullifierAlreadyExists.selector,
                nullifier
            )
        );
        registry.registerNullifier(nullifier, bytes32(0));
    }

    function test_registerNullifier_revertsZero() public {
        vm.prank(registrar);
        vm.expectRevert(INullifierRegistryV3.ZeroNullifier.selector);
        registry.registerNullifier(bytes32(0), bytes32(0));
    }

    function test_registerNullifier_onlyRegistrar() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        registry.registerNullifier(keccak256("x"), bytes32(0));
    }

    // ======= Batch Registration =======

    function test_batchRegister() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = keccak256("b1");
        nullifiers[1] = keccak256("b2");
        nullifiers[2] = keccak256("b3");
        bytes32[] memory commitments = new bytes32[](3);
        commitments[0] = keccak256("c1");
        commitments[1] = keccak256("c2");
        commitments[2] = keccak256("c3");

        vm.prank(registrar);
        uint256 startIdx = registry.batchRegisterNullifiers(
            nullifiers,
            commitments
        );

        assertEq(startIdx, 0);
        assertEq(registry.totalNullifiers(), 3);
        assertTrue(registry.isNullifierUsed(nullifiers[0]));
        assertTrue(registry.isNullifierUsed(nullifiers[1]));
        assertTrue(registry.isNullifierUsed(nullifiers[2]));
    }

    function test_batchRegister_emptyReverts() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(registrar);
        vm.expectRevert(INullifierRegistryV3.EmptyBatch.selector);
        registry.batchRegisterNullifiers(empty, empty);
    }

    function test_batchRegister_tooLargeReverts() public {
        bytes32[] memory tooMany = new bytes32[](21);
        for (uint256 i = 0; i < 21; i++) {
            tooMany[i] = keccak256(abi.encode(i));
        }
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.BatchTooLarge.selector,
                21,
                20
            )
        );
        registry.batchRegisterNullifiers(tooMany, empty);
    }

    function test_batchRegister_noCommitments() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256("nc1");
        nullifiers[1] = keccak256("nc2");
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(registrar);
        registry.batchRegisterNullifiers(nullifiers, empty);
        assertEq(registry.totalNullifiers(), 2);
    }

    // ======= Merkle Tree =======

    function test_merkleRootUpdatesOnRegistration() public {
        bytes32 initialRoot = registry.merkleRoot();

        vm.prank(registrar);
        registry.registerNullifier(keccak256("tree1"), bytes32(0));

        bytes32 newRoot = registry.merkleRoot();
        assertTrue(newRoot != initialRoot);
    }

    function test_historicalRootsTracked() public {
        bytes32 initialRoot = registry.merkleRoot();

        vm.prank(registrar);
        registry.registerNullifier(keccak256("h1"), bytes32(0));

        assertTrue(registry.isValidRoot(initialRoot));
        assertTrue(registry.isValidRoot(registry.merkleRoot()));
    }

    function test_batchExists() public {
        bytes32 n1 = keccak256("be1");
        bytes32 n2 = keccak256("be2");
        bytes32 n3 = keccak256("be3");

        vm.prank(registrar);
        registry.registerNullifier(n1, bytes32(0));

        bytes32[] memory toCheck = new bytes32[](3);
        toCheck[0] = n1;
        toCheck[1] = n2;
        toCheck[2] = n3;

        bool[] memory results = registry.batchExists(toCheck);
        assertTrue(results[0]);
        assertFalse(results[1]);
        assertFalse(results[2]);
    }

    // ======= Cross-chain =======

    function test_receiveCrossChainNullifiers() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256("cc1");
        nullifiers[1] = keccak256("cc2");
        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = keccak256("ccc1");
        commitments[1] = keccak256("ccc2");
        bytes32 srcRoot = keccak256("srcRoot");

        vm.prank(bridge);
        registry.receiveCrossChainNullifiers(
            42,
            nullifiers,
            commitments,
            srcRoot
        );

        assertEq(registry.totalNullifiers(), 2);
        assertEq(registry.getNullifierCountByChain(42), 2);
        assertTrue(registry.isNullifierUsed(nullifiers[0]));
    }

    function test_receiveCrossChain_revertsSameChain() public {
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = keccak256("same");
        bytes32[] memory commitments = new bytes32[](0);

        vm.prank(bridge);
        vm.expectRevert(INullifierRegistryV3.InvalidChainId.selector);
        registry.receiveCrossChainNullifiers(
            block.chainid,
            nullifiers,
            commitments,
            bytes32(0)
        );
    }

    function test_receiveCrossChain_skipsDuplicates() public {
        bytes32 nullifier = keccak256("ccdup");
        vm.prank(registrar);
        registry.registerNullifier(nullifier, bytes32(0));

        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = nullifier;
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(bridge);
        registry.receiveCrossChainNullifiers(
            42,
            nullifiers,
            empty,
            keccak256("testRoot")
        ); // S8-10: non-zero root

        // Should still be 1, not 2 (duplicate skipped)
        assertEq(registry.totalNullifiers(), 1);
    }

    // ======= View Functions =======

    function test_getNullifierData() public {
        bytes32 nullifier = keccak256("data1");
        bytes32 commitment = keccak256("dataC1");

        vm.prank(registrar);
        registry.registerNullifier(nullifier, commitment);

        INullifierRegistryV3.NullifierData memory data = registry
            .getNullifierData(nullifier);
        assertEq(data.commitment, commitment);
        assertEq(data.registrar, registrar);
        assertEq(uint256(data.sourceChainId), block.chainid);
    }

    function test_getNullifierData_revertsNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.NullifierNotFound.selector,
                keccak256("nope")
            )
        );
        registry.getNullifierData(keccak256("nope"));
    }

    function test_getTreeStats() public {
        (uint256 total, bytes32 root, uint256 histSize) = registry
            .getTreeStats();
        assertEq(total, 0);
        assertTrue(root != bytes32(0));
        assertEq(histSize, 100);
    }

    // ======= Admin =======

    function test_pause_unpause() public {
        registry.pause();

        vm.prank(registrar);
        vm.expectRevert();
        registry.registerNullifier(keccak256("paused"), bytes32(0));

        registry.unpause();

        vm.prank(registrar);
        registry.registerNullifier(keccak256("unpaused"), bytes32(0));
        assertTrue(registry.isNullifierUsed(keccak256("unpaused")));
    }

    function test_removeRegistrar() public {
        registry.removeRegistrar(registrar);

        vm.prank(registrar);
        vm.expectRevert();
        registry.registerNullifier(keccak256("removed"), bytes32(0));
    }

    // ======= Fuzz =======

    function testFuzz_registerNullifier(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        vm.prank(registrar);
        uint256 idx = registry.registerNullifier(nullifier, bytes32(0));

        assertEq(idx, 0);
        assertTrue(registry.isNullifierUsed(nullifier));
    }

    function testFuzz_batchRegisterPreservesOrder(uint8 count) public {
        count = uint8(bound(count, 1, 20));

        bytes32[] memory nullifiers = new bytes32[](count);
        bytes32[] memory empty = new bytes32[](0);
        for (uint256 i = 0; i < count; i++) {
            nullifiers[i] = keccak256(abi.encode("fuzz", i));
        }

        vm.prank(registrar);
        uint256 startIdx = registry.batchRegisterNullifiers(nullifiers, empty);

        assertEq(startIdx, 0);
        assertEq(registry.totalNullifiers(), count);

        for (uint256 i = 0; i < count; i++) {
            assertTrue(registry.isNullifierUsed(nullifiers[i]));
        }
    }
}
