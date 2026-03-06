// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {INullifierRegistryV3} from "../../contracts/interfaces/INullifierRegistryV3.sol";

contract NullifierRegistryV3FuzzTest is Test {
    NullifierRegistryV3 registry;

    address admin = address(this);
    address registrar = address(0xBEEF);
    address bridge = address(0xCAFE);

    function setUp() public {
        registry = new NullifierRegistryV3();

        // Grant roles using the contract's pre-computed constants
        registry.grantRole(registry.REGISTRAR_ROLE(), registrar);
        registry.grantRole(registry.BRIDGE_ROLE(), bridge);
    }

    /// @notice Registering unique nullifiers produces sequential indices
    function testFuzz_registerNullifier_uniqueIndex(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));

        uint256 expectedIndex = registry.totalNullifiers();

        vm.prank(registrar);
        uint256 index = registry.registerNullifier(nullifier, commitment);

        assertEq(
            index,
            expectedIndex,
            "index should equal previous totalNullifiers"
        );
        assertEq(
            registry.totalNullifiers(),
            expectedIndex + 1,
            "totalNullifiers should increment by 1"
        );
    }

    /// @notice Batch register reverts when nullifier and commitment array lengths differ
    function testFuzz_batchRegister_arrayLengthMismatch(
        uint8 nLen,
        uint8 cLen
    ) public {
        // Bound to valid batch sizes, ensure lengths differ and commitments non-empty
        uint256 n = bound(uint256(nLen), 1, registry.MAX_BATCH_SIZE());
        uint256 c = bound(uint256(cLen), 1, registry.MAX_BATCH_SIZE());
        vm.assume(n != c);

        bytes32[] memory nulls = new bytes32[](n);
        bytes32[] memory comms = new bytes32[](c);

        // Fill with unique non-zero nullifiers
        for (uint256 i = 0; i < n; i++) {
            nulls[i] = keccak256(abi.encodePacked("null", i));
        }
        for (uint256 i = 0; i < c; i++) {
            comms[i] = keccak256(abi.encodePacked("comm", i));
        }

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.BatchTooLarge.selector,
                c,
                n
            )
        );
        registry.batchRegisterNullifiers(nulls, comms);
    }

    /// @notice Batch register reverts when the same nullifier appears twice
    function testFuzz_batchRegister_duplicateInSameBatch(bytes32 base) public {
        vm.assume(base != bytes32(0));

        bytes32[] memory nulls = new bytes32[](2);
        nulls[0] = base;
        nulls[1] = base; // duplicate

        bytes32[] memory comms = new bytes32[](0);

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.NullifierAlreadyExists.selector,
                base
            )
        );
        registry.batchRegisterNullifiers(nulls, comms);
    }

    /// @notice Cross-chain receive reverts when sourceChainId == block.chainid
    function testFuzz_receiveCrossChain_replayProtection(
        bytes32 nullifier
    ) public {
        vm.assume(nullifier != bytes32(0));

        bytes32[] memory nulls = new bytes32[](1);
        nulls[0] = nullifier;
        bytes32[] memory comms = new bytes32[](0);

        vm.prank(bridge);
        vm.expectRevert(INullifierRegistryV3.InvalidChainId.selector);
        registry.receiveCrossChainNullifiers(
            block.chainid,
            nulls,
            comms,
            bytes32(uint256(1))
        );
    }

    /// @notice Merkle root changes after each distinct insert
    function testFuzz_merkleRoot_changesOnInsert(
        bytes32 n1,
        bytes32 n2
    ) public {
        vm.assume(n1 != bytes32(0) && n2 != bytes32(0));
        vm.assume(n1 != n2);

        bytes32 rootBefore = registry.merkleRoot();

        vm.startPrank(registrar);

        registry.registerNullifier(n1, bytes32(0));
        bytes32 rootAfterFirst = registry.merkleRoot();
        assertTrue(
            rootAfterFirst != rootBefore,
            "root should change after first insert"
        );

        registry.registerNullifier(n2, bytes32(0));
        bytes32 rootAfterSecond = registry.merkleRoot();
        assertTrue(
            rootAfterSecond != rootAfterFirst,
            "root should change after second insert"
        );

        vm.stopPrank();
    }

    /// @notice exists() returns true after registering a nullifier
    function testFuzz_exists_afterRegister(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));

        assertFalse(
            registry.exists(nullifier),
            "should not exist before registration"
        );

        vm.prank(registrar);
        registry.registerNullifier(nullifier, commitment);

        assertTrue(
            registry.exists(nullifier),
            "should exist after registration"
        );
    }

    /// @notice Registering the same nullifier twice reverts
    function testFuzz_doubleRegister_reverts(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        vm.startPrank(registrar);

        registry.registerNullifier(nullifier, bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(
                INullifierRegistryV3.NullifierAlreadyExists.selector,
                nullifier
            )
        );
        registry.registerNullifier(nullifier, bytes32(0));

        vm.stopPrank();
    }
}
