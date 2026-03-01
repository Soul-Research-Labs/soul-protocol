// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/core/NullifierRegistryV3.sol";

/**
 * @title NullifierRegistryV3 Cross-Chain Sync Integration Test
 * @notice Tests real NullifierRegistryV3 instances simulating cross-chain
 *         nullifier synchronization via the RELAY_ROLE pathway.
 *
 * Unlike CrossChainNullifierSync.t.sol which uses mocks, this test deploys
 * two full NullifierRegistryV3 contracts to verify the actual Merkle tree
 * state stays consistent across simulated chain boundaries.
 */
contract NullifierCrossChainSyncIntegration is Test {
    NullifierRegistryV3 public registryA; // Simulates Chain A (chainid=1)
    NullifierRegistryV3 public registryB; // Simulates Chain B (chainid=42161)

    address public admin = makeAddr("admin");
    address public bridge = makeAddr("bridge");
    address public registrar = makeAddr("registrar");

    bytes32 constant RELAY_ROLE = keccak256("RELAY_ROLE");
    bytes32 constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    function setUp() public {
        // Deploy Registry A on chain 1
        vm.chainId(1);
        registryA = new NullifierRegistryV3();

        // Deploy Registry B on chain 42161
        vm.chainId(42161);
        registryB = new NullifierRegistryV3();

        // Reset chain ID for tests
        vm.chainId(1);

        // Grant roles on both registries
        registryA.grantRole(RELAY_ROLE, bridge);
        registryA.grantRole(REGISTRAR_ROLE, registrar);
        registryB.grantRole(RELAY_ROLE, bridge);
        registryB.grantRole(REGISTRAR_ROLE, registrar);

        // Register cross-chain domains (each registry accepts nullifiers from the other chain)
        registryA.registerDomain(bytes32(uint256(42161))); // Chain A accepts from Chain B
        registryB.registerDomain(bytes32(uint256(1))); // Chain B accepts from Chain A
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE NULLIFIER SYNC
    //////////////////////////////////////////////////////////////*/

    function test_SingleNullifier_RegisterAndSync() public {
        bytes32 nullifier = keccak256("secret1");
        bytes32 commitment = keccak256("commitment1");

        // 1. Register on Chain A
        vm.prank(registrar);
        uint256 indexA = registryA.registerNullifier(nullifier, commitment);
        assertEq(indexA, 0);
        assertTrue(registryA.isNullifierUsed(nullifier));

        // 2. Sync to Chain B via bridge
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = nullifier;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = commitment;

        bytes32 sourceRoot = registryA.merkleRoot();

        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1, // sourceChainId
            nullifiers,
            commitments,
            sourceRoot
        );

        // 3. Verify nullifier exists on Chain B
        assertTrue(registryB.isNullifierUsed(nullifier));

        // 4. Verify nullifier data
        (
            uint64 timestamp,
            uint64 blockNumber,
            uint64 sourceChainId,
            address registrarAddr,
            bytes32 storedCommitment,
            uint256 storedIndex
        ) = registryB.nullifiers(nullifier);

        assertEq(sourceChainId, 1);
        assertEq(storedCommitment, commitment);
        assertGt(timestamp, 0);
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH NULLIFIER SYNC
    //////////////////////////////////////////////////////////////*/

    function test_BatchSync_MultipleNullifiers() public {
        uint256 batchSize = 5;

        bytes32[] memory nullifiers = new bytes32[](batchSize);
        bytes32[] memory commitments = new bytes32[](batchSize);

        // Register batch on Chain A
        for (uint256 i = 0; i < batchSize; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("nullifier", i));
            commitments[i] = keccak256(abi.encodePacked("commitment", i));
        }

        vm.prank(registrar);
        uint256 startIdx = registryA.batchRegisterNullifiers(
            nullifiers,
            commitments
        );
        assertEq(startIdx, 0);

        // Sync batch to Chain B
        bytes32 sourceRoot = registryA.merkleRoot();
        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            sourceRoot
        );

        // Verify all nullifiers exist on Chain B
        for (uint256 i = 0; i < batchSize; i++) {
            assertTrue(registryB.isNullifierUsed(nullifiers[i]));
        }

        // Verify total count
        assertEq(registryB.totalNullifiers(), batchSize);
    }

    /*//////////////////////////////////////////////////////////////
                    DUPLICATE SUPPRESSION
    //////////////////////////////////////////////////////////////*/

    function test_DuplicateSync_SkipsDuplicates() public {
        bytes32 nullifier = keccak256("unique-nullifier");
        bytes32 commitment = keccak256("commitment");

        // Register on Chain B first
        vm.prank(registrar);
        registryB.registerNullifier(nullifier, commitment);
        assertEq(registryB.totalNullifiers(), 1);

        // Now sync the same nullifier from Chain A
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = nullifier;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = commitment;

        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            keccak256("testRoot") // S8-10: source Merkle root must be non-zero
        );

        // Should still be 1, not 2
        assertEq(registryB.totalNullifiers(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                    BIDIRECTIONAL SYNC
    //////////////////////////////////////////////////////////////*/

    function test_BidirectionalSync() public {
        // Register different nullifiers on each chain, then sync both ways
        bytes32 nullifierA = keccak256("from-chain-A");
        bytes32 nullifierB = keccak256("from-chain-B");
        bytes32 commitA = keccak256("commit-A");
        bytes32 commitB = keccak256("commit-B");

        // Register on Chain A
        vm.prank(registrar);
        registryA.registerNullifier(nullifierA, commitA);

        // Register on Chain B
        vm.prank(registrar);
        registryB.registerNullifier(nullifierB, commitB);

        // Sync A → B
        bytes32[] memory nullsA = new bytes32[](1);
        nullsA[0] = nullifierA;
        bytes32[] memory commsA = new bytes32[](1);
        commsA[0] = commitA;

        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullsA,
            commsA,
            registryA.merkleRoot()
        );

        // Sync B → A
        bytes32[] memory nullsB = new bytes32[](1);
        nullsB[0] = nullifierB;
        bytes32[] memory commsB = new bytes32[](1);
        commsB[0] = commitB;

        vm.prank(bridge);
        registryA.receiveCrossChainNullifiers(
            42161,
            nullsB,
            commsB,
            registryB.merkleRoot()
        );

        // Both registries should know about both nullifiers
        assertTrue(registryA.isNullifierUsed(nullifierA));
        assertTrue(registryA.isNullifierUsed(nullifierB));
        assertTrue(registryB.isNullifierUsed(nullifierA));
        assertTrue(registryB.isNullifierUsed(nullifierB));

        assertEq(registryA.totalNullifiers(), 2);
        assertEq(registryB.totalNullifiers(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                    MERKLE ROOT CONSISTENCY
    //////////////////////////////////////////////////////////////*/

    function test_MerkleRoot_ChangesAfterSync() public {
        bytes32 rootBefore = registryB.merkleRoot();

        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = keccak256("test-nullifier");
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = keccak256("test-commitment");

        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            keccak256("testRoot") // S8-10: source Merkle root must be non-zero
        );

        bytes32 rootAfter = registryB.merkleRoot();
        assertTrue(
            rootBefore != rootAfter,
            "Merkle root should change after sync"
        );
    }

    function test_MerkleRoot_InHistory() public {
        bytes32 rootBefore = registryB.merkleRoot();

        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = keccak256("tracked-nullifier");
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = bytes32(0);

        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            keccak256("testRoot") // S8-10: source Merkle root must be non-zero
        );

        // Old root should still be in history
        assertTrue(registryB.isValidRoot(rootBefore));
        // New root should also be in history
        assertTrue(registryB.isValidRoot(registryB.merkleRoot()));
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_ReceiveCrossChain_RequiresBridgeRole() public {
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = keccak256("unauthorized");
        bytes32[] memory commitments = new bytes32[](1);

        address unauthorized = makeAddr("unauthorized");
        vm.prank(unauthorized);
        vm.expectRevert();
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            bytes32(0)
        );
    }

    function test_ReceiveCrossChain_RejectsSameChain() public {
        // Registry A has CHAIN_ID = 1 (set during deploy)
        // Trying to receive from chain 1 on registry deployed on chain 1 should revert
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = keccak256("self-sync");
        bytes32[] memory commitments = new bytes32[](1);

        vm.prank(bridge);
        vm.expectRevert(); // InvalidChainId
        registryA.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            bytes32(0)
        );
    }

    function test_ReceiveCrossChain_RejectsEmptyBatch() public {
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(bridge);
        vm.expectRevert(); // EmptyBatch
        registryB.receiveCrossChainNullifiers(1, empty, empty, bytes32(0));
    }

    function test_ReceiveCrossChain_RejectsOversizedBatch() public {
        uint256 tooMany = 21; // MAX_BATCH_SIZE = 20
        bytes32[] memory nullifiers = new bytes32[](tooMany);
        bytes32[] memory commitments = new bytes32[](tooMany);
        for (uint256 i = 0; i < tooMany; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("oversized", i));
        }

        vm.prank(bridge);
        vm.expectRevert(); // BatchTooLarge
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            bytes32(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                    MAX BATCH SIZE SYNC
    //////////////////////////////////////////////////////////////*/

    function test_MaxBatchSync() public {
        uint256 batchSize = 20; // MAX_BATCH_SIZE
        bytes32[] memory nullifiers = new bytes32[](batchSize);
        bytes32[] memory commitments = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("max-batch", i));
            commitments[i] = keccak256(abi.encodePacked("max-commit", i));
        }

        // Register on A
        vm.prank(registrar);
        registryA.batchRegisterNullifiers(nullifiers, commitments);

        // Sync to B
        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            registryA.merkleRoot()
        );

        assertEq(registryB.totalNullifiers(), batchSize);

        // Verify batchExists
        bool[] memory exists = registryB.batchExists(nullifiers);
        for (uint256 i = 0; i < batchSize; i++) {
            assertTrue(exists[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SyncArbitraryNullifier(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));

        // Register on Chain A
        vm.prank(registrar);
        registryA.registerNullifier(nullifier, commitment);

        // Sync to Chain B
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = nullifier;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = commitment;

        vm.prank(bridge);
        registryB.receiveCrossChainNullifiers(
            1,
            nullifiers,
            commitments,
            registryA.merkleRoot()
        );

        assertTrue(registryB.isNullifierUsed(nullifier));
    }
}
