// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PlinkoPIR} from "../../contracts/privacy/PlinkoPIR.sol";

/**
 * @title PlinkoPIRTest
 * @notice Foundry tests for Plinko PIR contract
 */
contract PlinkoPIRTest is Test {
    PlinkoPIR public pir;

    address public owner = address(this);
    address public user = address(0x1);
    address public relayer = address(0x2);

    bytes32 public constant TEST_DATABASE_ID = keccak256("test_database");
    bytes32 public constant TEST_MERKLE_ROOT = keccak256("merkle_root");
    uint256 public constant TEST_GRID_SIZE = 1024;
    uint256 public constant TEST_CELL_COUNT = 1024 * 1024;

    function setUp() public {
        pir = new PlinkoPIR(TEST_GRID_SIZE);
    }

    // ========================================================================
    // CONSTRUCTOR TESTS
    // ========================================================================

    function testConstructor() public view {
        assertEq(pir.gridSize(), TEST_GRID_SIZE);
        assertEq(pir.strictMode(), true);
        assertEq(pir.owner(), owner);
    }

    function testConstructor_invalidGridSize() public {
        vm.expectRevert(PlinkoPIR.InvalidGridSize.selector);
        new PlinkoPIR(0);
    }

    function testConstructor_maxGridSize() public {
        // Should work with max grid size (2^20)
        PlinkoPIR largePir = new PlinkoPIR(1 << 20);
        assertEq(largePir.gridSize(), 1 << 20);
    }

    // ========================================================================
    // DATABASE MANAGEMENT TESTS
    // ========================================================================

    function testRegisterDatabase() public {
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );

        (
            bytes32 merkleRoot,
            uint256 gridSize_,
            uint256 cellCount,
            uint256 lastUpdate,
            bool active
        ) = pir.getDatabase(TEST_DATABASE_ID);

        assertEq(merkleRoot, TEST_MERKLE_ROOT);
        assertEq(gridSize_, TEST_GRID_SIZE);
        assertEq(cellCount, TEST_CELL_COUNT);
        assertGt(lastUpdate, 0);
        assertTrue(active);
    }

    function testRegisterDatabase_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );
    }

    function testUpdateDatabaseRoot() public {
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );

        bytes32 newRoot = keccak256("new_merkle_root");
        pir.updateDatabaseRoot(TEST_DATABASE_ID, newRoot);

        (bytes32 merkleRoot, , , , ) = pir.getDatabase(TEST_DATABASE_ID);
        assertEq(merkleRoot, newRoot);
    }

    function testUpdateDatabaseRoot_notRegistered() public {
        vm.expectRevert(PlinkoPIR.DatabaseNotRegistered.selector);
        pir.updateDatabaseRoot(TEST_DATABASE_ID, TEST_MERKLE_ROOT);
    }

    // ========================================================================
    // PIR VERIFICATION TESTS
    // ========================================================================

    function testVerifyPIRProof_basic() public {
        // Register database
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );

        // Disable strict mode for basic test
        pir.setStrictMode(false);

        // Create a valid proof
        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = keccak256("response");
        bytes32 retrievedValue = hintCommitment ^ responseHintXor;

        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: TEST_MERKLE_ROOT,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        (bool success, bytes32 value) = pir.verifyPIRProof(
            proof,
            TEST_DATABASE_ID
        );

        assertTrue(success);
        assertEq(value, retrievedValue);
    }

    function testVerifyPIRProof_invalidValue() public {
        // Register database
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );

        pir.setStrictMode(false);

        // Create proof with mismatched value
        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: keccak256("response"),
            responseJunkXor: bytes32(0),
            hintCommitment: keccak256("hint"),
            retrievedValue: keccak256("wrong_value"), // Wrong!
            merkleRoot: TEST_MERKLE_ROOT,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        (bool success, ) = pir.verifyPIRProof(proof, TEST_DATABASE_ID);
        assertFalse(success);
    }

    function testVerifyPIRProof_withMerkleProof() public {
        // Create Merkle tree: leaf -> hash(leaf, sibling) = root
        bytes32 leaf = keccak256("retrieved_value");
        bytes32 sibling = keccak256("sibling");
        bytes32 root = keccak256(abi.encodePacked(leaf, sibling));

        // Register database with this root
        pir.registerDatabase(
            TEST_DATABASE_ID,
            root,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );

        // Create proof
        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = hintCommitment ^ leaf;

        bytes32[] memory merklePath = new bytes32[](1);
        merklePath[0] = sibling;

        uint8[] memory merklePathIndices = new uint8[](1);
        merklePathIndices[0] = 0; // leaf is on left

        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: leaf,
            merkleRoot: root,
            merklePath: merklePath,
            merklePathIndices: merklePathIndices
        });

        (bool success, bytes32 value) = pir.verifyPIRProof(
            proof,
            TEST_DATABASE_ID
        );

        assertTrue(success);
        assertEq(value, leaf);
    }

    function testVerifyPIRProof_databaseNotRegistered() public {
        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: bytes32(0),
            responseJunkXor: bytes32(0),
            hintCommitment: bytes32(0),
            retrievedValue: bytes32(0),
            merkleRoot: bytes32(0),
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        vm.expectRevert(PlinkoPIR.DatabaseNotRegistered.selector);
        pir.verifyPIRProof(proof, TEST_DATABASE_ID);
    }

    // ========================================================================
    // CROSS-CHAIN PIR TESTS
    // ========================================================================

    function testVerifyCrossChainPIR() public {
        // Setup state root
        uint64 sourceChain = 1;
        uint64 targetChain = 42161; // Arbitrum
        bytes32 sourceStateRoot = keccak256("state_root");

        pir.setTrustedRelayer(relayer, true);

        vm.prank(relayer);
        pir.updateStateRoot(sourceChain, sourceStateRoot);

        // Disable strict mode for simpler test
        pir.setStrictMode(false);

        // Create proof
        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = keccak256("response");
        bytes32 retrievedValue = hintCommitment ^ responseHintXor;
        bytes32 nullifier = keccak256("nullifier");

        PlinkoPIR.PIRProof memory pirProof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: sourceStateRoot,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        PlinkoPIR.CrossChainPIRProof memory proof = PlinkoPIR
            .CrossChainPIRProof({
                sourceChain: sourceChain,
                targetChain: targetChain,
                pirProof: pirProof,
                nullifier: nullifier,
                sourceStateRoot: sourceStateRoot
            });

        bool success = pir.verifyCrossChainPIR(proof);
        assertTrue(success);

        // Verify nullifier is marked as used
        assertTrue(pir.isNullifierUsed(nullifier));
    }

    function testVerifyCrossChainPIR_sameChain() public {
        PlinkoPIR.PIRProof memory pirProof = PlinkoPIR.PIRProof({
            queryCommitment: bytes32(0),
            responseHintXor: bytes32(0),
            responseJunkXor: bytes32(0),
            hintCommitment: bytes32(0),
            retrievedValue: bytes32(0),
            merkleRoot: bytes32(0),
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        PlinkoPIR.CrossChainPIRProof memory proof = PlinkoPIR
            .CrossChainPIRProof({
                sourceChain: 1,
                targetChain: 1, // Same chain!
                pirProof: pirProof,
                nullifier: bytes32(0),
                sourceStateRoot: bytes32(0)
            });

        vm.expectRevert(PlinkoPIR.InvalidChainId.selector);
        pir.verifyCrossChainPIR(proof);
    }

    function testVerifyCrossChainPIR_nullifierReplay() public {
        // Setup
        uint64 sourceChain = 1;
        uint64 targetChain = 42161;
        bytes32 sourceStateRoot = keccak256("state_root");
        bytes32 nullifier = keccak256("nullifier");

        pir.setTrustedRelayer(relayer, true);
        vm.prank(relayer);
        pir.updateStateRoot(sourceChain, sourceStateRoot);
        pir.setStrictMode(false);

        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = keccak256("response");
        bytes32 retrievedValue = hintCommitment ^ responseHintXor;

        PlinkoPIR.PIRProof memory pirProof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: sourceStateRoot,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        PlinkoPIR.CrossChainPIRProof memory proof = PlinkoPIR
            .CrossChainPIRProof({
                sourceChain: sourceChain,
                targetChain: targetChain,
                pirProof: pirProof,
                nullifier: nullifier,
                sourceStateRoot: sourceStateRoot
            });

        // First verification succeeds
        bool success = pir.verifyCrossChainPIR(proof);
        assertTrue(success);

        // Second verification fails (replay)
        vm.expectRevert(PlinkoPIR.NullifierAlreadyUsed.selector);
        pir.verifyCrossChainPIR(proof);
    }

    // ========================================================================
    // RELAYER TESTS
    // ========================================================================

    function testSetTrustedRelayer() public {
        pir.setTrustedRelayer(relayer, true);
        assertTrue(pir.trustedRelayers(relayer));

        pir.setTrustedRelayer(relayer, false);
        assertFalse(pir.trustedRelayers(relayer));
    }

    function testSetTrustedRelayer_zeroAddress() public {
        vm.expectRevert(PlinkoPIR.ZeroAddress.selector);
        pir.setTrustedRelayer(address(0), true);
    }

    function testUpdateStateRoot_trustedRelayer() public {
        pir.setTrustedRelayer(relayer, true);

        vm.prank(relayer);
        pir.updateStateRoot(1, keccak256("state_root"));

        assertEq(pir.getStateRoot(1), keccak256("state_root"));
    }

    function testUpdateStateRoot_untrustedRelayer() public {
        vm.prank(user);
        vm.expectRevert(PlinkoPIR.UnauthorizedRelayer.selector);
        pir.updateStateRoot(1, keccak256("state_root"));
    }

    function testUpdateStateRoot_owner() public {
        // Owner can always update
        pir.updateStateRoot(1, keccak256("state_root"));
        assertEq(pir.getStateRoot(1), keccak256("state_root"));
    }

    // ========================================================================
    // CONFIGURATION TESTS
    // ========================================================================

    function testSetGridSize() public {
        pir.setGridSize(2048);
        assertEq(pir.gridSize(), 2048);
    }

    function testSetGridSize_invalid() public {
        vm.expectRevert(PlinkoPIR.InvalidGridSize.selector);
        pir.setGridSize(0);
    }

    function testSetStrictMode() public {
        assertTrue(pir.strictMode());

        pir.setStrictMode(false);
        assertFalse(pir.strictMode());

        pir.setStrictMode(true);
        assertTrue(pir.strictMode());
    }

    // ========================================================================
    // QUERY COMMITMENT TESTS
    // ========================================================================

    function testSubmitQueryCommitment() public {
        bytes32 queryHash = keccak256("query");
        bytes32 hintCommitment = keccak256("hint");

        vm.prank(user);
        pir.submitQueryCommitment(queryHash, hintCommitment);

        (
            bytes32 storedQueryHash,
            bytes32 storedHintCommitment,
            uint256 gridSize_,
            uint256 timestamp
        ) = pir.queryCommitments(queryHash);

        assertEq(storedQueryHash, queryHash);
        assertEq(storedHintCommitment, hintCommitment);
        assertEq(gridSize_, TEST_GRID_SIZE);
        assertGt(timestamp, 0);
    }

    // ========================================================================
    // STATISTICS TESTS
    // ========================================================================

    function testStats() public {
        // Register database and submit proof
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );
        pir.setStrictMode(false);

        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = keccak256("response");
        bytes32 retrievedValue = hintCommitment ^ responseHintXor;

        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: TEST_MERKLE_ROOT,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        pir.verifyPIRProof(proof, TEST_DATABASE_ID);

        (
            uint256 total,
            uint256 successful,
            uint256 failed,
            uint256 gasUsed
        ) = pir.getStats();

        assertEq(total, 1);
        assertEq(successful, 1);
        assertEq(failed, 0);
        assertGt(gasUsed, 0);
    }

    // ========================================================================
    // BENCHMARK TESTS
    // ========================================================================

    function testBenchmark_verifyPIRProof() public {
        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );
        pir.setStrictMode(false);

        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = keccak256("response");
        bytes32 retrievedValue = hintCommitment ^ responseHintXor;

        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: TEST_MERKLE_ROOT,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < 100; i++) {
            pir.verifyPIRProof(proof, TEST_DATABASE_ID);
        }

        uint256 gasUsed = gasStart - gasleft();

        console.log("=== Plinko PIR Verification Benchmark ===");
        console.log("Iterations: 100");
        console.log("Total gas:", gasUsed);
        console.log("Avg gas per verify:", gasUsed / 100);
    }

    function testBenchmark_verifyWithMerkle() public {
        // Build 10-level Merkle tree
        bytes32[] memory leaves = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            leaves[i] = keccak256(abi.encodePacked("leaf", i));
        }

        // Compute root path
        bytes32[] memory path = new bytes32[](10);
        uint8[] memory indices = new uint8[](10);
        bytes32 computedRoot = leaves[0];

        for (uint256 i = 0; i < 10; i++) {
            path[i] = keccak256(abi.encodePacked("sibling", i));
            indices[i] = 0;
            computedRoot = keccak256(abi.encodePacked(computedRoot, path[i]));
        }

        pir.registerDatabase(
            TEST_DATABASE_ID,
            computedRoot,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );

        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = hintCommitment ^ leaves[0];

        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: leaves[0],
            merkleRoot: computedRoot,
            merklePath: path,
            merklePathIndices: indices
        });

        uint256 gasStart = gasleft();
        pir.verifyPIRProof(proof, TEST_DATABASE_ID);
        uint256 gasUsed = gasStart - gasleft();

        console.log("=== Plinko PIR + Merkle Verification ===");
        console.log("Merkle depth: 10");
        console.log("Gas used:", gasUsed);
    }

    // ========================================================================
    // FUZZ TESTS
    // ========================================================================

    function testFuzz_verifyPIRProof(
        bytes32 hintCommitment,
        bytes32 responseHintXor
    ) public {
        vm.assume(hintCommitment != bytes32(0));
        vm.assume(responseHintXor != bytes32(0));

        pir.registerDatabase(
            TEST_DATABASE_ID,
            TEST_MERKLE_ROOT,
            TEST_GRID_SIZE,
            TEST_CELL_COUNT
        );
        pir.setStrictMode(false);

        bytes32 retrievedValue = hintCommitment ^ responseHintXor;

        PlinkoPIR.PIRProof memory proof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: TEST_MERKLE_ROOT,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        (bool success, bytes32 value) = pir.verifyPIRProof(
            proof,
            TEST_DATABASE_ID
        );

        assertTrue(success);
        assertEq(value, retrievedValue);
    }

    function testFuzz_crossChainPIR(
        uint64 sourceChain,
        uint64 targetChain,
        bytes32 nullifier
    ) public {
        vm.assume(sourceChain != targetChain);
        vm.assume(sourceChain > 0 && targetChain > 0);
        vm.assume(nullifier != bytes32(0));

        pir.setStrictMode(false);

        bytes32 sourceStateRoot = keccak256(
            abi.encodePacked("state", sourceChain)
        );
        pir.updateStateRoot(sourceChain, sourceStateRoot);

        bytes32 hintCommitment = keccak256("hint");
        bytes32 responseHintXor = keccak256("response");
        bytes32 retrievedValue = hintCommitment ^ responseHintXor;

        PlinkoPIR.PIRProof memory pirProof = PlinkoPIR.PIRProof({
            queryCommitment: keccak256("query"),
            responseHintXor: responseHintXor,
            responseJunkXor: bytes32(0),
            hintCommitment: hintCommitment,
            retrievedValue: retrievedValue,
            merkleRoot: sourceStateRoot,
            merklePath: new bytes32[](0),
            merklePathIndices: new uint8[](0)
        });

        PlinkoPIR.CrossChainPIRProof memory proof = PlinkoPIR
            .CrossChainPIRProof({
                sourceChain: sourceChain,
                targetChain: targetChain,
                pirProof: pirProof,
                nullifier: nullifier,
                sourceStateRoot: sourceStateRoot
            });

        bool success = pir.verifyCrossChainPIR(proof);
        assertTrue(success);
        assertTrue(pir.isNullifierUsed(nullifier));
    }
}
