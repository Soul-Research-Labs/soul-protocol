// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/privacy/RecursiveProofAggregator.sol";

contract RecursiveProofAggregatorTest is Test {
    RecursiveProofAggregator public aggregator;
    RecursiveProofAggregator public impl;

    address public admin = makeAddr("admin");
    address public aggRole = makeAddr("aggregator");
    address public verifierRole = makeAddr("verifier");
    address public emergencyRole = makeAddr("emergency");

    function setUp() public {
        impl = new RecursiveProofAggregator();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(RecursiveProofAggregator.initialize.selector, admin)
        );
        aggregator = RecursiveProofAggregator(address(proxy));

        vm.startPrank(admin);
        aggregator.grantRole(aggregator.AGGREGATOR_ROLE(), aggRole);
        aggregator.grantRole(aggregator.VERIFIER_ROLE(), verifierRole);
        aggregator.grantRole(aggregator.EMERGENCY_ROLE(), emergencyRole);
        vm.stopPrank();
    }

    // ─── Initialization ─────────────────────────────────────

    function test_initialize() public view {
        assertTrue(aggregator.hasRole(aggregator.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.AGGREGATOR_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.VERIFIER_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.EMERGENCY_ROLE(), admin));
    }

    function test_initialize_revert_doubleInit() public {
        vm.expectRevert();
        aggregator.initialize(admin);
    }

    // ─── Proof Submission ───────────────────────────────────

    function test_submitProof_groth16() public {
        bytes32 proofId = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("commitment"),
            keccak256("publicInput"),
            1
        );
        assertTrue(proofId != bytes32(0));
        assertEq(aggregator.totalProofsSubmitted(), 1);

        RecursiveProofAggregator.ProofSubmission memory p = aggregator.getProofSubmission(proofId);
        assertEq(p.commitmentHash, keccak256("commitment"));
        assertEq(p.publicInputHash, keccak256("publicInput"));
        assertEq(p.chainId, 1);
        assertTrue(p.system == RecursiveProofAggregator.ProofSystem.GROTH16);
    }

    function test_submitProof_plonk() public {
        bytes32 proofId = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.PLONK,
            keccak256("c2"),
            keccak256("pi2"),
            42161
        );
        RecursiveProofAggregator.ProofSubmission memory p = aggregator.getProofSubmission(proofId);
        assertTrue(p.system == RecursiveProofAggregator.ProofSystem.PLONK);
    }

    function test_submitProof_multipleToBatch() public {
        // Submit enough proofs to test batch
        bytes32 proofId1 = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c1"), keccak256("p1"), 1
        );
        bytes32 proofId2 = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c2"), keccak256("p2"), 1
        );

        RecursiveProofAggregator.ProofSubmission memory p1 = aggregator.getProofSubmission(proofId1);
        RecursiveProofAggregator.ProofSubmission memory p2 = aggregator.getProofSubmission(proofId2);

        // Both should be in the same batch (same proof system)
        assertEq(p1.batchId, p2.batchId);
    }

    function test_submitProof_differentSystemsDifferentBatches() public {
        bytes32 pid1 = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c1"), keccak256("p1"), 1
        );
        bytes32 pid2 = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.PLONK,
            keccak256("c2"), keccak256("p2"), 1
        );

        RecursiveProofAggregator.ProofSubmission memory p1 = aggregator.getProofSubmission(pid1);
        RecursiveProofAggregator.ProofSubmission memory p2 = aggregator.getProofSubmission(pid2);
        assertTrue(p1.batchId != p2.batchId);
    }

    // ─── Batch Operations ───────────────────────────────────

    function test_triggerAggregation() public {
        // Submit MIN_BATCH_SIZE proofs (use non-zero commitment hashes)
        for (uint256 i = 0; i < 2; i++) {
            aggregator.submitProof(
                RecursiveProofAggregator.ProofSystem.GROTH16,
                keccak256(abi.encodePacked("commit", i)),
                keccak256(abi.encodePacked("input", i)),
                1
            );
        }

        bytes32 batchId = aggregator.activeBatches(RecursiveProofAggregator.ProofSystem.GROTH16);

        vm.prank(aggRole);
        aggregator.triggerAggregation(batchId);

        RecursiveProofAggregator.AggregationBatch memory batch = aggregator.getBatch(batchId);
        assertTrue(batch.state == RecursiveProofAggregator.BatchState.AGGREGATING);
    }

    function test_triggerAggregation_revert_batchTooSmall() public {
        // Only submit 1 proof (need MIN_BATCH_SIZE = 2)
        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c"), keccak256("p"), 1
        );

        bytes32 batchId = aggregator.activeBatches(RecursiveProofAggregator.ProofSystem.GROTH16);

        vm.prank(aggRole);
        vm.expectRevert(
            abi.encodeWithSelector(RecursiveProofAggregator.BatchTooSmall.selector, 1, 2)
        );
        aggregator.triggerAggregation(batchId);
    }

    function test_triggerAggregation_revert_notAggregator() public {
        for (uint256 i = 0; i < 2; i++) {
            aggregator.submitProof(
                RecursiveProofAggregator.ProofSystem.GROTH16,
                keccak256(abi.encodePacked("c", i)),
                keccak256(abi.encodePacked("p", i)),
                1
            );
        }
        bytes32 batchId = aggregator.activeBatches(RecursiveProofAggregator.ProofSystem.GROTH16);

        vm.prank(makeAddr("random"));
        vm.expectRevert();
        aggregator.triggerAggregation(batchId);
    }

    function test_finalizeBatchAggregation() public {
        // Submit 2 proofs and trigger aggregation
        for (uint256 i = 0; i < 2; i++) {
            aggregator.submitProof(
                RecursiveProofAggregator.ProofSystem.GROTH16,
                keccak256(abi.encodePacked("commit", i)),
                keccak256(abi.encodePacked("input", i)),
                1
            );
        }
        bytes32 batchId = aggregator.activeBatches(RecursiveProofAggregator.ProofSystem.GROTH16);

        vm.prank(aggRole);
        aggregator.triggerAggregation(batchId);

        bytes32 aggProofHash = keccak256("aggregated_proof");
        bytes32 merkleRoot = keccak256("merkle_root");

        vm.prank(aggRole);
        aggregator.finalizeBatchAggregation(batchId, aggProofHash, merkleRoot);

        RecursiveProofAggregator.AggregationBatch memory batch = aggregator.getBatch(batchId);
        assertEq(batch.aggregatedProofHash, aggProofHash);
        assertEq(batch.merkleRoot, merkleRoot);
    }

    // ─── Nova Folding ───────────────────────────────────────

    function test_submitNovaFolding() public {
        // Submit a NOVA proof
        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.NOVA,
            keccak256("c1"), keccak256("p1"), 1
        );
        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.NOVA,
            keccak256("c2"), keccak256("p2"), 1
        );

        bytes32 batchId = aggregator.activeBatches(RecursiveProofAggregator.ProofSystem.NOVA);

        RecursiveProofAggregator.NovaProof memory novaProof;
        novaProof.U = keccak256("U");
        novaProof.W = keccak256("W");
        novaProof.u = keccak256("u");
        novaProof.w = keccak256("w");
        novaProof.T = keccak256("T");
        novaProof.step = 1;
        novaProof.foldingProof = "folding_data";

        vm.prank(aggRole);
        aggregator.submitNovaFolding(batchId, novaProof);

        RecursiveProofAggregator.NovaProof memory stored = aggregator.getNovaState(batchId);
        assertEq(stored.step, 1);
        assertEq(stored.U, keccak256("U"));
    }

    function test_submitNovaFolding_revert_notAggregator() public {
        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.NOVA,
            keccak256("c"), keccak256("p"), 1
        );
        bytes32 batchId = aggregator.activeBatches(RecursiveProofAggregator.ProofSystem.NOVA);

        RecursiveProofAggregator.NovaProof memory novaProof;
        novaProof.U = keccak256("U");
        novaProof.W = keccak256("W");
        novaProof.u = keccak256("u");
        novaProof.w = keccak256("w");
        novaProof.T = keccak256("T");
        novaProof.step = 1;

        vm.prank(makeAddr("random"));
        vm.expectRevert();
        aggregator.submitNovaFolding(batchId, novaProof);
    }

    // ─── Cross-Chain Bundle ─────────────────────────────────

    function test_createCrossChainBundle() public {
        uint256[] memory chainIds = new uint256[](3);
        chainIds[0] = 1;
        chainIds[1] = 42161;
        chainIds[2] = 10;

        bytes32[] memory proofRoots = new bytes32[](3);
        proofRoots[0] = keccak256("root1");
        proofRoots[1] = keccak256("root2");
        proofRoots[2] = keccak256("root3");

        vm.prank(aggRole);
        bytes32 bundleId = aggregator.createCrossChainBundle(chainIds, proofRoots);
        assertTrue(bundleId != bytes32(0));

        RecursiveProofAggregator.CrossChainProofBundle memory bundle =
            aggregator.getCrossChainBundle(bundleId);
        assertEq(bundle.chainIds.length, 3);
        assertEq(bundle.proofRoots.length, 3);
        assertFalse(bundle.verified);
    }

    function test_finalizeCrossChainBundle() public {
        uint256[] memory chainIds = new uint256[](2);
        chainIds[0] = 1;
        chainIds[1] = 10;

        bytes32[] memory proofRoots = new bytes32[](2);
        proofRoots[0] = keccak256("root1");
        proofRoots[1] = keccak256("root2");

        vm.prank(aggRole);
        bytes32 bundleId = aggregator.createCrossChainBundle(chainIds, proofRoots);

        bytes32 aggRoot = keccak256("aggRoot");
        bytes memory aggProof = "aggregated_proof_bytes";

        vm.prank(aggRole);
        aggregator.finalizeCrossChainBundle(bundleId, aggRoot, aggProof);

        RecursiveProofAggregator.CrossChainProofBundle memory bundle =
            aggregator.getCrossChainBundle(bundleId);
        assertTrue(bundle.verified);
        assertEq(bundle.aggregatedRoot, aggRoot);
    }

    // ─── Verifier Management ────────────────────────────────

    function test_setVerifier() public {
        address verifier = makeAddr("groth16_verifier");
        vm.prank(admin);
        aggregator.setVerifier(RecursiveProofAggregator.ProofSystem.GROTH16, verifier);

        assertEq(aggregator.verifiers(RecursiveProofAggregator.ProofSystem.GROTH16), verifier);
    }

    function test_setVerifier_revert_notAdmin() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        aggregator.setVerifier(RecursiveProofAggregator.ProofSystem.GROTH16, makeAddr("v"));
    }

    // ─── Pause / Unpause ────────────────────────────────────

    function test_pause() public {
        vm.prank(emergencyRole);
        aggregator.pause();

        vm.expectRevert();
        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c"), keccak256("p"), 1
        );
    }

    function test_unpause() public {
        vm.prank(emergencyRole);
        aggregator.pause();

        vm.prank(admin);
        aggregator.unpause();

        // Should work now
        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c"), keccak256("p"), 1
        );
    }

    function test_pause_revert_notEmergency() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        aggregator.pause();
    }

    // ─── View Functions ─────────────────────────────────────

    function test_getBatch_nonexistent() public {
        RecursiveProofAggregator.AggregationBatch memory batch =
            aggregator.getBatch(keccak256("nonexistent"));
        assertEq(batch.proofCount, 0);
    }

    function test_isRootVerified() public {
        assertFalse(aggregator.isRootVerified(keccak256("some_root")));
    }

    function test_totalCounters() public {
        assertEq(aggregator.totalProofsSubmitted(), 0);
        assertEq(aggregator.totalProofsAggregated(), 0);
        assertEq(aggregator.totalBatches(), 0);

        aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256("c"), keccak256("p"), 1
        );
        assertEq(aggregator.totalProofsSubmitted(), 1);
        assertGe(aggregator.totalBatches(), 1);
    }

    // ─── Fuzz ───────────────────────────────────────────────

    function testFuzz_submitProof_systemTypes(uint8 systemRaw) public {
        // Only valid systems
        vm.assume(systemRaw <= uint8(RecursiveProofAggregator.ProofSystem.HALO2));
        RecursiveProofAggregator.ProofSystem system =
            RecursiveProofAggregator.ProofSystem(systemRaw);

        bytes32 proofId = aggregator.submitProof(
            system, keccak256(abi.encodePacked(systemRaw)), keccak256("p"), 1
        );
        RecursiveProofAggregator.ProofSubmission memory p = aggregator.getProofSubmission(proofId);
        assertTrue(p.system == system);
    }

    function testFuzz_submitProof_chainId(uint256 chainId) public {
        chainId = bound(chainId, 1, type(uint64).max);
        bytes32 proofId = aggregator.submitProof(
            RecursiveProofAggregator.ProofSystem.GROTH16,
            keccak256(abi.encodePacked(chainId)),
            keccak256("p"),
            chainId
        );
        RecursiveProofAggregator.ProofSubmission memory p = aggregator.getProofSubmission(proofId);
        assertEq(p.chainId, chainId);
    }
}
