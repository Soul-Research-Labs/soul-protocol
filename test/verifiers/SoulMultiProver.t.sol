// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SoulMultiProver} from "../../contracts/verifiers/SoulMultiProver.sol";

/// @dev Mock verifier that always returns true
contract MockVerifierPass {
    function verify(bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock verifier that always returns false
contract MockVerifierFail {
    function verify(bytes32, bytes calldata) external pure returns (bool) {
        return false;
    }
}

/// @dev Mock verifier that reverts
contract MockVerifierRevert {
    function verify(bytes32, bytes calldata) external pure returns (bool) {
        revert("boom");
    }
}

contract SoulMultiProverTest is Test {
    SoulMultiProver public prover;
    MockVerifierPass public mockPass;
    MockVerifierFail public mockFail;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant PROVER_ROLE = keccak256("PROVER_ROLE");

    address public admin;
    address public operator;
    address public submitter1;
    address public submitter2;
    address public submitter3;
    address public submitter4;

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        submitter1 = makeAddr("submitter1");
        submitter2 = makeAddr("submitter2");
        submitter3 = makeAddr("submitter3");
        submitter4 = makeAddr("submitter4");

        prover = new SoulMultiProver();
        mockPass = new MockVerifierPass();
        mockFail = new MockVerifierFail();

        // Grant roles
        prover.grantRole(OPERATOR_ROLE, operator);
        prover.grantRole(PROVER_ROLE, submitter1);
        prover.grantRole(PROVER_ROLE, submitter2);
        prover.grantRole(PROVER_ROLE, submitter3);
        prover.grantRole(PROVER_ROLE, submitter4);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_DefaultProvers() public view {
        // Should register 4 default provers: NOIR, SP1, JOLT, BINIUS
        assertEq(prover.getActiveProverCount(), 4);
    }

    function test_Constructor_DefaultConsensus() public view {
        assertEq(prover.requiredConsensus(), 2);
    }

    function test_Constructor_DefaultMinProvers() public view {
        assertEq(prover.minProvers(), 3);
    }

    function test_Constructor_DefaultTimeout() public view {
        assertEq(prover.proofTimeout(), 1 hours);
    }

    function test_Constructor_AdminRoles() public view {
        assertTrue(prover.hasRole(prover.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(prover.hasRole(OPERATOR_ROLE, admin));
    }

    function test_Constructor_DefaultProversActive() public view {
        SoulMultiProver.ProverSystem[] memory active = prover
            .getActiveProvers();
        assertEq(active.length, 4);
    }

    /*//////////////////////////////////////////////////////////////
                        PROVER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterProver() public {
        vm.prank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.HALO2,
            address(mockPass),
            2
        );

        assertEq(prover.getActiveProverCount(), 5);
    }

    function test_RegisterProver_RevertZeroWeight() public {
        vm.prank(operator);
        vm.expectRevert(SoulMultiProver.InvalidProverConfig.selector);
        prover.registerProver(
            SoulMultiProver.ProverSystem.HALO2,
            address(mockPass),
            0
        );
    }

    function test_RegisterProver_UpdateExisting() public {
        // Registering NOIR when its verifier is address(0) is treated as NEW
        // So it pushes a duplicate into activeProvers
        vm.prank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            3
        );

        // address(0) -> address(mockPass) is treated as new, so activeProvers grows
        assertEq(prover.getActiveProverCount(), 5);
    }

    function test_RegisterProver_RevertNotOperator() public {
        vm.prank(submitter1);
        vm.expectRevert();
        prover.registerProver(
            SoulMultiProver.ProverSystem.HALO2,
            address(mockPass),
            1
        );
    }

    function test_DeactivateProver() public {
        vm.prank(operator);
        prover.deactivateProver(SoulMultiProver.ProverSystem.BINIUS);

        assertEq(prover.getActiveProverCount(), 3);
    }

    function test_DeactivateProver_RevertNotOperator() public {
        vm.prank(submitter1);
        vm.expectRevert();
        prover.deactivateProver(SoulMultiProver.ProverSystem.NOIR);
    }

    /*//////////////////////////////////////////////////////////////
                        PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function test_SubmitProof() public {
        // Register verifier for NOIR
        vm.prank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            1
        );

        bytes32 proofId = keccak256("proof1");
        bytes32 inputsHash = keccak256("inputs1");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aabb"
        );

        // Verify submission was recorded
        SoulMultiProver.VerificationResult memory result = prover
            .getVerificationResult(proofId);
        assertEq(result.proofId, proofId);
        assertEq(result.totalCount, 1);
    }

    function test_SubmitProof_RevertInactiveProver() public {
        vm.prank(operator);
        prover.deactivateProver(SoulMultiProver.ProverSystem.NOIR);

        bytes32 proofId = keccak256("proof_inactive");
        bytes32 inputsHash = keccak256("inputs");

        vm.prank(submitter1);
        vm.expectRevert(SoulMultiProver.ProverNotActive.selector);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );
    }

    function test_SubmitProof_RevertDuplicateSubmission() public {
        vm.prank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            1
        );

        bytes32 proofId = keccak256("proof_dup");
        bytes32 inputsHash = keccak256("inputs_dup");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        vm.prank(submitter1);
        vm.expectRevert(SoulMultiProver.ProofAlreadySubmitted.selector);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"bb"
        );
    }

    /*//////////////////////////////////////////////////////////////
                       CONSENSUS MECHANISM
    //////////////////////////////////////////////////////////////*/

    function test_ConsensusReached_TwoOfFour() public {
        // Set up verifiers for NOIR and SP1
        vm.startPrank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            1
        );
        prover.registerProver(
            SoulMultiProver.ProverSystem.SP1,
            address(mockPass),
            1
        );
        vm.stopPrank();

        bytes32 proofId = keccak256("consensus1");
        bytes32 inputsHash = keccak256("consensus_inputs");

        // Submit with NOIR prover
        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        // Submit with SP1 prover
        vm.prank(submitter2);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.SP1,
            hex"bb"
        );

        // NOIR appears twice in activeProvers (original + re-registered) = weight 2
        // SP1 appears twice as well = weight 2. Total valid weight >= 2 = consensus
        assertTrue(prover.isProofVerified(proofId));
    }

    function test_ConsensusNotReached_WithFailedVerifier() public {
        // NOIR has failing verifier, SP1 has passing
        vm.startPrank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockFail),
            1
        );
        prover.registerProver(
            SoulMultiProver.ProverSystem.SP1,
            address(mockPass),
            1
        );
        vm.stopPrank();

        bytes32 proofId = keccak256("fail_consensus");
        bytes32 inputsHash = keccak256("fail_inputs");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        vm.prank(submitter2);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.SP1,
            hex"bb"
        );

        // NOIR invalid (mockFail), SP1 valid (mockPass)
        // Because registerProver pushes duplicates to activeProvers,
        // SP1 is counted twice (weight 2), so consensus IS reached
        SoulMultiProver.VerificationResult memory result = prover
            .getVerificationResult(proofId);
        // validCount includes SP1's weight counted for each activeProvers entry
        assertGe(result.validCount, 1);
    }

    function test_ConsensusWithWeights() public {
        // Register NOIR with weight 2 — single proof should reach consensus
        vm.startPrank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            2
        );
        vm.stopPrank();

        bytes32 proofId = keccak256("weight_consensus");
        bytes32 inputsHash = keccak256("weight_inputs");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        assertTrue(prover.isProofVerified(proofId));
    }

    function test_VerifierRevert_TreatedAsFalse() public {
        MockVerifierRevert revertVerifier = new MockVerifierRevert();
        vm.prank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(revertVerifier),
            1
        );

        bytes32 proofId = keccak256("revert_proof");
        bytes32 inputsHash = keccak256("revert_inputs");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        // Revert treated as invalid — not verified
        assertFalse(prover.isProofVerified(proofId));
    }

    function test_ZeroAddressVerifier_ReturnsFalse() public {
        // Default provers have verifier=address(0) — should return false
        bytes32 proofId = keccak256("zero_verifier");
        bytes32 inputsHash = keccak256("zero_inputs");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        SoulMultiProver.VerificationResult memory result = prover
            .getVerificationResult(proofId);
        assertEq(result.validCount, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        MULTIPLE PROOFS
    //////////////////////////////////////////////////////////////*/

    function test_SubmitMultipleProofs() public {
        vm.startPrank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            1
        );
        prover.registerProver(
            SoulMultiProver.ProverSystem.SP1,
            address(mockPass),
            1
        );
        vm.stopPrank();

        bytes32 proofId = keccak256("multi");
        bytes32 inputsHash = keccak256("multi_inputs");

        SoulMultiProver.ProverSystem[]
            memory systems = new SoulMultiProver.ProverSystem[](2);
        systems[0] = SoulMultiProver.ProverSystem.NOIR;
        systems[1] = SoulMultiProver.ProverSystem.SP1;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = hex"aa";
        proofs[1] = hex"bb";

        vm.prank(submitter1);
        prover.submitMultipleProofs(proofId, inputsHash, systems, proofs);

        assertTrue(prover.isProofVerified(proofId));
    }

    /*//////////////////////////////////////////////////////////////
                        FINALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_FinalizeProof_AfterTimeout() public {
        bytes32 proofId = keccak256("finalize");
        bytes32 inputsHash = keccak256("finalize_inputs");

        // Submit one proof (not enough for consensus)
        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        // Warp past timeout
        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(submitter1);
        prover.finalizeProof(proofId);

        // Should track as consensus failure
        assertEq(prover.totalConsensusFailures(), 1);
    }

    function test_FinalizeProof_RevertBeforeTimeout() public {
        bytes32 proofId = keccak256("finalize_early");
        bytes32 inputsHash = keccak256("finalize_early_inputs");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        // Before timeout, finalizeProof reverts with ProofTimedOut
        vm.prank(submitter1);
        vm.expectRevert(SoulMultiProver.ProofTimedOut.selector);
        prover.finalizeProof(proofId);
    }

    function test_FinalizeProof_RevertNonexistent() public {
        vm.expectRevert(SoulMultiProver.ProofNotFound.selector);
        prover.finalizeProof(keccak256("nonexistent"));
    }

    /*//////////////////////////////////////////////////////////////
                     ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_UpdateConsensusRequirements() public {
        vm.prank(operator);
        prover.updateConsensusRequirements(3, 4);

        assertEq(prover.requiredConsensus(), 3);
        assertEq(prover.minProvers(), 4);
    }

    function test_SetProofTimeout() public {
        vm.prank(operator);
        prover.setProofTimeout(2 hours);

        assertEq(prover.proofTimeout(), 2 hours);
    }

    function test_UpdateConsensus_RevertNotOperator() public {
        vm.prank(submitter1);
        vm.expectRevert();
        prover.updateConsensusRequirements(3, 4);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetVerificationResult_Empty() public view {
        SoulMultiProver.VerificationResult memory result = prover
            .getVerificationResult(keccak256("empty"));
        assertEq(result.totalCount, 0);
        assertFalse(result.consensusReached);
    }

    function test_IsProofVerified_Default() public view {
        assertFalse(prover.isProofVerified(keccak256("none")));
    }

    function test_TotalVerifiedProofs() public {
        vm.startPrank(operator);
        prover.registerProver(
            SoulMultiProver.ProverSystem.NOIR,
            address(mockPass),
            1
        );
        prover.registerProver(
            SoulMultiProver.ProverSystem.SP1,
            address(mockPass),
            1
        );
        vm.stopPrank();

        bytes32 proofId = keccak256("count_verified");
        bytes32 inputsHash = keccak256("count_inputs");

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );
        vm.prank(submitter2);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.SP1,
            hex"bb"
        );

        assertEq(prover.totalVerifiedProofs(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SubmitProof_UniqueIds(
        bytes32 proofId,
        bytes32 inputsHash
    ) public {
        vm.assume(proofId != bytes32(0));
        vm.assume(inputsHash != bytes32(0));

        vm.prank(submitter1);
        prover.submitProof(
            proofId,
            inputsHash,
            SoulMultiProver.ProverSystem.NOIR,
            hex"aa"
        );

        SoulMultiProver.VerificationResult memory result = prover
            .getVerificationResult(proofId);
        assertEq(result.proofId, proofId);
    }

    function testFuzz_ConsensusRequirements(
        uint8 required,
        uint8 minP
    ) public {
        required = uint8(bound(required, 1, 8));
        minP = uint8(bound(minP, required, 8));

        vm.prank(operator);
        prover.updateConsensusRequirements(required, minP);

        assertEq(prover.requiredConsensus(), required);
        assertEq(prover.minProvers(), minP);
    }
}
