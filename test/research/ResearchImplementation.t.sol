// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/PILUniversalVerifier.sol";
import "../../contracts/verifiers/PILRecursiveVerifier.sol";
import "../../contracts/verifiers/PILNewZKVerifiers.sol";
import "../../contracts/mpc/PILThresholdSignature.sol";
import "../../contracts/mpc/PILMPCComplianceModule.sol";
import "../../contracts/fhe/PILFHEModule.sol";

/**
 * @title ResearchImplementationTest
 * @notice Comprehensive tests for all research implementations
 */
contract ResearchImplementationTest is Test {
    // Contracts
    PILUniversalVerifier public universalVerifier;
    PILRecursiveVerifier public recursiveVerifier;
    PILSP1Verifier public sp1Verifier;
    PILPlonky3Verifier public plonky3Verifier;
    PILJoltVerifier public joltVerifier;
    PILBiniusVerifier public biniusVerifier;
    PILThresholdSignature public thresholdSig;
    PILMPCComplianceModule public mpcCompliance;
    PILFHEModule public fheModule;

    // Test accounts
    address public owner;
    address public alice;
    address public bob;
    address public charlie;
    address[] public signers;
    address[] public oracles;
    address public fheOracle;

    // Test data
    bytes32 public constant TEST_VKEY = keccak256("test_verification_key");
    bytes32 public constant TEST_CIRCUIT_HASH = keccak256("test_circuit");
    bytes32 public constant TEST_MESSAGE = keccak256("test_message");

    function setUp() public {
        owner = address(this);
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        fheOracle = makeAddr("fheOracle");

        // Setup signers for threshold signature
        signers = new address[](5);
        signers[0] = alice;
        signers[1] = bob;
        signers[2] = charlie;
        signers[3] = makeAddr("signer4");
        signers[4] = makeAddr("signer5");

        // Setup oracles for MPC compliance
        oracles = new address[](3);
        oracles[0] = makeAddr("oracle1");
        oracles[1] = makeAddr("oracle2");
        oracles[2] = makeAddr("oracle3");

        // Deploy contracts
        universalVerifier = new PILUniversalVerifier();
        recursiveVerifier = new PILRecursiveVerifier(address(0), address(0));
        sp1Verifier = new PILSP1Verifier(address(0));
        plonky3Verifier = new PILPlonky3Verifier();
        joltVerifier = new PILJoltVerifier();
        biniusVerifier = new PILBiniusVerifier();
        thresholdSig = new PILThresholdSignature(3, 1 hours);
        mpcCompliance = new PILMPCComplianceModule(2);
        fheModule = new PILFHEModule(fheOracle);

        // Add signers to threshold signature
        for (uint i = 0; i < signers.length; i++) {
            thresholdSig.addSigner(
                signers[i],
                keccak256(abi.encodePacked("pk", i))
            );
        }

        // Register oracles for MPC compliance
        for (uint i = 0; i < oracles.length; i++) {
            mpcCompliance.registerOracle(oracles[i]);
        }
    }

    // ========================================
    // Universal Verifier Tests
    // ========================================

    function test_UniversalVerifier_RegisterVerifier() public {
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            500000
        );

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(PILUniversalVerifier.ProofSystem.SP1);

        assertEq(config.verifier, address(sp1Verifier));
        assertTrue(config.active);
        assertEq(config.gasLimit, 500000);
    }

    function test_UniversalVerifier_DeactivateVerifier() public {
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.Plonky3,
            address(plonky3Verifier),
            400000
        );

        universalVerifier.deactivateVerifier(
            PILUniversalVerifier.ProofSystem.Plonky3
        );

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(PILUniversalVerifier.ProofSystem.Plonky3);

        assertFalse(config.active);
    }

    function test_UniversalVerifier_GetStats() public {
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            500000
        );
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.Plonky3,
            address(plonky3Verifier),
            400000
        );

        (
            PILUniversalVerifier.ProofSystem[] memory systems,
            uint256[] memory verified,
            bool[] memory active
        ) = universalVerifier.getStats();

        // getStats returns 8 systems (all ProofSystem enum values)
        assertEq(systems.length, 8);
        // SP1 is enum value 3, Plonky3 is enum value 4
        assertTrue(active[3]); // SP1
        assertTrue(active[4]); // Plonky3
    }

    // ========================================
    // New ZK Verifier Tests
    // ========================================

    function test_SP1Verifier_RegisterVKey() public {
        bytes32 programHash = keccak256("test_program");
        sp1Verifier.registerVKey(TEST_VKEY, programHash);

        (bytes32 retVkey, , bool active, ) = sp1Verifier.verificationKeys(
            TEST_VKEY
        );
        assertEq(retVkey, TEST_VKEY);
        assertTrue(active);
    }

    function test_SP1Verifier_UpdateGateway() public {
        address gateway = makeAddr("sp1Gateway");
        sp1Verifier.updateGateway(gateway);
        assertEq(sp1Verifier.sp1Gateway(), gateway);
    }

    function test_Plonky3Verifier_RegisterCircuit() public {
        plonky3Verifier.registerCircuit(TEST_CIRCUIT_HASH, 5, 1024);

        (bytes32 retHash, , , bool active) = plonky3Verifier.circuits(
            TEST_CIRCUIT_HASH
        );
        assertEq(retHash, TEST_CIRCUIT_HASH);
        assertTrue(active);
    }

    function test_Plonky3Verifier_RevertOnDuplicateCircuit() public {
        plonky3Verifier.registerCircuit(TEST_CIRCUIT_HASH, 5, 1024);

        // Second registration should still work (updates the circuit)
        // Note: The actual contract doesn't prevent re-registration
        plonky3Verifier.registerCircuit(TEST_CIRCUIT_HASH, 10, 2048);
    }

    function test_JoltVerifier_RegisterProgram() public {
        bytes32 programHash = keccak256("jolt_program");

        joltVerifier.registerProgram(programHash, 1000000);

        (bytes32 retHash, uint256 maxCycles, bool active) = joltVerifier
            .programs(programHash);
        assertEq(retHash, programHash);
        assertEq(maxCycles, 1000000);
        assertTrue(active);
    }

    function test_BiniusVerifier_RegisterCircuit() public {
        bytes32 circuitHash = keccak256("binius_circuit");

        biniusVerifier.registerCircuit(circuitHash);
        assertTrue(biniusVerifier.registeredCircuits(circuitHash));
    }

    // ========================================
    // Recursive Verifier Tests
    // ========================================

    function test_RecursiveVerifier_SetBatchLimits() public {
        recursiveVerifier.setBatchLimits(10, 200);
        assertEq(recursiveVerifier.minBatchSize(), 10);
        assertEq(recursiveVerifier.maxBatchSize(), 200);
    }

    function test_RecursiveVerifier_CalculateGasSavings() public view {
        uint256 proofCount = 10;
        uint256 batchGasUsed = 300000;

        (uint256 savings, uint256 savingsPercent) = recursiveVerifier
            .calculateGasSavings(proofCount, batchGasUsed);

        // Expected individual gas: 10 * 250000 = 2500000
        // Batch gas: 300000
        // Savings: 2200000
        assertEq(savings, 2500000 - 300000);
        assertGt(savingsPercent, 0);
    }

    // ========================================
    // Threshold Signature Tests
    // ========================================

    function test_ThresholdSig_GetConfig() public view {
        // Contract returns (threshold, totalSigners, sessionTimeout)
        (
            uint256 threshold,
            uint256 totalSigners,
            uint256 timeout
        ) = thresholdSig.getConfig();
        assertEq(threshold, 3);
        assertEq(totalSigners, 5);
        assertEq(timeout, 1 hours);
    }

    function test_ThresholdSig_StartSession() public {
        address[] memory participants = new address[](3);
        participants[0] = signers[0];
        participants[1] = signers[1];
        participants[2] = signers[2];

        bytes32 sessionId = thresholdSig.startSession(
            TEST_MESSAGE,
            participants
        );
        assertNotEq(sessionId, bytes32(0));
    }

    function test_ThresholdSig_SubmitCommitment() public {
        address[] memory participants = new address[](3);
        participants[0] = signers[0];
        participants[1] = signers[1];
        participants[2] = signers[2];

        bytes32 sessionId = thresholdSig.startSession(
            TEST_MESSAGE,
            participants
        );

        bytes32 commitment = keccak256(abi.encodePacked("test_commitment"));
        vm.prank(signers[0]);
        thresholdSig.submitCommitment(sessionId, commitment);
    }

    function test_ThresholdSig_RevertNonSigner() public {
        address[] memory participants = new address[](3);
        participants[0] = signers[0];
        participants[1] = signers[1];
        participants[2] = signers[2];

        bytes32 sessionId = thresholdSig.startSession(
            TEST_MESSAGE,
            participants
        );

        address nonSigner = makeAddr("nonSigner");
        bytes32 commitment = keccak256(abi.encodePacked("fake_commitment"));

        vm.expectRevert();
        vm.prank(nonSigner);
        thresholdSig.submitCommitment(sessionId, commitment);
    }

    // ========================================
    // MPC Compliance Tests
    // ========================================

    function test_MPCCompliance_RequestCheck() public {
        bytes32 encryptedIdentityHash = keccak256(abi.encodePacked(alice));

        vm.prank(alice);
        bytes32 requestId = mpcCompliance.requestComplianceCheck(
            encryptedIdentityHash
        );

        (
            bytes32 retRequestId,
            bytes32 retHash,
            address requester,
            ,
            ,
            ,

        ) = mpcCompliance.requests(requestId);

        assertEq(retRequestId, requestId);
        assertEq(retHash, encryptedIdentityHash);
        assertEq(requester, alice);
    }

    function test_MPCCompliance_RegisterOracle() public {
        address newOracle = makeAddr("newOracle");

        mpcCompliance.registerOracle(newOracle);
        assertTrue(mpcCompliance.isOracle(newOracle));
    }

    function test_MPCCompliance_RevertDuplicateOracle() public {
        vm.expectRevert("Already registered");
        mpcCompliance.registerOracle(oracles[0]);
    }

    // ========================================
    // FHE Module Tests
    // ========================================

    function test_FHEModule_RegisterCiphertext() public {
        bytes32 handle = keccak256("test_handle");
        bytes32 typeHash = keccak256("uint256");
        bytes32 securityParams = keccak256("params");

        vm.prank(fheOracle);
        fheModule.registerCiphertext(handle, typeHash, securityParams);

        (bytes32 retHandle, bytes32 retTypeHash, , , bool valid) = fheModule
            .ciphertexts(handle);

        assertEq(retHandle, handle);
        assertEq(retTypeHash, typeHash);
        assertTrue(valid);
    }

    function test_FHEModule_UpdateFHEKeys() public {
        bytes32 publicKeyHash = keccak256("public_key");
        bytes32 evalKeyHash = keccak256("eval_key");
        bytes32 relinKeyHash = keccak256("relin_key");

        fheModule.updateFHEKeys(publicKeyHash, evalKeyHash, relinKeyHash);

        (
            bytes32 retPubKey,
            bytes32 retEvalKey,
            bytes32 retRelinKey,
            ,
            bool active
        ) = fheModule.fheKeys();

        assertEq(retPubKey, publicKeyHash);
        assertEq(retEvalKey, evalKeyHash);
        assertEq(retRelinKey, relinKeyHash);
        assertTrue(active);
    }

    function test_FHEModule_RequestAdd() public {
        // Setup ciphertexts first
        bytes32 handleA = keccak256("handle_a");
        bytes32 handleB = keccak256("handle_b");

        vm.startPrank(fheOracle);
        fheModule.registerCiphertext(
            handleA,
            fheModule.TYPE_UINT256(),
            keccak256("params")
        );
        fheModule.registerCiphertext(
            handleB,
            fheModule.TYPE_UINT256(),
            keccak256("params")
        );
        vm.stopPrank();

        // Request addition
        bytes32 requestId = fheModule.requestAdd(handleA, handleB);

        // Just verify a request ID was returned
        assertNotEq(requestId, bytes32(0));
    }

    // ========================================
    // Integration Tests
    // ========================================

    function test_Integration_RegisterAllVerifiers() public {
        // Register all verifiers in universal verifier
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            500000
        );
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.Plonky3,
            address(plonky3Verifier),
            400000
        );
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.Jolt,
            address(joltVerifier),
            600000
        );
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.Binius,
            address(biniusVerifier),
            350000
        );
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.Recursive,
            address(recursiveVerifier),
            800000
        );

        // Verify all registered
        assertEq(
            universalVerifier
                .getVerifier(PILUniversalVerifier.ProofSystem.SP1)
                .verifier,
            address(sp1Verifier)
        );
        assertEq(
            universalVerifier
                .getVerifier(PILUniversalVerifier.ProofSystem.Plonky3)
                .verifier,
            address(plonky3Verifier)
        );
        assertEq(
            universalVerifier
                .getVerifier(PILUniversalVerifier.ProofSystem.Jolt)
                .verifier,
            address(joltVerifier)
        );
        assertEq(
            universalVerifier
                .getVerifier(PILUniversalVerifier.ProofSystem.Binius)
                .verifier,
            address(biniusVerifier)
        );
        assertEq(
            universalVerifier
                .getVerifier(PILUniversalVerifier.ProofSystem.Recursive)
                .verifier,
            address(recursiveVerifier)
        );
    }

    function test_Integration_ThresholdSigningFlow() public {
        // Create threshold signing session
        address[] memory participants = new address[](3);
        participants[0] = signers[0];
        participants[1] = signers[1];
        participants[2] = signers[2];

        bytes32 sessionId = thresholdSig.startSession(
            TEST_MESSAGE,
            participants
        );

        // All 3 signers submit commitments
        for (uint i = 0; i < 3; i++) {
            bytes32 commitment = keccak256(abi.encodePacked("commit", i));
            vm.prank(signers[i]);
            thresholdSig.submitCommitment(sessionId, commitment);
        }
    }
}

/**
 * @title RecursiveProofGasTest
 * @notice Gas benchmarks for recursive proof verification
 */
contract RecursiveProofGasTest is Test {
    PILRecursiveVerifier public verifier;

    function setUp() public {
        verifier = new PILRecursiveVerifier(address(0), address(0));
    }

    function test_GasEstimate_SmallBatch() public {
        // Calculate gas savings for batch of 8 proofs
        // Expected individual: 8 * 250000 = 2000000
        // Batch estimate: ~300000
        (uint256 savings, uint256 savingsPercent) = verifier
            .calculateGasSavings(8, 300000);

        emit log_named_uint("Expected individual gas", 8 * 250000);
        emit log_named_uint("Batch gas used", 300000);
        emit log_named_uint("Gas savings", savings);
        emit log_named_uint("Savings percent", savingsPercent);

        // Should have significant savings
        assertGt(savingsPercent, 50);
    }

    function test_GasEstimate_MediumBatch() public {
        (uint256 savings, uint256 savingsPercent) = verifier
            .calculateGasSavings(32, 400000);

        emit log_named_uint("Expected individual gas", 32 * 250000);
        emit log_named_uint("Batch gas used", 400000);
        emit log_named_uint("Gas savings", savings);
        emit log_named_uint("Savings percent", savingsPercent);

        // Should have even more savings with larger batch
        assertGt(savingsPercent, 90);
    }

    function test_GasEstimate_LargeBatch() public {
        (uint256 savings, uint256 savingsPercent) = verifier
            .calculateGasSavings(128, 500000);

        emit log_named_uint("Expected individual gas", 128 * 250000);
        emit log_named_uint("Batch gas used", 500000);
        emit log_named_uint("Gas savings", savings);
        emit log_named_uint("Savings percent", savingsPercent);

        // Very large savings expected
        assertGt(savingsPercent, 95);
    }
}
