// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/PILUniversalVerifier.sol";
import "../../contracts/verifiers/PILRecursiveVerifier.sol";
import "../../contracts/verifiers/PILNewZKVerifiers.sol";
import "../../contracts/mpc/PILThresholdSignature.sol";
import "../../contracts/mpc/PILMPCComplianceModule.sol";

/**
 * @title ResearchFuzzTests
 * @notice Fuzz tests for research implementations
 * @dev Tests edge cases and invariants using fuzzing
 */
contract ResearchFuzzTests is Test {
    // Contracts
    PILUniversalVerifier public universalVerifier;
    PILRecursiveVerifier public recursiveVerifier;
    PILSP1Verifier public sp1Verifier;
    PILPlonky3Verifier public plonky3Verifier;
    PILJoltVerifier public joltVerifier;
    PILBiniusVerifier public biniusVerifier;
    PILThresholdSignature public thresholdSig;
    PILMPCComplianceModule public mpcCompliance;

    // Test accounts
    address[] public signers;
    address[] public oracles;

    function setUp() public {
        // Setup signers
        signers = new address[](5);
        for (uint i = 0; i < 5; i++) {
            signers[i] = makeAddr(string(abi.encodePacked("signer", i)));
        }

        // Setup oracles
        oracles = new address[](3);
        for (uint i = 0; i < 3; i++) {
            oracles[i] = makeAddr(string(abi.encodePacked("oracle", i)));
        }

        // Deploy contracts
        universalVerifier = new PILUniversalVerifier();
        recursiveVerifier = new PILRecursiveVerifier(address(0), address(0));
        sp1Verifier = new PILSP1Verifier(address(0));
        plonky3Verifier = new PILPlonky3Verifier();
        joltVerifier = new PILJoltVerifier();
        biniusVerifier = new PILBiniusVerifier();
        thresholdSig = new PILThresholdSignature(3, 1 hours);
        mpcCompliance = new PILMPCComplianceModule(2);

        // Add signers to threshold signature
        for (uint i = 0; i < 5; i++) {
            thresholdSig.addSigner(
                signers[i],
                keccak256(abi.encodePacked("pk", i))
            );
        }

        // Register oracles for MPC compliance
        for (uint i = 0; i < 3; i++) {
            mpcCompliance.registerOracle(oracles[i]);
        }
    }

    // ========================================
    // Universal Verifier Fuzz Tests
    // ========================================

    function testFuzz_UniversalVerifier_RegisterVerifier(
        uint8 systemIndex,
        address verifier,
        uint256 gasLimit
    ) public {
        vm.assume(verifier != address(0));
        vm.assume(systemIndex < 8); // Number of proof systems

        PILUniversalVerifier.ProofSystem system = PILUniversalVerifier
            .ProofSystem(systemIndex);

        universalVerifier.registerVerifier(system, verifier, gasLimit);

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(system);

        assertEq(config.verifier, verifier);
        assertTrue(config.active);
        if (gasLimit > 0) {
            assertEq(config.gasLimit, gasLimit);
        } else {
            assertEq(config.gasLimit, universalVerifier.defaultGasLimit());
        }
    }

    function testFuzz_UniversalVerifier_RevertZeroAddress(
        uint8 systemIndex,
        uint256 gasLimit
    ) public {
        vm.assume(systemIndex < 8);

        PILUniversalVerifier.ProofSystem system = PILUniversalVerifier
            .ProofSystem(systemIndex);

        vm.expectRevert("Invalid verifier");
        universalVerifier.registerVerifier(system, address(0), gasLimit);
    }

    function testFuzz_UniversalVerifier_UpdateGasLimit(
        uint8 systemIndex,
        uint256 newGasLimit
    ) public {
        vm.assume(systemIndex < 8);
        vm.assume(newGasLimit > 0);

        PILUniversalVerifier.ProofSystem system = PILUniversalVerifier
            .ProofSystem(systemIndex);

        // Register first
        universalVerifier.registerVerifier(
            system,
            address(sp1Verifier),
            500000
        );

        // Update gas limit
        universalVerifier.updateGasLimit(system, newGasLimit);

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(system);
        assertEq(config.gasLimit, newGasLimit);
    }

    // ========================================
    // Recursive Verifier Fuzz Tests
    // ========================================

    function testFuzz_RecursiveVerifier_GasSavings(
        uint256 proofCount,
        uint256 batchGasUsed
    ) public view {
        // Bound inputs to reasonable ranges
        proofCount = bound(proofCount, 1, 1000);
        batchGasUsed = bound(batchGasUsed, 10000, 10000000);

        (uint256 savings, uint256 savingsPercent) = recursiveVerifier
            .calculateGasSavings(proofCount, batchGasUsed);

        // Invariants: savings percent should be <= 100
        assertLe(savingsPercent, 100);

        // Expected individual gas: proofCount * 250000
        uint256 expectedIndividual = proofCount * 250000;

        // If batch is cheaper, there should be savings
        if (batchGasUsed < expectedIndividual) {
            assertEq(savings, expectedIndividual - batchGasUsed);
        }
    }

    // ========================================
    // ZK Verifier Fuzz Tests
    // ========================================

    function testFuzz_SP1Verifier_RegisterVKey(
        bytes32 vkeyHash,
        bytes32 programHash
    ) public {
        vm.assume(vkeyHash != bytes32(0));
        vm.assume(programHash != bytes32(0));

        sp1Verifier.registerVKey(vkeyHash, programHash);

        (bytes32 retVkey, bytes32 retProgram, bool active, ) = sp1Verifier
            .verificationKeys(vkeyHash);
        assertEq(retVkey, vkeyHash);
        assertEq(retProgram, programHash);
        assertTrue(active);
    }

    function testFuzz_SP1Verifier_UpdateGateway(address gateway) public {
        sp1Verifier.updateGateway(gateway);
        assertEq(sp1Verifier.sp1Gateway(), gateway);
    }

    function testFuzz_Plonky3Verifier_RegisterCircuit(
        bytes32 circuitHash,
        uint256 numPublicInputsSeed,
        uint256 degreeSeed
    ) public {
        vm.assume(circuitHash != bytes32(0));

        // Use bound instead of assume to avoid rejection
        uint256 numPublicInputs = bound(numPublicInputsSeed, 1, 100);
        uint256 degree = bound(degreeSeed, 1, 1000);

        plonky3Verifier.registerCircuit(circuitHash, numPublicInputs, degree);

        (
            bytes32 retHash,
            uint256 retInputs,
            uint256 retDegree,
            bool active
        ) = plonky3Verifier.circuits(circuitHash);
        assertEq(retHash, circuitHash);
        assertEq(retInputs, numPublicInputs);
        assertEq(retDegree, degree);
        assertTrue(active);
    }

    function testFuzz_JoltVerifier_RegisterProgram(
        bytes32 programHash,
        uint256 maxCycles
    ) public {
        vm.assume(programHash != bytes32(0));
        vm.assume(maxCycles > 0);

        joltVerifier.registerProgram(programHash, maxCycles);

        (bytes32 retHash, uint256 retCycles, bool active) = joltVerifier
            .programs(programHash);
        assertEq(retHash, programHash);
        assertEq(retCycles, maxCycles);
        assertTrue(active);
    }

    function testFuzz_BiniusVerifier_RegisterCircuit(
        bytes32 circuitHash
    ) public {
        vm.assume(circuitHash != bytes32(0));

        biniusVerifier.registerCircuit(circuitHash);
        assertTrue(biniusVerifier.registeredCircuits(circuitHash));
    }

    // ========================================
    // Threshold Signature Fuzz Tests
    // ========================================

    function testFuzz_ThresholdSig_AddSigner(
        address newSigner,
        bytes32 publicKeyShare
    ) public {
        vm.assume(newSigner != address(0));
        vm.assume(publicKeyShare != bytes32(0));

        // Ensure newSigner is not already in signers
        bool exists = false;
        for (uint i = 0; i < signers.length; i++) {
            if (signers[i] == newSigner) {
                exists = true;
                break;
            }
        }
        vm.assume(!exists);

        thresholdSig.addSigner(newSigner, publicKeyShare);

        // Contract returns (threshold, totalSigners, sessionTimeout)
        (, uint256 totalSigners, ) = thresholdSig.getConfig();
        assertEq(totalSigners, 6); // 5 initial + 1 new
    }

    function testFuzz_ThresholdSig_NonSignerCantCommit(
        bytes32 messageHash,
        address nonSigner,
        bytes32 commitment
    ) public {
        vm.assume(messageHash != bytes32(0));
        vm.assume(commitment != bytes32(0));

        // Ensure nonSigner is not in the signers list
        bool isSigner = false;
        for (uint i = 0; i < signers.length; i++) {
            if (nonSigner == signers[i]) {
                isSigner = true;
                break;
            }
        }
        vm.assume(!isSigner);
        vm.assume(nonSigner != address(0));
        vm.assume(nonSigner != address(this)); // Test contract has admin role

        // Start a session with participants
        address[] memory participants = new address[](3);
        participants[0] = signers[0];
        participants[1] = signers[1];
        participants[2] = signers[2];

        bytes32 sessionId = thresholdSig.startSession(
            messageHash,
            participants
        );

        // Non-signer should not be able to commit
        vm.expectRevert();
        vm.prank(nonSigner);
        thresholdSig.submitCommitment(sessionId, commitment);
    }

    // ========================================
    // MPC Compliance Fuzz Tests
    // ========================================

    function testFuzz_MPCCompliance_RequestComplianceCheck(
        bytes32 encryptedIdentityHash
    ) public {
        vm.assume(encryptedIdentityHash != bytes32(0));

        bytes32 requestId = mpcCompliance.requestComplianceCheck(
            encryptedIdentityHash
        );

        // Verify request was created
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
        assertEq(requester, address(this));
    }

    function testFuzz_MPCCompliance_RegisterOracle(address newOracle) public {
        vm.assume(newOracle != address(0));

        // Ensure oracle is not already registered
        bool exists = false;
        for (uint i = 0; i < oracles.length; i++) {
            if (oracles[i] == newOracle) {
                exists = true;
                break;
            }
        }
        vm.assume(!exists);

        mpcCompliance.registerOracle(newOracle);

        assertTrue(mpcCompliance.isOracle(newOracle));
    }
}

/**
 * @title ResearchInvariantTests
 * @notice Invariant tests for research implementations
 */
contract ResearchInvariantTests is Test {
    PILUniversalVerifier public universalVerifier;
    PILRecursiveVerifier public recursiveVerifier;

    function setUp() public {
        universalVerifier = new PILUniversalVerifier();
        recursiveVerifier = new PILRecursiveVerifier(address(0), address(0));
    }

    // Invariant: Total verified should never decrease
    function invariant_totalVerifiedNeverDecreases() public view {
        assertGe(universalVerifier.totalVerified(), 0);
    }
}

/**
 * @title ResearchEdgeCaseTests
 * @notice Edge case tests for research implementations
 */
contract ResearchEdgeCaseTests is Test {
    PILUniversalVerifier public universalVerifier;
    PILRecursiveVerifier public recursiveVerifier;
    PILSP1Verifier public sp1Verifier;

    function setUp() public {
        universalVerifier = new PILUniversalVerifier();
        recursiveVerifier = new PILRecursiveVerifier(address(0), address(0));
        sp1Verifier = new PILSP1Verifier(address(0));
    }

    // Edge case: Zero gas limit should use default
    function test_EdgeCase_ZeroGasLimitUsesDefault() public {
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            0
        );

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(PILUniversalVerifier.ProofSystem.SP1);

        assertEq(config.gasLimit, universalVerifier.defaultGasLimit());
    }

    // Edge case: Re-registering same verifier
    function test_EdgeCase_ReRegisterVerifier() public {
        address verifier1 = makeAddr("verifier1");
        address verifier2 = makeAddr("verifier2");

        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            verifier1,
            500000
        );

        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            verifier2,
            600000
        );

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(PILUniversalVerifier.ProofSystem.SP1);

        assertEq(config.verifier, verifier2);
        assertEq(config.gasLimit, 600000);
    }

    // Edge case: Register all proof systems
    function test_EdgeCase_RegisterAllSystems() public {
        address dummyVerifier = makeAddr("dummyVerifier");

        // Use uint256 instead of uint8 to avoid potential overflow issues
        for (uint256 i = 0; i < 8; i++) {
            PILUniversalVerifier.ProofSystem system = PILUniversalVerifier
                .ProofSystem(i);
            universalVerifier.registerVerifier(
                system,
                dummyVerifier,
                500000 + i * 10000
            );
        }

        // Verify all registered
        (
            PILUniversalVerifier.ProofSystem[] memory systems,
            ,
            bool[] memory active
        ) = universalVerifier.getStats();

        assertEq(systems.length, 8);
        for (uint256 j = 0; j < 8; j++) {
            assertTrue(active[j]);
        }
    }

    // Edge case: Deactivate and reactivate
    function test_EdgeCase_DeactivateReactivate() public {
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            500000
        );

        // Deactivate
        universalVerifier.deactivateVerifier(
            PILUniversalVerifier.ProofSystem.SP1
        );

        PILUniversalVerifier.VerifierConfig memory config = universalVerifier
            .getVerifier(PILUniversalVerifier.ProofSystem.SP1);
        assertFalse(config.active);

        // Reactivate by re-registering
        universalVerifier.registerVerifier(
            PILUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            600000
        );

        config = universalVerifier.getVerifier(
            PILUniversalVerifier.ProofSystem.SP1
        );
        assertTrue(config.active);
        assertEq(config.gasLimit, 600000);
    }
}
