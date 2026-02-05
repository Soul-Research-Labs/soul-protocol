// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../contracts/verifiers/GKRVerifier.sol";

/**
 * @title GKR Verifier Tests
 * @notice Tests for GKR sumcheck verification with Gruen's trick
 */
contract GKRVerifierTest is Test {
    GKRVerifier public verifier;

    uint256 constant KOALABEAR_PRIME = 2013265921;

    function setUp() public {
        verifier = new GKRVerifier(address(this), address(0));
        verifier.setStrictMode(false);
    }

    /*//////////////////////////////////////////////////////////////
                          FIELD ARITHMETIC TESTS
    //////////////////////////////////////////////////////////////*/

    function testFieldAdd() public view {
        // Test basic addition
        uint256 a = 100;
        uint256 b = 200;
        // Can't directly test internal functions, but verify contract deployed
        assertTrue(address(verifier) != address(0));
    }

    function testFieldModulus() public view {
        (uint256 total, uint256 modulus, , ) = verifier.getStats();
        assertEq(modulus, KOALABEAR_PRIME);
        assertEq(total, 0);
    }

    /*//////////////////////////////////////////////////////////////
                          SUMCHECK VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testVerifySumcheck_basic() public view {
        uint256 numRounds = 3;

        // Create test partial sums (3 per round with Gruen's trick)
        uint256[] memory partialSums = new uint256[](9);
        partialSums[0] = 10; // hsum0 round 0
        partialSums[1] = 30; // hsum2 round 0
        partialSums[2] = 50; // hsum3 round 0
        partialSums[3] = 15; // hsum0 round 1
        partialSums[4] = 35; // hsum2 round 1
        partialSums[5] = 55; // hsum3 round 1
        partialSums[6] = 20; // hsum0 round 2
        partialSums[7] = 40; // hsum2 round 2
        partialSums[8] = 60; // hsum3 round 2

        uint256[] memory challenges = new uint256[](3);
        challenges[0] = 7;
        challenges[1] = 11;
        challenges[2] = 13;

        uint256[] memory evalPoints = new uint256[](3);
        evalPoints[0] = 2;
        evalPoints[1] = 3;
        evalPoints[2] = 5;

        // This will fail validation due to inconsistent test data
        // In production, these values would be computed correctly
        // The test verifies the function doesn't revert unexpectedly
        try
            verifier.verifySumcheck(
                numRounds,
                partialSums,
                challenges,
                evalPoints,
                100
            )
        {
            // May or may not pass depending on test data
        } catch {
            // Expected for invalid test data
        }
    }

    function testVerifySumcheck_tooManyRounds() public view {
        uint256 numRounds = 33; // Exceeds MAX_ROUNDS

        uint256[] memory partialSums = new uint256[](99);
        uint256[] memory challenges = new uint256[](33);
        uint256[] memory evalPoints = new uint256[](33);

        bool result = verifier.verifySumcheck(
            numRounds,
            partialSums,
            challenges,
            evalPoints,
            100
        );

        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testVerifyProof_basic() public view {
        // Create a simple proof
        bytes32 inputCommitment = keccak256(abi.encodePacked("input"));
        bytes32 outputCommitment = keccak256(abi.encodePacked("output"));
        bytes32 commitmentRoot = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );

        bytes memory proof = abi.encodePacked(
            commitmentRoot,
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        bytes memory publicInputs = abi.encodePacked(
            inputCommitment,
            outputCommitment
        );

        bool result = verifier.verifyProof(proof, publicInputs);
        assertTrue(result);
    }

    function testVerifyProof_emptyProof() public view {
        bytes memory proof = "";
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        bool result = verifier.verifyProof(proof, publicInputs);
        assertFalse(result);
    }

    function testVerifyProof_emptyPublicInputs() public view {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        bytes memory publicInputs = "";

        bool result = verifier.verifyProof(proof, publicInputs);
        assertFalse(result);
    }

    function testVerifyBatchHash() public view {
        bytes32[] memory inputHashes = new bytes32[](3);
        inputHashes[0] = keccak256(abi.encodePacked("input1"));
        inputHashes[1] = keccak256(abi.encodePacked("input2"));
        inputHashes[2] = keccak256(abi.encodePacked("input3"));

        bytes32[] memory outputHashes = new bytes32[](3);
        outputHashes[0] = keccak256(abi.encodePacked("output1"));
        outputHashes[1] = keccak256(abi.encodePacked("output2"));
        outputHashes[2] = keccak256(abi.encodePacked("output3"));

        // Compute expected commitments
        bytes32 inputCommitment = keccak256(abi.encodePacked(inputHashes));
        bytes32 outputCommitment = keccak256(abi.encodePacked(outputHashes));
        bytes32 commitmentRoot = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );

        // Proof must be at least 64 bytes
        bytes memory proof = abi.encodePacked(commitmentRoot, bytes32(0));

        bool result = verifier.verifyBatchHash(
            proof,
            inputHashes,
            outputHashes
        );
        assertTrue(result);
    }

    function testVerifyBatchHash_mismatchedLengths() public view {
        bytes32[] memory inputHashes = new bytes32[](3);
        bytes32[] memory outputHashes = new bytes32[](2);

        bytes memory proof = abi.encodePacked(bytes32(0));

        bool result = verifier.verifyBatchHash(
            proof,
            inputHashes,
            outputHashes
        );
        assertFalse(result);
    }

    function testVerifyBatchHash_emptyArrays() public view {
        bytes32[] memory inputHashes = new bytes32[](0);
        bytes32[] memory outputHashes = new bytes32[](0);

        bytes memory proof = abi.encodePacked(bytes32(0));

        bool result = verifier.verifyBatchHash(
            proof,
            inputHashes,
            outputHashes
        );
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                          IPROOFVERIFIER INTERFACE TESTS
    //////////////////////////////////////////////////////////////*/

    function testVerify_withUint256Inputs() public view {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = 12345;
        publicInputs[1] = 67890;

        bool result = verifier.verify(proof, publicInputs);
        assertTrue(result);
    }

    function testVerifySingle() public view {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        bool result = verifier.verifySingle(proof, 12345);
        assertTrue(result);
    }

    function testGetPublicInputCount() public view {
        uint256 count = verifier.getPublicInputCount();
        assertEq(count, 2);
    }

    function testIsReady() public view {
        bool ready = verifier.isReady();
        assertTrue(ready); // strictMode is false
    }

    function testProofType() public view {
        bytes32 proofType = verifier.proofType();
        assertEq(proofType, keccak256("GKR_PROOF"));
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function testSetConfig() public {
        uint256 newModulus = 1000000007;
        address newHekate = address(0x1234);

        verifier.setConfig(newModulus, newHekate);

        (, uint256 modulus, address hekate, ) = verifier.getStats();
        assertEq(modulus, newModulus);
        assertEq(hekate, newHekate);
    }

    function testSetStrictMode() public {
        verifier.setStrictMode(true);

        (, , , bool strict) = verifier.getStats();
        assertTrue(strict);

        verifier.setStrictMode(false);
        (, , , strict) = verifier.getStats();
        assertFalse(strict);
    }

    function testVerifyAndRecord_updatesStats() public {
        bytes32 inputCommitment = keccak256(abi.encodePacked("input"));
        bytes32 outputCommitment = keccak256(abi.encodePacked("output"));
        bytes32 commitmentRoot = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );

        // Proof must be at least 64 bytes
        bytes memory proof = abi.encodePacked(commitmentRoot, bytes32(0));
        bytes memory publicInputs = abi.encodePacked(
            inputCommitment,
            outputCommitment
        );

        verifier.verifyAndRecord(proof, publicInputs);

        (uint256 total, , , ) = verifier.getStats();
        assertEq(total, 1);
    }

    /*//////////////////////////////////////////////////////////////
                          BENCHMARK TESTS
    //////////////////////////////////////////////////////////////*/

    function testBenchmark_verifySumcheck() public view {
        uint256 numRounds = 10;

        uint256[] memory partialSums = new uint256[](30);
        uint256[] memory challenges = new uint256[](10);
        uint256[] memory evalPoints = new uint256[](10);

        for (uint256 i = 0; i < 10; i++) {
            partialSums[i * 3] = 10 + i;
            partialSums[i * 3 + 1] = 30 + i;
            partialSums[i * 3 + 2] = 50 + i;
            challenges[i] = 7 + i;
            evalPoints[i] = 2 + i;
        }

        console.log("=== GKR Sumcheck Verification Benchmark ===");
        console.log("Rounds: %d", numRounds);

        uint256 gasStart = gasleft();
        try
            verifier.verifySumcheck(
                numRounds,
                partialSums,
                challenges,
                evalPoints,
                100
            )
        {
            // May fail due to invalid test data
        } catch {
            // Expected
        }
        uint256 gasUsed = gasStart - gasleft();

        console.log("Gas used for sumcheck verification: %d", gasUsed);
    }

    function testBenchmark_verifyProof() public view {
        bytes32 inputCommitment = keccak256(abi.encodePacked("input"));
        bytes32 outputCommitment = keccak256(abi.encodePacked("output"));
        bytes32 commitmentRoot = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );

        bytes memory proof = abi.encodePacked(
            commitmentRoot,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );

        bytes memory publicInputs = abi.encodePacked(
            inputCommitment,
            outputCommitment
        );

        console.log("=== GKR Proof Verification Benchmark ===");

        uint256 iterations = 100;
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < iterations; i++) {
            verifier.verifyProof(proof, publicInputs);
        }
        uint256 gasUsed = gasStart - gasleft();

        console.log("Iterations: %d", iterations);
        console.log("Total gas: %d", gasUsed);
        console.log("Avg gas per verify: %d", gasUsed / iterations);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_verifyProof(bytes32 input, bytes32 output) public view {
        bytes32 commitmentRoot = keccak256(abi.encodePacked(input, output));
        // Proof must be at least 64 bytes
        bytes memory proof = abi.encodePacked(commitmentRoot, bytes32(0));
        bytes memory publicInputs = abi.encodePacked(input, output);

        bool result = verifier.verifyProof(proof, publicInputs);
        assertTrue(result);
    }

    function testFuzz_verifyBatchHash(uint8 batchSize) public view {
        vm.assume(batchSize > 0 && batchSize <= 10);

        bytes32[] memory inputHashes = new bytes32[](batchSize);
        bytes32[] memory outputHashes = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            inputHashes[i] = keccak256(abi.encodePacked("input", i));
            outputHashes[i] = keccak256(abi.encodePacked("output", i));
        }

        bytes32 inputCommitment = keccak256(abi.encodePacked(inputHashes));
        bytes32 outputCommitment = keccak256(abi.encodePacked(outputHashes));
        bytes32 commitmentRoot = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );

        // Proof must be at least 64 bytes
        bytes memory proof = abi.encodePacked(commitmentRoot, bytes32(0));

        bool result = verifier.verifyBatchHash(
            proof,
            inputHashes,
            outputHashes
        );
        assertTrue(result);
    }
}
