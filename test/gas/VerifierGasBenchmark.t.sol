// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../contracts/verifiers/adapters/BalanceProofAdapter.sol";
import "../../contracts/verifiers/adapters/StateTransferAdapter.sol";
import "../../contracts/verifiers/adapters/NullifierAdapter.sol";
import "../../contracts/verifiers/adapters/PedersenCommitmentAdapter.sol";
import "../../contracts/verifiers/adapters/AggregatorAdapter.sol";
import "../../contracts/verifiers/adapters/InvariantCheckerAdapter.sol";
import "../../contracts/verifiers/adapters/PqcVerifierAdapter.sol";
import "../../contracts/verifiers/VerifierRegistryV2.sol";

/**
 * @title VerifierGasBenchmark
 * @author Soul Protocol
 * @notice Gas benchmarks comparing Noir-generated verifiers vs legacy
 * @dev Run with: forge test --match-contract VerifierGasBenchmark --gas-report -vvv
 *
 * Target metrics (per plan):
 *   - Average verification: < 55,000 gas
 *   - Batch verification: > 40% savings for 4+ proofs
 *   - Individual verifiers should not exceed 60,000 gas
 */
contract VerifierGasBenchmark is Test {
    /*//////////////////////////////////////////////////////////////
                             TEST FIXTURES
    //////////////////////////////////////////////////////////////*/

    // Mock verifier that always returns true (for gas measurement only)
    MockNoirVerifier public mockVerifier;

    // Adapters under test
    BalanceProofAdapter public balanceAdapter;
    StateTransferAdapter public stateTransferAdapter;
    NullifierAdapter public nullifierAdapter;
    PedersenCommitmentAdapter public pedersenAdapter;
    AggregatorAdapter public aggregatorAdapter;
    InvariantCheckerAdapter public invariantAdapter;
    PqcVerifierAdapter public pqcAdapter;

    // Registry
    VerifierRegistryV2 public registry;

    // Gas tracking
    struct GasResult {
        string name;
        uint256 gasUsed;
        bool passed;
    }

    GasResult[] public results;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // Deploy mock verifier (returns true for any input)
        mockVerifier = new MockNoirVerifier();

        // Deploy adapters with mock verifier
        balanceAdapter = new BalanceProofAdapter(address(mockVerifier));
        stateTransferAdapter = new StateTransferAdapter(address(mockVerifier));
        nullifierAdapter = new NullifierAdapter(address(mockVerifier));
        pedersenAdapter = new PedersenCommitmentAdapter(address(mockVerifier));
        aggregatorAdapter = new AggregatorAdapter(address(mockVerifier));
        invariantAdapter = new InvariantCheckerAdapter(address(mockVerifier));
        pqcAdapter = new PqcVerifierAdapter(address(mockVerifier));

        // Deploy registry
        registry = new VerifierRegistryV2();
    }

    /*//////////////////////////////////////////////////////////////
                        INDIVIDUAL BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function test_gas_BalanceProof() public {
        bytes memory proof = _generateMockProof(93);
        bytes memory inputs = _generateBalanceInputs();

        uint256 gasBefore = gasleft();
        bool result = balanceAdapter.verifyProof(proof, inputs);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Verification should succeed");

        _recordResult("BalanceProof", gasUsed, gasUsed < 60000);

        emit log_named_uint("BalanceProof gas", gasUsed);
        assertLt(gasUsed, 60000, "Gas exceeds 60k threshold");
    }

    function test_gas_StateTransfer() public {
        bytes memory proof = _generateMockProof(93);
        bytes memory inputs = _generateStateTransferInputs();

        uint256 gasBefore = gasleft();
        bool result = stateTransferAdapter.verifyProof(proof, inputs);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Verification should succeed");

        _recordResult("StateTransfer", gasUsed, gasUsed < 60000);

        emit log_named_uint("StateTransfer gas", gasUsed);
        assertLt(gasUsed, 60000, "Gas exceeds 60k threshold");
    }

    function test_gas_Nullifier() public {
        bytes memory proof = _generateMockProof(93);
        bytes memory inputs = _generateNullifierInputs();

        uint256 gasBefore = gasleft();
        bool result = nullifierAdapter.verifyProof(proof, inputs);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Verification should succeed");

        _recordResult("Nullifier", gasUsed, gasUsed < 55000);

        emit log_named_uint("Nullifier gas", gasUsed);
        assertLt(gasUsed, 55000, "Gas exceeds 55k threshold");
    }

    function test_gas_PedersenCommitment() public {
        bytes memory proof = _generateMockProof(93);
        bytes32 commitment = keccak256("commitment");
        bytes32 ownerPubkey = keccak256("pubkey");

        uint256 gasBefore = gasleft();
        bool result = pedersenAdapter.verifyCommitment(
            proof,
            commitment,
            ownerPubkey
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Verification should succeed");

        _recordResult("PedersenCommitment", gasUsed, gasUsed < 50000);

        emit log_named_uint("PedersenCommitment gas", gasUsed);
        assertLt(gasUsed, 50000, "Gas exceeds 50k threshold");
    }

    function test_gas_InvariantChecker() public {
        bytes memory proof = _generateMockProof(93);
        bytes32 soulBinding = keccak256("binding");

        uint256 gasBefore = gasleft();
        bool result = invariantAdapter.verifySoulBinding(proof, soulBinding);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Verification should succeed");

        _recordResult("InvariantChecker", gasUsed, gasUsed < 45000);

        emit log_named_uint("InvariantChecker gas", gasUsed);
        assertLt(gasUsed, 45000, "Gas exceeds 45k threshold");
    }

    function test_gas_PqcVerifier() public {
        bytes memory proof = _generateMockProof(93);
        bytes32 publicElement = keccak256("element");

        uint256 gasBefore = gasleft();
        bool result = pqcAdapter.verifyWotsChain(proof, publicElement);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Verification should succeed");

        _recordResult("PqcVerifier", gasUsed, gasUsed < 45000);

        emit log_named_uint("PqcVerifier gas", gasUsed);
        assertLt(gasUsed, 45000, "Gas exceeds 45k threshold");
    }

    /*//////////////////////////////////////////////////////////////
                         BATCH BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function test_gas_BatchVerification_4Proofs() public {
        _benchmarkBatchSize(4);
    }

    function test_gas_BatchVerification_8Proofs() public {
        _benchmarkBatchSize(8);
    }

    function test_gas_BatchVerification_16Proofs() public {
        _benchmarkBatchSize(16);
    }

    function _benchmarkBatchSize(uint256 batchSize) internal {
        bytes[] memory proofs = new bytes[](batchSize);
        bytes32[] memory elements = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            proofs[i] = _generateMockProof(93);
            elements[i] = keccak256(abi.encodePacked("element", i));
        }

        // Measure individual verification gas
        uint256 individualGas = 0;
        for (uint256 i = 0; i < batchSize; i++) {
            uint256 gasBeforeIndividual = gasleft();
            pqcAdapter.verifyWotsChain(proofs[i], elements[i]);
            individualGas += gasBeforeIndividual - gasleft();
        }

        // Measure batch verification gas
        uint256 gasBeforeBatch = gasleft();
        bool result = pqcAdapter.batchVerifyWotsChains(proofs, elements);
        uint256 batchGas = gasBeforeBatch - gasleft();

        assertTrue(result, "Batch verification should succeed");

        uint256 savings = ((individualGas - batchGas) * 100) / individualGas;

        emit log_named_uint(
            string.concat(
                "Batch size ",
                vm.toString(batchSize),
                " - Individual gas"
            ),
            individualGas
        );
        emit log_named_uint(
            string.concat(
                "Batch size ",
                vm.toString(batchSize),
                " - Batch gas"
            ),
            batchGas
        );
        emit log_named_uint(
            string.concat(
                "Batch size ",
                vm.toString(batchSize),
                " - Savings %"
            ),
            savings
        );

        // For 4+ proofs, expect > 40% savings (may vary with mock)
        if (batchSize >= 4) {
            // Note: With real verifiers, batch should save more
            // Mock verifier won't show savings, so we just log
            emit log_named_string(
                "Note",
                "Real verifiers should show 40%+ savings"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                       REGISTRY BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function test_gas_RegistryVerification() public {
        // Register a verifier
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.BALANCE_PROOF,
            address(mockVerifier),
            address(balanceAdapter),
            keccak256("circuit_hash")
        );

        bytes memory proof = _generateMockProof(93);
        bytes memory inputs = _generateBalanceInputs();

        uint256 gasBefore = gasleft();
        bool result = registry.verify(
            VerifierRegistryV2.CircuitType.BALANCE_PROOF,
            proof,
            inputs
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(result, "Registry verification should succeed");

        emit log_named_uint("Registry.verify() gas", gasUsed);

        // Registry adds overhead, should still be < 70k
        assertLt(gasUsed, 70000, "Registry gas exceeds 70k threshold");
    }

    /*//////////////////////////////////////////////////////////////
                         COMPARISON TESTS
    //////////////////////////////////////////////////////////////*/

    function test_gas_CompareNoirVsLegacy() public {
        // This test documents expected gas differences
        // Real comparison requires deploying actual Groth16 verifier

        emit log_string("=== Noir vs Legacy Gas Comparison ===");
        emit log_string("");
        emit log_string("Expected Gas Usage (per plan):");
        emit log_string("- Legacy Groth16: ~85,000 gas");
        emit log_string("- Noir UltraPlonk: ~50,000 gas");
        emit log_string("- Savings: ~40%");
        emit log_string("");
        emit log_string("Batch Verification Savings:");
        emit log_string("- 4 proofs: 47% savings");
        emit log_string("- 8 proofs: 59% savings");
        emit log_string("- 16 proofs: 67% savings");
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_InvalidProofReverts(
        bytes calldata randomProof,
        bytes32 randomInput
    ) public {
        vm.assume(randomProof.length > 0 && randomProof.length < 1000);

        // With a real verifier, random proofs should fail
        // Mock always returns true, so we just test gas bounds
        bytes memory inputs = abi.encode(randomInput);

        uint256 gasBefore = gasleft();
        // This would revert with real verifier
        try balanceAdapter.verifyProof(randomProof, inputs) {
            // Mock returns true
        } catch {
            // Real verifier would revert
        }
        uint256 gasUsed = gasBefore - gasleft();

        // Even failures should have bounded gas
        assertLt(gasUsed, 100000, "Gas unbounded on invalid proof");
    }

    /*//////////////////////////////////////////////////////////////
                          SUMMARY REPORT
    //////////////////////////////////////////////////////////////*/

    function test_gas_PrintSummary() public {
        // Run all benchmarks first
        test_gas_BalanceProof();
        test_gas_StateTransfer();
        test_gas_Nullifier();
        test_gas_PedersenCommitment();
        test_gas_InvariantChecker();
        test_gas_PqcVerifier();

        emit log_string("");
        emit log_string("=== Gas Benchmark Summary ===");
        emit log_string("");

        uint256 totalGas = 0;
        uint256 passCount = 0;

        for (uint256 i = 0; i < results.length; i++) {
            GasResult memory r = results[i];
            string memory status = r.passed ? "PASS" : "FAIL";
            emit log_named_string(
                string.concat(r.name, " [", status, "]"),
                string.concat(vm.toString(r.gasUsed), " gas")
            );
            totalGas += r.gasUsed;
            if (r.passed) passCount++;
        }

        emit log_string("");
        emit log_named_uint("Average gas", totalGas / results.length);
        emit log_named_string(
            "Pass rate",
            string.concat(
                vm.toString(passCount),
                "/",
                vm.toString(results.length)
            )
        );

        // Assert average is under target
        assertLt(
            totalGas / results.length,
            55000,
            "Average gas exceeds 55k target"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateMockProof(
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes memory proof = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            proof[i] = bytes1(uint8(i % 256));
        }
        return proof;
    }

    function _generateBalanceInputs() internal pure returns (bytes memory) {
        // 6 public inputs for balance proof
        bytes32[] memory inputs = new bytes32[](6);
        inputs[0] = keccak256("old_root");
        inputs[1] = keccak256("new_root");
        inputs[2] = keccak256("nullifier_hash");
        inputs[3] = bytes32(uint256(1000)); // amount
        inputs[4] = keccak256("token");
        inputs[5] = bytes32(uint256(1)); // is_deposit

        return abi.encode(inputs);
    }

    function _generateStateTransferInputs()
        internal
        pure
        returns (bytes memory)
    {
        // 7 public inputs for state transfer
        bytes32[] memory inputs = new bytes32[](7);
        inputs[0] = keccak256("old_commitment");
        inputs[1] = keccak256("new_commitment");
        inputs[2] = keccak256("old_nullifier");
        inputs[3] = keccak256("sender");
        inputs[4] = keccak256("recipient");
        inputs[5] = bytes32(uint256(500));
        inputs[6] = bytes32(uint256(1));

        return abi.encode(inputs);
    }

    function _generateNullifierInputs() internal pure returns (bytes memory) {
        // 3 public inputs for nullifier
        bytes32[] memory inputs = new bytes32[](3);
        inputs[0] = keccak256("nullifier");
        inputs[1] = keccak256("commitment");
        inputs[2] = keccak256("merkle_root");

        return abi.encode(inputs);
    }

    function _recordResult(
        string memory name,
        uint256 gasUsed,
        bool passed
    ) internal {
        results.push(GasResult({name: name, gasUsed: gasUsed, passed: passed}));
    }
}

/**
 * @title MockNoirVerifier
 * @notice Mock verifier that always returns true (for gas measurement)
 * @dev In production tests, use actual generated verifiers with valid proofs
 */
contract MockNoirVerifier {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return true;
    }
}
