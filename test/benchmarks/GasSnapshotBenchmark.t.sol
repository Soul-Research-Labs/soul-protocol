// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {ZKBoundStateLocks} from "../../contracts/primitives/ZKBoundStateLocks.sol";
import {FlashLoanGuard} from "../../contracts/security/FlashLoanGuard.sol";
import {MEVProtection} from "../../contracts/security/MEVProtection.sol";
import {MockProofVerifier} from "../../contracts/mocks/MockProofVerifier.sol";

/**
 * @title GasSnapshotBenchmark
 * @author ZASEON
 * @notice Gas benchmark tests for critical protocol operations
 * @dev Run with: forge test --match-contract GasSnapshotBenchmark --gas-report
 *      Compare against .gas-snapshot: forge snapshot --match-contract GasSnapshotBenchmark
 *
 * Gas budget targets (per operation):
 * - registerNullifier:  < 1_100_000 (tree depth 32)
 * - createLock:         <   300_000
 * - unlock:             <   300_000
 * - validateOperation:  <    80_000
 * - commit + reveal:    <   250_000
 */
contract GasSnapshotBenchmark is Test {
    NullifierRegistryV3 public nullReg;
    ZKBoundStateLocks public stateLocks;
    FlashLoanGuard public flashGuard;
    MEVProtection public mevProtect;
    MockProofVerifier public verifier;

    bytes32 constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 constant MOCK_VK_HASH = keccak256("MOCK_VK");
    bytes32 testDomain;

    function setUp() public {
        nullReg = new NullifierRegistryV3();
        nullReg.grantRole(REGISTRAR_ROLE, address(this));

        verifier = new MockProofVerifier();
        verifier.setVerificationResult(true);

        stateLocks = new ZKBoundStateLocks(address(verifier));
        testDomain = stateLocks.registerDomain(
            uint64(block.chainid),
            1,
            0,
            "Benchmark"
        );

        flashGuard = new FlashLoanGuard(500, 1000, address(this));
        mevProtect = new MEVProtection(2, 100, address(this));
    }

    // =====================================================================
    // NullifierRegistryV3 Benchmarks
    // =====================================================================

    /// @notice Benchmark: first nullifier registration (cold storage)
    function test_gas_registerNullifier_first() public {
        nullReg.registerNullifier(keccak256("null_1"), keccak256("commit_1"));
    }

    /// @notice Benchmark: subsequent nullifier registration (warm storage)
    function test_gas_registerNullifier_warm() public {
        nullReg.registerNullifier(keccak256("null_1"), keccak256("commit_1"));
        // Measure second registration (storage partially warm)
        nullReg.registerNullifier(keccak256("null_2"), keccak256("commit_2"));
    }

    /// @notice Benchmark: batch register 10 nullifiers
    function test_gas_batchRegister_10() public {
        bytes32[] memory nullifiers = new bytes32[](10);
        bytes32[] memory commits = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("batch_null", i));
            commits[i] = keccak256(abi.encodePacked("batch_commit", i));
        }
        nullReg.batchRegisterNullifiers(nullifiers, commits);
    }

    /// @notice Benchmark: nullifier existence check
    function test_gas_nullifierExists() public {
        bytes32 n = keccak256("check_null");
        nullReg.registerNullifier(n, bytes32(0));
        // Measure the view call
        nullReg.exists(n);
    }

    // =====================================================================
    // ZKBoundStateLocks Benchmarks
    // =====================================================================

    /// @notice Benchmark: create a new lock
    function test_gas_createLock() public {
        stateLocks.createLock(
            keccak256("state"),
            keccak256("predicate"),
            keccak256("policy"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );
    }

    /// @notice Benchmark: unlock an existing lock
    function test_gas_unlock() public {
        bytes32 lockId = stateLocks.createLock(
            keccak256("state_u"),
            keccak256("predicate_u"),
            keccak256("policy_u"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("new_state"),
                nullifier: keccak256("null_unlock"),
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        stateLocks.unlock(proof);
    }

    /// @notice Benchmark: register domain
    function test_gas_registerDomain() public {
        stateLocks.registerDomain(42, 2, 1, "BenchDomain");
    }

    // =====================================================================
    // Security Module Benchmarks
    // =====================================================================

    /// @notice Benchmark: FlashLoanGuard validateOperation
    function test_gas_validateOperation() public {
        flashGuard.validateOperation(address(this), address(0), 1 ether);
    }

    /// @notice Benchmark: MEVProtection commit
    function test_gas_mevCommit() public {
        bytes32 hash = mevProtect.calculateCommitHash(
            address(this),
            keccak256("OP"),
            abi.encode(1),
            keccak256("salt")
        );
        mevProtect.commit(hash);
    }

    /// @notice Benchmark: MEVProtection commit + reveal round-trip
    function test_gas_mevCommitReveal() public {
        bytes32 opType = keccak256("OP");
        bytes memory data = abi.encode(1);
        bytes32 salt = keccak256("salt");

        bytes32 hash = mevProtect.calculateCommitHash(
            address(this),
            opType,
            data,
            salt
        );
        bytes32 commitId = mevProtect.commit(hash);

        vm.roll(block.number + 3);
        mevProtect.reveal(commitId, opType, data, salt);
    }
}
