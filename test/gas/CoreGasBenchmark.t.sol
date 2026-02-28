// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../contracts/libraries/PoseidonT3.sol";
import "../../contracts/libraries/PoseidonYul.sol";

/**
 * @title CoreGasBenchmark
 * @author ZASEON
 * @notice Gas benchmarks for core protocol operations
 * @dev Run with: forge test --match-contract CoreGasBenchmark --gas-report -vvv
 *
 * Tracks gas costs for:
 *   - PoseidonT3 full 65-round hash
 *   - PoseidonYul wrapper (delegates to PoseidonT3)
 *   - Merkle tree hashing chains (simulated depth-32 tree insertions)
 *   - Batch hashing throughput
 */
contract CoreGasBenchmark is Test {
    /*//////////////////////////////////////////////////////////////
                             HARNESSES
    //////////////////////////////////////////////////////////////*/

    PoseidonT3GasHarness poseidonT3;
    PoseidonYulGasHarness poseidonYul;

    function setUp() public {
        poseidonT3 = new PoseidonT3GasHarness();
        poseidonYul = new PoseidonYulGasHarness();
    }

    /*//////////////////////////////////////////////////////////////
                      POSEIDON T3 GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure single PoseidonT3 hash
    function test_gas_PoseidonT3_singleHash() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.hash2(1, 2);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("PoseidonT3 single hash gas:", gasUsed);
        assertLt(gasUsed, 150_000, "PoseidonT3 single hash exceeds 150k gas");
    }

    /// @notice Measure PoseidonT3 hash with zero inputs
    function test_gas_PoseidonT3_zeroInputs() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.hash2(0, 0);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("PoseidonT3 zero-input hash gas:", gasUsed);
    }

    /// @notice Measure PoseidonT3 hash with large field elements
    function test_gas_PoseidonT3_largeInputs() public view {
        uint256 P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256 gasBefore = gasleft();
        poseidonT3.hash2(P - 1, P - 1);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("PoseidonT3 large-input hash gas:", gasUsed);
    }

    /// @notice Measure PoseidonYul wrapper (should be same as T3 + DELEGATECALL overhead)
    function test_gas_PoseidonYul_wrapper() public view {
        uint256 gasBefore = gasleft();
        poseidonYul.hash2(1, 2);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("PoseidonYul wrapper hash gas:", gasUsed);
    }

    /*//////////////////////////////////////////////////////////////
                    MERKLE TREE INSERTION SIMULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Simulate a depth-32 Merkle tree leaf insertion (32 hashes)
    function test_gas_MerkleInsertion_depth32() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.simulateMerkleInsert(bytes32(uint256(42)), 32);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Merkle insert (depth 32) gas:", gasUsed);
        // 32 Poseidon hashes for one Merkle path
        assertLt(gasUsed, 5_000_000, "Merkle insert exceeds 5M gas");
    }

    /// @notice Simulate depth-20 Merkle tree (~1M leaves)
    function test_gas_MerkleInsertion_depth20() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.simulateMerkleInsert(bytes32(uint256(42)), 20);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Merkle insert (depth 20) gas:", gasUsed);
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH HASHING BENCHMARK
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for 10 sequential hashes
    function test_gas_PoseidonT3_batch10() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.batchHash(10);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("PoseidonT3 batch 10 hashes gas:", gasUsed);
        console.log("PoseidonT3 avg per hash (batch 10):", gasUsed / 10);
    }

    /// @notice Measure gas for 50 sequential hashes
    function test_gas_PoseidonT3_batch50() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.batchHash(50);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("PoseidonT3 batch 50 hashes gas:", gasUsed);
        console.log("PoseidonT3 avg per hash (batch 50):", gasUsed / 50);
    }
}

/*//////////////////////////////////////////////////////////////
                         HARNESS CONTRACTS
//////////////////////////////////////////////////////////////*/

contract PoseidonT3GasHarness {
    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return PoseidonT3.hash2(a, b);
    }

    /// @notice Simulate Merkle tree insertion by hashing up the tree
    function simulateMerkleInsert(
        bytes32 leaf,
        uint256 depth
    ) external pure returns (bytes32) {
        bytes32 currentHash = leaf;
        bytes32 zero = bytes32(
            uint256(
                0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c
            )
        );
        for (uint256 i = 0; i < depth; i++) {
            // Hash with sibling (simulate left child, pair with zero)
            currentHash = bytes32(
                PoseidonT3.hash2(uint256(currentHash), uint256(zero))
            );
            zero = bytes32(PoseidonT3.hash2(uint256(zero), uint256(zero)));
        }
        return currentHash;
    }

    /// @notice Sequentially hash (n) times, chaining outputs
    function batchHash(uint256 n) external pure returns (uint256) {
        uint256 h = 0;
        for (uint256 i = 0; i < n; i++) {
            h = PoseidonT3.hash2(h, i);
        }
        return h;
    }
}

contract PoseidonYulGasHarness {
    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return PoseidonYul.hash2(a, b);
    }
}
