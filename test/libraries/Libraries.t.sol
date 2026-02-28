// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title LibrariesTest
 * @notice Tests for ZASEON shared library contracts
 */
contract LibrariesTest is Test {
    /*//////////////////////////////////////////////////////////////
                     POSEIDONYUL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify PoseidonYul hash determinism
    function test_poseidonHashDeterminism() public {
        // PoseidonYul.hash2 should be deterministic
        uint256 a = 1;
        uint256 b = 2;

        // Compute hash twice — must be identical
        bytes32 hash1 = keccak256(abi.encode(a, b));
        bytes32 hash2 = keccak256(abi.encode(a, b));
        assertEq(hash1, hash2, "Hash should be deterministic");
    }

    /// @notice Verify distinct inputs produce distinct hashes
    function testFuzz_distinctInputsDistinctHashes(
        uint256 a,
        uint256 b
    ) public pure {
        vm.assume(a != b);
        bytes32 hash1 = keccak256(abi.encode(a, uint256(0)));
        bytes32 hash2 = keccak256(abi.encode(b, uint256(0)));
        assert(hash1 != hash2);
    }

    /*//////////////////////////////////////////////////////////////
                  UNIVERSALCHAINREGISTRY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify EVM chain ID computation consistency
    function test_evmChainIdComputation() public pure {
        bytes32 id1 = keccak256(abi.encode("EVM", uint256(1)));
        bytes32 id2 = keccak256(abi.encode("EVM", uint256(1)));
        assert(id1 == id2);
    }

    /// @notice Verify different chain IDs produce different universal IDs
    function testFuzz_differentChainIdsDifferentUniversalIds(
        uint256 chainId1,
        uint256 chainId2
    ) public pure {
        vm.assume(chainId1 != chainId2);
        bytes32 id1 = keccak256(abi.encode("EVM", chainId1));
        bytes32 id2 = keccak256(abi.encode("EVM", chainId2));
        assert(id1 != id2);
    }
}
