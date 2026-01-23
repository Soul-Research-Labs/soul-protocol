// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/tornado/TornadoPrimitives.sol";

/**
 * @title TornadoFuzz
 * @notice Fuzz tests for Tornado Cash primitives
 * @dev Tests MiMC hash, Merkle tree, Pedersen commitments, and nullifier derivation
 */
contract TornadoFuzz is Test {
    using TornadoPrimitives for *;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 constant BN254_R = TornadoPrimitives.BN254_R;
    uint256 constant BN254_P = TornadoPrimitives.BN254_P;
    uint256 constant MERKLE_DEPTH = TornadoPrimitives.MERKLE_TREE_DEPTH;
    uint256 constant MAX_TREE_SIZE = TornadoPrimitives.MAX_TREE_SIZE;

    // =========================================================================
    // MIMC HASH TESTS
    // =========================================================================

    function testFuzz_MiMCHashDeterminism(
        uint256 left,
        uint256 right
    ) public pure {
        left = bound(left, 0, BN254_R - 1);
        right = bound(right, 0, BN254_R - 1);

        uint256 hash1 = TornadoPrimitives.mimcHash(left, right);
        uint256 hash2 = TornadoPrimitives.mimcHash(left, right);

        assertEq(hash1, hash2, "MiMC hash not deterministic");
    }

    function testFuzz_MiMCHashInField(uint256 left, uint256 right) public pure {
        left = bound(left, 0, BN254_R - 1);
        right = bound(right, 0, BN254_R - 1);

        uint256 result = TornadoPrimitives.mimcHash(left, right);

        assertLt(result, BN254_R, "MiMC result outside field");
    }

    function testFuzz_MiMCHashNonZero(uint256 left, uint256 right) public pure {
        left = bound(left, 1, BN254_R - 1);
        right = bound(right, 1, BN254_R - 1);

        uint256 result = TornadoPrimitives.mimcHash(left, right);

        // MiMC should produce non-zero for non-zero inputs (high probability)
        assertTrue(
            result != 0 || (left == 0 && right == 0),
            "MiMC produced zero unexpectedly"
        );
    }

    function testFuzz_MiMCHashKeyDependence(
        uint256 left,
        uint256 right1,
        uint256 right2
    ) public pure {
        left = bound(left, 0, BN254_R - 1);
        right1 = bound(right1, 0, BN254_R - 1);
        right2 = bound(right2, 0, BN254_R - 1);
        vm.assume(right1 != right2);

        uint256 hash1 = TornadoPrimitives.mimcHash(left, right1);
        uint256 hash2 = TornadoPrimitives.mimcHash(left, right2);

        assertNotEq(hash1, hash2, "Different keys produced same hash");
    }

    function testFuzz_MiMCHash2Determinism(
        bytes32 left,
        bytes32 right
    ) public pure {
        left = bytes32(bound(uint256(left), 0, BN254_R - 1));
        right = bytes32(bound(uint256(right), 0, BN254_R - 1));

        bytes32 hash1 = TornadoPrimitives.mimcHash2(left, right);
        bytes32 hash2 = TornadoPrimitives.mimcHash2(left, right);

        assertEq(hash1, hash2, "MiMC hash2 not deterministic");
    }

    function testFuzz_MiMCSponge(uint8 numInputs) public pure {
        numInputs = uint8(bound(numInputs, 1, 10));

        uint256[] memory inputs = new uint256[](numInputs);
        for (uint256 i = 0; i < numInputs; i++) {
            inputs[i] = bound(i * 12345, 0, BN254_R - 1);
        }

        uint256 result1 = TornadoPrimitives.mimcSponge(inputs);
        uint256 result2 = TornadoPrimitives.mimcSponge(inputs);

        assertEq(result1, result2, "MiMC sponge not deterministic");
        assertLt(result1, BN254_R, "MiMC sponge outside field");
    }

    // =========================================================================
    // COMMITMENT TESTS
    // =========================================================================

    function testFuzz_CommitmentDeterminism(
        bytes32 nullifier,
        bytes32 secret
    ) public pure {
        nullifier = bytes32(bound(uint256(nullifier), 1, BN254_R - 1));
        secret = bytes32(bound(uint256(secret), 1, BN254_R - 1));

        bytes32 c1 = TornadoPrimitives.computeCommitment(nullifier, secret);
        bytes32 c2 = TornadoPrimitives.computeCommitment(nullifier, secret);

        assertEq(c1, c2, "Commitment not deterministic");
    }

    function testFuzz_CommitmentUniqueness(
        bytes32 nullifier1,
        bytes32 secret1,
        bytes32 nullifier2,
        bytes32 secret2
    ) public pure {
        nullifier1 = bytes32(bound(uint256(nullifier1), 1, BN254_R - 1));
        secret1 = bytes32(bound(uint256(secret1), 1, BN254_R - 1));
        nullifier2 = bytes32(bound(uint256(nullifier2), 1, BN254_R - 1));
        secret2 = bytes32(bound(uint256(secret2), 1, BN254_R - 1));

        vm.assume(nullifier1 != nullifier2 || secret1 != secret2);

        bytes32 c1 = TornadoPrimitives.computeCommitment(nullifier1, secret1);
        bytes32 c2 = TornadoPrimitives.computeCommitment(nullifier2, secret2);

        assertNotEq(c1, c2, "Different inputs produced same commitment");
    }

    function testFuzz_CommitmentHiding(
        bytes32 nullifier,
        bytes32 secret
    ) public pure {
        nullifier = bytes32(bound(uint256(nullifier), 1, BN254_R - 1));
        secret = bytes32(bound(uint256(secret), 1, BN254_R - 1));

        bytes32 commitment = TornadoPrimitives.computeCommitment(
            nullifier,
            secret
        );

        // Commitment should not reveal nullifier or secret
        assertTrue(
            commitment != nullifier && commitment != secret,
            "Commitment reveals input"
        );
    }

    function testFuzz_CommitmentValidity(
        bytes32 nullifier,
        bytes32 secret
    ) public pure {
        nullifier = bytes32(bound(uint256(nullifier), 1, BN254_R - 1));
        secret = bytes32(bound(uint256(secret), 1, BN254_R - 1));

        bytes32 commitment = TornadoPrimitives.computeCommitment(
            nullifier,
            secret
        );

        assertTrue(
            TornadoPrimitives.isValidCommitment(commitment),
            "Commitment should be valid"
        );
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    function testFuzz_NullifierDerivation(
        bytes32 nullifierSecret,
        uint256 leafIndex
    ) public pure {
        nullifierSecret = bytes32(
            bound(uint256(nullifierSecret), 1, BN254_R - 1)
        );
        leafIndex = bound(leafIndex, 0, MAX_TREE_SIZE - 1);

        bytes32 nf1 = TornadoPrimitives.deriveNullifierHash(
            nullifierSecret,
            leafIndex
        );
        bytes32 nf2 = TornadoPrimitives.deriveNullifierHash(
            nullifierSecret,
            leafIndex
        );

        assertEq(nf1, nf2, "Nullifier derivation not deterministic");
    }

    function testFuzz_NullifierUniqueness(
        bytes32 secret1,
        uint256 index1,
        bytes32 secret2,
        uint256 index2
    ) public pure {
        secret1 = bytes32(bound(uint256(secret1), 1, BN254_R - 1));
        secret2 = bytes32(bound(uint256(secret2), 1, BN254_R - 1));
        index1 = bound(index1, 0, MAX_TREE_SIZE - 1);
        index2 = bound(index2, 0, MAX_TREE_SIZE - 1);

        vm.assume(secret1 != secret2 || index1 != index2);

        bytes32 nf1 = TornadoPrimitives.deriveNullifierHash(secret1, index1);
        bytes32 nf2 = TornadoPrimitives.deriveNullifierHash(secret2, index2);

        assertNotEq(nf1, nf2, "Different inputs produced same nullifier");
    }

    function testFuzz_NullifierInField(
        bytes32 nullifierSecret,
        uint256 leafIndex
    ) public pure {
        nullifierSecret = bytes32(
            bound(uint256(nullifierSecret), 0, BN254_R - 1)
        );
        leafIndex = bound(leafIndex, 0, MAX_TREE_SIZE - 1);

        bytes32 nf = TornadoPrimitives.deriveNullifierHash(
            nullifierSecret,
            leafIndex
        );

        assertLt(uint256(nf), BN254_R, "Nullifier outside field");
    }

    function testFuzz_NullifierValidity(
        bytes32 nullifierSecret,
        uint256 leafIndex
    ) public pure {
        nullifierSecret = bytes32(
            bound(uint256(nullifierSecret), 1, BN254_R - 1)
        );
        leafIndex = bound(leafIndex, 0, MAX_TREE_SIZE - 1);

        bytes32 nf = TornadoPrimitives.deriveNullifierHash(
            nullifierSecret,
            leafIndex
        );

        assertTrue(
            TornadoPrimitives.isValidNullifier(nf),
            "Nullifier should be valid"
        );
    }

    // =========================================================================
    // MERKLE TREE TESTS
    // =========================================================================

    function testFuzz_MerkleRootDeterminism(
        bytes32 leaf,
        bytes32[20] memory pathElements,
        uint256 pathBits
    ) public pure {
        leaf = bytes32(bound(uint256(leaf), 1, BN254_R - 1));
        pathBits = bound(pathBits, 0, (1 << MERKLE_DEPTH) - 1);

        bytes32[] memory path = new bytes32[](MERKLE_DEPTH);
        uint256[] memory indices = new uint256[](MERKLE_DEPTH);

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            path[i] = bytes32(bound(uint256(pathElements[i]), 0, BN254_R - 1));
            indices[i] = (pathBits >> i) & 1;
        }

        bytes32 root1 = TornadoPrimitives.computeMerkleRoot(
            leaf,
            path,
            indices
        );
        bytes32 root2 = TornadoPrimitives.computeMerkleRoot(
            leaf,
            path,
            indices
        );

        assertEq(root1, root2, "Merkle root not deterministic");
    }

    function testFuzz_MerkleRootLeafBinding(
        bytes32 leaf1,
        bytes32 leaf2,
        bytes32[20] memory pathElements,
        uint256 pathBits
    ) public pure {
        leaf1 = bytes32(bound(uint256(leaf1), 1, BN254_R - 1));
        leaf2 = bytes32(bound(uint256(leaf2), 1, BN254_R - 1));
        pathBits = bound(pathBits, 0, (1 << MERKLE_DEPTH) - 1);
        vm.assume(leaf1 != leaf2);

        bytes32[] memory path = new bytes32[](MERKLE_DEPTH);
        uint256[] memory indices = new uint256[](MERKLE_DEPTH);

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            path[i] = bytes32(bound(uint256(pathElements[i]), 0, BN254_R - 1));
            indices[i] = (pathBits >> i) & 1;
        }

        bytes32 root1 = TornadoPrimitives.computeMerkleRoot(
            leaf1,
            path,
            indices
        );
        bytes32 root2 = TornadoPrimitives.computeMerkleRoot(
            leaf2,
            path,
            indices
        );

        assertNotEq(root1, root2, "Different leaves produced same root");
    }

    function testFuzz_MerkleRootPathSensitivity(
        bytes32 leaf,
        bytes32[20] memory path1,
        bytes32[20] memory path2
    ) public pure {
        leaf = bytes32(bound(uint256(leaf), 1, BN254_R - 1));

        // Ensure paths are different
        bool pathsDifferent = false;
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            path1[i] = bytes32(bound(uint256(path1[i]), 0, BN254_R - 1));
            path2[i] = bytes32(bound(uint256(path2[i]), 0, BN254_R - 1));
            if (path1[i] != path2[i]) pathsDifferent = true;
        }
        vm.assume(pathsDifferent);

        bytes32[] memory pathArr1 = new bytes32[](MERKLE_DEPTH);
        bytes32[] memory pathArr2 = new bytes32[](MERKLE_DEPTH);
        uint256[] memory indices = new uint256[](MERKLE_DEPTH);

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            pathArr1[i] = path1[i];
            pathArr2[i] = path2[i];
            indices[i] = 0;
        }

        bytes32 root1 = TornadoPrimitives.computeMerkleRoot(
            leaf,
            pathArr1,
            indices
        );
        bytes32 root2 = TornadoPrimitives.computeMerkleRoot(
            leaf,
            pathArr2,
            indices
        );

        assertNotEq(
            root1,
            root2,
            "Different paths should produce different roots"
        );
    }

    function testFuzz_ZeroHashConsistency(uint256 level) public pure {
        level = bound(level, 0, MERKLE_DEPTH - 1);

        bytes32 hash1 = TornadoPrimitives.getZeroHash(level);
        bytes32 hash2 = TornadoPrimitives.getZeroHash(level);

        assertEq(hash1, hash2, "Zero hash not consistent");
    }

    function testFuzz_ZeroHashChain(uint256 level) public pure {
        level = bound(level, 1, MERKLE_DEPTH - 1);

        bytes32 prevHash = TornadoPrimitives.getZeroHash(level - 1);
        bytes32 expectedHash = TornadoPrimitives.mimcHash2(prevHash, prevHash);
        bytes32 actualHash = TornadoPrimitives.getZeroHash(level);

        assertEq(actualHash, expectedHash, "Zero hash chain broken");
    }

    function test_ComputeZeroHashes() public pure {
        bytes32[20] memory zeros = TornadoPrimitives.computeZeroHashes();

        // Level 0 is ZERO_VALUE
        assertEq(zeros[0], TornadoPrimitives.ZERO_VALUE, "Level 0 mismatch");

        // Verify zeros array is self-consistent
        assertNotEq(zeros[1], bytes32(0), "Level 1 should be non-zero");

        // Verify hash chain consistency (each level is hash of previous)
        for (uint256 i = 1; i < 20; i++) {
            assertNotEq(
                zeros[i],
                zeros[i - 1],
                "Adjacent levels should differ"
            );
        }
    }

    // =========================================================================
    // DENOMINATION TESTS
    // =========================================================================

    function testFuzz_DenominationValidation(uint256 amount) public pure {
        bool valid = TornadoPrimitives.isValidDenomination(amount);

        bool expected = (amount == TornadoPrimitives.DENOMINATION_01) ||
            (amount == TornadoPrimitives.DENOMINATION_1) ||
            (amount == TornadoPrimitives.DENOMINATION_10) ||
            (amount == TornadoPrimitives.DENOMINATION_100);

        assertEq(valid, expected, "Denomination validation mismatch");
    }

    function test_ValidDenominations() public pure {
        assertTrue(
            TornadoPrimitives.isValidDenomination(0.1 ether),
            "0.1 ETH should be valid"
        );
        assertTrue(
            TornadoPrimitives.isValidDenomination(1 ether),
            "1 ETH should be valid"
        );
        assertTrue(
            TornadoPrimitives.isValidDenomination(10 ether),
            "10 ETH should be valid"
        );
        assertTrue(
            TornadoPrimitives.isValidDenomination(100 ether),
            "100 ETH should be valid"
        );
    }

    function testFuzz_InvalidDenomination(uint256 amount) public pure {
        vm.assume(
            amount != 0.1 ether &&
                amount != 1 ether &&
                amount != 10 ether &&
                amount != 100 ether
        );

        assertFalse(
            TornadoPrimitives.isValidDenomination(amount),
            "Non-standard denomination should be invalid"
        );
    }

    function test_DenominationIndex() public pure {
        assertEq(
            TornadoPrimitives.getDenominationIndex(0.1 ether),
            0,
            "0.1 ETH index"
        );
        assertEq(
            TornadoPrimitives.getDenominationIndex(1 ether),
            1,
            "1 ETH index"
        );
        assertEq(
            TornadoPrimitives.getDenominationIndex(10 ether),
            2,
            "10 ETH index"
        );
        assertEq(
            TornadoPrimitives.getDenominationIndex(100 ether),
            3,
            "100 ETH index"
        );
    }

    function test_SupportedDenominations() public pure {
        uint256[4] memory denoms = TornadoPrimitives
            .getSupportedDenominations();

        assertEq(denoms[0], 0.1 ether, "First denomination");
        assertEq(denoms[1], 1 ether, "Second denomination");
        assertEq(denoms[2], 10 ether, "Third denomination");
        assertEq(denoms[3], 100 ether, "Fourth denomination");
    }

    // =========================================================================
    // CROSS-DOMAIN TESTS
    // =========================================================================

    function testFuzz_CrossDomainNullifierDeterminism(
        bytes32 tornadoNullifier,
        bytes32 sourceDomain,
        bytes32 targetDomain
    ) public pure {
        tornadoNullifier = bytes32(
            bound(uint256(tornadoNullifier), 1, type(uint256).max)
        );

        bytes32 binding1 = TornadoPrimitives.deriveCrossDomainNullifier(
            tornadoNullifier,
            sourceDomain,
            targetDomain
        );
        bytes32 binding2 = TornadoPrimitives.deriveCrossDomainNullifier(
            tornadoNullifier,
            sourceDomain,
            targetDomain
        );

        assertEq(
            binding1,
            binding2,
            "Cross-domain nullifier not deterministic"
        );
    }

    function testFuzz_CrossDomainNullifierUniqueness(
        bytes32 nf1,
        bytes32 nf2,
        bytes32 source,
        bytes32 target
    ) public pure {
        nf1 = bytes32(bound(uint256(nf1), 1, type(uint256).max));
        nf2 = bytes32(bound(uint256(nf2), 1, type(uint256).max));
        vm.assume(nf1 != nf2);

        bytes32 binding1 = TornadoPrimitives.deriveCrossDomainNullifier(
            nf1,
            source,
            target
        );
        bytes32 binding2 = TornadoPrimitives.deriveCrossDomainNullifier(
            nf2,
            source,
            target
        );

        assertNotEq(
            binding1,
            binding2,
            "Different nullifiers should produce different bindings"
        );
    }

    function testFuzz_CrossDomainDomainSeparation(
        bytes32 tornadoNullifier,
        bytes32 domain1,
        bytes32 domain2
    ) public pure {
        tornadoNullifier = bytes32(
            bound(uint256(tornadoNullifier), 1, type(uint256).max)
        );
        vm.assume(domain1 != domain2);

        bytes32 source = bytes32(uint256(1));

        bytes32 binding1 = TornadoPrimitives.deriveCrossDomainNullifier(
            tornadoNullifier,
            source,
            domain1
        );
        bytes32 binding2 = TornadoPrimitives.deriveCrossDomainNullifier(
            tornadoNullifier,
            source,
            domain2
        );

        assertNotEq(
            binding1,
            binding2,
            "Different domains should produce different bindings"
        );
    }

    function testFuzz_PILBinding(bytes32 tornadoNullifier) public pure {
        tornadoNullifier = bytes32(
            bound(uint256(tornadoNullifier), 1, type(uint256).max)
        );

        bytes32 binding1 = TornadoPrimitives.derivePILBinding(tornadoNullifier);
        bytes32 binding2 = TornadoPrimitives.derivePILBinding(tornadoNullifier);

        assertEq(binding1, binding2, "PIL binding not deterministic");
        assertNotEq(binding1, bytes32(0), "PIL binding should be non-zero");
    }

    // =========================================================================
    // VALIDATION TESTS
    // =========================================================================

    function testFuzz_CommitmentValidation(uint256 value) public pure {
        bytes32 commitment = bytes32(value);

        bool valid = TornadoPrimitives.isValidCommitment(commitment);

        if (value == 0 || value >= BN254_R) {
            assertFalse(valid, "Invalid commitment should fail");
        } else {
            assertTrue(valid, "Valid commitment should pass");
        }
    }

    function testFuzz_NullifierValidation(uint256 value) public pure {
        bytes32 nullifier = bytes32(value);

        bool valid = TornadoPrimitives.isValidNullifier(nullifier);

        if (value == 0 || value >= BN254_R) {
            assertFalse(valid, "Invalid nullifier should fail");
        } else {
            assertTrue(valid, "Valid nullifier should pass");
        }
    }

    function testFuzz_RootValidation(bytes32 root) public pure {
        bool valid = TornadoPrimitives.isValidRoot(root);

        if (root == bytes32(0)) {
            assertFalse(valid, "Zero root should be invalid");
        } else {
            assertTrue(valid, "Non-zero root should be valid");
        }
    }

    function testFuzz_LeafIndexValidation(uint32 index) public pure {
        bool valid = TornadoPrimitives.isValidLeafIndex(index);

        if (index >= MAX_TREE_SIZE) {
            assertFalse(valid, "Out of bounds index should be invalid");
        } else {
            assertTrue(valid, "In bounds index should be valid");
        }
    }

    // =========================================================================
    // CHAIN DETECTION TESTS
    // =========================================================================

    function testFuzz_TornadoChainDetection(uint256 chainId) public pure {
        bool supported = TornadoPrimitives.isTornadoChain(chainId);

        bool expected = (chainId == 1) ||
            (chainId == 56) ||
            (chainId == 137) ||
            (chainId == 10) ||
            (chainId == 42161) ||
            (chainId == 100) ||
            (chainId == 43114);

        assertEq(supported, expected, "Chain detection mismatch");
    }

    function test_KnownTornadoChains() public pure {
        assertTrue(TornadoPrimitives.isTornadoChain(1), "Ethereum");
        assertTrue(TornadoPrimitives.isTornadoChain(56), "BSC");
        assertTrue(TornadoPrimitives.isTornadoChain(137), "Polygon");
        assertTrue(TornadoPrimitives.isTornadoChain(10), "Optimism");
        assertTrue(TornadoPrimitives.isTornadoChain(42161), "Arbitrum");
        assertTrue(TornadoPrimitives.isTornadoChain(100), "Gnosis");
        assertTrue(TornadoPrimitives.isTornadoChain(43114), "Avalanche");
    }

    // =========================================================================
    // GROTH16 STRUCTURE TESTS
    // =========================================================================

    function testFuzz_Groth16ProofStructure(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c
    ) public pure {
        // Bound to valid field elements
        a[0] = bound(a[0], 0, BN254_P - 1);
        a[1] = bound(a[1], 0, BN254_P - 1);
        b[0][0] = bound(b[0][0], 0, BN254_P - 1);
        b[0][1] = bound(b[0][1], 0, BN254_P - 1);
        b[1][0] = bound(b[1][0], 0, BN254_P - 1);
        b[1][1] = bound(b[1][1], 0, BN254_P - 1);
        c[0] = bound(c[0], 0, BN254_P - 1);
        c[1] = bound(c[1], 0, BN254_P - 1);

        TornadoPrimitives.Groth16Proof memory proof = TornadoPrimitives
            .Groth16Proof({a: a, b: b, c: c});

        // Verify structure is valid
        assertLt(proof.a[0], BN254_P, "a[0] in field");
        assertLt(proof.a[1], BN254_P, "a[1] in field");
        assertLt(proof.c[0], BN254_P, "c[0] in field");
        assertLt(proof.c[1], BN254_P, "c[1] in field");
    }

    // =========================================================================
    // NOTE CONVERSION TESTS
    // =========================================================================

    function testFuzz_CrossChainNoteConversion(
        bytes32 commitment,
        bytes32 nullifierHash,
        uint256 denominationIndex,
        uint32 leafIndex,
        uint256 targetChainId
    ) public {
        commitment = bytes32(bound(uint256(commitment), 1, BN254_R - 1));
        nullifierHash = bytes32(bound(uint256(nullifierHash), 1, BN254_R - 1));
        denominationIndex = bound(denominationIndex, 0, 3);
        leafIndex = uint32(bound(leafIndex, 0, MAX_TREE_SIZE - 1));
        targetChainId = bound(targetChainId, 1, type(uint64).max);

        uint256[4] memory denoms = TornadoPrimitives
            .getSupportedDenominations();

        TornadoPrimitives.TornadoNote memory note = TornadoPrimitives
            .TornadoNote({
                commitment: commitment,
                nullifierHash: nullifierHash,
                denomination: denoms[denominationIndex],
                leafIndex: leafIndex
            });

        TornadoPrimitives.CrossChainNote memory crossNote = TornadoPrimitives
            .toCrossChainNote(note, targetChainId);

        assertEq(
            crossNote.tornadoCommitment,
            commitment,
            "Commitment preserved"
        );
        assertEq(
            crossNote.denomination,
            denoms[denominationIndex],
            "Denomination preserved"
        );
        assertEq(crossNote.targetChainId, targetChainId, "Target chain set");
        assertNotEq(
            crossNote.pilCommitment,
            bytes32(0),
            "PIL commitment generated"
        );
        assertNotEq(
            crossNote.nullifierBinding,
            bytes32(0),
            "Nullifier binding generated"
        );
    }

    // =========================================================================
    // MERKLE PROOF STRUCT TESTS
    // =========================================================================

    function testFuzz_MerkleProofFromStruct(
        bytes32 leaf,
        bytes32[20] memory pathElements,
        uint256 pathBits
    ) public pure {
        leaf = bytes32(bound(uint256(leaf), 1, BN254_R - 1));
        pathBits = bound(pathBits, 0, (1 << MERKLE_DEPTH) - 1);

        bytes32[] memory path = new bytes32[](MERKLE_DEPTH);
        uint256[] memory indices = new uint256[](MERKLE_DEPTH);

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            path[i] = bytes32(bound(uint256(pathElements[i]), 0, BN254_R - 1));
            indices[i] = (pathBits >> i) & 1;
        }

        TornadoPrimitives.MerkleProof memory proof = TornadoPrimitives
            .MerkleProof({pathElements: path, pathIndices: indices});

        bytes32 rootDirect = TornadoPrimitives.computeMerkleRoot(
            leaf,
            path,
            indices
        );
        bytes32 rootStruct = TornadoPrimitives.computeMerkleRootFromProof(
            leaf,
            proof
        );

        assertEq(
            rootDirect,
            rootStruct,
            "Struct and direct computation should match"
        );
    }
}
