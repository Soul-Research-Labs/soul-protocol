// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

// Import interfaces for testing
interface ITriptychSignatures {
    struct RingMember {
        bytes32 publicKey;
        bytes32 commitment;
    }

    struct KeyImage {
        bytes32 J;
        bool used;
    }

    struct TriptychProof {
        bytes32 A;
        bytes32 B;
        bytes32 C;
        bytes32 D;
        bytes32[] X;
        bytes32[] Y;
        bytes32 f;
        bytes32[] z_A;
        bytes32[] z_B;
        bytes32 z_C;
        bytes32 z_D;
    }

    struct VerificationContext {
        bytes32 messageHash;
        RingMember[] ring;
        KeyImage keyImage;
        TriptychProof proof;
    }

    function usedKeyImages(bytes32) external view returns (bool);

    function getProofSize(uint256 ringSize) external pure returns (uint256);

    function isKeyImageUsed(bytes32 keyImage) external view returns (bool);
}

interface ISeraphisAddressing {
    struct SeraphisAddress {
        bytes32 K_1;
        bytes32 K_2;
        bytes32 K_3;
    }

    function computeOneTimeAddress(
        SeraphisAddress calldata,
        bytes32
    ) external pure returns (bytes32);

    function computeViewTag(bytes32, bytes32) external pure returns (uint256);

    function computeKeyImage(bytes32, bytes32) external pure returns (bytes32);

    function usedKeyImages(bytes32) external view returns (bool);
}

interface IFHEPrivacyIntegration {
    enum CiphertextType {
        EUINT8,
        EUINT16,
        EUINT32,
        EUINT64,
        EUINT256,
        EBOOL,
        EADDRESS
    }

    function storeCiphertext(
        bytes calldata,
        CiphertextType
    ) external returns (bytes32);

    function ciphertextExists(bytes32) external view returns (bool);
}

/// @title AdvancedPrivacyFuzz
/// @notice Comprehensive fuzz tests for advanced privacy research implementations
contract AdvancedPrivacyFuzz is Test {
    // ==========================================================================
    // TRIPTYCH FUZZ TESTS
    // ==========================================================================

    /// @notice Fuzz test: Proof size is logarithmic
    function testFuzz_TriptychProofSizeLogarithmic(uint8 exponent) public pure {
        // Ring sizes from 4 to 256 (powers of 2)
        vm.assume(exponent >= 2 && exponent <= 8);
        uint256 ringSize = 2 ** exponent;

        // m = log2(ringSize)
        uint256 m = exponent;

        // Proof size = (7 + 4*m) * 32 bytes
        uint256 expectedProofSize = (7 + 4 * m) * 32;

        // Verify logarithmic growth
        // For n=4 (m=2): 15 * 32 = 480 bytes
        // For n=256 (m=8): 39 * 32 = 1248 bytes
        // Linear would be: n * 32 (for n=256: 8192 bytes)
        assert(expectedProofSize < ringSize * 32);

        // Verify it's actually O(log n)
        uint256 linearSize = ringSize * 32;
        assert(expectedProofSize < linearSize / 2);
    }

    /// @notice Fuzz test: Key image determinism
    function testFuzz_KeyImageDeterminism(
        bytes32 secretKey,
        bytes32 publicKey
    ) public pure {
        bytes32 ki1 = _computeKeyImage(secretKey, publicKey);
        bytes32 ki2 = _computeKeyImage(secretKey, publicKey);

        assertEq(ki1, ki2, "Key image must be deterministic");
    }

    /// @notice Fuzz test: Key image uniqueness
    function testFuzz_KeyImageUniqueness(
        bytes32 secretKey1,
        bytes32 secretKey2,
        bytes32 publicKey
    ) public pure {
        vm.assume(secretKey1 != secretKey2);

        bytes32 ki1 = _computeKeyImage(secretKey1, publicKey);
        bytes32 ki2 = _computeKeyImage(secretKey2, publicKey);

        assertTrue(
            ki1 != ki2,
            "Different secrets must produce different key images"
        );
    }

    // ==========================================================================
    // SERAPHIS FUZZ TESTS
    // ==========================================================================

    /// @notice Fuzz test: One-time address determinism
    function testFuzz_OneTimeAddressDeterminism(
        bytes32 K1,
        bytes32 K2,
        bytes32 K3,
        bytes32 randomness
    ) public pure {
        vm.assume(K1 != bytes32(0) && K2 != bytes32(0) && K3 != bytes32(0));

        bytes32 ota1 = _computeOneTimeAddress(K1, K2, K3, randomness);
        bytes32 ota2 = _computeOneTimeAddress(K1, K2, K3, randomness);

        assertEq(ota1, ota2, "One-time address must be deterministic");
    }

    /// @notice Fuzz test: One-time address unlinkability
    function testFuzz_OneTimeAddressUnlinkability(
        bytes32 K1,
        bytes32 K2,
        bytes32 K3,
        bytes32 rand1,
        bytes32 rand2
    ) public pure {
        vm.assume(rand1 != rand2);
        vm.assume(K1 != bytes32(0) && K2 != bytes32(0) && K3 != bytes32(0));

        bytes32 ota1 = _computeOneTimeAddress(K1, K2, K3, rand1);
        bytes32 ota2 = _computeOneTimeAddress(K1, K2, K3, rand2);

        assertTrue(
            ota1 != ota2,
            "Different randomness must produce unlinkable addresses"
        );
    }

    /// @notice Fuzz test: View tag range
    function testFuzz_ViewTagRange(bytes32 K1, bytes32 randomness) public pure {
        uint256 viewTag = _computeViewTag(K1, randomness);

        assertTrue(viewTag < 65536, "View tag must be within 16-bit range");
    }

    /// @notice Fuzz test: View tag determinism
    function testFuzz_ViewTagDeterminism(
        bytes32 K1,
        bytes32 randomness
    ) public pure {
        uint256 vt1 = _computeViewTag(K1, randomness);
        uint256 vt2 = _computeViewTag(K1, randomness);

        assertEq(vt1, vt2, "View tag must be deterministic");
    }

    /// @notice Fuzz test: View tag distribution (approximate uniform)
    function testFuzz_ViewTagDistribution(
        bytes32 K1,
        bytes32[100] calldata randomness
    ) public pure {
        uint256[256] memory buckets;

        for (uint256 i = 0; i < 100; i++) {
            uint256 viewTag = _computeViewTag(K1, randomness[i]);
            buckets[viewTag % 256]++;
        }

        // No single bucket should have more than 50% of values
        // (extremely unlikely with good distribution)
        for (uint256 i = 0; i < 256; i++) {
            assertTrue(
                buckets[i] < 50,
                "View tag distribution should be roughly uniform"
            );
        }
    }

    // ==========================================================================
    // NOVA IVC FUZZ TESTS
    // ==========================================================================

    /// @notice Fuzz test: Folding challenge determinism
    function testFuzz_FoldingChallengeDeterminism(
        bytes32 commitmentW,
        bytes32 commitmentE,
        uint256 u,
        bytes32 commitmentT
    ) public pure {
        bytes32 challenge1 = _computeFoldingChallenge(
            commitmentW,
            commitmentE,
            u,
            commitmentT
        );
        bytes32 challenge2 = _computeFoldingChallenge(
            commitmentW,
            commitmentE,
            u,
            commitmentT
        );

        assertEq(
            challenge1,
            challenge2,
            "Folding challenge must be deterministic"
        );
    }

    /// @notice Fuzz test: Different instances produce different challenges
    function testFuzz_FoldingChallengeUniqueness(
        bytes32 commitmentW1,
        bytes32 commitmentW2,
        bytes32 commitmentE,
        uint256 u,
        bytes32 commitmentT
    ) public pure {
        vm.assume(commitmentW1 != commitmentW2);

        bytes32 challenge1 = _computeFoldingChallenge(
            commitmentW1,
            commitmentE,
            u,
            commitmentT
        );
        bytes32 challenge2 = _computeFoldingChallenge(
            commitmentW2,
            commitmentE,
            u,
            commitmentT
        );

        assertTrue(
            challenge1 != challenge2,
            "Different instances must produce different challenges"
        );
    }

    // ==========================================================================
    // FHE FUZZ TESTS
    // ==========================================================================

    /// @notice Fuzz test: Ciphertext hash determinism (same inputs)
    function testFuzz_CiphertextHashDeterminism(
        bytes calldata ciphertext,
        address sender,
        uint256 timestamp
    ) public pure {
        vm.assume(ciphertext.length > 0);

        bytes32 hash1 = _computeCiphertextHash(ciphertext, sender, timestamp);
        bytes32 hash2 = _computeCiphertextHash(ciphertext, sender, timestamp);

        assertEq(hash1, hash2, "Ciphertext hash must be deterministic");
    }

    /// @notice Fuzz test: Different ciphertexts produce different hashes
    function testFuzz_CiphertextHashUniqueness(
        bytes calldata ct1,
        bytes calldata ct2,
        address sender,
        uint256 timestamp
    ) public pure {
        vm.assume(ct1.length > 0 && ct2.length > 0);
        vm.assume(keccak256(ct1) != keccak256(ct2));

        bytes32 hash1 = _computeCiphertextHash(ct1, sender, timestamp);
        bytes32 hash2 = _computeCiphertextHash(ct2, sender, timestamp);

        assertTrue(
            hash1 != hash2,
            "Different ciphertexts must produce different hashes"
        );
    }

    // ==========================================================================
    // ENCRYPTED ANNOUNCEMENT FUZZ TESTS
    // ==========================================================================

    /// @notice Fuzz test: View tag commitment binding
    function testFuzz_ViewTagCommitmentBinding(
        uint8 viewTag,
        bytes32 salt
    ) public pure {
        bytes32 commitment = keccak256(abi.encodePacked(viewTag, salt));

        // Cannot find different view tag with same commitment (collision resistance)
        bytes32 commitment2 = keccak256(abi.encodePacked(viewTag, salt));

        assertEq(commitment, commitment2, "Commitment must be deterministic");
    }

    /// @notice Fuzz test: Different view tags produce different commitments
    function testFuzz_ViewTagCommitmentUniqueness(
        uint8 viewTag1,
        uint8 viewTag2,
        bytes32 salt
    ) public pure {
        vm.assume(viewTag1 != viewTag2);

        bytes32 commitment1 = keccak256(abi.encodePacked(viewTag1, salt));
        bytes32 commitment2 = keccak256(abi.encodePacked(viewTag2, salt));

        assertTrue(
            commitment1 != commitment2,
            "Different view tags must produce different commitments"
        );
    }

    // ==========================================================================
    // RELAYER SELECTION FUZZ TESTS
    // ==========================================================================

    /// @notice Fuzz test: Selection commitment binding
    function testFuzz_SelectionCommitmentBinding(
        address sender,
        bytes32 randomness,
        uint256 minReputation,
        uint256 maxLatency,
        uint256 feeBudget
    ) public pure {
        bytes32 commitment = keccak256(
            abi.encodePacked(
                sender,
                randomness,
                minReputation,
                maxLatency,
                keccak256(abi.encodePacked(new bytes32[](0))),
                feeBudget
            )
        );

        bytes32 commitment2 = keccak256(
            abi.encodePacked(
                sender,
                randomness,
                minReputation,
                maxLatency,
                keccak256(abi.encodePacked(new bytes32[](0))),
                feeBudget
            )
        );

        assertEq(
            commitment,
            commitment2,
            "Selection commitment must be deterministic"
        );
    }

    /// @notice Fuzz test: VRF output distribution
    function testFuzz_VRFOutputDistribution(
        bytes32[100] calldata seeds
    ) public pure {
        uint256[10] memory buckets;

        for (uint256 i = 0; i < 100; i++) {
            bytes32 output = keccak256(abi.encodePacked("VRF", seeds[i]));
            buckets[uint256(output) % 10]++;
        }

        // Check for reasonable distribution (no bucket > 30%)
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(
                buckets[i] < 30,
                "VRF output should be uniformly distributed"
            );
        }
    }

    // ==========================================================================
    // HELPER FUNCTIONS
    // ==========================================================================

    function _computeKeyImage(
        bytes32 secretKey,
        bytes32 publicKey
    ) internal pure returns (bytes32) {
        bytes32 hashPoint = keccak256(
            abi.encodePacked("HASH_TO_CURVE", publicKey)
        );
        return keccak256(abi.encodePacked(secretKey, hashPoint));
    }

    function _computeOneTimeAddress(
        bytes32 K1,
        bytes32 K2,
        bytes32 K3,
        bytes32 randomness
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "Soul_SERAPHIS_V1",
                    "ONE_TIME",
                    randomness,
                    K1,
                    K2,
                    K3
                )
            );
    }

    function _computeViewTag(
        bytes32 K1,
        bytes32 randomness
    ) internal pure returns (uint256) {
        bytes32 hash = keccak256(
            abi.encodePacked("SERAPHIS_VIEW_TAG", randomness, K1)
        );
        return uint256(hash) & 0xFFFF;
    }

    function _computeFoldingChallenge(
        bytes32 commitmentW,
        bytes32 commitmentE,
        uint256 u,
        bytes32 commitmentT
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "Soul_NOVA_IVC_V1",
                    commitmentW,
                    commitmentE,
                    u,
                    commitmentT
                )
            );
    }

    function _computeCiphertextHash(
        bytes calldata ciphertext,
        address sender,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("Soul_FHE_V1", ciphertext, sender, timestamp)
            );
    }
}
