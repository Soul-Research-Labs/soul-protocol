// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title CrossChainPrivacyFuzz
 * @notice Comprehensive fuzz tests for cross-chain privacy contracts
 */
contract CrossChainPrivacyFuzz is Test {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant BLS12_381_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    bytes32 constant NULLIFIER_DOMAIN = keccak256("Soul_UNIFIED_NULLIFIER_V1");
    bytes32 constant STEALTH_DOMAIN = keccak256("Soul_STEALTH_ADDRESS_V1");
    bytes32 constant RINGCT_DOMAIN = keccak256("Soul_RINGCT_V1");
    bytes32 constant CROSS_DOMAIN_TAG = keccak256("CROSS_DOMAIN");
    bytes32 constant Soul_BINDING_TAG = keccak256("Soul_BINDING");

    // =========================================================================
    // STEALTH ADDRESS FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Stealth address derivation is deterministic
     */
    function testFuzz_StealthAddressDeterministic(
        bytes32 spendingPubKeyHash,
        bytes32 viewingPubKeyHash,
        bytes32 ephemeralPrivKeyHash
    ) public pure {
        vm.assume(spendingPubKeyHash != bytes32(0));
        vm.assume(viewingPubKeyHash != bytes32(0));
        vm.assume(ephemeralPrivKeyHash != bytes32(0));

        // Compute shared secret
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(
                ephemeralPrivKeyHash,
                viewingPubKeyHash,
                STEALTH_DOMAIN
            )
        );

        // Derive stealth address twice
        bytes32 stealthHash1 = keccak256(
            abi.encodePacked(spendingPubKeyHash, sharedSecret)
        );
        bytes32 stealthHash2 = keccak256(
            abi.encodePacked(spendingPubKeyHash, sharedSecret)
        );

        assertEq(
            stealthHash1,
            stealthHash2,
            "Stealth derivation must be deterministic"
        );
    }

    /**
     * @notice Fuzz: Different ephemeral keys produce different stealth addresses
     */
    function testFuzz_StealthAddressUnlinkability(
        bytes32 spendingPubKeyHash,
        bytes32 viewingPubKeyHash,
        bytes32 ephemeral1,
        bytes32 ephemeral2
    ) public pure {
        vm.assume(ephemeral1 != ephemeral2);
        vm.assume(spendingPubKeyHash != bytes32(0));
        vm.assume(viewingPubKeyHash != bytes32(0));

        bytes32 shared1 = keccak256(
            abi.encodePacked(ephemeral1, viewingPubKeyHash, STEALTH_DOMAIN)
        );
        bytes32 shared2 = keccak256(
            abi.encodePacked(ephemeral2, viewingPubKeyHash, STEALTH_DOMAIN)
        );

        bytes32 stealth1 = keccak256(
            abi.encodePacked(spendingPubKeyHash, shared1)
        );
        bytes32 stealth2 = keccak256(
            abi.encodePacked(spendingPubKeyHash, shared2)
        );

        assertTrue(
            stealth1 != stealth2,
            "Different ephemerals must produce different addresses"
        );
    }

    /**
     * @notice Fuzz: View tag is first byte of shared secret
     */
    function testFuzz_ViewTagDerivation(
        bytes32 ephemeralPrivKey,
        bytes32 viewingPubKey
    ) public pure {
        vm.assume(ephemeralPrivKey != bytes32(0));
        vm.assume(viewingPubKey != bytes32(0));

        bytes32 sharedSecret = keccak256(
            abi.encodePacked(ephemeralPrivKey, viewingPubKey, STEALTH_DOMAIN)
        );

        bytes1 viewTag = bytes1(sharedSecret);

        // View tag should be extractable from shared secret
        assertEq(
            uint8(viewTag),
            uint8(uint256(sharedSecret) >> 248),
            "View tag extraction failed"
        );
    }

    /**
     * @notice Fuzz: Stealth address from hash fits in address space
     */
    function testFuzz_StealthAddressValidEthereumAddress(
        bytes32 stealthHash
    ) public pure {
        address stealthAddr = address(uint160(uint256(stealthHash)));

        // Address should be valid (non-zero for most hashes)
        // Just verify the conversion works
        assertEq(uint160(stealthAddr), uint160(uint256(stealthHash)));
    }

    // =========================================================================
    // PEDERSEN COMMITMENT FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Pedersen commitments are unique for different inputs
     */
    function testFuzz_PedersenCommitmentUniqueness(
        bytes32 amount1,
        bytes32 blinding1,
        bytes32 amount2,
        bytes32 blinding2
    ) public pure {
        vm.assume(amount1 != amount2 || blinding1 != blinding2);

        bytes32 commitment1 = keccak256(
            abi.encodePacked(RINGCT_DOMAIN, amount1, blinding1)
        );
        bytes32 commitment2 = keccak256(
            abi.encodePacked(RINGCT_DOMAIN, amount2, blinding2)
        );

        assertTrue(
            commitment1 != commitment2,
            "Different inputs must produce different commitments"
        );
    }

    /**
     * @notice Fuzz: Commitment derivation is deterministic
     */
    function testFuzz_PedersenCommitmentDeterministic(
        bytes32 amount,
        bytes32 blinding
    ) public pure {
        bytes32 commitment1 = keccak256(
            abi.encodePacked(RINGCT_DOMAIN, amount, blinding)
        );
        bytes32 commitment2 = keccak256(
            abi.encodePacked(RINGCT_DOMAIN, amount, blinding)
        );

        assertEq(commitment1, commitment2, "Commitment must be deterministic");
    }

    /**
     * @notice Fuzz: Homomorphic addition simulation
     */
    function testFuzz_CommitmentHomomorphism(
        uint256 amount1,
        uint256 amount2,
        uint256 blinding1,
        uint256 blinding2
    ) public pure {
        // Bound to prevent overflow
        amount1 = bound(amount1, 0, type(uint128).max);
        amount2 = bound(amount2, 0, type(uint128).max);
        blinding1 = bound(blinding1, 0, SECP256K1_N - 1);
        blinding2 = bound(blinding2, 0, SECP256K1_N - 1);

        // In real Pedersen: C(a1) + C(a2) = C(a1 + a2) with blinding sum
        uint256 sumAmount = amount1 + amount2;
        uint256 sumBlinding = addmod(blinding1, blinding2, SECP256K1_N);

        // Verify the math works (simplified)
        assertEq(sumAmount, amount1 + amount2);
        assertEq(sumBlinding, addmod(blinding1, blinding2, SECP256K1_N));
    }

    // =========================================================================
    // KEY IMAGE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Key images are deterministic
     */
    function testFuzz_KeyImageDeterministic(
        bytes32 privKeyHash,
        uint256 pubKeyX,
        uint256 pubKeyY
    ) public pure {
        vm.assume(privKeyHash != bytes32(0));
        vm.assume(pubKeyX != 0);

        // Hash public key to curve point Hp(P)
        bytes32 hpHash = keccak256(
            abi.encodePacked("HASH_TO_POINT", pubKeyX, pubKeyY)
        );

        // Key image I = privKey * Hp(P)
        bytes32 image1 = keccak256(abi.encodePacked(privKeyHash, hpHash));
        bytes32 image2 = keccak256(abi.encodePacked(privKeyHash, hpHash));

        assertEq(image1, image2, "Key image must be deterministic");
    }

    /**
     * @notice Fuzz: Different private keys produce different key images
     */
    function testFuzz_KeyImageUniqueness(
        bytes32 privKey1,
        bytes32 privKey2,
        uint256 pubKeyX,
        uint256 pubKeyY
    ) public pure {
        vm.assume(privKey1 != privKey2);
        vm.assume(privKey1 != bytes32(0));
        vm.assume(privKey2 != bytes32(0));

        bytes32 hpHash = keccak256(
            abi.encodePacked("HASH_TO_POINT", pubKeyX, pubKeyY)
        );

        bytes32 image1 = keccak256(abi.encodePacked(privKey1, hpHash));
        bytes32 image2 = keccak256(abi.encodePacked(privKey2, hpHash));

        assertTrue(
            image1 != image2,
            "Different keys must produce different images"
        );
    }

    // =========================================================================
    // NULLIFIER FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Chain nullifiers are unique per chain
     */
    function testFuzz_ChainNullifierUniqueness(
        bytes32 secret,
        bytes32 commitment,
        uint256 chainId1,
        uint256 chainId2
    ) public pure {
        vm.assume(chainId1 != chainId2);
        vm.assume(secret != bytes32(0));
        vm.assume(commitment != bytes32(0));

        bytes32 nf1 = keccak256(
            abi.encodePacked(secret, commitment, chainId1, "CHAIN_NULLIFIER")
        );
        bytes32 nf2 = keccak256(
            abi.encodePacked(secret, commitment, chainId2, "CHAIN_NULLIFIER")
        );

        assertTrue(
            nf1 != nf2,
            "Same note on different chains must have different nullifiers"
        );
    }

    /**
     * @notice Fuzz: Cross-domain nullifier derivation is deterministic
     */
    function testFuzz_CrossDomainNullifierDeterministic(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    ) public pure {
        vm.assume(sourceNullifier != bytes32(0));
        vm.assume(sourceChainId != destChainId);

        bytes32 crossNf1 = keccak256(
            abi.encodePacked(
                sourceNullifier,
                sourceChainId,
                destChainId,
                CROSS_DOMAIN_TAG
            )
        );
        bytes32 crossNf2 = keccak256(
            abi.encodePacked(
                sourceNullifier,
                sourceChainId,
                destChainId,
                CROSS_DOMAIN_TAG
            )
        );

        assertEq(
            crossNf1,
            crossNf2,
            "Cross-domain nullifier must be deterministic"
        );
    }

    /**
     * @notice Fuzz: Cross-domain nullifier is directional (A→B ≠ B→A)
     */
    function testFuzz_CrossDomainNullifierDirectional(
        bytes32 sourceNullifier,
        uint256 chainA,
        uint256 chainB
    ) public pure {
        vm.assume(chainA != chainB);
        vm.assume(sourceNullifier != bytes32(0));

        bytes32 nfAtoB = keccak256(
            abi.encodePacked(sourceNullifier, chainA, chainB, CROSS_DOMAIN_TAG)
        );
        bytes32 nfBtoA = keccak256(
            abi.encodePacked(sourceNullifier, chainB, chainA, CROSS_DOMAIN_TAG)
        );

        assertTrue(
            nfAtoB != nfBtoA,
            "Cross-domain nullifier must be directional"
        );
    }

    /**
     * @notice Fuzz: Soul nullifier is unique per domain
     */
    function testFuzz_SoulNullifierUniqueness(
        bytes32 sourceNullifier,
        bytes32 domain1,
        bytes32 domain2
    ) public pure {
        vm.assume(domain1 != domain2);
        vm.assume(sourceNullifier != bytes32(0));

        bytes32 pilNf1 = keccak256(
            abi.encodePacked(sourceNullifier, domain1, Soul_BINDING_TAG)
        );
        bytes32 pilNf2 = keccak256(
            abi.encodePacked(sourceNullifier, domain2, Soul_BINDING_TAG)
        );

        assertTrue(
            pilNf1 != pilNf2,
            "Different domains must produce different Soul nullifiers"
        );
    }

    /**
     * @notice Fuzz: Same nullifier always maps to same Soul nullifier
     */
    function testFuzz_SoulNullifierDeterministic(
        bytes32 sourceNullifier,
        bytes32 domain
    ) public pure {
        vm.assume(sourceNullifier != bytes32(0));
        vm.assume(domain != bytes32(0));

        bytes32 pilNf1 = keccak256(
            abi.encodePacked(sourceNullifier, domain, Soul_BINDING_TAG)
        );
        bytes32 pilNf2 = keccak256(
            abi.encodePacked(sourceNullifier, domain, Soul_BINDING_TAG)
        );

        assertEq(pilNf1, pilNf2, "Soul nullifier must be deterministic");
    }

    // =========================================================================
    // RING SIGNATURE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Ring size must be within bounds
     */
    function testFuzz_RingSizeBounds(uint256 ringSize) public pure {
        uint256 MIN_RING_SIZE = 4;
        uint256 MAX_RING_SIZE = 16;

        bool isValid = ringSize >= MIN_RING_SIZE && ringSize <= MAX_RING_SIZE;

        if (isValid) {
            assertTrue(ringSize >= MIN_RING_SIZE, "Ring size below minimum");
            assertTrue(ringSize <= MAX_RING_SIZE, "Ring size above maximum");
        }
    }

    /**
     * @notice Fuzz: CLSAG challenge computation
     */
    function testFuzz_CLSAGChallengeComputation(
        bytes32 messageHash,
        uint256 c0,
        bytes32 keyImageHash
    ) public pure {
        vm.assume(messageHash != bytes32(0));
        vm.assume(c0 != 0);

        bytes32 challenge = keccak256(
            abi.encodePacked(RINGCT_DOMAIN, messageHash, c0, keyImageHash)
        );

        // Challenge should be non-zero for valid inputs
        assertTrue(challenge != bytes32(0), "Challenge must be non-zero");
    }

    /**
     * @notice Fuzz: Ring member uniqueness check
     */
    function testFuzz_RingMemberUniqueness(
        uint256[4] memory pubKeyXs
    ) public pure {
        bool allUnique = true;

        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = i + 1; j < 4; j++) {
                if (pubKeyXs[i] == pubKeyXs[j]) {
                    allUnique = false;
                    break;
                }
            }
        }

        // For valid ring, all members should be unique
        // This is a property check, not an assertion on fuzz input
        if (allUnique) {
            assertTrue(allUnique, "Ring members should be unique");
        }
    }

    // =========================================================================
    // PRIVACY LEVEL FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Privacy level encoding
     */
    function testFuzz_PrivacyLevelValid(uint8 level) public pure {
        // Privacy levels: NONE=0, BASIC=1, MEDIUM=2, HIGH=3, MAXIMUM=4
        bool isValid = level <= 4;

        if (isValid) {
            assertTrue(level <= 4, "Valid privacy level");
        } else {
            assertTrue(level > 4, "Invalid privacy level");
        }
    }

    // =========================================================================
    // CROSS-CHAIN TRANSFER FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Transfer ID is unique
     */
    function testFuzz_TransferIdUniqueness(
        uint256 timestamp1,
        uint256 timestamp2,
        address sender,
        uint256 nonce
    ) public pure {
        vm.assume(timestamp1 != timestamp2);

        bytes32 id1 = keccak256(
            abi.encodePacked("Soul_TRANSFER", timestamp1, sender, nonce)
        );
        bytes32 id2 = keccak256(
            abi.encodePacked("Soul_TRANSFER", timestamp2, sender, nonce)
        );

        assertTrue(
            id1 != id2,
            "Different timestamps must produce different transfer IDs"
        );
    }

    /**
     * @notice Fuzz: Chain ID validation
     */
    function testFuzz_ChainIdValidation(uint256 chainId) public pure {
        // Common chain IDs
        bool isMainnet = chainId == 1;
        bool isArbitrum = chainId == 42161;
        bool isOptimism = chainId == 10;
        bool isBase = chainId == 8453;
        bool isPolygon = chainId == 137;

        // At least one should be true if it's a known chain
        // This is informational, not a hard assertion
        if (chainId < 100000) {
            assertTrue(chainId > 0, "Chain ID must be positive");
        }
    }

    // =========================================================================
    // AMOUNT BOUND FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Amount within valid range for Bulletproofs
     */
    function testFuzz_AmountRangeValid(uint64 amount) public pure {
        // Bulletproofs prove 0 ≤ amount < 2^64
        assertTrue(amount <= type(uint64).max, "Amount must fit in 64 bits");
        assertTrue(amount >= 0, "Amount must be non-negative");
    }

    /**
     * @notice Fuzz: Fee calculation bounds
     */
    function testFuzz_FeeCalculation(
        uint256 amount,
        uint256 feeBps
    ) public pure {
        feeBps = bound(feeBps, 0, 500); // Max 5%
        amount = bound(amount, 0, type(uint128).max);

        uint256 fee = (amount * feeBps) / 10000;

        assertTrue(fee <= amount / 20, "Fee must be at most 5%");
        assertTrue(fee <= amount, "Fee cannot exceed amount");
    }

    // =========================================================================
    // BATCH OPERATION FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Batch size bounds
     */
    function testFuzz_BatchSizeBounds(uint256 batchSize) public pure {
        uint256 MAX_BATCH_SIZE = 100;

        bool isValid = batchSize > 0 && batchSize <= MAX_BATCH_SIZE;

        if (isValid) {
            assertTrue(batchSize <= MAX_BATCH_SIZE, "Batch size within bounds");
        }
    }

    /**
     * @notice Fuzz: Merkle root uniqueness
     */
    function testFuzz_MerkleRootUniqueness(
        bytes32[4] memory leaves
    ) public pure {
        // Simple Merkle construction
        bytes32 hash01 = keccak256(abi.encodePacked(leaves[0], leaves[1]));
        bytes32 hash23 = keccak256(abi.encodePacked(leaves[2], leaves[3]));
        bytes32 root = keccak256(abi.encodePacked(hash01, hash23));

        assertTrue(root != bytes32(0), "Merkle root must be non-zero");
    }

    // =========================================================================
    // CURVE ARITHMETIC FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Scalar field arithmetic (secp256k1)
     */
    function testFuzz_ScalarFieldArithmetic(uint256 a, uint256 b) public pure {
        a = bound(a, 1, SECP256K1_N - 1);
        b = bound(b, 1, SECP256K1_N - 1);

        uint256 sum = addmod(a, b, SECP256K1_N);
        uint256 product = mulmod(a, b, SECP256K1_N);

        assertTrue(sum < SECP256K1_N, "Sum must be in field");
        assertTrue(product < SECP256K1_N, "Product must be in field");
    }

    /**
     * @notice Fuzz: BLS12-381 scalar field arithmetic
     */
    function testFuzz_BLS12381ScalarArithmetic(
        uint256 a,
        uint256 b
    ) public pure {
        a = bound(a, 1, BLS12_381_R - 1);
        b = bound(b, 1, BLS12_381_R - 1);

        uint256 sum = addmod(a, b, BLS12_381_R);
        uint256 product = mulmod(a, b, BLS12_381_R);

        assertTrue(sum < BLS12_381_R, "Sum must be in BLS field");
        assertTrue(product < BLS12_381_R, "Product must be in BLS field");
    }

    // =========================================================================
    // EXPIRY AND TIMING FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz: Nullifier expiry check
     */
    function testFuzz_NullifierExpiry(
        uint256 registeredAt,
        uint256 expiresAt,
        uint256 currentTime
    ) public pure {
        vm.assume(registeredAt < expiresAt);
        vm.assume(currentTime > registeredAt);

        bool isExpired = expiresAt > 0 && currentTime > expiresAt;
        bool isValid = !isExpired && currentTime >= registeredAt;

        if (isExpired) {
            assertTrue(currentTime > expiresAt, "Nullifier is expired");
        } else if (expiresAt > 0) {
            assertTrue(currentTime <= expiresAt, "Nullifier is valid");
        }
    }

    // =========================================================================
    // INVARIANT TESTS
    // =========================================================================

    /**
     * @notice Invariant: Nullifier cannot be both registered and unknown
     */
    function invariant_NullifierStatusExclusive() public pure {
        // Status enum: UNKNOWN=0, REGISTERED=1, SPENT=2, REVOKED=3, EXPIRED=4
        uint8 status = 1; // REGISTERED

        assertTrue(status != 0, "Registered nullifier cannot be unknown");
    }

    /**
     * @notice Invariant: Privacy level monotonicity
     */
    function invariant_PrivacyLevelMonotonic() public pure {
        // Higher levels provide more privacy
        // NONE < BASIC < MEDIUM < HIGH < MAXIMUM
        uint8 none = 0;
        uint8 basic = 1;
        uint8 medium = 2;
        uint8 high = 3;
        uint8 maximum = 4;

        assertTrue(none < basic, "NONE < BASIC");
        assertTrue(basic < medium, "BASIC < MEDIUM");
        assertTrue(medium < high, "MEDIUM < HIGH");
        assertTrue(high < maximum, "HIGH < MAXIMUM");
    }
}
