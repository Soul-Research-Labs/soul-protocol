// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../../contracts/pqc/DilithiumVerifier.sol";
import "../../contracts/pqc/SPHINCSPlusVerifier.sol";
import "../../contracts/pqc/KyberKEM.sol";
import "../../contracts/pqc/PQCRegistry.sol";
import "../../contracts/pqc/lib/HybridSignatureLib.sol";

/**
 * @title PostQuantumCryptoTest
 * @notice Comprehensive tests for Soul post-quantum cryptography implementation
 */
contract PostQuantumCryptoTest is Test {
    DilithiumVerifier public dilithiumVerifier;
    SPHINCSPlusVerifier public sphincsVerifier;
    KyberKEM public kyberKEM;
    PQCRegistry public registry;

    address public admin = address(0x1);
    address public alice = address(0x2);
    address public bob = address(0x3);

    // Test key material
    bytes public dilithium3PublicKey;
    bytes public dilithium3Signature;
    bytes public sphincsPublicKey;
    bytes public sphincsSignature;
    bytes public kyberPublicKey;

    function setUp() public {
        vm.startPrank(admin);

        // Deploy verifiers
        dilithiumVerifier = new DilithiumVerifier();
        sphincsVerifier = new SPHINCSPlusVerifier();
        kyberKEM = new KyberKEM();

        // Deploy registry with verifiers
        registry = new PQCRegistry(
            address(dilithiumVerifier),
            address(sphincsVerifier),
            address(kyberKEM)
        );

        // Generate mock keys of correct sizes
        dilithium3PublicKey = _generateBytes(1952);
        dilithium3Signature = _generateBytes(3293);
        sphincsPublicKey = _generateBytes(32);
        sphincsSignature = _generateBytes(7856);
        kyberPublicKey = _generateBytes(1184); // Kyber768

        // Add trusted keys for testing
        bytes32 d3KeyHash = keccak256(dilithium3PublicKey);
        bytes32 sphincsKeyHash = keccak256(sphincsPublicKey);

        dilithiumVerifier.addTrustedKey(d3KeyHash);
        sphincsVerifier.addTrustedKey(sphincsKeyHash);

        vm.stopPrank();
    }

    // ==========================================================================
    // DILITHIUM VERIFIER TESTS
    // ==========================================================================

    function test_DilithiumVerifier_Deployment() public view {
        assertTrue(dilithiumVerifier.useMockVerification());
        assertEq(dilithiumVerifier.owner(), admin);
    }

    function test_DilithiumVerifier_VerifyDilithium3() public {
        bytes32 message = keccak256("test message");

        bool valid = dilithiumVerifier.verifyDilithium3(
            message,
            dilithium3Signature,
            dilithium3PublicKey
        );

        assertTrue(valid);
    }

    function test_DilithiumVerifier_RejectInvalidKeySize() public {
        bytes32 message = keccak256("test message");
        bytes memory invalidKey = _generateBytes(100); // Wrong size

        vm.expectRevert(
            abi.encodeWithSelector(
                DilithiumVerifier.InvalidPublicKeySize.selector,
                1952,
                100
            )
        );
        dilithiumVerifier.verifyDilithium3(
            message,
            dilithium3Signature,
            invalidKey
        );
    }

    function test_DilithiumVerifier_RejectInvalidSignatureSize() public {
        bytes32 message = keccak256("test message");
        bytes memory invalidSig = _generateBytes(100);

        vm.expectRevert(
            abi.encodeWithSelector(
                DilithiumVerifier.InvalidSignatureSize.selector,
                3293,
                100
            )
        );
        dilithiumVerifier.verifyDilithium3(
            message,
            invalidSig,
            dilithium3PublicKey
        );
    }

    function test_DilithiumVerifier_Dilithium5() public {
        bytes memory d5PublicKey = _generateBytes(2592);
        bytes memory d5Signature = _generateBytes(4595);
        bytes32 message = keccak256("test message");

        // Add trusted key
        vm.prank(admin);
        dilithiumVerifier.addTrustedKey(keccak256(d5PublicKey));

        bool valid = dilithiumVerifier.verifyDilithium5(
            message,
            d5Signature,
            d5PublicKey
        );
        assertTrue(valid);
    }

    function test_DilithiumVerifier_BatchVerify() public {
        bytes32[] memory messages = new bytes32[](3);
        bytes[] memory signatures = new bytes[](3);
        bytes[] memory publicKeys = new bytes[](3);
        DilithiumVerifier.DilithiumLevel[]
            memory levels = new DilithiumVerifier.DilithiumLevel[](3);

        for (uint256 i = 0; i < 3; i++) {
            messages[i] = keccak256(abi.encode("message", i));
            signatures[i] = dilithium3Signature;
            publicKeys[i] = dilithium3PublicKey;
            levels[i] = DilithiumVerifier.DilithiumLevel.Level3;
        }

        bool allValid = dilithiumVerifier.batchVerify(
            messages,
            signatures,
            publicKeys,
            levels
        );
        assertTrue(allValid);
    }

    function test_DilithiumVerifier_GasEstimate() public view {
        uint256 level3Gas = dilithiumVerifier.estimateGas(
            DilithiumVerifier.DilithiumLevel.Level3
        );
        uint256 level5Gas = dilithiumVerifier.estimateGas(
            DilithiumVerifier.DilithiumLevel.Level5
        );

        assertEq(level3Gas, 150_000);
        assertEq(level5Gas, 200_000);
    }

    // ==========================================================================
    // SPHINCS+ VERIFIER TESTS
    // ==========================================================================

    function test_SPHINCSVerifier_Deployment() public view {
        assertTrue(sphincsVerifier.useMockVerification());
        assertEq(sphincsVerifier.owner(), admin);
    }

    function test_SPHINCSVerifier_Verify128s() public {
        bytes32 message = keccak256("sphincs test");

        bool valid = sphincsVerifier.verifySPHINCS128s(
            message,
            sphincsSignature,
            sphincsPublicKey
        );

        assertTrue(valid);
    }

    function test_SPHINCSVerifier_Verify256s() public {
        bytes memory pk256 = _generateBytes(64);
        bytes memory sig256 = _generateBytes(29792);
        bytes32 message = keccak256("sphincs 256 test");

        vm.prank(admin);
        sphincsVerifier.addTrustedKey(keccak256(pk256));

        bool valid = sphincsVerifier.verifySPHINCS256s(message, sig256, pk256);
        assertTrue(valid);
    }

    function test_SPHINCSVerifier_CacheVerification() public {
        bytes32 message = keccak256("cache test");

        // First verification
        bool valid1 = sphincsVerifier.verifySPHINCS128s(
            message,
            sphincsSignature,
            sphincsPublicKey
        );
        assertTrue(valid1);

        // Second verification should hit cache
        bool valid2 = sphincsVerifier.verifySPHINCS128s(
            message,
            sphincsSignature,
            sphincsPublicKey
        );
        assertTrue(valid2);
    }

    // ==========================================================================
    // KYBER KEM TESTS
    // ==========================================================================

    function test_KyberKEM_RegisterPublicKey() public {
        vm.prank(alice);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );

        KyberKEM.KyberKeyPair memory keyPair = kyberKEM.getKeyInfo(alice);
        assertTrue(keyPair.isActive);
        assertEq(uint8(keyPair.variant), uint8(KyberKEM.KyberVariant.Kyber768));
    }

    function test_KyberKEM_RejectDuplicateRegistration() public {
        vm.startPrank(alice);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );

        vm.expectRevert(KyberKEM.KeyAlreadyRegistered.selector);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );
        vm.stopPrank();
    }

    function test_KyberKEM_Encapsulate() public {
        // Register Bob's key
        vm.prank(bob);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );

        // Alice encapsulates for Bob
        vm.prank(alice);
        (
            bytes32 exchangeId,
            bytes memory ciphertext,
            bytes32 sharedSecretHash
        ) = kyberKEM.encapsulate(bob, keccak256("randomness"));

        assertTrue(exchangeId != bytes32(0));
        assertEq(ciphertext.length, 1088); // Kyber768 ciphertext size
        assertTrue(sharedSecretHash != bytes32(0));
    }

    function test_KyberKEM_ConfirmDecapsulation() public {
        vm.prank(bob);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );

        vm.prank(alice);
        (bytes32 exchangeId, , bytes32 sharedSecretHash) = kyberKEM.encapsulate(
            bob,
            keccak256("randomness")
        );

        // Bob confirms decapsulation
        vm.prank(bob);
        kyberKEM.confirmDecapsulation(exchangeId, sharedSecretHash);

        assertTrue(kyberKEM.isExchangeCompleted(exchangeId));
    }

    function test_KyberKEM_RevokeKey() public {
        vm.startPrank(alice);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );

        kyberKEM.revokeKey();

        KyberKEM.KyberKeyPair memory keyPair = kyberKEM.getKeyInfo(alice);
        assertFalse(keyPair.isActive);
        vm.stopPrank();
    }

    function test_KyberKEM_SizeValidation() public {
        (uint256 pkSize, uint256 skSize, uint256 ctSize) = kyberKEM.getSizes(
            KyberKEM.KyberVariant.Kyber768
        );

        assertEq(pkSize, 1184);
        assertEq(skSize, 2400);
        assertEq(ctSize, 1088);
    }

    // ==========================================================================
    // PQC REGISTRY TESTS
    // ==========================================================================

    function test_Registry_ConfigureAccount() public {
        bytes32 sigKeyHash = keccak256(dilithium3PublicKey);
        bytes32 kemKeyHash = keccak256(kyberPublicKey);

        vm.prank(alice);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            kemKeyHash,
            true
        );

        assertTrue(registry.isPQCEnabled(alice));

        PQCRegistry.AccountPQConfig memory config = registry.getAccountConfig(
            alice
        );
        assertEq(
            uint8(config.signatureAlgorithm),
            uint8(PQCRegistry.PQCPrimitive.Dilithium3)
        );
        assertEq(
            uint8(config.kemAlgorithm),
            uint8(PQCRegistry.PQCPrimitive.Kyber768)
        );
        assertTrue(config.hybridEnabled);
    }

    function test_Registry_VerifySignature() public {
        bytes32 sigKeyHash = keccak256(dilithium3PublicKey);

        vm.prank(alice);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            false
        );

        bytes32 message = keccak256("verify test");

        bool valid = registry.verifySignature(
            alice,
            message,
            dilithium3Signature,
            dilithium3PublicKey
        );

        assertTrue(valid);
    }

    function test_Registry_PhaseTransition() public {
        assertEq(
            uint8(registry.currentPhase()),
            uint8(PQCRegistry.TransitionPhase.ClassicalOnly)
        );

        vm.prank(admin);
        registry.transitionPhase(PQCRegistry.TransitionPhase.HybridOptional);

        assertEq(
            uint8(registry.currentPhase()),
            uint8(PQCRegistry.TransitionPhase.HybridOptional)
        );
    }

    function test_Registry_HybridMandatory() public {
        vm.prank(admin);
        registry.transitionPhase(PQCRegistry.TransitionPhase.HybridMandatory);

        bytes32 sigKeyHash = keccak256(dilithium3PublicKey);

        // Should fail without hybrid
        vm.prank(alice);
        vm.expectRevert(PQCRegistry.HybridRequired.selector);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            false // hybrid disabled
        );
    }

    function test_Registry_Statistics() public {
        bytes32 sigKeyHash = keccak256(dilithium3PublicKey);

        vm.prank(alice);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            keccak256(kyberPublicKey),
            true
        );

        PQCRegistry.PQCStats memory stats = registry.getStats();
        assertEq(stats.totalAccounts, 1);
        assertEq(stats.dilithiumAccounts, 1);
        assertEq(stats.kyberAccounts, 1);
    }

    function test_Registry_Recommendations() public view {
        (
            PQCRegistry.PQCPrimitive sig,
            PQCRegistry.PQCPrimitive kem,
            bool hybridEnabled
        ) = registry.getRecommendedConfig();

        assertEq(uint8(sig), uint8(PQCRegistry.PQCPrimitive.Dilithium3));
        assertEq(uint8(kem), uint8(PQCRegistry.PQCPrimitive.Kyber768));
        assertFalse(hybridEnabled); // ClassicalOnly phase
    }

    // ==========================================================================
    // HYBRID SIGNATURE LIBRARY TESTS
    // ==========================================================================

    function test_HybridSigLib_Create() public pure {
        bytes memory ecdsaSig = new bytes(65);
        bytes memory pqSig = new bytes(3293);
        bytes memory pqPubKey = new bytes(1952);

        HybridSignatureLib.HybridSig memory sig = HybridSignatureLib.create(
            HybridSignatureLib.ALG_DILITHIUM3,
            ecdsaSig,
            pqSig,
            pqPubKey
        );

        assertEq(sig.magic, HybridSignatureLib.HYBRID_SIG_MAGIC);
        assertEq(sig.version, HybridSignatureLib.VERSION);
        assertEq(sig.algorithm, HybridSignatureLib.ALG_DILITHIUM3);
    }

    function test_HybridSigLib_EncodeAndDecode() public {
        bytes memory ecdsaSig = new bytes(65);
        bytes memory pqSig = new bytes(100);
        bytes memory pqPubKey = new bytes(50);

        // Fill with some data
        for (uint256 i = 0; i < 65; i++) {
            ecdsaSig[i] = bytes1(uint8(i));
        }

        HybridSignatureLib.HybridSig memory original = HybridSignatureLib
            .create(
                HybridSignatureLib.ALG_DILITHIUM3,
                ecdsaSig,
                pqSig,
                pqPubKey
            );

        bytes memory encoded = HybridSignatureLib.encode(original);
        HybridSignatureLib.HybridSig memory decoded = this.decodeHybridSig(
            encoded
        );

        assertEq(decoded.magic, original.magic);
        assertEq(decoded.version, original.version);
        assertEq(decoded.algorithm, original.algorithm);
        assertEq(decoded.ecdsaSig.length, original.ecdsaSig.length);
    }

    // Helper to pass memory as calldata for decode
    function decodeHybridSig(
        bytes calldata encoded
    ) external pure returns (HybridSignatureLib.HybridSig memory) {
        return HybridSignatureLib.decode(encoded);
    }

    function test_HybridSigLib_IsHybridSignature() public {
        bytes memory ecdsaSig = new bytes(65);
        bytes memory pqSig = new bytes(100);
        bytes memory pqPubKey = new bytes(50);

        HybridSignatureLib.HybridSig memory sig = HybridSignatureLib.create(
            HybridSignatureLib.ALG_DILITHIUM3,
            ecdsaSig,
            pqSig,
            pqPubKey
        );

        bytes memory encoded = HybridSignatureLib.encode(sig);
        assertTrue(this.checkIsHybrid(encoded));

        bytes memory notHybrid = new bytes(100);
        assertFalse(this.checkIsHybrid(notHybrid));
    }

    // Helper to pass memory as calldata
    function checkIsHybrid(bytes calldata sig) external pure returns (bool) {
        return HybridSignatureLib.isHybridSignature(sig);
    }

    function test_HybridSigLib_EstimateSize() public pure {
        uint256 dilithium3Size = HybridSignatureLib.estimateSize(
            HybridSignatureLib.ALG_DILITHIUM3
        );
        uint256 sphincs256Size = HybridSignatureLib.estimateSize(
            HybridSignatureLib.ALG_SPHINCS_256S
        );

        // Dilithium3: base(77) + sig(3293) + pubkey(1952)
        assertEq(dilithium3Size, 5322);

        // SPHINCS-256s: base(77) + sig(29792) + pubkey(64)
        assertEq(sphincs256Size, 29933);
    }

    function test_HybridSigLib_AlgorithmName() public pure {
        string memory name = HybridSignatureLib.algorithmName(
            HybridSignatureLib.ALG_DILITHIUM3
        );
        assertEq(name, "Dilithium3");

        name = HybridSignatureLib.algorithmName(
            HybridSignatureLib.ALG_SPHINCS_128S
        );
        assertEq(name, "SPHINCS+-128s");
    }

    // ==========================================================================
    // GAS BENCHMARKS
    // ==========================================================================

    function test_GasBenchmark_DilithiumVerify() public {
        bytes32 message = keccak256("benchmark");

        uint256 gasBefore = gasleft();
        dilithiumVerifier.verifyDilithium3(
            message,
            dilithium3Signature,
            dilithium3PublicKey
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Dilithium3 verify gas (mock)", gasUsed);
        // Mock mode has overhead from key validation and storage lookups
        assertTrue(gasUsed < 500_000, "Dilithium3 gas exceeds limit");
    }

    function test_GasBenchmark_SPHINCSVerify() public {
        bytes32 message = keccak256("benchmark");

        uint256 gasBefore = gasleft();
        sphincsVerifier.verifySPHINCS128s(
            message,
            sphincsSignature,
            sphincsPublicKey
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("SPHINCS-128s verify gas (mock)", gasUsed);
        // Mock mode has overhead from signature size validation
        assertTrue(gasUsed < 800_000, "SPHINCS verify gas exceeds limit");
    }

    function test_GasBenchmark_KyberEncapsulate() public {
        vm.prank(bob);
        kyberKEM.registerPublicKey(
            kyberPublicKey,
            KyberKEM.KyberVariant.Kyber768
        );

        uint256 gasBefore = gasleft();
        vm.prank(alice);
        kyberKEM.encapsulate(bob, keccak256("randomness"));
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Kyber768 encapsulate gas (mock)", gasUsed);
        // Encapsulation includes storage writes for exchange tracking
        assertTrue(gasUsed < 2_500_000, "Kyber encapsulate gas exceeds limit");
    }

    // ==========================================================================
    // FUZZ TESTS
    // ==========================================================================

    function testFuzz_DilithiumKeySize(uint256 size) public {
        size = bound(size, 1, 10000);
        if (size == 1952) return; // Valid size, skip

        bytes memory invalidKey = _generateBytes(size);
        bytes32 message = keccak256("fuzz test");

        vm.expectRevert();
        dilithiumVerifier.verifyDilithium3(
            message,
            dilithium3Signature,
            invalidKey
        );
    }

    function testFuzz_KyberVariantSizes(uint8 variantNum) public view {
        variantNum = uint8(bound(variantNum, 0, 2));
        KyberKEM.KyberVariant variant = KyberKEM.KyberVariant(variantNum);

        (uint256 pkSize, uint256 skSize, uint256 ctSize) = kyberKEM.getSizes(
            variant
        );

        assertTrue(pkSize > 0);
        assertTrue(skSize > 0);
        assertTrue(ctSize > 0);
        assertTrue(pkSize < skSize); // SK always larger than PK
    }

    // ==========================================================================
    // HELPERS
    // ==========================================================================

    function _generateBytes(
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes memory data = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            // Generate pseudo-random but deterministic data
            data[i] = bytes1(
                uint8(uint256(keccak256(abi.encode(i, length))) % 256)
            );
        }
        return data;
    }
}
