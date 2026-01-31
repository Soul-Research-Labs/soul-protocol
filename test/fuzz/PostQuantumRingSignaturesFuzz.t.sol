// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import "../../contracts/privacy/PostQuantumRingSignatures.sol";

/**
 * @title PostQuantumRingSignaturesFuzz
 * @notice Fuzz tests for PostQuantumRingSignatures contract
 */
contract PostQuantumRingSignaturesFuzz is Test {
    PostQuantumRingSignatures public pqSig;

    // Constants from contract
    bytes32 public constant PQ_RING_DOMAIN = keccak256("Soul_PQ_RING_SIGNATURES_V1");
    uint256 public constant MLWE_K = 3;
    uint256 public constant MAX_RING_SIZE = 64;

    function setUp() public {
        pqSig = new PostQuantumRingSignatures();
    }

    // =========================================================================
    // SIS COMMITMENT FUZZING
    // =========================================================================

    function testFuzz_SISCommitmentDeterminism(uint256 value, bytes32 randomness) public {
        PostQuantumRingSignatures.SISCommitment memory c1 = pqSig.createSISCommitment(value, randomness);
        PostQuantumRingSignatures.SISCommitment memory c2 = pqSig.createSISCommitment(value, randomness);

        assertEq(c1.commitment, c2.commitment, "Commitment must be deterministic");
        assertEq(c1.opening, c2.opening, "Opening must be deterministic");
    }

    function testFuzz_SISCommitmentVerification(uint256 value, bytes32 randomness) public {
        value = bound(value, 0, type(uint256).max - 1);
        PostQuantumRingSignatures.SISCommitment memory comm = pqSig.createSISCommitment(value, randomness);
        
        bool valid = pqSig.verifySISCommitment(comm, value, randomness);
        assertTrue(valid, "Valid commitment verification failed");

        bool invalidValue = pqSig.verifySISCommitment(comm, value + 1, randomness);
        assertFalse(invalidValue, "Invalid value verification passed");

        bool invalidRandomness = pqSig.verifySISCommitment(comm, value, keccak256(abi.encode(randomness)));
        assertFalse(invalidRandomness, "Invalid randomness verification passed");
    }

    // =========================================================================
    // MLWE RING SIGNATURE FUZZING
    // =========================================================================

    function testFuzz_VerifyLatticeRingSignature_InvalidSize(uint256 listLength) public {
        listLength = bound(listLength, MAX_RING_SIZE + 1, 100);
        
        PostQuantumRingSignatures.PQRingMember[] memory ring = new PostQuantumRingSignatures.PQRingMember[](listLength);
        PostQuantumRingSignatures.LatticeRingSignature memory sig; // Empty sig is fine for this check

        vm.expectRevert(abi.encodeWithSelector(PostQuantumRingSignatures.InvalidRingSize.selector, listLength));
        pqSig.verifyLatticeRingSignature(bytes32(0), ring, sig);
    }
    
    function testFuzz_VerifyLatticeRingSignature_ZeroSize() public {
        PostQuantumRingSignatures.PQRingMember[] memory ring = new PostQuantumRingSignatures.PQRingMember[](0);
        PostQuantumRingSignatures.LatticeRingSignature memory sig;

        vm.expectRevert(abi.encodeWithSelector(PostQuantumRingSignatures.InvalidRingSize.selector, 0));
        pqSig.verifyLatticeRingSignature(bytes32(0), ring, sig);
    }

    function testFuzz_VerifyLatticeRingSignature_Valid(
        bytes32 messageHash,
        uint256 ringSize,
        bytes32 keyImage,
        uint8 seedBase
    ) public {
        ringSize = bound(ringSize, 1, MAX_RING_SIZE);
        vm.assume(keyImage != bytes32(0));

        // 1. Setup Ring
        PostQuantumRingSignatures.PQRingMember[] memory ring = new PostQuantumRingSignatures.PQRingMember[](ringSize);
        bytes32[] memory z = new bytes32[](ringSize * MLWE_K);
        bytes32[] memory hints = new bytes32[](ringSize); // Needs at least some hints

        // Fill ring with dummy data
        for (uint256 i = 0; i < ringSize; i++) {
            ring[i].publicKey.seedA = keccak256(abi.encodePacked("seedA", seedBase, i));
            ring[i].publicKey.t = new bytes32[](MLWE_K);
            for(uint256 k=0; k<MLWE_K; k++) {
                ring[i].publicKey.t[k] = keccak256(abi.encodePacked("t", seedBase, i, k));
            }
            // Fill z with non-zero (so norm check passes)
             for(uint256 k=0; k<MLWE_K; k++) {
                z[i*MLWE_K + k] = keccak256(abi.encodePacked("z", seedBase, i, k));
            }
            hints[i] = bytes32(uint256(1)); // Just needs length check
        }
        
        // 2. Compute Expected Challenge (Manually replicating contract logic)
        bytes memory packed = abi.encode(PQ_RING_DOMAIN, messageHash);
        for (uint256 i = 0; i < ring.length; i++) {
            packed = abi.encode(
                packed,
                ring[i].publicKey.seedA,
                ring[i].publicKey.t
            );
        }
        packed = abi.encode(packed, z, hints);
        bytes32 expectedChallenge = keccak256(packed);

        // 3. Construct Signature
        PostQuantumRingSignatures.LatticeRingSignature memory sig = PostQuantumRingSignatures.LatticeRingSignature({
            c: expectedChallenge,
            z: z,
            hints: hints,
            keyImage: keyImage
        });

        // 4. Verify
        bool valid = pqSig.verifyLatticeRingSignature(messageHash, ring, sig);
        assertTrue(valid, "Valid lattice signature failed");

        // 5. Check State
        assertTrue(pqSig.isPQKeyImageUsed(keyImage), "Key image not marked as used");
    }

    function testFuzz_VerifyLatticeRingSignature_DoubleSpend(
        bytes32 messageHash,
        bytes32 keyImage
    ) public {
        vm.assume(keyImage != bytes32(0));
        
        // Minimal valid setup from previous test
        uint256 ringSize = 1;
        PostQuantumRingSignatures.PQRingMember[] memory ring = new PostQuantumRingSignatures.PQRingMember[](ringSize);
        bytes32[] memory z = new bytes32[](MLWE_K);
        bytes32[] memory hints = new bytes32[](1);
        
        // Populate dummy non-zero
        ring[0].publicKey.seedA = bytes32(uint256(1));
        ring[0].publicKey.t = new bytes32[](MLWE_K);
        for(uint256 k=0; k<MLWE_K; k++) {
             ring[0].publicKey.t[k] = bytes32(uint256(1));
             z[k] = bytes32(uint256(1));
        }
        hints[0] = bytes32(uint256(1));

        // Compute Challenge
        bytes memory packed = abi.encode(PQ_RING_DOMAIN, messageHash);
        packed = abi.encode(packed, ring[0].publicKey.seedA, ring[0].publicKey.t);
        packed = abi.encode(packed, z, hints);
        bytes32 c = keccak256(packed);

        PostQuantumRingSignatures.LatticeRingSignature memory sig = PostQuantumRingSignatures.LatticeRingSignature({
            c: c,
            z: z,
            hints: hints,
            keyImage: keyImage
        });

        // First verified
        assertTrue(pqSig.verifyLatticeRingSignature(messageHash, ring, sig));

        // Second should revert
        vm.expectRevert(abi.encodeWithSelector(PostQuantumRingSignatures.KeyImageAlreadyUsed.selector, keyImage));
        pqSig.verifyLatticeRingSignature(messageHash, ring, sig);
    }

    // =========================================================================
    // KEY MANAGEMENT FUZZING
    // =========================================================================

    function testFuzz_RegisterPublicKey(bytes32 seedA, bytes32[3] memory t) public {
        bytes32[] memory tDyn = new bytes32[](3);
        tDyn[0] = t[0]; tDyn[1] = t[1]; tDyn[2] = t[2];

        bytes32 keyHash = pqSig.registerPublicKey(seedA, tDyn);
        
        bytes32 expectedHash = keccak256(abi.encode(seedA, tDyn));
        assertEq(keyHash, expectedHash, "Key hash mismatch");
    }
    
    function testFuzz_ComputeKeyImage(bytes32 secret, bytes32 pubKeyHash) public {
         bytes32 expected = keccak256(abi.encodePacked(
             secret, 
             keccak256(abi.encodePacked("LATTICE_HASH_TO_POINT", pubKeyHash))
         ));
         
         bytes32 actual = pqSig.computeKeyImage(secret, pubKeyHash);
         assertEq(actual, expected, "Key image computation mismatch");
    }

    // =========================================================================
    // HYBRID SIGNATURE FUZZING
    // =========================================================================

    function testFuzz_VerifyHybridSignature_Valid(
         bytes32 messageHash,
         bytes32 classicalKeyImage,
         bytes32 pqKeyImage,
         bytes32 classicalChallenge
    ) public {
        vm.assume(classicalKeyImage != bytes32(0));
        vm.assume(pqKeyImage != bytes32(0));
        vm.assume(classicalChallenge != bytes32(0));
        
        // 1. Setup Data
        uint256 ringSize = 1; 
        bytes32[] memory ring = new bytes32[](ringSize);
        bytes32[] memory classicalResponses = new bytes32[](ringSize);
        // Setup so classical verification passes: 
        // uint256(recomputed) % (2**128) == uint256(classicalChallenge) % (2**128)
        // recomputed = keccak256(abi.encode(messageHash, ring, responses));
        
        // We can't easily force the hash collision, but we can bypass it if we 
        // calculate challenge AFTER responses. But wait, verifyClassicalComponent logic is:
        // recomputed % 2^128 == challenge % 2^128.
        // It does NOT enforce challenge == recomputed. It compares truncated values.
        
        // Actually, the easiest way to pass `verifyClassicalComponent` in fuzzing:
        // The contract checks: 
        //     bytes32 recomputed = keccak256(abi.encode(messageHash, ring, responses));
        //     return uint256(recomputed) % (2 ** 128) == uint256(challenge) % (2 ** 128);
        
        // So we calculate `recomputed` first based on random inputs, then set `challenge` 
        // to have the same lower 128 bits. The upper bits can be random (fuzzed).
        
        bytes32 recomputed = keccak256(abi.encode(messageHash, ring, classicalResponses));
        
        // Construct challenge to match lower 128 bits
        uint256 mask = (1 << 128) - 1;
        bytes32 validChallenge = bytes32(
            (uint256(classicalChallenge) & ~mask) | (uint256(recomputed) & mask)
        );
        // Ensure non-zero
        if (validChallenge == bytes32(0)) validChallenge = bytes32(uint256(1)); 

        // 2. Setup PQ Component (Simplified verify)
        // _verifyPQComponent checks:
        //   expectedChallenge = keccak256(abi.encode(PQ_RING_DOMAIN, messageHash, sig.z, sig.keyImage));
        //   sig.c == expectedChallenge
        
        bytes32[] memory z = new bytes32[](1); z[0] = bytes32(uint256(1)); // len > 0
        
        bytes32 expectedPQChallenge = keccak256(
            abi.encode(PQ_RING_DOMAIN, messageHash, z, pqKeyImage)
        );
        
        PostQuantumRingSignatures.LatticeRingSignature memory pqSigStruct = PostQuantumRingSignatures.LatticeRingSignature({
            c: expectedPQChallenge,
            z: z,
            hints: new bytes32[](0), // Not used in _verifyPQComponent
            keyImage: pqKeyImage
        });

        // 3. Setup Binding
        bytes32 bindingHash = keccak256(
            abi.encode(
                validChallenge,
                classicalKeyImage,
                expectedPQChallenge, // pqSig.c
                pqKeyImage
            )
        );
        
        PostQuantumRingSignatures.HybridRingSignature memory sig = PostQuantumRingSignatures.HybridRingSignature({
            classicalChallenge: validChallenge,
            classicalResponses: classicalResponses,
            classicalKeyImage: classicalKeyImage,
            pqSignature: pqSigStruct,
            bindingHash: bindingHash
        });

        // 4. Verify
        bool valid = pqSig.verifyHybridSignature(messageHash, ring, sig);
        assertTrue(valid, "Valid hybrid signature failed");
    }
}
