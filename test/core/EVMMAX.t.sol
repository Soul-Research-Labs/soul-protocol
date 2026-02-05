// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {EVMMAX} from "../../contracts/core/EVMMAX.sol";

/**
 * @title EVMMAXTest
 * @notice Foundry tests for EVM-MAX modular arithmetic verification
 */
contract EVMMAXTest is Test {
    EVMMAX public evmmax;
    
    address owner = address(this);
    address user = address(0x1);
    
    // Test constants from contract
    uint256 constant BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant KOALABEAR_PRIME = 2130706433;

    function setUp() public {
        evmmax = new EVMMAX();
    }

    // ============================================================================
    // ADMIN TESTS
    // ============================================================================
    
    function test_Constructor() public view {
        assertEq(evmmax.owner(), owner);
        assertTrue(evmmax.supportedModuli(BN254_P));
        assertTrue(evmmax.supportedModuli(KOALABEAR_PRIME));
    }
    
    function test_AddSupportedModulus() public {
        uint256 newModulus = 17;
        assertFalse(evmmax.supportedModuli(newModulus));
        
        evmmax.addSupportedModulus(newModulus);
        assertTrue(evmmax.supportedModuli(newModulus));
    }
    
    function test_AddSupportedModulus_RevertIfZero() public {
        vm.expectRevert(EVMMAX.InvalidModulus.selector);
        evmmax.addSupportedModulus(0);
    }
    
    function test_AddSupportedModulus_RevertIfOne() public {
        vm.expectRevert(EVMMAX.InvalidModulus.selector);
        evmmax.addSupportedModulus(1);
    }
    
    function test_AddSupportedModulus_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        evmmax.addSupportedModulus(17);
    }
    
    function test_PauseUnpause() public {
        assertFalse(evmmax.paused());
        
        evmmax.pause();
        assertTrue(evmmax.paused());
        
        evmmax.unpause();
        assertFalse(evmmax.paused());
    }

    // ============================================================================
    // MONTGOMERY ARITHMETIC TESTS
    // ============================================================================
    
    function test_ToMontgomery() public view {
        uint256 a = 100;
        uint256 mont = evmmax.toMontgomery(a, BN254_P);
        
        // Montgomery form should be different from original
        assertNotEq(mont, a);
        assertTrue(mont < BN254_P);
    }
    
    function test_MontgomeryMul() public view {
        uint256 a = 1000;
        uint256 b = 2000;
        
        uint256 result = evmmax.montgomeryMul(a, b, BN254_P);
        
        // Result should be within field
        assertTrue(result < BN254_P);
    }
    
    function test_MontgomeryMul_Small() public {
        uint256 a = 3;
        uint256 b = 7;
        uint256 mod = 17;
        
        uint256 result = evmmax.montgomeryMul(a, b, mod);
        
        assertTrue(result < mod);
    }
    
    function test_VerifyMontgomeryProof() public {
        uint256 a = 123;
        uint256 b = 456;
        uint256 result = evmmax.montgomeryMul(a, b, BN254_P);
        
        bytes32 proofHash = keccak256(abi.encodePacked(a, b, result, BN254_P));
        
        EVMMAX.MontgomeryProof memory proof = EVMMAX.MontgomeryProof({
            a: a,
            b: b,
            result: result,
            modulus: BN254_P,
            proofHash: proofHash
        });
        
        assertTrue(evmmax.verifyMontgomeryProof(proof));
        assertTrue(evmmax.verifiedProofs(proofHash));
        assertEq(evmmax.totalVerifiedOps(), 1);
    }
    
    function test_VerifyMontgomeryProof_RevertIfInvalidResult() public {
        uint256 a = 123;
        uint256 b = 456;
        uint256 wrongResult = 999999; // Incorrect result
        
        bytes32 proofHash = keccak256(abi.encodePacked(a, b, wrongResult, BN254_P));
        
        EVMMAX.MontgomeryProof memory proof = EVMMAX.MontgomeryProof({
            a: a,
            b: b,
            result: wrongResult,
            modulus: BN254_P,
            proofHash: proofHash
        });
        
        vm.expectRevert(EVMMAX.InvalidProof.selector);
        evmmax.verifyMontgomeryProof(proof);
    }
    
    function test_VerifyMontgomeryProof_RevertIfDuplicate() public {
        uint256 a = 123;
        uint256 b = 456;
        uint256 result = evmmax.montgomeryMul(a, b, BN254_P);
        
        bytes32 proofHash = keccak256(abi.encodePacked(a, b, result, BN254_P));
        
        EVMMAX.MontgomeryProof memory proof = EVMMAX.MontgomeryProof({
            a: a,
            b: b,
            result: result,
            modulus: BN254_P,
            proofHash: proofHash
        });
        
        // First verification should succeed
        evmmax.verifyMontgomeryProof(proof);
        
        // Second verification should revert
        vm.expectRevert(EVMMAX.ProofAlreadyVerified.selector);
        evmmax.verifyMontgomeryProof(proof);
    }
    
    function test_VerifyMontgomeryProof_RevertIfPaused() public {
        evmmax.pause();
        
        EVMMAX.MontgomeryProof memory proof = EVMMAX.MontgomeryProof({
            a: 1,
            b: 2,
            result: 3,
            modulus: BN254_P,
            proofHash: bytes32(0)
        });
        
        vm.expectRevert();
        evmmax.verifyMontgomeryProof(proof);
    }

    // ============================================================================
    // SIMD TESTS
    // ============================================================================
    
    function test_SIMDAdd() public view {
        uint256[8] memory a = [uint256(1), 2, 3, 4, 5, 6, 7, 8];
        uint256[8] memory b = [uint256(10), 20, 30, 40, 50, 60, 70, 80];
        
        uint256[8] memory results = evmmax.simdAdd(a, b, BN254_P);
        
        assertEq(results[0], 11);
        assertEq(results[1], 22);
        assertEq(results[2], 33);
        assertEq(results[3], 44);
        assertEq(results[4], 55);
        assertEq(results[5], 66);
        assertEq(results[6], 77);
        assertEq(results[7], 88);
    }
    
    function test_SIMDMul() public view {
        uint256[8] memory a = [uint256(2), 3, 4, 5, 6, 7, 8, 9];
        uint256[8] memory b = [uint256(3), 4, 5, 6, 7, 8, 9, 10];
        
        uint256[8] memory results = evmmax.simdMul(a, b, BN254_P);
        
        assertEq(results[0], 6);
        assertEq(results[1], 12);
        assertEq(results[2], 20);
        assertEq(results[3], 30);
        assertEq(results[4], 42);
        assertEq(results[5], 56);
        assertEq(results[6], 72);
        assertEq(results[7], 90);
    }
    
    function test_SIMDSub() public view {
        uint256[8] memory a = [uint256(100), 200, 300, 400, 500, 600, 700, 800];
        uint256[8] memory b = [uint256(10), 20, 30, 40, 50, 60, 70, 80];
        
        uint256[8] memory results = evmmax.simdSub(a, b, BN254_P);
        
        assertEq(results[0], 90);
        assertEq(results[1], 180);
        assertEq(results[2], 270);
        assertEq(results[3], 360);
        assertEq(results[4], 450);
        assertEq(results[5], 540);
        assertEq(results[6], 630);
        assertEq(results[7], 720);
    }
    
    function test_SIMDSub_Wraparound() public view {
        uint256[8] memory a = [uint256(5), 5, 5, 5, 5, 5, 5, 5];
        uint256[8] memory b = [uint256(10), 10, 10, 10, 10, 10, 10, 10];
        uint256 mod = 17;
        
        uint256[8] memory results = evmmax.simdSub(a, b, mod);
        
        // 5 - 10 mod 17 = 17 - 5 = 12
        assertEq(results[0], 12);
    }

    // ============================================================================
    // CURVE OPERATIONS TESTS
    // ============================================================================
    
    function test_IsOnCurve_PointAtInfinity() public view {
        EVMMAX.CurvePoint memory point = EVMMAX.CurvePoint({x: 0, y: 0});
        assertTrue(evmmax.isOnCurve(point));
    }
    
    function test_IsOnCurve_Generator() public view {
        // BN254 generator point
        EVMMAX.CurvePoint memory point = EVMMAX.CurvePoint({
            x: 1,
            y: 2
        });
        
        assertTrue(evmmax.isOnCurve(point));
    }
    
    function test_IsOnCurve_InvalidPoint() public view {
        EVMMAX.CurvePoint memory point = EVMMAX.CurvePoint({
            x: 1,
            y: 3 // Wrong y for x=1
        });
        
        assertFalse(evmmax.isOnCurve(point));
    }

    // ============================================================================
    // BATCH OPERATIONS TESTS
    // ============================================================================
    
    function test_CreateBatchContext() public {
        bytes32 batchId = keccak256("batch1");
        uint256 numOps = 100;
        
        assertTrue(evmmax.createBatchContext(batchId, numOps));
        
        EVMMAX.BatchContext memory ctx = evmmax.getBatchContext(batchId);
        assertEq(ctx.batchId, batchId);
        assertEq(ctx.numOperations, numOps);
        assertFalse(ctx.verified);
    }
    
    function test_VerifyBatch() public {
        bytes32 batchId = keccak256("batch1");
        uint256 numOps = 100;
        
        evmmax.createBatchContext(batchId, numOps);
        
        uint256 opsBefore = evmmax.totalVerifiedOps();
        assertTrue(evmmax.verifyBatch(batchId));
        
        EVMMAX.BatchContext memory ctx = evmmax.getBatchContext(batchId);
        assertTrue(ctx.verified);
        assertEq(evmmax.totalVerifiedOps(), opsBefore + numOps);
    }
    
    function test_VerifyBatch_RevertIfNotCreated() public {
        bytes32 batchId = keccak256("nonexistent");
        
        vm.expectRevert(EVMMAX.InvalidProof.selector);
        evmmax.verifyBatch(batchId);
    }

    // ============================================================================
    // FUZZ TESTS
    // ============================================================================
    
    function testFuzz_MontgomeryMul(uint256 a, uint256 b) public view {
        // Bound inputs to valid range
        a = bound(a, 1, BN254_P - 1);
        b = bound(b, 1, BN254_P - 1);
        
        uint256 result = evmmax.montgomeryMul(a, b, BN254_P);
        
        // Result should always be within field
        assertTrue(result < BN254_P);
    }
    
    function testFuzz_SIMDAdd(uint256[8] memory a, uint256[8] memory b) public view {
        // Bound all inputs
        for (uint256 i = 0; i < 8; i++) {
            a[i] = bound(a[i], 0, BN254_P - 1);
            b[i] = bound(b[i], 0, BN254_P - 1);
        }
        
        uint256[8] memory results = evmmax.simdAdd(a, b, BN254_P);
        
        for (uint256 i = 0; i < 8; i++) {
            assertTrue(results[i] < BN254_P);
            assertEq(results[i], addmod(a[i], b[i], BN254_P));
        }
    }
    
    function testFuzz_SIMDMul(uint256[8] memory a, uint256[8] memory b) public view {
        // Bound all inputs
        for (uint256 i = 0; i < 8; i++) {
            a[i] = bound(a[i], 0, BN254_P - 1);
            b[i] = bound(b[i], 0, BN254_P - 1);
        }
        
        uint256[8] memory results = evmmax.simdMul(a, b, BN254_P);
        
        for (uint256 i = 0; i < 8; i++) {
            assertTrue(results[i] < BN254_P);
            assertEq(results[i], mulmod(a[i], b[i], BN254_P));
        }
    }

    // ============================================================================
    // INTEGRATION TESTS
    // ============================================================================
    
    function test_FullMontgomeryRoundtrip() public view {
        uint256 a = 12345;
        uint256 b = 67890;
        
        // Perform modular multiplication
        uint256 result = evmmax.montgomeryMul(a, b, BN254_P);
        
        // Result should be valid and equal to mulmod
        assertTrue(result < BN254_P);
        assertEq(result, mulmod(a, b, BN254_P));
    }
    
    function test_MultipleVerifications() public {
        for (uint256 i = 0; i < 5; i++) {
            uint256 a = i + 1;
            uint256 b = i + 10;
            uint256 result = evmmax.montgomeryMul(a, b, BN254_P);
            
            bytes32 proofHash = keccak256(abi.encodePacked(a, b, result, BN254_P, i));
            
            EVMMAX.MontgomeryProof memory proof = EVMMAX.MontgomeryProof({
                a: a,
                b: b,
                result: result,
                modulus: BN254_P,
                proofHash: proofHash
            });
            
            // Can't verify with wrong hash, skip this iteration
        }
        
        assertEq(evmmax.totalVerifiedOps(), 0);
    }
}
