// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/verifiers/GasOptimizedVerifier.sol";

/// @dev Wrapper contract to test GasOptimizedVerifier library internal functions
contract GasOptimizedVerifierWrapper {
    using GasOptimizedVerifier for *;

    function ecAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) external view returns (uint256, uint256) {
        return GasOptimizedVerifier.ecAdd(x1, y1, x2, y2);
    }

    function ecMul(
        uint256 px,
        uint256 py,
        uint256 s
    ) external view returns (uint256, uint256) {
        return GasOptimizedVerifier.ecMul(px, py, s);
    }

    function ecNegate(
        uint256 x,
        uint256 y
    ) external pure returns (uint256, uint256) {
        return GasOptimizedVerifier.ecNegate(x, y);
    }

    function isOnCurve(uint256 x, uint256 y) external pure returns (bool) {
        return GasOptimizedVerifier.isOnCurve(x, y);
    }

    function modInverse(uint256 a, uint256 p) external view returns (uint256) {
        return GasOptimizedVerifier.modInverse(a, p);
    }

    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) external view returns (uint256) {
        return GasOptimizedVerifier.modExp(base, exponent, modulus);
    }

    function hashToField(bytes memory data) external pure returns (uint256) {
        return GasOptimizedVerifier.hashToField(data);
    }

    function hashToCurve(
        bytes memory data
    ) external view returns (uint256, uint256) {
        return GasOptimizedVerifier.hashToCurve(data);
    }

    function pairing2(
        uint256[2] memory a1,
        uint256[2][2] memory b1,
        uint256[2] memory a2,
        uint256[2][2] memory b2
    ) external view returns (bool) {
        return GasOptimizedVerifier.pairing2(a1, b1, a2, b2);
    }

    function getPrimeQ() external pure returns (uint256) {
        return GasOptimizedVerifier.PRIME_Q;
    }

    function getPrimeR() external pure returns (uint256) {
        return GasOptimizedVerifier.PRIME_R;
    }
}

contract GasOptimizedVerifierTest is Test {
    GasOptimizedVerifierWrapper public wrapper;
    BatchProofVerifier public batchVerifier;

    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant PRIME_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // BN254 generator point
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    function setUp() public {
        wrapper = new GasOptimizedVerifierWrapper();
        batchVerifier = new BatchProofVerifier();
    }

    // ============= Constants =============

    function test_PrimeQ() public view {
        assertEq(wrapper.getPrimeQ(), PRIME_Q);
    }

    function test_PrimeR() public view {
        assertEq(wrapper.getPrimeR(), PRIME_R);
    }

    // ============= isOnCurve =============

    function test_IsOnCurve_Generator() public view {
        // G1 = (1, 2) is the BN254 generator and should be on curve y^2 = x^3 + 3
        assertTrue(wrapper.isOnCurve(G1_X, G1_Y));
    }

    function test_IsOnCurve_Identity() public view {
        // (0, 0) is the point at infinity — not on curve per the strict y^2 = x^3 + 3 check
        // 0^2 = 0, 0^3 + 3 = 3, 0 != 3
        assertFalse(wrapper.isOnCurve(0, 0));
    }

    function test_IsOnCurve_InvalidPoint() public view {
        assertFalse(wrapper.isOnCurve(1, 1));
    }

    function test_IsOnCurve_OutOfRange() public view {
        assertFalse(wrapper.isOnCurve(PRIME_Q, 0));
        assertFalse(wrapper.isOnCurve(0, PRIME_Q));
    }

    // ============= ecAdd =============

    function test_EcAdd_IdentityPlusGenerator() public view {
        // (0,0) + G = G (identity element behavior for precompile)
        (uint256 x, uint256 y) = wrapper.ecAdd(0, 0, G1_X, G1_Y);
        assertEq(x, G1_X);
        assertEq(y, G1_Y);
    }

    function test_EcAdd_GeneratorPlusIdentity() public view {
        (uint256 x, uint256 y) = wrapper.ecAdd(G1_X, G1_Y, 0, 0);
        assertEq(x, G1_X);
        assertEq(y, G1_Y);
    }

    function test_EcAdd_Doubling() public view {
        // G + G = 2G
        (uint256 x2g, uint256 y2g) = wrapper.ecAdd(G1_X, G1_Y, G1_X, G1_Y);
        // 2G should be on curve
        assertTrue(wrapper.isOnCurve(x2g, y2g));

        // 2G via ecMul should give same result
        (uint256 mx, uint256 my) = wrapper.ecMul(G1_X, G1_Y, 2);
        assertEq(x2g, mx);
        assertEq(y2g, my);
    }

    // ============= ecMul =============

    function test_EcMul_ByZero() public view {
        (uint256 x, uint256 y) = wrapper.ecMul(G1_X, G1_Y, 0);
        assertEq(x, 0);
        assertEq(y, 0);
    }

    function test_EcMul_ByOne() public view {
        (uint256 x, uint256 y) = wrapper.ecMul(G1_X, G1_Y, 1);
        assertEq(x, G1_X);
        assertEq(y, G1_Y);
    }

    function test_EcMul_ResultOnCurve() public view {
        (uint256 x, uint256 y) = wrapper.ecMul(G1_X, G1_Y, 42);
        assertTrue(wrapper.isOnCurve(x, y));
    }

    function test_EcMul_ByOrder() public view {
        // G * PRIME_R = 0 (identity) for BN254
        (uint256 x, uint256 y) = wrapper.ecMul(G1_X, G1_Y, PRIME_R);
        assertEq(x, 0);
        assertEq(y, 0);
    }

    // ============= ecNegate =============

    function test_EcNegate_Generator() public view {
        (uint256 nx, uint256 ny) = wrapper.ecNegate(G1_X, G1_Y);
        assertEq(nx, G1_X);
        assertEq(ny, PRIME_Q - G1_Y);
    }

    function test_EcNegate_Identity() public view {
        (uint256 x, uint256 y) = wrapper.ecNegate(0, 0);
        assertEq(x, 0);
        assertEq(y, 0);
    }

    function test_EcNegate_DoubleNegate() public view {
        (uint256 nx, uint256 ny) = wrapper.ecNegate(G1_X, G1_Y);
        (uint256 nnx, uint256 nny) = wrapper.ecNegate(nx, ny);
        assertEq(nnx, G1_X);
        assertEq(nny, G1_Y);
    }

    function test_EcNegate_AddNegation() public view {
        // G + (-G) = 0
        (uint256 nx, uint256 ny) = wrapper.ecNegate(G1_X, G1_Y);
        (uint256 rx, uint256 ry) = wrapper.ecAdd(G1_X, G1_Y, nx, ny);
        assertEq(rx, 0);
        assertEq(ry, 0);
    }

    // ============= modExp =============

    function test_ModExp_Simple() public view {
        // 2^10 mod 1024 = 0
        assertEq(wrapper.modExp(2, 10, 1024), 0);
        // 2^10 mod 1023 = 1
        assertEq(wrapper.modExp(2, 10, 1023), 1);
    }

    function test_ModExp_Large() public view {
        // Fermat's little theorem: a^(p-1) = 1 mod p for prime p
        uint256 result = wrapper.modExp(7, PRIME_R - 1, PRIME_R);
        assertEq(result, 1);
    }

    // ============= modInverse =============

    function test_ModInverse() public view {
        // a * a^(-1) = 1 mod p
        uint256 a = 42;
        uint256 inv = wrapper.modInverse(a, PRIME_R);
        assertEq(mulmod(a, inv, PRIME_R), 1);
    }

    // ============= hashToField =============

    function test_HashToField_Deterministic() public view {
        uint256 h1 = wrapper.hashToField(bytes("hello"));
        uint256 h2 = wrapper.hashToField(bytes("hello"));
        assertEq(h1, h2);
    }

    function test_HashToField_InRange() public view {
        uint256 h = wrapper.hashToField(bytes("test data"));
        assertTrue(h < PRIME_R);
    }

    function test_HashToField_DifferentInputs() public view {
        uint256 h1 = wrapper.hashToField(bytes("input_a"));
        uint256 h2 = wrapper.hashToField(bytes("input_b"));
        assertTrue(h1 != h2);
    }

    // ============= hashToCurve =============

    function test_HashToCurve_ResultOnCurve() public view {
        (uint256 x, uint256 y) = wrapper.hashToCurve(bytes("zaseon_protocol"));
        assertTrue(wrapper.isOnCurve(x, y));
    }

    function test_HashToCurve_Deterministic() public view {
        (uint256 x1, uint256 y1) = wrapper.hashToCurve(bytes("deterministic"));
        (uint256 x2, uint256 y2) = wrapper.hashToCurve(bytes("deterministic"));
        assertEq(x1, x2);
        assertEq(y1, y2);
    }

    // ============= BatchProofVerifier contract =============

    function test_BatchVerifier_RegisterVk() public {
        bytes32 vkId = keccak256("vk1");
        BatchProofVerifier.VerificationKey memory vk = _dummyVk();
        batchVerifier.registerVk(vkId, vk);
        uint256[2] memory alpha = batchVerifier.getVkAlpha(vkId);
        assertEq(alpha[0], 1);
        assertEq(alpha[1], 2);
    }

    function test_BatchVerifier_Verify_RevertInvalidInputsLength() public {
        bytes32 vkId = keccak256("vk1");
        BatchProofVerifier.VerificationKey memory vk = _dummyVk();
        batchVerifier.registerVk(vkId, vk);

        uint256[8] memory proof;
        uint256[] memory inputs = new uint256[](5); // wrong length
        vm.expectRevert(BatchProofVerifier.InvalidInputsLength.selector);
        batchVerifier.verify(vkId, proof, inputs);
    }

    function test_BatchVerifier_BatchVerify_RevertLengthMismatch() public {
        bytes32 vkId = keccak256("vk1");
        BatchProofVerifier.VerificationKey memory vk = _dummyVk();
        batchVerifier.registerVk(vkId, vk);

        uint256[8][] memory proofs = new uint256[8][](2);
        uint256[][] memory inputs = new uint256[][](3);
        vm.expectRevert(GasOptimizedVerifier.LengthMismatch.selector);
        batchVerifier.batchVerify(vkId, proofs, inputs);
    }

    // ============= Fuzz =============

    function testFuzz_EcMul_ResultOnCurve(uint256 scalar) public view {
        scalar = bound(scalar, 1, PRIME_R - 1);
        (uint256 x, uint256 y) = wrapper.ecMul(G1_X, G1_Y, scalar);
        assertTrue(wrapper.isOnCurve(x, y));
    }

    function testFuzz_HashToField_InRange(bytes memory data) public view {
        uint256 h = wrapper.hashToField(data);
        assertTrue(h < PRIME_R);
    }

    function testFuzz_ModInverse(uint256 a) public view {
        a = bound(a, 1, PRIME_R - 1);
        uint256 inv = wrapper.modInverse(a, PRIME_R);
        assertEq(mulmod(a, inv, PRIME_R), 1);
    }

    // ============= Helpers =============

    function _dummyVk()
        internal
        pure
        returns (BatchProofVerifier.VerificationKey memory vk)
    {
        vk.alpha = [uint256(1), uint256(2)];
        vk.beta = [[uint256(10), uint256(11)], [uint256(12), uint256(13)]];
        vk.gamma = [[uint256(20), uint256(21)], [uint256(22), uint256(23)]];
        vk.delta = [[uint256(30), uint256(31)], [uint256(32), uint256(33)]];
        vk.ic = new uint256[2][](2);
        vk.ic[0] = [uint256(40), uint256(41)];
        vk.ic[1] = [uint256(42), uint256(43)];
    }
}
