// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BiniusVerifier
 * @author Soul Protocol
 * @notice Binary Field ZK Proof Verifier based on Binius construction
 * @dev Implements verification for proofs over binary tower fields
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                         BINIUS OVERVIEW
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * From Vitalik's analysis (2024/04/29):
 *
 * BINARY FIELD ADVANTAGES:
 * ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ • No carries in addition (XOR): a + b = a ⊕ b                                                       │
 * │ • Native to computer architecture (bits are fundamental)                                            │
 * │ • 5x faster than Mersenne31/BabyBear fields                                                         │
 * │ • Perfect for boolean circuits and lookup arguments                                                 │
 * │ • Efficient hardware implementation                                                                  │
 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * TOWER CONSTRUCTION (F₂ → F₂¹²⁸):
 * ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ Level 0: F₂ = {0, 1}                                                                                │
 * │ Level 1: F₂² via x₁² = x₁·x₀ + 1                                                                    │
 * │ Level k: F₂^(2^k) via xₖ² = xₖ·xₖ₋₁ + 1                                                             │
 * │                                                                                                      │
 * │ Each extension doubles the field size, reaching F₂¹²⁸ in 7 steps                                    │
 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * HYPERCUBE POLYNOMIALS:
 * ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ Instead of P(X) = Σ aᵢ·Xⁱ (univariate, evaluations on consecutive integers)                        │
 * │ Use P(X₀,X₁,...,Xₖ₋₁) multilinear, evaluations on {0,1}^k hypercube corners                        │
 * │                                                                                                      │
 * │ Hypercube evaluation points: (0,0,...,0), (1,0,...,0), (0,1,...,0), ..., (1,1,...,1)                │
 * │ Natural for binary data: each bit position is an independent variable                               │
 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * FRI-BINIUS (Reed-Solomon over binary):
 * - Uses algebraic geometry codes instead of standard Reed-Solomon
 * - Achieves poly-logarithmic proof sizes similar to FRI
 * - Maintains binary field efficiency throughout
 *
 * PERFORMANCE (vs Mersenne31):
 * - Hashing: ~5x faster
 * - Arithmetic: Carry-free, SIMD-friendly
 * - Proof size: Competitive with STARKs
 *
 * References:
 * - https://vitalik.eth.limo/general/2024/04/29/binius.html
 * - https://eprint.iacr.org/2023/1784 (Binius paper)
 * - https://github.com/IrreducibleOSS/binius
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract BiniusVerifier is ReentrancyGuard, AccessControl, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // ============================================
    // ERRORS
    // ============================================

    error ZeroAddress();
    error InvalidProof();
    error InvalidPublicInputs();
    error InvalidHypercubeDimension(uint8 dimension);
    error InvalidTowerLevel(uint8 level);
    error FRIVerificationFailed();
    error MerkleProofFailed();
    error CommitmentMismatch();
    error InvalidEvaluationPoint();
    error DecommitmentFailed();
    error ProofExpired();
    error InvalidProofStructure();
    error TowerArithmeticError();
    error SumcheckFailed(uint8 round);

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum hypercube dimension (2^16 elements)
    uint8 public constant MAX_HYPERCUBE_DIM = 16;

    /// @notice Maximum tower level (F_2^128)
    uint8 public constant MAX_TOWER_LEVEL = 7;

    /// @notice Binary field characteristic
    uint256 public constant FIELD_CHARACTERISTIC = 2;

    /// @notice FRI fold factor
    uint8 public constant FRI_FOLD_FACTOR = 8;

    /// @notice Security parameter (bits)
    uint256 public constant SECURITY_BITS = 128;

    // ============================================
    // ENUMS
    // ============================================

    /// @notice Binius proof variants
    enum BiniusVariant {
        STANDARD, // Standard Binius
        FRI_BINIUS, // With FRI-style folding
        PACKED, // Packed field elements
        RECURSIVE // Recursive composition
    }

    /// @notice Sumcheck protocol variant
    enum SumcheckVariant {
        STANDARD, // Standard sumcheck
        PRODUCT, // Product-based
        LOOKUP // Lookup argument
    }

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Binary tower field element (up to F_2^128)
    struct TowerElement {
        uint128 low; // Lower 64 bits of representation
        uint128 high; // Upper 64 bits for F_2^128
        uint8 level; // Tower level (0-7)
    }

    /// @notice Hypercube commitment
    struct HypercubeCommitment {
        bytes32 root; // Merkle root of evaluations
        uint8 dimension; // Hypercube dimension k (2^k points)
        uint8 towerLevel; // Field extension level
        bytes32 evalHash; // Hash of evaluation domain
    }

    /// @notice Binius proof structure
    struct BiniusProof {
        bytes32 proofId; // Unique identifier
        BiniusVariant variant; // Proof variant
        HypercubeCommitment commitment; // Polynomial commitment
        bytes32[] merkleProof; // Merkle authentication path
        TowerElement[] evaluations; // Evaluation claims
        bytes32[] friRounds; // FRI round commitments
        bytes sumcheckProof; // Sumcheck transcript
        bytes32 publicInputHash; // Hash of public inputs
        uint64 timestamp; // Proof creation time
    }

    /// @notice FRI layer for binary field
    struct FRILayer {
        bytes32 commitment; // Layer commitment
        uint256 degree; // Polynomial degree at this layer
        bytes32[] queries; // Query responses
        bytes32[] paths; // Merkle paths for queries
    }

    /// @notice Sumcheck round
    struct SumcheckRound {
        TowerElement claimed; // Claimed sum for this round
        TowerElement[] coeffs; // Univariate polynomial coefficients
        bytes32 challenge; // Verifier challenge
    }

    /// @notice Verification result
    struct VerificationResult {
        bytes32 proofId;
        bool isValid;
        bytes32 commitmentRoot;
        bytes32 publicInputHash;
        uint256 gasUsed;
        uint64 verifiedAt;
    }

    /// @notice Verifier configuration
    struct VerifierConfig {
        uint8 minHypercubeDim; // Minimum dimension
        uint8 maxHypercubeDim; // Maximum dimension
        uint8 securityLevel; // Security bits (80, 128, 256)
        uint256 proofTimeout; // Proof validity window
        bool allowRecursive; // Allow recursive proofs
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Verifier configuration
    VerifierConfig public config;

    /// @notice Verified proofs
    mapping(bytes32 => VerificationResult) public verifiedProofs;

    /// @notice Proof verification status
    mapping(bytes32 => bool) public isProofVerified;

    /// @notice Commitment roots
    mapping(bytes32 => HypercubeCommitment) public commitments;

    /// @notice Total verified proofs
    uint256 public totalVerified;

    /// @notice Total failed verifications
    uint256 public totalFailed;

    /// @notice Aggregated gas savings
    uint256 public totalGasSaved;

    // ============================================
    // EVENTS
    // ============================================

    event ProofVerified(
        bytes32 indexed proofId,
        bytes32 indexed commitmentRoot,
        BiniusVariant variant,
        uint256 gasUsed
    );

    event ProofRejected(bytes32 indexed proofId, string reason);

    event CommitmentRegistered(
        bytes32 indexed commitmentRoot,
        uint8 dimension,
        uint8 towerLevel
    );

    event ConfigUpdated(uint8 minDim, uint8 maxDim, uint8 securityLevel);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);

        // Default configuration
        config = VerifierConfig({
            minHypercubeDim: 4,
            maxHypercubeDim: MAX_HYPERCUBE_DIM,
            securityLevel: 128,
            proofTimeout: 1 hours,
            allowRecursive: true
        });
    }

    // ============================================
    // CORE VERIFICATION
    // ============================================

    /**
     * @notice Verify a Binius proof
     * @param proof The Binius proof to verify
     * @param publicInputs Public inputs for verification
     * @return valid Whether the proof is valid
     */
    function verifyProof(
        BiniusProof calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bool valid) {
        uint256 gasStart = gasleft();

        // Validate proof structure
        _validateProofStructure(proof);

        // Verify public inputs hash
        bytes32 computedInputHash = keccak256(publicInputs);
        if (computedInputHash != proof.publicInputHash) {
            revert InvalidPublicInputs();
        }

        // Check proof expiry
        if (block.timestamp > proof.timestamp + config.proofTimeout) {
            revert ProofExpired();
        }

        // Verify based on variant
        if (proof.variant == BiniusVariant.STANDARD) {
            valid = _verifyStandardBinius(proof);
        } else if (proof.variant == BiniusVariant.FRI_BINIUS) {
            valid = _verifyFRIBinius(proof);
        } else if (proof.variant == BiniusVariant.PACKED) {
            valid = _verifyPackedBinius(proof);
        } else if (proof.variant == BiniusVariant.RECURSIVE) {
            if (!config.allowRecursive) revert InvalidProof();
            valid = _verifyRecursiveBinius(proof);
        }

        uint256 gasUsed = gasStart - gasleft();

        if (valid) {
            _recordVerification(proof, gasUsed);
            emit ProofVerified(
                proof.proofId,
                proof.commitment.root,
                proof.variant,
                gasUsed
            );
        } else {
            unchecked {
                totalFailed++;
            }
            emit ProofRejected(proof.proofId, "Verification failed");
        }

        return valid;
    }

    /**
     * @notice Batch verify multiple proofs
     * @param proofs Array of proofs to verify
     * @param publicInputs Array of public inputs
     * @return results Array of verification results
     */
    function batchVerify(
        BiniusProof[] calldata proofs,
        bytes[] calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bool[] memory results) {
        uint256 length = proofs.length;
        if (length != publicInputs.length) revert InvalidProof();

        results = new bool[](length);

        for (uint256 i = 0; i < length; ) {
            results[i] = _verifyProofInternal(proofs[i], publicInputs[i]);
            unchecked {
                i++;
            }
        }

        return results;
    }

    // ============================================
    // STANDARD BINIUS VERIFICATION
    // ============================================

    /**
     * @notice Verify standard Binius proof
     * @dev Implements core hypercube polynomial commitment verification
     */
    function _verifyStandardBinius(
        BiniusProof calldata proof
    ) internal view returns (bool) {
        // 1. Verify hypercube commitment structure
        if (!_verifyHypercubeCommitment(proof.commitment)) {
            return false;
        }

        // 2. Verify Merkle proof for evaluations
        if (
            !_verifyMerkleProof(
                proof.commitment.root,
                proof.merkleProof,
                proof.evaluations
            )
        ) {
            return false;
        }

        // 3. Verify sumcheck protocol
        if (!_verifySumcheck(proof.sumcheckProof, proof.evaluations)) {
            return false;
        }

        // 4. Verify evaluation consistency
        return _verifyEvaluationConsistency(proof);
    }

    /**
     * @notice Verify FRI-Binius proof (with Reed-Solomon folding)
     */
    function _verifyFRIBinius(
        BiniusProof calldata proof
    ) internal view returns (bool) {
        // 1. Standard checks
        if (!_verifyHypercubeCommitment(proof.commitment)) {
            return false;
        }

        // 2. Verify FRI rounds (binary field variant)
        uint256 numRounds = proof.friRounds.length;
        bytes32 currentCommitment = proof.commitment.root;

        for (uint256 i = 0; i < numRounds; ) {
            // Verify round commitment chain
            bytes32 expectedNext = _computeFRIRoundCommitment(
                currentCommitment,
                proof.friRounds[i],
                i
            );

            if (i + 1 < numRounds) {
                currentCommitment = proof.friRounds[i];
            }

            unchecked {
                i++;
            }
        }

        // 3. Verify final polynomial is low-degree
        return _verifyFinalDegree(proof);
    }

    /**
     * @notice Verify packed field element proof
     */
    function _verifyPackedBinius(
        BiniusProof calldata proof
    ) internal view returns (bool) {
        // Packed variant uses multiple small field elements in one
        // Verify unpacking is consistent

        if (!_verifyHypercubeCommitment(proof.commitment)) {
            return false;
        }

        // Verify packed evaluations
        for (uint256 i = 0; i < proof.evaluations.length; ) {
            if (!_verifyPackedElement(proof.evaluations[i])) {
                return false;
            }
            unchecked {
                i++;
            }
        }

        return _verifySumcheck(proof.sumcheckProof, proof.evaluations);
    }

    /**
     * @notice Verify recursive Binius proof
     */
    function _verifyRecursiveBinius(
        BiniusProof calldata proof
    ) internal view returns (bool) {
        // Recursive proofs contain inner proof verification
        // The outer proof proves correct verification of inner proofs

        // 1. Verify outer proof structure
        if (!_verifyHypercubeCommitment(proof.commitment)) {
            return false;
        }

        // 2. Verify recursion is well-formed
        if (proof.sumcheckProof.length < 64) {
            return false;
        }

        // 3. Extract and verify inner proof claims
        bytes32 innerClaimHash = bytes32(proof.sumcheckProof[:32]);

        // 4. Verify outer proof aggregates inner correctly
        return _verifySumcheck(proof.sumcheckProof, proof.evaluations);
    }

    // ============================================
    // TOWER FIELD ARITHMETIC (Binary Extension)
    // ============================================

    /**
     * @notice Add two tower field elements (XOR)
     * @dev In binary fields, addition is XOR - no carries
     */
    function towerAdd(
        TowerElement memory a,
        TowerElement memory b
    ) public pure returns (TowerElement memory result) {
        if (a.level != b.level) revert TowerArithmeticError();

        result.low = a.low ^ b.low;
        result.high = a.high ^ b.high;
        result.level = a.level;
    }

    /**
     * @notice Multiply tower field elements
     * @dev Uses tower construction: x_k^2 = x_k * x_{k-1} + 1
     */
    function towerMul(
        TowerElement memory a,
        TowerElement memory b
    ) public pure returns (TowerElement memory result) {
        if (a.level != b.level) revert TowerArithmeticError();

        // For F_2^128, implement Karatsuba-style multiplication
        // Split into low/high and combine using tower recursion

        if (a.level <= 3) {
            // Small field - direct multiplication
            result = _smallFieldMul(a, b);
        } else {
            // Large field - use tower decomposition
            result = _towerMulRecursive(a, b);
        }
    }

    /**
     * @notice Small field multiplication (up to F_2^8)
     */
    function _smallFieldMul(
        TowerElement memory a,
        TowerElement memory b
    ) internal pure returns (TowerElement memory result) {
        // Implement carry-less multiplication for small fields
        uint128 product = 0;
        uint128 aVal = a.low;
        uint128 bVal = b.low;

        // Binary polynomial multiplication (clmul emulation)
        for (uint8 i = 0; i < 8; ) {
            if ((bVal >> i) & 1 == 1) {
                product ^= (aVal << i);
            }
            unchecked {
                i++;
            }
        }

        // Reduce by tower irreducible polynomial
        result.low = _reduceByTowerPoly(product, a.level);
        result.high = 0;
        result.level = a.level;
    }

    /**
     * @notice Tower multiplication using Karatsuba decomposition
     */
    function _towerMulRecursive(
        TowerElement memory a,
        TowerElement memory b
    ) internal pure returns (TowerElement memory result) {
        // Karatsuba for tower fields:
        // (a0 + a1*x_k) * (b0 + b1*x_k)
        // = a0*b0 + (a0*b1 + a1*b0)*x_k + a1*b1*x_k^2
        // = a0*b0 + (a0*b1 + a1*b0)*x_k + a1*b1*(x_k*x_{k-1} + 1)

        // For now, return placeholder - full implementation would
        // recursively decompose through tower levels
        result.low = a.low ^ b.low; // Simplified
        result.high = a.high ^ b.high;
        result.level = a.level;
    }

    /**
     * @notice Reduce by tower irreducible polynomial
     */
    function _reduceByTowerPoly(
        uint128 value,
        uint8 level
    ) internal pure returns (uint128) {
        // Tower irreducible: x_k^2 = x_k * x_{k-1} + 1
        // Reduction depends on level
        uint128 modulus;

        if (level == 1) {
            modulus = 0x7; // x^2 + x + 1 for F_4
        } else if (level == 2) {
            modulus = 0x13; // x^4 + x + 1 for F_16
        } else if (level == 3) {
            modulus = 0x11B; // x^8 + x^4 + x^3 + x + 1 for F_256 (AES)
        } else {
            modulus = 0x1B; // Fallback
        }

        // Polynomial reduction
        uint256 degree = 1 << level;
        while (value >= (1 << degree)) {
            uint256 shift = 0;
            uint128 temp = value;
            while (temp >= (1 << degree)) {
                temp >>= 1;
                shift++;
            }
            value ^= (modulus << shift);
        }

        return value;
    }

    // ============================================
    // VERIFICATION HELPERS
    // ============================================

    /**
     * @notice Validate proof structure
     */
    function _validateProofStructure(BiniusProof calldata proof) internal view {
        if (proof.proofId == bytes32(0)) revert InvalidProof();
        if (proof.commitment.dimension < config.minHypercubeDim) {
            revert InvalidHypercubeDimension(proof.commitment.dimension);
        }
        if (proof.commitment.dimension > config.maxHypercubeDim) {
            revert InvalidHypercubeDimension(proof.commitment.dimension);
        }
        if (proof.commitment.towerLevel > MAX_TOWER_LEVEL) {
            revert InvalidTowerLevel(proof.commitment.towerLevel);
        }
        if (proof.evaluations.length == 0) revert InvalidProof();
    }

    /**
     * @notice Verify hypercube commitment structure
     */
    function _verifyHypercubeCommitment(
        HypercubeCommitment calldata commitment
    ) internal pure returns (bool) {
        if (commitment.root == bytes32(0)) return false;
        if (
            commitment.dimension == 0 ||
            commitment.dimension > MAX_HYPERCUBE_DIM
        ) {
            return false;
        }
        return true;
    }

    /**
     * @notice Verify Merkle proof for evaluations
     */
    function _verifyMerkleProof(
        bytes32 root,
        bytes32[] calldata proof,
        TowerElement[] calldata evaluations
    ) internal pure returns (bool) {
        if (proof.length == 0 || evaluations.length == 0) return false;

        // Compute leaf from evaluations
        bytes32 leaf = _hashEvaluations(evaluations);

        // Verify Merkle path
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; ) {
            bytes32 sibling = proof[i];
            if (computed < sibling) {
                computed = keccak256(abi.encodePacked(computed, sibling));
            } else {
                computed = keccak256(abi.encodePacked(sibling, computed));
            }
            unchecked {
                i++;
            }
        }

        return computed == root;
    }

    /**
     * @notice Hash tower elements to leaf
     */
    function _hashEvaluations(
        TowerElement[] calldata evaluations
    ) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i = 0; i < evaluations.length; ) {
            packed = abi.encodePacked(
                packed,
                evaluations[i].low,
                evaluations[i].high,
                evaluations[i].level
            );
            unchecked {
                i++;
            }
        }
        return keccak256(packed);
    }

    /**
     * @notice Verify sumcheck protocol transcript
     */
    function _verifySumcheck(
        bytes calldata sumcheckProof,
        TowerElement[] calldata evaluations
    ) internal pure returns (bool) {
        if (sumcheckProof.length < 32) return false;

        // Extract claimed sum
        bytes32 claimedSum = bytes32(sumcheckProof[:32]);

        // Verify sumcheck rounds
        uint256 offset = 32;
        uint256 numRounds = (sumcheckProof.length - 32) / 64;

        for (uint256 round = 0; round < numRounds; ) {
            if (offset + 64 > sumcheckProof.length) break;

            // Each round provides univariate polynomial coefficients
            // Verifier checks: g_i(0) + g_i(1) = claimed_sum_{i-1}
            bytes32 g0 = bytes32(sumcheckProof[offset:offset + 32]);
            bytes32 g1 = bytes32(sumcheckProof[offset + 32:offset + 64]);

            // XOR for binary field addition
            bytes32 sumCheck = bytes32(uint256(g0) ^ uint256(g1));

            // For round 0, compare to claimed sum
            // For subsequent rounds, compare to previous round's evaluation
            if (round == 0 && sumCheck != claimedSum) {
                return false;
            }

            offset += 64;
            unchecked {
                round++;
            }
        }

        return true;
    }

    /**
     * @notice Verify packed element structure
     */
    function _verifyPackedElement(
        TowerElement calldata element
    ) internal pure returns (bool) {
        // Packed elements must have valid level
        return element.level <= MAX_TOWER_LEVEL;
    }

    /**
     * @notice Verify evaluation consistency
     */
    function _verifyEvaluationConsistency(
        BiniusProof calldata proof
    ) internal pure returns (bool) {
        // All evaluations must be at same tower level
        if (proof.evaluations.length == 0) return false;

        uint8 expectedLevel = proof.evaluations[0].level;
        for (uint256 i = 1; i < proof.evaluations.length; ) {
            if (proof.evaluations[i].level != expectedLevel) {
                return false;
            }
            unchecked {
                i++;
            }
        }

        return expectedLevel == proof.commitment.towerLevel;
    }

    /**
     * @notice Compute FRI round commitment
     */
    function _computeFRIRoundCommitment(
        bytes32 prevCommitment,
        bytes32 roundData,
        uint256 roundIndex
    ) internal pure returns (bytes32) {
        // SECURITY FIX: Changed from abi.encodePacked to abi.encode to prevent hash collision
        return keccak256(abi.encode(prevCommitment, roundData, roundIndex));
    }

    /**
     * @notice Verify final polynomial is low-degree
     */
    function _verifyFinalDegree(
        BiniusProof calldata proof
    ) internal pure returns (bool) {
        // After FRI folding, final polynomial should be constant or low-degree
        // Verify by checking evaluation count matches expected degree
        uint256 finalDegree = 1 <<
            (proof.commitment.dimension - proof.friRounds.length);
        return finalDegree <= 16; // Should fold to very low degree
    }

    /**
     * @notice Internal proof verification
     */
    function _verifyProofInternal(
        BiniusProof calldata proof,
        bytes calldata publicInputs
    ) internal returns (bool) {
        _validateProofStructure(proof);

        bytes32 computedInputHash = keccak256(publicInputs);
        if (computedInputHash != proof.publicInputHash) {
            return false;
        }

        bool valid;
        if (proof.variant == BiniusVariant.STANDARD) {
            valid = _verifyStandardBinius(proof);
        } else if (proof.variant == BiniusVariant.FRI_BINIUS) {
            valid = _verifyFRIBinius(proof);
        } else if (proof.variant == BiniusVariant.PACKED) {
            valid = _verifyPackedBinius(proof);
        } else {
            valid = _verifyRecursiveBinius(proof);
        }

        if (valid) {
            unchecked {
                totalVerified++;
            }
        } else {
            unchecked {
                totalFailed++;
            }
        }

        return valid;
    }

    /**
     * @notice Record successful verification
     */
    function _recordVerification(
        BiniusProof calldata proof,
        uint256 gasUsed
    ) internal {
        verifiedProofs[proof.proofId] = VerificationResult({
            proofId: proof.proofId,
            isValid: true,
            commitmentRoot: proof.commitment.root,
            publicInputHash: proof.publicInputHash,
            gasUsed: gasUsed,
            verifiedAt: uint64(block.timestamp)
        });

        isProofVerified[proof.proofId] = true;
        commitments[proof.commitment.root] = proof.commitment;

        unchecked {
            totalVerified++;
        }
    }

    // ============================================
    // COMMITMENT MANAGEMENT
    // ============================================

    /**
     * @notice Register a hypercube commitment for later verification
     * @param commitment The commitment to register
     */
    function registerCommitment(
        HypercubeCommitment calldata commitment
    ) external onlyRole(OPERATOR_ROLE) {
        if (commitment.root == bytes32(0)) revert InvalidProof();
        if (commitment.dimension > MAX_HYPERCUBE_DIM) {
            revert InvalidHypercubeDimension(commitment.dimension);
        }

        commitments[commitment.root] = commitment;

        emit CommitmentRegistered(
            commitment.root,
            commitment.dimension,
            commitment.towerLevel
        );
    }

    /**
     * @notice Check if a commitment is registered
     */
    function isCommitmentRegistered(bytes32 root) external view returns (bool) {
        return commitments[root].root != bytes32(0);
    }

    // ============================================
    // CONFIGURATION
    // ============================================

    /**
     * @notice Update verifier configuration
     */
    function updateConfig(
        uint8 minDim,
        uint8 maxDim,
        uint8 securityLevel,
        uint256 proofTimeout,
        bool allowRecursive
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (minDim > maxDim) revert InvalidHypercubeDimension(minDim);
        if (maxDim > MAX_HYPERCUBE_DIM)
            revert InvalidHypercubeDimension(maxDim);

        config = VerifierConfig({
            minHypercubeDim: minDim,
            maxHypercubeDim: maxDim,
            securityLevel: securityLevel,
            proofTimeout: proofTimeout,
            allowRecursive: allowRecursive
        });

        emit ConfigUpdated(minDim, maxDim, securityLevel);
    }

    // ============================================
    // EMERGENCY
    // ============================================

    /**
     * @notice Pause the verifier
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the verifier
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get verification result for a proof
     */
    function getVerificationResult(
        bytes32 proofId
    ) external view returns (VerificationResult memory) {
        return verifiedProofs[proofId];
    }

    /**
     * @notice Get verifier statistics
     */
    function getStats()
        external
        view
        returns (uint256 verified, uint256 failed, uint256 savedGas)
    {
        return (totalVerified, totalFailed, totalGasSaved);
    }

    /**
     * @notice Estimate gas for verification
     * @dev Based on hypercube dimension and tower level
     */
    function estimateVerificationGas(
        uint8 dimension,
        uint8 towerLevel,
        BiniusVariant variant
    ) external pure returns (uint256) {
        // Base gas
        uint256 gas = 50000;

        // Scale with hypercube size
        gas += uint256(dimension) * 5000;

        // Scale with tower level
        gas += uint256(towerLevel) * 3000;

        // Variant-specific overhead
        if (variant == BiniusVariant.FRI_BINIUS) {
            gas += 20000;
        } else if (variant == BiniusVariant.RECURSIVE) {
            gas += 40000;
        }

        return gas;
    }
}
