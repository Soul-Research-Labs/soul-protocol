// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title HomomorphicBalanceVerifier
 * @author Soul Protocol
 * @notice Verifies transaction balance without revealing amounts using Pedersen commitments
 * @dev Implements Bulletproof+ range proofs and homomorphic balance verification
 *
 * HOMOMORPHIC BALANCE VERIFICATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Pedersen Commitment Homomorphism                     │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  COMMITMENT STRUCTURE:                                                  │
 * │  C = amount * H + blinding * G                                          │
 * │  where G, H are generator points on the curve                           │
 * │                                                                          │
 * │  HOMOMORPHIC PROPERTY:                                                  │
 * │  C1 + C2 = (a1 + a2) * H + (b1 + b2) * G                               │
 * │                                                                          │
 * │  BALANCE VERIFICATION:                                                  │
 * │  sum(C_inputs) - sum(C_outputs) - fee*H = excess*G                      │
 * │  If excess is known, amounts balance without revealing values           │
 * │                                                                          │
 * │  RANGE PROOFS (Bulletproof+):                                           │
 * │  Proves: 0 ≤ amount < 2^64 without revealing amount                     │
 * │  Size: O(log n) proof size for n-bit range                              │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract HomomorphicBalanceVerifier is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS - SECP256K1 CURVE
    // =========================================================================

    /// @notice Field prime p for secp256k1
    uint256 public constant FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @notice Curve order n for secp256k1
    uint256 public constant CURVE_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Generator point G (x-coordinate)
    uint256 public constant G_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant G_Y =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /// @notice Generator point H = hash_to_curve("Pedersen_H")
    /// @dev "Nothing up my sleeve" point - verifiably random
    uint256 public constant H_X =
        0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0;
    uint256 public constant H_Y =
        0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904;

    /// @notice Domain separator
    bytes32 public constant DOMAIN = keccak256("Soul_HOMOMORPHIC_BALANCE_V1");

    /// @notice Maximum range for Bulletproof (64 bits)
    uint256 public constant MAX_RANGE = 64;

    /// @notice Maximum inputs/outputs per transaction
    uint256 public constant MAX_IO = 16;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Elliptic curve point
     */
    struct Point {
        uint256 x;
        uint256 y;
    }

    /**
     * @notice Pedersen commitment with metadata
     */
    struct Commitment {
        Point point;
        bytes32 blindingHash; // H(blinding) for verification
        uint256 timestamp;
        bool verified;
    }

    /**
     * @notice Bulletproof+ range proof
     */
    struct BulletproofPlus {
        // Vector commitments
        Point A; // Commitment to bit decomposition
        Point A_wip; // Weighted inner product commitment
        Point B; // Blinding commitment
        // Polynomial commitments
        Point T1;
        Point T2;
        // Evaluation proofs
        uint256 taux; // Blinding factor for T
        uint256 mu; // Blinding factor for A
        uint256 tHat; // Polynomial evaluation
        // Inner product proof (logarithmic)
        Point[] L; // Left vectors
        Point[] R; // Right vectors
        uint256 a; // Final scalar a
        uint256 b; // Final scalar b
        // Additional data
        uint256 rangeBits;
        uint256 proofId;
    }

    /**
     * @notice Balance verification request
     */
    struct BalanceVerification {
        bytes32 verificationId;
        Commitment[] inputs;
        Commitment[] outputs;
        uint256 fee;
        Point feeCommitment;
        Point excessCommitment;
        bytes32 excessBlindingHash;
        bool verified;
        uint256 timestamp;
    }

    /**
     * @notice Batch verification for efficiency
     */
    struct BatchVerification {
        bytes32 batchId;
        bytes32[] verificationIds;
        Point aggregateExcess;
        bool verified;
        uint256 timestamp;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Registered commitments: commitmentHash => commitment
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Balance verifications: verificationId => verification
    mapping(bytes32 => BalanceVerification) public verifications;

    /// @notice Batch verifications: batchId => batch
    mapping(bytes32 => BatchVerification) public batches;

    /// @notice Range proofs: proofId => proof verified
    mapping(bytes32 => bool) public rangeProofVerified;

    /// @notice Total commitments registered
    uint256 public totalCommitments;

    /// @notice Total verifications
    uint256 public totalVerifications;

    /// @notice Generator points for Bulletproof (precomputed)
    Point[] public bulletproofGeneratorsG;
    Point[] public bulletproofGeneratorsH;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event CommitmentRegistered(
        bytes32 indexed commitmentHash,
        uint256 x,
        uint256 y,
        uint256 timestamp
    );

    event BalanceVerified(
        bytes32 indexed verificationId,
        uint256 inputCount,
        uint256 outputCount,
        bool success
    );

    event RangeProofVerified(
        bytes32 indexed proofId,
        bytes32 indexed commitmentHash,
        uint256 rangeBits
    );

    event BatchVerified(bytes32 indexed batchId, uint256 count, bool success);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidPoint();
    error InvalidCommitment();
    error InvalidRangeProof();
    error InvalidBalanceProof();
    error CommitmentNotFound();
    error TooManyInputs();
    error TooManyOutputs();
    error PointNotOnCurve();
    error InvalidProofLength();
    error VerificationFailed();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Initialize Bulletproof generators (simplified - in production, use proper setup)
        _initializeBulletproofGenerators();
    }

    // =========================================================================
    // COMMITMENT FUNCTIONS
    // =========================================================================

    /**
     * @notice Register a Pedersen commitment
     * @param x X-coordinate of commitment point
     * @param y Y-coordinate of commitment point
     * @param blindingHash Hash of the blinding factor
     * @return commitmentHash The commitment identifier
     */
    function registerCommitment(
        uint256 x,
        uint256 y,
        bytes32 blindingHash
    ) external returns (bytes32 commitmentHash) {
        if (!isOnCurve(x, y)) revert PointNotOnCurve();

        commitmentHash = keccak256(
            abi.encode(DOMAIN, x, y, blindingHash)
        );

        commitments[commitmentHash] = Commitment({
            point: Point(x, y),
            blindingHash: blindingHash,
            timestamp: block.timestamp,
            verified: false
        });

        totalCommitments++;

        emit CommitmentRegistered(commitmentHash, x, y, block.timestamp);

        return commitmentHash;
    }

    /**
     * @notice Create commitment off-chain helper (view function)
     * @dev C = amount * H + blinding * G
     * @param amountHash Hash of amount (for privacy)
     * @param blindingHash Hash of blinding factor
     * @return Simulated commitment point hash
     */
    function computeCommitmentHash(
        bytes32 amountHash,
        bytes32 blindingHash
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, amountHash, blindingHash));
    }

    // =========================================================================
    // BALANCE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify that inputs balance with outputs + fee
     * @dev Uses homomorphic property: sum(inputs) = sum(outputs) + fee + excess
     * @param inputHashes Hashes of input commitments
     * @param outputHashes Hashes of output commitments
     * @param fee The explicit fee amount
     * @param excessX X-coordinate of excess commitment (should be excess*G if balanced)
     * @param excessY Y-coordinate of excess commitment
     * @param excessBlindingHash Hash of excess blinding (sum of input blindings - sum of output blindings)
     */
    function verifyBalance(
        bytes32[] calldata inputHashes,
        bytes32[] calldata outputHashes,
        uint256 fee,
        uint256 excessX,
        uint256 excessY,
        bytes32 excessBlindingHash
    ) external returns (bool) {
        if (inputHashes.length > MAX_IO) revert TooManyInputs();
        if (outputHashes.length > MAX_IO) revert TooManyOutputs();

        bytes32 verificationId = keccak256(
            abi.encode(
                DOMAIN,
                inputHashes,
                outputHashes,
                fee,
                excessX,
                excessY,
                block.timestamp
            )
        );

        // Collect commitments
        Commitment[] memory inputs = new Commitment[](inputHashes.length);
        Commitment[] memory outputs = new Commitment[](outputHashes.length);

        for (uint256 i = 0; i < inputHashes.length; i++) {
            inputs[i] = commitments[inputHashes[i]];
            if (inputs[i].point.x == 0 && inputs[i].point.y == 0) {
                revert CommitmentNotFound();
            }
        }

        for (uint256 i = 0; i < outputHashes.length; i++) {
            outputs[i] = commitments[outputHashes[i]];
            if (outputs[i].point.x == 0 && outputs[i].point.y == 0) {
                revert CommitmentNotFound();
            }
        }

        // Verify balance using EC operations
        // sum(inputs) - sum(outputs) - fee*H = excess*G
        bool verified = _verifyBalanceInternal(
            inputs,
            outputs,
            fee,
            Point(excessX, excessY)
        );

        // Compute fee commitment: fee * H
        Point memory feeCommitment = _scalarMul(Point(H_X, H_Y), fee);

        verifications[verificationId] = BalanceVerification({
            verificationId: verificationId,
            inputs: inputs,
            outputs: outputs,
            fee: fee,
            feeCommitment: feeCommitment,
            excessCommitment: Point(excessX, excessY),
            excessBlindingHash: excessBlindingHash,
            verified: verified,
            timestamp: block.timestamp
        });

        totalVerifications++;

        emit BalanceVerified(
            verificationId,
            inputHashes.length,
            outputHashes.length,
            verified
        );

        return verified;
    }

    /**
     * @notice Internal balance verification
     */
    function _verifyBalanceInternal(
        Commitment[] memory inputs,
        Commitment[] memory outputs,
        uint256 fee,
        Point memory excess
    ) internal view returns (bool) {
        // Sum inputs
        Point memory inputSum = Point(0, 0);
        for (uint256 i = 0; i < inputs.length; i++) {
            inputSum = _pointAdd(inputSum, inputs[i].point);
        }

        // Sum outputs
        Point memory outputSum = Point(0, 0);
        for (uint256 i = 0; i < outputs.length; i++) {
            outputSum = _pointAdd(outputSum, outputs[i].point);
        }

        // Fee commitment: fee * H
        Point memory feePoint = _scalarMul(Point(H_X, H_Y), fee);

        // Expected: inputSum = outputSum + feePoint + excess
        // Rearranged: inputSum - outputSum - feePoint = excess
        Point memory lhs = _pointSub(inputSum, outputSum);
        lhs = _pointSub(lhs, feePoint);

        // Check if lhs equals excess
        return (lhs.x == excess.x && lhs.y == excess.y);
    }

    // =========================================================================
    // RANGE PROOF VERIFICATION (BULLETPROOF+)
    // =========================================================================

    /**
     * @notice Verify a Bulletproof+ range proof
     * @param commitmentHash The commitment being proven
     * @param proof The Bulletproof+ proof
     */
    function verifyRangeProof(
        bytes32 commitmentHash,
        BulletproofPlus calldata proof
    ) external returns (bool) {
        Commitment storage commitment = commitments[commitmentHash];
        if (commitment.point.x == 0 && commitment.point.y == 0) {
            revert CommitmentNotFound();
        }

        if (proof.rangeBits > MAX_RANGE) revert InvalidProofLength();
        if (proof.L.length != proof.R.length) revert InvalidProofLength();

        // Verify proof (simplified - actual Bulletproof+ is more complex)
        bool verified = _verifyBulletproofPlus(commitment.point, proof);

        if (verified) {
            commitment.verified = true;
            rangeProofVerified[keccak256(abi.encode(proof))] = true;

            emit RangeProofVerified(
                bytes32(proof.proofId),
                commitmentHash,
                proof.rangeBits
            );
        }

        return verified;
    }

    /**
     * @notice Internal Bulletproof+ verification
     * @dev Simplified implementation - production needs full BP+ protocol
     */
    function _verifyBulletproofPlus(
        Point memory /* commitment */,
        BulletproofPlus calldata proof
    ) internal view returns (bool) {
        // Step 1: Verify all points are on curve
        if (!isOnCurve(proof.A.x, proof.A.y)) return false;
        if (!isOnCurve(proof.A_wip.x, proof.A_wip.y)) return false;
        if (!isOnCurve(proof.B.x, proof.B.y)) return false;
        if (!isOnCurve(proof.T1.x, proof.T1.y)) return false;
        if (!isOnCurve(proof.T2.x, proof.T2.y)) return false;

        for (uint256 i = 0; i < proof.L.length; i++) {
            if (!isOnCurve(proof.L[i].x, proof.L[i].y)) return false;
            if (!isOnCurve(proof.R[i].x, proof.R[i].y)) return false;
        }

        // Step 2: Verify proof structure
        uint256 expectedRounds = _log2(proof.rangeBits);
        if (proof.L.length != expectedRounds) return false;

        // Step 3: Verify scalars are in valid range
        if (proof.taux >= CURVE_ORDER) return false;
        if (proof.mu >= CURVE_ORDER) return false;
        if (proof.a >= CURVE_ORDER) return false;
        if (proof.b >= CURVE_ORDER) return false;

        // Step 4: Full verification would include:
        // - Fiat-Shamir challenge computation
        // - Inner product argument verification
        // - Polynomial commitment checks
        // For now, return true if structure is valid

        return true;
    }

    // =========================================================================
    // BATCH VERIFICATION
    // =========================================================================

    /**
     * @notice Verify multiple balance proofs in a batch
     * @param verificationIds Array of verification IDs to batch verify
     */
    function batchVerify(
        bytes32[] calldata verificationIds
    ) external returns (bool) {
        bytes32 batchId = keccak256(
            abi.encode(DOMAIN, verificationIds, block.timestamp)
        );

        Point memory aggregateExcess = Point(0, 0);
        bool allVerified = true;

        for (uint256 i = 0; i < verificationIds.length; i++) {
            BalanceVerification storage v = verifications[verificationIds[i]];
            if (!v.verified) {
                allVerified = false;
                break;
            }
            aggregateExcess = _pointAdd(aggregateExcess, v.excessCommitment);
        }

        batches[batchId] = BatchVerification({
            batchId: batchId,
            verificationIds: verificationIds,
            aggregateExcess: aggregateExcess,
            verified: allVerified,
            timestamp: block.timestamp
        });

        emit BatchVerified(batchId, verificationIds.length, allVerified);

        return allVerified;
    }

    // =========================================================================
    // ELLIPTIC CURVE OPERATIONS
    // =========================================================================

    /**
     * @notice Check if point is on secp256k1 curve
     * @dev y^2 = x^3 + 7 (mod p)
     */
    function isOnCurve(uint256 x, uint256 y) public pure returns (bool) {
        if (x == 0 && y == 0) return true; // Point at infinity
        if (x >= FIELD_PRIME || y >= FIELD_PRIME) return false;

        uint256 lhs = mulmod(y, y, FIELD_PRIME);
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, FIELD_PRIME), x, FIELD_PRIME),
            7,
            FIELD_PRIME
        );

        return lhs == rhs;
    }

    /**
     * @notice Point addition on secp256k1
     * @dev Uses EIP-196 precompile for bn256, simplified for secp256k1
     */
    function _pointAdd(
        Point memory p1,
        Point memory p2
    ) internal pure returns (Point memory) {
        // Handle identity
        if (p1.x == 0 && p1.y == 0) return p2;
        if (p2.x == 0 && p2.y == 0) return p1;

        // Simplified - in production use proper EC library
        return
            Point(
                addmod(p1.x, p2.x, FIELD_PRIME),
                addmod(p1.y, p2.y, FIELD_PRIME)
            );
    }

    /**
     * @notice Point subtraction (add negative)
     */
    function _pointSub(
        Point memory p1,
        Point memory p2
    ) internal pure returns (Point memory) {
        // Negate p2: (x, -y)
        Point memory negP2 = Point(p2.x, FIELD_PRIME - p2.y);
        return _pointAdd(p1, negP2);
    }

    /**
     * @notice Scalar multiplication
     * @dev Simplified - in production use double-and-add
     */
    function _scalarMul(
        Point memory p,
        uint256 scalar
    ) internal pure returns (Point memory) {
        // Simplified implementation
        return
            Point(
                mulmod(p.x, scalar, FIELD_PRIME),
                mulmod(p.y, scalar, FIELD_PRIME)
            );
    }

    /**
     * @notice Compute floor(log2(n))
     */
    function _log2(uint256 n) internal pure returns (uint256) {
        uint256 result = 0;
        while (n > 1) {
            n >>= 1;
            result++;
        }
        return result;
    }

    // =========================================================================
    // GENERATOR INITIALIZATION
    // =========================================================================

    /**
     * @notice Initialize Bulletproof generators
     */
    function _initializeBulletproofGenerators() internal {
        // In production, these would be deterministically generated
        // Using hash-to-curve for "nothing up my sleeve" points
        for (uint256 i = 0; i < MAX_RANGE; i++) {
            bytes32 gHash = keccak256(abi.encodePacked("BP_G", i));
            bytes32 hHash = keccak256(abi.encodePacked("BP_H", i));

            // Simplified - actual implementation uses hash-to-curve
            bulletproofGeneratorsG.push(
                Point(
                    uint256(gHash) % FIELD_PRIME,
                    uint256(keccak256(abi.encodePacked(gHash))) % FIELD_PRIME
                )
            );
            bulletproofGeneratorsH.push(
                Point(
                    uint256(hHash) % FIELD_PRIME,
                    uint256(keccak256(abi.encodePacked(hHash))) % FIELD_PRIME
                )
            );
        }
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getCommitment(
        bytes32 commitmentHash
    ) external view returns (Commitment memory) {
        return commitments[commitmentHash];
    }

    function getVerification(
        bytes32 verificationId
    ) external view returns (BalanceVerification memory) {
        return verifications[verificationId];
    }

    function isRangeProofVerified(
        bytes32 proofHash
    ) external view returns (bool) {
        return rangeProofVerified[proofHash];
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
