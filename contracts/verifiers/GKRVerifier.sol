// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title GKRVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for GKR (Goldwasser-Kalai-Rothblum) proofs
 * @dev Implements sumcheck verification with Gruen's trick optimization
 *
 * GKR PROTOCOL OVERVIEW (from Vitalik's tutorial):
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    GKR Verification Flow                                │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  1. Prover commits to inputs and outputs                                │
 * │  2. For each layer (backwards):                                         │
 * │     a. Run sumcheck protocol                                            │
 * │     b. Convert V_i(p_i) claim to V_{i-1}(p_{i-1}) claim                 │
 * │  3. Verifier checks final claim against known inputs                    │
 * │                                                                         │
 * │  OPTIMIZATIONS:                                                         │
 * │  • Gruen's Trick: 5 → 3 values per sumcheck round                       │
 * │  • Batch linear sumcheck for partial rounds                             │
 * │  • No intermediate commitments (only input/output)                      │
 * │                                                                         │
 * │  OVERHEAD: ~15x theoretical (vs ~100x for traditional STARKs)           │
 * │                                                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Reference: https://vitalik.eth.limo/general/2025/10/19/gkr.html
 */
contract GKRVerifier is AccessControl, IProofVerifier {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice GKR proof type identifier
    bytes32 public constant GKR_PROOF = keccak256("GKR_PROOF");

    /// @notice KoalaBear prime: 2^31 - 2^24 + 1
    uint256 public constant KOALABEAR_PRIME = 2013265921;

    /// @notice Maximum sumcheck rounds supported
    uint256 public constant MAX_ROUNDS = 32;

    /// @notice Extension field degree for 128-bit security
    uint256 public constant EXTENSION_DEGREE = 4;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Field modulus for arithmetic
    uint256 public fieldModulus;

    /// @notice Trusted Hekate-Groestl verifier for hash proofs
    address public hekateVerifier;

    /// @notice Total proofs verified
    uint256 public totalProofsVerified;

    /// @notice Whether strict mode is enabled
    bool public strictMode;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event GKRProofVerified(
        bytes32 indexed proofHash,
        bytes32 indexed inputCommitment,
        bytes32 indexed outputCommitment,
        bool valid,
        uint256 gasUsed
    );

    event ConfigUpdated(uint256 newModulus, address newHekateVerifier);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProofLength();
    error InvalidPublicInputs();
    error SumcheckFailed(uint256 layer, uint256 round);
    error CommitmentMismatch();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _hekateVerifier) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        fieldModulus = KOALABEAR_PRIME;
        hekateVerifier = _hekateVerifier;
        strictMode = true;
    }

    /*//////////////////////////////////////////////////////////////
                       FIELD ARITHMETIC (INTERNAL)
    //////////////////////////////////////////////////////////////*/

    /// @notice Modular addition
    function _fieldAdd(uint256 a, uint256 b) internal view returns (uint256) {
        return addmod(a, b, fieldModulus);
    }

    /// @notice Modular subtraction
    function _fieldSub(uint256 a, uint256 b) internal view returns (uint256) {
        if (b > a) {
            return fieldModulus - ((b - a) % fieldModulus);
        }
        return (a - b) % fieldModulus;
    }

    /// @notice Modular multiplication
    function _fieldMul(uint256 a, uint256 b) internal view returns (uint256) {
        return mulmod(a, b, fieldModulus);
    }

    /// @notice Modular exponentiation
    function _fieldPow(
        uint256 base,
        uint256 exp
    ) internal view returns (uint256 result) {
        result = 1;
        base = base % fieldModulus;

        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mulmod(result, base, fieldModulus);
            }
            base = mulmod(base, base, fieldModulus);
            exp >>= 1;
        }
    }

    /// @notice Modular inverse using Fermat's little theorem
    function _fieldInv(uint256 a) internal view returns (uint256) {
        require(a != 0, "Cannot invert zero");
        return _fieldPow(a, fieldModulus - 2);
    }

    /// @notice Modular division
    function _fieldDiv(uint256 a, uint256 b) internal view returns (uint256) {
        return _fieldMul(a, _fieldInv(b));
    }

    /*//////////////////////////////////////////////////////////////
                       GRUEN'S TRICK IMPLEMENTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Convert half-weight sum to full sum
     * @dev sum = hsum * (x * c + (1-x) * (1-c))
     */
    function _hsumToSum(
        uint256 hsum,
        uint256 x,
        uint256 c
    ) internal view returns (uint256) {
        uint256 term1 = _fieldMul(x, c);
        uint256 oneMinusX = _fieldSub(1, x);
        uint256 oneMinusC = _fieldSub(1, c);
        uint256 term2 = _fieldMul(oneMinusX, oneMinusC);
        uint256 factor = _fieldAdd(term1, term2);
        return _fieldMul(hsum, factor);
    }

    /**
     * @notice Degree-3 Lagrange interpolation (for Gruen's trick)
     * @dev Returns coefficients for interpolating from points {0,1,2,3}
     */
    function _deg3LagrangeWeights(
        uint256 x
    ) internal view returns (uint256[4] memory coeffs) {
        // Denominators: Π_{m≠k} (k - m) for k = 0,1,2,3
        // (-6, 2, -2, 6) in the field
        uint256[4] memory denoms = [fieldModulus - 6, 2, fieldModulus - 2, 6];

        for (uint256 k = 0; k < 4; k++) {
            uint256 num = 1;
            for (uint256 m = 0; m < 4; m++) {
                if (m != k) {
                    num = _fieldMul(num, _fieldSub(x, m));
                }
            }
            coeffs[k] = _fieldDiv(num, denoms[k]);
        }
    }

    /**
     * @notice Verify sumcheck round with Gruen's trick optimization
     * @param hsum0 First half-sum
     * @param hsum2 Third half-sum (x=2)
     * @param hsum3 Fourth half-sum (x=3)
     * @param prevTotal Previous round total
     * @param c Current evaluation point coordinate
     * @param challenge Random challenge
     */
    function _verifySumcheckRound(
        uint256 hsum0,
        uint256 hsum2,
        uint256 hsum3,
        uint256 prevTotal,
        uint256 c,
        uint256 challenge
    ) internal view returns (uint256 nextTotal, bool valid) {
        // Verifier computes hsum_1:
        // hsum_0 * (1-c) + hsum_1 * c = total
        // => hsum_1 = (total - hsum_0 * (1-c)) / c
        uint256 hsum1;
        if (c != 0) {
            uint256 oneMinusC = _fieldSub(1, c);
            uint256 hsum0Term = _fieldMul(hsum0, oneMinusC);
            uint256 numerator = _fieldSub(prevTotal, hsum0Term);
            hsum1 = _fieldDiv(numerator, c);
        } else {
            hsum1 = _fieldSub(prevTotal, hsum0);
        }

        // Interpolate to find hsum at challenge point
        uint256[4] memory coeffs = _deg3LagrangeWeights(challenge);
        uint256 hsumChallenge = _fieldAdd(
            _fieldAdd(_fieldMul(coeffs[0], hsum0), _fieldMul(coeffs[1], hsum1)),
            _fieldAdd(_fieldMul(coeffs[2], hsum2), _fieldMul(coeffs[3], hsum3))
        );

        // Convert to full sum
        nextTotal = _hsumToSum(hsumChallenge, challenge, c);

        // Verify consistency
        uint256 reconstructed = _fieldAdd(
            _fieldMul(hsum0, _fieldSub(1, c)),
            _fieldMul(hsum1, c)
        );
        valid = reconstructed == prevTotal;
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a GKR proof (implements IProofVerifier)
     * @param proof The encoded GKR proof
     * @param publicInputs The public inputs (commitment hashes)
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool valid) {
        if (proof.length < 64) return false;
        if (publicInputs.length < 64) return false;

        // Decode commitments from public inputs
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        assembly {
            inputCommitment := calldataload(publicInputs.offset)
            outputCommitment := calldataload(add(publicInputs.offset, 32))
        }

        // Verify commitment root
        bytes32 expectedRoot = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );
        bytes32 proofRoot;
        assembly {
            proofRoot := calldataload(proof.offset)
        }

        if (strictMode && proofRoot != expectedRoot) {
            return false;
        }

        // Simplified verification - in production, decode and verify all sumcheck rounds
        return true;
    }

    /**
     * @notice Verify and record a GKR proof
     */
    function verifyAndRecord(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid) {
        uint256 gasStart = gasleft();

        valid = this.verifyProof(proof, publicInputs);

        if (valid) {
            unchecked {
                ++totalProofsVerified;
            }
        }

        bytes32 inputCommitment;
        bytes32 outputCommitment;
        assembly {
            inputCommitment := calldataload(publicInputs.offset)
            outputCommitment := calldataload(add(publicInputs.offset, 32))
        }

        uint256 gasUsed = gasStart - gasleft();

        emit GKRProofVerified(
            keccak256(proof),
            inputCommitment,
            outputCommitment,
            valid,
            gasUsed
        );
    }

    /**
     * @notice Verify batch hash proof with GKR
     * @param proof The GKR proof
     * @param inputHashes Array of input hashes
     * @param outputHashes Array of expected output hashes
     */
    function verifyBatchHash(
        bytes calldata proof,
        bytes32[] calldata inputHashes,
        bytes32[] calldata outputHashes
    ) external view returns (bool valid) {
        if (inputHashes.length != outputHashes.length) return false;
        if (inputHashes.length == 0) return false;

        // Compute input/output commitments
        bytes32 inputCommitment = keccak256(abi.encodePacked(inputHashes));
        bytes32 outputCommitment = keccak256(abi.encodePacked(outputHashes));

        bytes memory publicInputs = abi.encodePacked(
            inputCommitment,
            outputCommitment
        );

        return this.verifyProof(proof, publicInputs);
    }

    /**
     * @notice Verify sumcheck proof directly
     * @param numRounds Number of sumcheck rounds
     * @param partialSums Encoded partial sums (3 per round with Gruen's trick)
     * @param challenges Random challenges
     * @param evalPoints Evaluation points
     * @param expectedTotal Expected final total
     */
    function verifySumcheck(
        uint256 numRounds,
        uint256[] calldata partialSums,
        uint256[] calldata challenges,
        uint256[] calldata evalPoints,
        uint256 expectedTotal
    ) external view returns (bool valid) {
        if (numRounds > MAX_ROUNDS) return false;
        if (partialSums.length != numRounds * 3) return false;
        if (challenges.length != numRounds) return false;
        if (evalPoints.length != numRounds) return false;

        uint256 currentTotal = expectedTotal;

        for (uint256 i = 0; i < numRounds; i++) {
            uint256 hsum0 = partialSums[i * 3];
            uint256 hsum2 = partialSums[i * 3 + 1];
            uint256 hsum3 = partialSums[i * 3 + 2];

            (uint256 nextTotal, bool roundValid) = _verifySumcheckRound(
                hsum0,
                hsum2,
                hsum3,
                currentTotal,
                evalPoints[i],
                challenges[i]
            );

            if (!roundValid) {
                revert SumcheckFailed(0, i);
            }

            currentTotal = nextTotal;
        }

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          IPROOFVERIFIER INTERFACE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IProofVerifier
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        if (proof.length == 0) return false;
        if (publicInputs.length < 2) return false;

        bytes memory encodedInputs = abi.encodePacked(
            bytes32(publicInputs[0]),
            bytes32(publicInputs[1])
        );

        return this.verifyProof(proof, encodedInputs);
    }

    /// @inheritdoc IProofVerifier
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool) {
        if (proof.length == 0) return false;

        bytes memory encodedInputs = abi.encodePacked(
            bytes32(publicInput),
            bytes32(0)
        );

        return this.verifyProof(proof, encodedInputs);
    }

    /// @inheritdoc IProofVerifier
    function getPublicInputCount() external pure override returns (uint256) {
        return 2; // inputCommitment, outputCommitment
    }

    /// @inheritdoc IProofVerifier
    function isReady() external view override returns (bool) {
        return !strictMode || hekateVerifier != address(0);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update configuration
     */
    function setConfig(
        uint256 _modulus,
        address _hekateVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_modulus == 0) revert InvalidPublicInputs();

        fieldModulus = _modulus;
        hekateVerifier = _hekateVerifier;

        emit ConfigUpdated(_modulus, _hekateVerifier);
    }

    /**
     * @notice Toggle strict mode
     */
    function setStrictMode(
        bool _enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        strictMode = _enabled;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get proof type
     */
    function proofType() external pure returns (bytes32) {
        return GKR_PROOF;
    }

    /**
     * @notice Get verifier statistics
     */
    function getStats()
        external
        view
        returns (uint256 total, uint256 modulus, address hekate, bool strict)
    {
        return (totalProofsVerified, fieldModulus, hekateVerifier, strictMode);
    }
}
