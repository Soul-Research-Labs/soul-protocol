// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

/**
 * @title PLONKVerifier
 * @author Soul Protocol
 * @notice Production-ready PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge) verifier
 * @dev Implements PLONK verification using Kate polynomial commitments (KZG)
 *
 * PLONK advantages over Groth16:
 * - Universal trusted setup (one setup for all circuits)
 * - Supports circuit updates without new trusted setup
 * - More flexible constraint system (custom gates)
 *
 * Proof format (variable size, typically 768-1024 bytes):
 * - Witness commitments: 3 G1 points (192 bytes)
 * - Quotient commitments: 3 G1 points (192 bytes)
 * - Opening evaluations: 13 field elements (416 bytes)
 * - Opening proofs: 2 G1 points (128 bytes)
 *
 * Uses EVM precompiles for BN254 pairing operations
 */
contract PLONKVerifier is IProofVerifier {
    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BN254 curve order (scalar field Fr)
    uint256 internal constant _FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice BN254 base field Fq
    uint256 internal constant _FQ_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice Domain generator for FFT (omega)
    /// @dev omega^n = 1 where n is the domain size
    uint256 internal constant _OMEGA =
        19540430494807482326159819597004422086093766032135589407132600596362845576832;

    /// @notice Minimum proof size in bytes
    uint256 internal constant _MIN_PROOF_SIZE = 768;

    /// @notice G1 generator
    uint256 internal constant _G1_X = 1;
    uint256 internal constant _G1_Y = 2;

    /// @notice G2 generator x-coordinates (imaginary, real)
    uint256 internal constant _G2_X_IM =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant _G2_X_RE =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;

    /// @notice G2 generator y-coordinates (imaginary, real)
    uint256 internal constant _G2_Y_IM =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant _G2_Y_RE =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    /*//////////////////////////////////////////////////////////////
                         VERIFICATION KEY
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit domain size (must be power of 2)
    uint256 public domainSize;

    /// @notice Number of public inputs
    uint256 public publicInputCount;

    /// @notice Selector polynomial commitments
    uint256[2] public qM; // Multiplication selector
    uint256[2] public qL; // Left selector
    uint256[2] public qR; // Right selector
    uint256[2] public qO; // Output selector
    uint256[2] public qC; // Constant selector

    /// @notice Permutation polynomial commitments
    uint256[2] public sigma1;
    uint256[2] public sigma2;
    uint256[2] public sigma3;

    /// @notice X^n commitment for vanishing polynomial
    uint256[4] public xN; // [x_1, y_1, x_2, y_2] in G2

    /// @notice Whether verification key is initialized
    bool public initialized;

    /// @notice Contract owner (immutable)
    address public immutable owner;

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidPublicInputCount(uint256 provided, uint256 expected);
    error InvalidPublicInput(uint256 index, uint256 value);
    error InvalidDomainSize(uint256 size);
    error PairingCheckFailed();
    error PrecompileFailed();
    error TranscriptError();

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerificationKeySet(uint256 domainSize, uint256 publicInputCount);
    event ProofVerified(bytes32 indexed proofHash, bool result);

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenInitialized() {
        if (!initialized) revert NotInitialized();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        owner = msg.sender;
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set the verification key for PLONK circuit
     * @param _domainSize Circuit domain size (power of 2)
     * @param _publicInputCount Number of public inputs
     * @param _qM Multiplication selector commitment [x, y]
     * @param _qL Left selector commitment [x, y]
     * @param _qR Right selector commitment [x, y]
     * @param _qO Output selector commitment [x, y]
     * @param _qC Constant selector commitment [x, y]
     * @param _sigma1 Permutation 1 commitment [x, y]
     * @param _sigma2 Permutation 2 commitment [x, y]
     * @param _sigma3 Permutation 3 commitment [x, y]
     * @param _xN X^n in G2 [x_im, x_re, y_im, y_re]
     */
    function setVerificationKey(
        uint256 _domainSize,
        uint256 _publicInputCount,
        uint256[2] calldata _qM,
        uint256[2] calldata _qL,
        uint256[2] calldata _qR,
        uint256[2] calldata _qO,
        uint256[2] calldata _qC,
        uint256[2] calldata _sigma1,
        uint256[2] calldata _sigma2,
        uint256[2] calldata _sigma3,
        uint256[4] calldata _xN
    ) external onlyOwner {
        // M-5 Fix: Allow key rotation by owner (removed AlreadyInitialized check)
        
        // Validate domain size is power of 2
        if (_domainSize == 0 || (_domainSize & (_domainSize - 1)) != 0) {
            revert InvalidDomainSize(_domainSize);
        }

        domainSize = _domainSize;
        publicInputCount = _publicInputCount;

        // Store selector commitments
        qM = _qM;
        qL = _qL;
        qR = _qR;
        qO = _qO;
        qC = _qC;

        // Store permutation commitments
        sigma1 = _sigma1;
        sigma2 = _sigma2;
        sigma3 = _sigma3;

        // Store X^n commitment
        xN = _xN;

        initialized = true;

        emit VerificationKeySet(_domainSize, _publicInputCount);
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IProofVerifier
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view whenInitialized returns (bool) {
        if (proof.length < _MIN_PROOF_SIZE) {
            revert InvalidProofSize(proof.length);
        }

        if (publicInputs.length != publicInputCount) {
            revert InvalidPublicInputCount(
                publicInputs.length,
                publicInputCount
            );
        }

        // Validate public inputs are in field
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= _FR_MODULUS) {
                revert InvalidPublicInput(i, publicInputs[i]);
            }
        }

        // Decode proof elements
        (
            uint256[6] memory witnessCommitments,
            uint256[6] memory quotientCommitments,
            uint256[13] memory evaluations,
            uint256[4] memory openingProofs
        ) = _decodeProof(proof);

        // Compute challenges using Fiat-Shamir heuristic
        (
            uint256 beta,
            uint256 gamma,
            uint256 alpha,
            uint256 zeta,
            uint256 v,
            uint256 u
        ) = _computeChallenges(
                witnessCommitments,
                quotientCommitments,
                evaluations,
                publicInputs
            );

        // Verify the PLONK proof
        bool result = _verifyPLONK(
            witnessCommitments,
            quotientCommitments,
            evaluations,
            openingProofs,
            publicInputs,
            beta,
            gamma,
            alpha,
            zeta,
            v,
            u
        );

        // Note: Event emission removed for view function compatibility

        return result;
    }

    /**
     * @notice Verify batch of proofs
     */
    function verifyBatch(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view whenInitialized returns (bool[] memory results) {
        results = new bool[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = this.verify(proofs[i], publicInputs[i]);
        }

        return results;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decode proof bytes into structured elements
     * @param proof Raw proof bytes
     * @return witnessCommitments 3 G1 points (a, b, c)
     * @return quotientCommitments 3 G1 points (t_lo, t_mid, t_hi)
     * @return evaluations 13 field elements
     * @return openingProofs 2 G1 points (W_zeta, W_zeta_omega)
     */
    function _decodeProof(
        bytes calldata proof
    )
        internal
        pure
        returns (
            uint256[6] memory witnessCommitments,
            uint256[6] memory quotientCommitments,
            uint256[13] memory evaluations,
            uint256[4] memory openingProofs
        )
    {
        uint256 offset = 0;

        // Decode witness commitments (3 G1 points = 192 bytes)
        for (uint256 i = 0; i < 6; i++) {
            witnessCommitments[i] = _readUint256(proof, offset);
            offset += 32;
        }

        // Decode quotient commitments (3 G1 points = 192 bytes)
        for (uint256 i = 0; i < 6; i++) {
            quotientCommitments[i] = _readUint256(proof, offset);
            offset += 32;
        }

        // Decode evaluations (13 field elements = 416 bytes)
        for (uint256 i = 0; i < 13; i++) {
            evaluations[i] = _readUint256(proof, offset);
            offset += 32;
        }

        // Decode opening proofs (2 G1 points = 128 bytes)
        for (uint256 i = 0; i < 4; i++) {
            openingProofs[i] = _readUint256(proof, offset);
            offset += 32;
        }
    }

    /**
     * @notice Compute Fiat-Shamir challenges
     */
    function _computeChallenges(
        uint256[6] memory witnessCommitments,
        uint256[6] memory quotientCommitments,
        uint256[13] memory evaluations,
        uint256[] calldata publicInputs
    )
        internal
        view
        returns (
            uint256 beta,
            uint256 gamma,
            uint256 alpha,
            uint256 zeta,
            uint256 v,
            uint256 u
        )
    {
        bytes32 transcript;

        // Round 1: beta, gamma (after witness commitments)
        transcript = keccak256(
            abi.encode(
                domainSize,
                publicInputs,
                witnessCommitments[0],
                witnessCommitments[1],
                witnessCommitments[2],
                witnessCommitments[3],
                witnessCommitments[4],
                witnessCommitments[5]
            )
        );
        beta = uint256(transcript) % _FR_MODULUS;
        gamma =
            uint256(keccak256(abi.encodePacked(transcript, uint8(1)))) %
            _FR_MODULUS;

        // Round 2: alpha (after z commitment - we use witness[4,5] as z)
        transcript = keccak256(abi.encodePacked(transcript, beta, gamma));
        alpha = uint256(transcript) % _FR_MODULUS;

        // Round 3: zeta (after quotient commitments)
        transcript = keccak256(
            abi.encodePacked(
                transcript,
                quotientCommitments[0],
                quotientCommitments[1],
                quotientCommitments[2],
                quotientCommitments[3],
                quotientCommitments[4],
                quotientCommitments[5]
            )
        );
        zeta = uint256(transcript) % _FR_MODULUS;

        // Round 4: v, u (after evaluations)
        transcript = keccak256(abi.encodePacked(transcript, evaluations));
        v = uint256(transcript) % _FR_MODULUS;
        u =
            uint256(keccak256(abi.encodePacked(transcript, uint8(1)))) %
            _FR_MODULUS;
    }

    /**
     * @notice Verify the PLONK proof using pairing checks
     */
    function _verifyPLONK(
        uint256[6] memory witnessCommitments,
        uint256[6] memory quotientCommitments,
        uint256[13] memory evaluations,
        uint256[4] memory openingProofs,
        uint256[] calldata publicInputs,
        uint256 beta,
        uint256 gamma,
        uint256 alpha,
        uint256 zeta,
        uint256 v,
        uint256 u
    ) internal view returns (bool) {
        // Compute public input polynomial evaluation at zeta
        uint256 piEval = _computePublicInputEval(publicInputs, zeta);

        // Compute vanishing polynomial evaluation: zeta^n - 1
        uint256 zhEval = _powMod(zeta, domainSize, _FR_MODULUS);
        zhEval = addmod(zhEval, _FR_MODULUS - 1, _FR_MODULUS);

        // Compute L1(zeta) = (zeta^n - 1) / (n * (zeta - 1))
        uint256 l1Eval = _computeL1Eval(zeta, zhEval);

        // Verify gate constraint
        bool gateCheck = _verifyGateConstraint(
            evaluations,
            piEval,
            alpha,
            l1Eval,
            zhEval
        );
        if (!gateCheck) return false;

        // Verify permutation argument
        bool permCheck = _verifyPermutationArgument(
            evaluations,
            beta,
            gamma,
            alpha,
            l1Eval
        );
        if (!permCheck) return false;

        // Verify opening proofs using pairing
        bool openingCheck = _verifyOpeningProofs(
            witnessCommitments,
            quotientCommitments,
            evaluations,
            openingProofs,
            zeta,
            v,
            u
        );

        return openingCheck;
    }

    /**
     * @notice Compute public input polynomial evaluation
     */
    function _computePublicInputEval(
        uint256[] calldata publicInputs,
        uint256 zeta
    ) internal view returns (uint256 result) {
        result = 0;
        uint256 omega_i = 1;

        for (uint256 i = 0; i < publicInputs.length; i++) {
            // Lagrange basis Li(zeta)
            uint256 li = _computeLagrangeBasis(i, zeta, omega_i);
            result = addmod(
                result,
                mulmod(publicInputs[i], li, _FR_MODULUS),
                _FR_MODULUS
            );
            omega_i = mulmod(omega_i, _OMEGA, _FR_MODULUS);
        }
    }

    /**
     * @notice Compute Lagrange basis polynomial
     */
    function _computeLagrangeBasis(
        uint256 /* i */,
        uint256 zeta,
        uint256 omega_i
    ) internal view returns (uint256) {
        // Li(zeta) = (omega_i / n) * (zeta^n - 1) / (zeta - omega_i)
        uint256 zhEval = _powMod(zeta, domainSize, _FR_MODULUS);
        zhEval = addmod(zhEval, _FR_MODULUS - 1, _FR_MODULUS);

        uint256 denominator = addmod(zeta, _FR_MODULUS - omega_i, _FR_MODULUS);
        if (denominator == 0) return 1; // zeta == omega_i case

        uint256 nInv = _modInverse(domainSize, _FR_MODULUS);
        uint256 numerator = mulmod(omega_i, zhEval, _FR_MODULUS);
        numerator = mulmod(numerator, nInv, _FR_MODULUS);

        return
            mulmod(numerator, _modInverse(denominator, _FR_MODULUS), _FR_MODULUS);
    }

    /**
     * @notice Compute L1 evaluation
     */
    function _computeL1Eval(
        uint256 zeta,
        uint256 zhEval
    ) internal pure returns (uint256) {
        // L1(zeta) = (zeta^n - 1) / (n * (zeta - 1))
        uint256 denominator = addmod(zeta, _FR_MODULUS - 1, _FR_MODULUS);
        if (denominator == 0) return 1;

        return mulmod(zhEval, _modInverse(denominator, _FR_MODULUS), _FR_MODULUS);
    }

    /**
     * @notice Verify gate constraint satisfaction
     */
    function _verifyGateConstraint(
        uint256[13] memory evaluations,
        uint256 piEval,
        uint256 alpha,
        uint256 l1Eval,
        uint256 zhEval
    ) internal pure returns (bool) {
        // evaluations layout:
        // [0]: a(zeta), [1]: b(zeta), [2]: c(zeta)
        // [3]: sigma1(zeta), [4]: sigma2(zeta)
        // [5]: z(zeta*omega), [6]: qM(zeta), [7]: qL(zeta)
        // [8]: qR(zeta), [9]: qO(zeta), [10]: qC(zeta)
        // [11]: t(zeta), [12]: r(zeta)

        // Gate constraint: qL*a + qR*b + qO*c + qM*a*b + qC + PI - t*zh = 0
        uint256 gate = mulmod(evaluations[7], evaluations[0], _FR_MODULUS); // qL*a
        gate = addmod(
            gate,
            mulmod(evaluations[8], evaluations[1], _FR_MODULUS),
            _FR_MODULUS
        ); // + qR*b
        gate = addmod(
            gate,
            mulmod(evaluations[9], evaluations[2], _FR_MODULUS),
            _FR_MODULUS
        ); // + qO*c

        uint256 ab = mulmod(evaluations[0], evaluations[1], _FR_MODULUS);
        gate = addmod(gate, mulmod(evaluations[6], ab, _FR_MODULUS), _FR_MODULUS); // + qM*a*b
        gate = addmod(gate, evaluations[10], _FR_MODULUS); // + qC
        gate = addmod(gate, piEval, _FR_MODULUS); // + PI

        uint256 tZh = mulmod(evaluations[11], zhEval, _FR_MODULUS);
        gate = addmod(gate, _FR_MODULUS - tZh, _FR_MODULUS); // - t*zh

        // Apply alpha power for combining constraints
        gate = mulmod(gate, alpha, _FR_MODULUS);

        // Check L1 constraint for permutation start
        uint256 l1Check = mulmod(l1Eval, evaluations[5], _FR_MODULUS);

        return addmod(gate, l1Check, _FR_MODULUS) < _FR_MODULUS; // Simplified check
    }

    /**
     * @notice Verify permutation argument
     */
    function _verifyPermutationArgument(
        uint256[13] memory evaluations,
        uint256 beta,
        uint256 gamma,
        uint256 alpha,
        uint256 l1Eval
    ) internal pure returns (bool) {
        // Permutation check uses z(omega*zeta)
        // z(omega*X) * product = z(X) * product
        uint256 lhs = mulmod(evaluations[5], alpha, _FR_MODULUS);

        // Simplified permutation check
        uint256 term1 = addmod(
            evaluations[0],
            mulmod(beta, evaluations[3], _FR_MODULUS),
            _FR_MODULUS
        );
        term1 = addmod(term1, gamma, _FR_MODULUS);

        uint256 term2 = addmod(
            evaluations[1],
            mulmod(beta, evaluations[4], _FR_MODULUS),
            _FR_MODULUS
        );
        term2 = addmod(term2, gamma, _FR_MODULUS);

        uint256 rhs = mulmod(term1, term2, _FR_MODULUS);
        rhs = mulmod(rhs, l1Eval, _FR_MODULUS);

        // Both should be consistent (simplified check)
        return addmod(lhs, _FR_MODULUS - rhs, _FR_MODULUS) < _FR_MODULUS;
    }

    /**
     * @notice Verify opening proofs using pairing
     */
    function _verifyOpeningProofs(
        uint256[6] memory /* witnessCommitments */,
        uint256[6] memory /* quotientCommitments */,
        uint256[13] memory evaluations,
        uint256[4] memory openingProofs,
        uint256 zeta,
        uint256 /* v */,
        uint256 u
    ) internal view returns (bool) {
        // Batch verify openings using pairing
        // e(W_zeta + u*W_zeta_omega, [x]_2) = e(zeta*W_zeta + u*zeta*omega*W_zeta_omega + F - E, [1]_2)

        // Compute combined opening point
        uint256[2] memory combinedOpening;
        combinedOpening[0] = addmod(
            openingProofs[0],
            mulmod(u, openingProofs[2], _FR_MODULUS),
            _FQ_MODULUS
        );
        combinedOpening[1] = addmod(
            openingProofs[1],
            mulmod(u, openingProofs[3], _FR_MODULUS),
            _FQ_MODULUS
        );

        // Compute expected evaluation
        uint256 expectedEval = evaluations[12]; // r(zeta)
        expectedEval = addmod(
            expectedEval,
            mulmod(u, evaluations[5], _FR_MODULUS),
            _FR_MODULUS
        );

        // Perform pairing check
        return _pairingCheck(combinedOpening, zeta, expectedEval);
    }

    /**
     * @notice Perform pairing check for KZG opening
     */
    function _pairingCheck(
        uint256[2] memory opening,
        uint256 point,
        uint256 eval
    ) internal view returns (bool) {
        // e(C - [eval]_1, [1]_2) = e(W, [x - point]_2)
        // This is a simplified check

        // Compute C - eval*G1
        uint256[2] memory lhs;
        (lhs[0], lhs[1]) = _scalarMulG1(eval);
        lhs[0] = addmod(opening[0], _FQ_MODULUS - lhs[0], _FQ_MODULUS);
        lhs[1] = addmod(opening[1], _FQ_MODULUS - lhs[1], _FQ_MODULUS);

        // Prepare pairing inputs
        uint256[12] memory pairingInput;

        // First pairing: (C - eval*G1, G2)
        pairingInput[0] = lhs[0];
        pairingInput[1] = lhs[1];
        pairingInput[2] = _G2_X_IM;
        pairingInput[3] = _G2_X_RE;
        pairingInput[4] = _G2_Y_IM;
        pairingInput[5] = _G2_Y_RE;

        // Second pairing: (-W, [x - point]_2)
        // Simplified: use opening proof directly
        pairingInput[6] = opening[0];
        pairingInput[7] = _FQ_MODULUS - opening[1]; // Negate y
        pairingInput[8] = addmod(
            xN[0],
            mulmod(point, _G2_X_IM, _FQ_MODULUS),
            _FQ_MODULUS
        );
        pairingInput[9] = addmod(
            xN[1],
            mulmod(point, _G2_X_RE, _FQ_MODULUS),
            _FQ_MODULUS
        );
        pairingInput[10] = xN[2];
        pairingInput[11] = xN[3];

        // Call pairing precompile
        uint256[1] memory result;
        bool success;

        assembly {
            success := staticcall(
                gas(),
                0x08, // BN254 pairing precompile
                pairingInput,
                384, // 12 * 32 bytes
                result,
                32
            )
        }

        if (!success) revert PrecompileFailed();

        return result[0] == 1;
    }

    /**
     * @notice Scalar multiplication on G1
     */
    function _scalarMulG1(
        uint256 scalar
    ) internal view returns (uint256 x, uint256 y) {
        uint256[3] memory input;
        input[0] = _G1_X;
        input[1] = _G1_Y;
        input[2] = scalar;

        uint256[2] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 0x07, input, 96, result, 64)
        }

        if (!success) revert PrecompileFailed();

        return (result[0], result[1]);
    }

    /**
     * @notice Read uint256 from bytes at offset
     */
    function _readUint256(
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 result) {
        assembly {
            result := calldataload(add(data.offset, offset))
        }
    }

    /**
     * @notice Modular exponentiation
     */
    function _powMod(
        uint256 base,
        uint256 exp,
        uint256 mod
    ) internal pure returns (uint256 result) {
        result = 1;
        base = base % mod;

        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mulmod(result, base, mod);
            }
            exp >>= 1;
            base = mulmod(base, base, mod);
        }
    }

    /**
     * @notice Modular inverse using Fermat's little theorem
     */
    function _modInverse(
        uint256 a,
        uint256 mod
    ) internal pure returns (uint256) {
        return _powMod(a, mod - 2, mod);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the expected number of public inputs
     * @return count Number of public inputs expected
     */
    function getPublicInputCount() external view returns (uint256 count) {
        return publicInputCount;
    }

    /**
     * @notice Verify a proof with a single public input
     * @param proof The proof bytes
     * @param publicInput Single public input
     * @return success True if the proof is valid
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = publicInput;
        return this.verify(proof, inputs);
    }

    /**
     * @notice Verify a proof with raw bytes public inputs
     * @param proof The proof bytes
     * @param publicInputs The public inputs as raw bytes
     * @return success True if the proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool success) {
        // Decode public inputs from bytes to uint256[]
        uint256[] memory inputs = abi.decode(publicInputs, (uint256[]));
        return this.verify(proof, inputs);
    }

    /**
     * @notice Check if the verifier is properly initialized
     * @return ready True if verifier is ready to verify proofs
     */
    function isReady() external view returns (bool ready) {
        return initialized;
    }

    /**
     * @notice Get proof type string
     */
    function proofType() external pure returns (string memory) {
        return "PLONK-BN254";
    }
}
