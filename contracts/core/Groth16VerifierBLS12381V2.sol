// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Groth16VerifierBN254
/// @author Soul Protocol
/// @notice Production-ready Groth16 verifier for BN254 curve using EVM precompiles
/// @dev Uses bn256Add (0x06), bn256ScalarMul (0x07), and bn256Pairing (0x08) precompiles
contract Groth16VerifierBN254 {
    /// @notice BN254 curve order (scalar field Fr)
    uint256 internal constant _FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice BN254 base field Fq
    uint256 internal constant _Q_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice Precompile addresses
    uint256 internal constant _PRECOMSoulE_ADD = 0x06;
    uint256 internal constant _PRECOMSoulE_MUL = 0x07;
    uint256 internal constant _PRECOMSoulE_PAIRING = 0x08;

    /// @notice Verification key components (to be set during deployment)
    struct VerificationKey {
        uint256[2] alpha; // G1 point
        uint256[4] beta; // G2 point [x_im, x_re, y_im, y_re]
        uint256[4] gamma; // G2 point
        uint256[4] delta; // G2 point
        uint256[2][] ic; // Input commitments (G1 points)
    }

    /// @notice The verification key for this circuit
    VerificationKey internal _vk;

    /// @notice Whether the verification key has been initialized
    bool public initialized;

    /// @notice Contract owner for key initialization (immutable)
    address public immutable owner;

    /// @notice Custom errors
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofLength();
    error InvalidPublicInputsLength();
    error InvalidPublicInput(uint256 index);
    error NotOwner();
    error PairingCheckFailed();
    error PrecompileFailed();
    error LengthMismatch();

    /// @notice Emitted when verification key is set
    event VerificationKeySet(address indexed setter);

    /// @notice Modifier to restrict to owner
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Sets the verification key (can only be called once)
    /// @param alpha The alpha component of the verification key (G1 point)
    /// @param beta The beta component (G2 point: [x_im, x_re, y_im, y_re])
    /// @param gamma The gamma component (G2 point)
    /// @param delta The delta component (G2 point)
    /// @param ic The input commitment points (G1 points)
    function setVerificationKey(
        uint256[2] calldata alpha,
        uint256[4] calldata beta,
        uint256[4] calldata gamma,
        uint256[4] calldata delta,
        uint256[2][] calldata ic
    ) external onlyOwner {
        if (initialized) revert AlreadyInitialized();

        _vk.alpha = alpha;
        _vk.beta = beta;
        _vk.gamma = gamma;
        _vk.delta = delta;

        delete _vk.ic;
        for (uint256 i = 0; i < ic.length; i++) {
            _vk.ic.push(ic[i]);
        }

        initialized = true;
        emit VerificationKeySet(msg.sender);
    }

    /// @notice Verifies a Groth16 proof using BN254 pairing precompile
    /// @param proof The proof bytes: A (64) + B (128) + C (64) = 256 bytes
    /// @param publicInputs The public inputs bytes (32 bytes per input)
    /// @return valid True if the proof is valid
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        if (!initialized) revert NotInitialized();

        // Proof must be exactly 256 bytes: A (2*32) + B (4*32) + C (2*32)
        if (proof.length != 256) revert InvalidProofLength();

        // Must have at least one public input and match IC length
        uint256 numInputs = publicInputs.length / 32;
        if (numInputs + 1 != _vk.ic.length) revert InvalidPublicInputsLength();

        // Parse proof points
        uint256[8] memory proofData = [uint256(0), 0, 0, 0, 0, 0, 0, 0];
        for (uint256 i = 0; i < 8; i++) {
            proofData[i] = _bytesToUint(proof, i * 32);
        }

        // Parse and validate public inputs
        uint256[] memory inputs = new uint256[](numInputs);
        for (uint256 i = 0; i < numInputs; i++) {
            inputs[i] = _bytesToUint(publicInputs, i * 32);
            if (inputs[i] >= _FIELD_MODULUS) revert InvalidPublicInput(i);
        }

        // Compute vk_x = IC[0] + sum(inputs[i] * IC[i+1])
        (uint256 vkX_x, uint256 vkX_y) = _computeLinearCombination(inputs);

        // Perform pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        return
            _verifyPairing(
                proofData[0],
                proofData[1], // A
                proofData[2],
                proofData[3],
                proofData[4],
                proofData[5], // B
                proofData[6],
                proofData[7], // C
                vkX_x,
                vkX_y
            );
    }

    /// @notice Verifies a Groth16 proof with parsed inputs (alternative interface)
    /// @param pA G1 point A
    /// @param pB G2 point B
    /// @param pC G1 point C
    /// @param pubSignals Array of public signals
    /// @return valid True if the proof is valid
    function verifyProofParsed(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[] calldata pubSignals
    ) external view returns (bool valid) {
        if (!initialized) revert NotInitialized();
        if (pubSignals.length + 1 != _vk.ic.length)
            revert InvalidPublicInputsLength();

        // Validate public inputs are in field
        for (uint256 i = 0; i < pubSignals.length; i++) {
            if (pubSignals[i] >= _FIELD_MODULUS) revert InvalidPublicInput(i);
        }

        // Compute vk_x
        (uint256 vkX_x, uint256 vkX_y) = _computeLinearCombination(pubSignals);

        // Note: pB ordering is [x_re, x_im][y_re, y_im] from snarkjs
        return
            _verifyPairing(
                pA[0],
                pA[1],
                pB[0][1],
                pB[0][0],
                pB[1][1],
                pB[1][0], // Reorder for pairing precompile
                pC[0],
                pC[1],
                vkX_x,
                vkX_y
            );
    }

    /// @notice Batch verifies multiple proofs (gas optimization)
    /// @param proofs Array of proofs
    /// @param publicInputsArray Array of public inputs
    /// @return allValid True if all proofs are valid
    function batchVerifyProofs(
        bytes[] calldata proofs,
        bytes[] calldata publicInputsArray
    ) external view returns (bool allValid) {
        if (proofs.length != publicInputsArray.length) revert LengthMismatch();

        for (uint256 i = 0; i < proofs.length; i++) {
            if (!this.verifyProof(proofs[i], publicInputsArray[i])) {
                return false;
            }
        }
        return true;
    }

    /// @notice Returns the number of input commitments
    /// @return count The number of IC points
    function getICCount() external view returns (uint256 count) {
        return _vk.ic.length;
    }

    /// @dev Computes the linear combination for public inputs
    /// @param inputs The public inputs array
    /// @return x X coordinate of result
    /// @return y Y coordinate of result
    function _computeLinearCombination(
        uint256[] memory inputs
    ) internal view returns (uint256 x, uint256 y) {
        // Start with IC[0]
        x = _vk.ic[0][0];
        y = _vk.ic[0][1];

        // Add inputs[i] * IC[i+1] for each input
        for (uint256 i = 0; i < inputs.length; i++) {
            uint256[2] storage icPoint = _vk.ic[i + 1];

            // Scalar multiplication: inputs[i] * IC[i+1]
            (uint256 mulX, uint256 mulY) = _ecMul(
                icPoint[0],
                icPoint[1],
                inputs[i]
            );

            // Point addition: acc + (inputs[i] * IC[i+1])
            (x, y) = _ecAdd(x, y, mulX, mulY);
        }
    }

    /// @dev Performs the Groth16 pairing check
    /// @return True if pairing check passes
    function _verifyPairing(
        uint256 aX,
        uint256 aY,
        uint256 bX_im,
        uint256 bX_re,
        uint256 bY_im,
        uint256 bY_re,
        uint256 cX,
        uint256 cY,
        uint256 vkX_x,
        uint256 vkX_y
    ) internal view returns (bool) {
        // Pairing check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1

        uint256[24] memory input;

        // -A (negate Y coordinate: -Y mod Q)
        input[0] = aX;
        input[1] = aY == 0 ? 0 : _Q_MODULUS - aY;
        // B
        input[2] = bX_im;
        input[3] = bX_re;
        input[4] = bY_im;
        input[5] = bY_re;

        // Alpha
        input[6] = _vk.alpha[0];
        input[7] = _vk.alpha[1];
        // Beta
        input[8] = _vk.beta[0];
        input[9] = _vk.beta[1];
        input[10] = _vk.beta[2];
        input[11] = _vk.beta[3];

        // vk_x
        input[12] = vkX_x;
        input[13] = vkX_y;
        // Gamma
        input[14] = _vk.gamma[0];
        input[15] = _vk.gamma[1];
        input[16] = _vk.gamma[2];
        input[17] = _vk.gamma[3];

        // C
        input[18] = cX;
        input[19] = cY;
        // Delta
        input[20] = _vk.delta[0];
        input[21] = _vk.delta[1];
        input[22] = _vk.delta[2];
        input[23] = _vk.delta[3];

        // Call pairing precompile
        uint256[1] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 8, input, 768, result, 32)
        }

        if (!success) revert PrecompileFailed();
        return result[0] == 1;
    }

    /// @dev Elliptic curve point addition using precompile 0x06
    function _ecAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256 x, uint256 y) {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory result;

        bool success;
        assembly {
            success := staticcall(gas(), 6, input, 128, result, 64)
        }

        if (!success) revert PrecompileFailed();
        return (result[0], result[1]);
    }

    /// @dev Elliptic curve scalar multiplication using precompile 0x07
    function _ecMul(
        uint256 x,
        uint256 y,
        uint256 scalar
    ) internal view returns (uint256 rx, uint256 ry) {
        uint256[3] memory input = [x, y, scalar];
        uint256[2] memory result;

        bool success;
        assembly {
            success := staticcall(gas(), 7, input, 96, result, 64)
        }

        if (!success) revert PrecompileFailed();
        return (result[0], result[1]);
    }

    /// @dev Converts bytes to uint256 at given offset
    function _bytesToUint(
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 result) {
        assembly {
            result := calldataload(add(data.offset, offset))
        }
    }
}
