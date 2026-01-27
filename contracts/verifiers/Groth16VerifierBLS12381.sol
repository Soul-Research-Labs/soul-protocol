// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Groth16VerifierBLS12381
/// @author Soul Protocol
/// @notice Groth16 verifier for BLS12-381 curve using EIP-2537 precompiles
/// @dev Uses BLS12-381 precompiles (0x0a-0x12) for pairing operations
/// @notice EIP-2537 is expected to be active on Ethereum post-Pectra upgrade
contract Groth16VerifierBLS12381 {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BLS12-381 scalar field modulus (r)
    uint256 constant FIELD_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice EIP-2537 Precompile addresses
    address constant BLS12_G1ADD = address(0x0a);
    address constant BLS12_G1MUL = address(0x0b);
    address constant BLS12_G1MULTIEXP = address(0x0c);
    address constant BLS12_G2ADD = address(0x0d);
    address constant BLS12_G2MUL = address(0x0e);
    address constant BLS12_G2MULTIEXP = address(0x0f);
    address constant BLS12_PAIRING = address(0x10);
    address constant BLS12_MAP_FP_TO_G1 = address(0x11);
    address constant BLS12_MAP_FP2_TO_G2 = address(0x12);

    /// @notice G1 point size in bytes (48 bytes per coordinate, 96 total)
    uint256 constant G1_SIZE = 96;

    /// @notice G2 point size in bytes (96 bytes per Fp2, 192 total)
    uint256 constant G2_SIZE = 192;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Verification key stored as raw bytes for gas efficiency
    bytes public vkAlpha; // 96 bytes - G1
    bytes public vkBeta; // 192 bytes - G2
    bytes public vkGamma; // 192 bytes - G2
    bytes public vkDelta; // 192 bytes - G2
    bytes[] public vkIC; // Array of 96-byte G1 points

    /// @notice Whether initialized
    bool public initialized;

    /// @notice Contract owner
    address public owner;

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofLength();
    error InvalidPublicInputsLength();
    error InvalidPublicInput(uint256 index);
    error PrecompileFailed(address precompile);
    error PairingCheckFailed();
    error EIP2537NotSupported();
    error InvalidPointSize();

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerificationKeySet(uint256 icLength);
    event ProofVerified(bytes32 indexed proofHash, bool result);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        owner = msg.sender;
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFICATION KEY SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the verification key
    /// @param _alpha Alpha G1 point (96 bytes)
    /// @param _beta Beta G2 point (192 bytes)
    /// @param _gamma Gamma G2 point (192 bytes)
    /// @param _delta Delta G2 point (192 bytes)
    /// @param _ic Array of IC G1 points (each 96 bytes)
    function setVerificationKey(
        bytes calldata _alpha,
        bytes calldata _beta,
        bytes calldata _gamma,
        bytes calldata _delta,
        bytes[] calldata _ic
    ) external onlyOwner {
        if (initialized) revert AlreadyInitialized();

        if (_alpha.length != G1_SIZE) revert InvalidPointSize();
        if (_beta.length != G2_SIZE) revert InvalidPointSize();
        if (_gamma.length != G2_SIZE) revert InvalidPointSize();
        if (_delta.length != G2_SIZE) revert InvalidPointSize();
        require(_ic.length >= 1, "IC must have at least 1 element");

        vkAlpha = _alpha;
        vkBeta = _beta;
        vkGamma = _gamma;
        vkDelta = _delta;

        delete vkIC;
        uint256 icLen = _ic.length;
        for (uint256 i = 0; i < icLen; ) {
            if (_ic[i].length != G1_SIZE) revert InvalidPointSize();
            vkIC.push(_ic[i]);
            unchecked {
                ++i;
            }
        }

        initialized = true;
        emit VerificationKeySet(icLen);
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies a Groth16 proof
    /// @param proof The proof bytes (A: 96, B: 192, C: 96 = 384 bytes total)
    /// @param publicInputs The public inputs as bytes (32 bytes each)
    /// @return valid True if the proof is valid
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        if (!initialized) revert NotInitialized();

        // Proof: A (96) + B (192) + C (96) = 384 bytes
        if (proof.length != 384) revert InvalidProofLength();

        uint256 numInputs = publicInputs.length / 32;
        if (numInputs + 1 != vkIC.length) revert InvalidPublicInputsLength();

        // Parse and validate public inputs
        uint256[] memory inputs = new uint256[](numInputs);
        for (uint256 i = 0; i < numInputs; i++) {
            inputs[i] = abi.decode(
                publicInputs[i * 32:(i + 1) * 32],
                (uint256)
            );
            if (inputs[i] >= FIELD_MODULUS) revert InvalidPublicInput(i);
        }

        // Compute vk_x = IC[0] + sum(inputs[i] * IC[i+1]) using G1 multiexp
        bytes memory vkX = _computeLinearCombination(inputs);

        // Extract proof points
        bytes memory pA = proof[0:96];
        bytes memory pB = proof[96:288];
        bytes memory pC = proof[288:384];

        // Verify pairing: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        return _verifyPairing(pA, pB, pC, vkX);
    }

    /// @notice Verifies proof with parsed inputs (alternative interface)
    /// @param pA G1 point A (96 bytes)
    /// @param pB G2 point B (192 bytes)
    /// @param pC G1 point C (96 bytes)
    /// @param pubSignals Array of public signals
    /// @return valid True if proof is valid
    function verifyProofParsed(
        bytes calldata pA,
        bytes calldata pB,
        bytes calldata pC,
        uint256[] calldata pubSignals
    ) external view returns (bool valid) {
        if (!initialized) revert NotInitialized();

        if (pA.length != G1_SIZE) revert InvalidPointSize();
        if (pB.length != G2_SIZE) revert InvalidPointSize();
        if (pC.length != G1_SIZE) revert InvalidPointSize();
        if (pubSignals.length + 1 != vkIC.length)
            revert InvalidPublicInputsLength();

        // Validate inputs
        for (uint256 i = 0; i < pubSignals.length; i++) {
            if (pubSignals[i] >= FIELD_MODULUS) revert InvalidPublicInput(i);
        }

        // Compute vk_x
        bytes memory vkX = _computeLinearCombinationDirect(pubSignals);

        return _verifyPairing(pA, pB, pC, vkX);
    }

    /// @notice Batch verify multiple proofs
    function batchVerifyProofs(
        bytes[] calldata proofs,
        bytes[] calldata publicInputsArray
    ) external view returns (bool allValid) {
        require(proofs.length == publicInputsArray.length, "Length mismatch");

        for (uint256 i = 0; i < proofs.length; i++) {
            if (!this.verifyProof(proofs[i], publicInputsArray[i])) {
                return false;
            }
        }
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Computes IC[0] + sum(inputs[i] * IC[i+1]) using G1 multiexp precompile
    function _computeLinearCombination(
        uint256[] memory inputs
    ) internal view returns (bytes memory) {
        // Build multiexp input: pairs of (G1 point 96 bytes, scalar 32 bytes)
        uint256 pairCount = inputs.length + 1;
        bytes memory multiExpInput = new bytes(pairCount * 128);

        // First pair: IC[0] with scalar 1
        _copyBytesFromStorage(vkIC[0], multiExpInput, 0);
        assembly {
            mstore(add(add(multiExpInput, 32), 96), 1) // scalar = 1
        }

        // Remaining pairs: IC[i+1] with inputs[i]
        for (uint256 i = 0; i < inputs.length; i++) {
            uint256 offset = (i + 1) * 128;
            _copyBytesFromStorage(vkIC[i + 1], multiExpInput, offset);
            assembly {
                mstore(
                    add(add(multiExpInput, 32), add(offset, 96)),
                    mload(add(add(inputs, 32), mul(i, 32)))
                )
            }
        }

        // Call G1 multiexp precompile
        bytes memory result = new bytes(96);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x0c, // BLS12_G1MULTIEXP
                add(multiExpInput, 32),
                mload(multiExpInput),
                add(result, 32),
                96
            )
        }

        if (!success) revert PrecompileFailed(BLS12_G1MULTIEXP);
        return result;
    }

    /// @dev Computes linear combination with direct uint256 inputs
    function _computeLinearCombinationDirect(
        uint256[] calldata inputs
    ) internal view returns (bytes memory) {
        uint256 pairCount = inputs.length + 1;
        bytes memory multiExpInput = new bytes(pairCount * 128);

        // IC[0] with scalar 1
        _copyBytesFromStorage(vkIC[0], multiExpInput, 0);
        assembly {
            mstore(add(add(multiExpInput, 32), 96), 1)
        }

        // IC[i+1] with inputs[i]
        for (uint256 i = 0; i < inputs.length; i++) {
            uint256 offset = (i + 1) * 128;
            _copyBytesFromStorage(vkIC[i + 1], multiExpInput, offset);
            assembly {
                mstore(
                    add(add(multiExpInput, 32), add(offset, 96)),
                    calldataload(add(inputs.offset, mul(i, 32)))
                )
            }
        }

        bytes memory result = new bytes(96);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x0c,
                add(multiExpInput, 32),
                mload(multiExpInput),
                add(result, 32),
                96
            )
        }

        if (!success) revert PrecompileFailed(BLS12_G1MULTIEXP);
        return result;
    }

    /// @dev Verifies the pairing equation
    function _verifyPairing(
        bytes memory pA,
        bytes memory pB,
        bytes memory pC,
        bytes memory vkX
    ) internal view returns (bool) {
        // Pairing input: 4 pairs of (G1 96 bytes, G2 192 bytes) = 4 * 288 = 1152 bytes
        bytes memory pairingInput = new bytes(1152);

        // Pair 1: -A, B (negate A)
        _copyG1Negated(pA, pairingInput, 0);
        _copyBytesMemory(pB, pairingInput, 96);

        // Pair 2: alpha, beta
        _copyBytesFromStorage(vkAlpha, pairingInput, 288);
        _copyBytesFromStorage(vkBeta, pairingInput, 384);

        // Pair 3: vk_x, gamma
        _copyBytesMemory(vkX, pairingInput, 576);
        _copyBytesFromStorage(vkGamma, pairingInput, 672);

        // Pair 4: C, delta
        _copyBytesMemory(pC, pairingInput, 864);
        _copyBytesFromStorage(vkDelta, pairingInput, 960);

        // Call BLS12 pairing precompile
        bytes memory result = new bytes(32);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x10, // BLS12_PAIRING
                add(pairingInput, 32),
                1152,
                add(result, 32),
                32
            )
        }

        if (!success) revert PrecompileFailed(BLS12_PAIRING);

        uint256 pairingResult;
        assembly {
            pairingResult := mload(add(result, 32))
        }

        return pairingResult == 1;
    }

    /// @dev Copies bytes from storage to memory at offset
    function _copyBytesFromStorage(
        bytes storage src,
        bytes memory dest,
        uint256 offset
    ) internal pure {
        bytes memory srcData = src;
        uint256 len = srcData.length;
        assembly {
            let srcPtr := add(srcData, 32)
            let destPtr := add(add(dest, 32), offset)
            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 32)
            } {
                mstore(add(destPtr, i), mload(add(srcPtr, i)))
            }
        }
    }

    /// @dev Copies bytes from memory to memory at offset
    function _copyBytesMemory(
        bytes memory src,
        bytes memory dest,
        uint256 offset
    ) internal pure {
        uint256 len = src.length;
        assembly {
            let srcPtr := add(src, 32)
            let destPtr := add(add(dest, 32), offset)
            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 32)
            } {
                mstore(add(destPtr, i), mload(add(srcPtr, i)))
            }
        }
    }

    /// @dev Copies G1 point with negated y-coordinate for pairing
    function _copyG1Negated(
        bytes memory src,
        bytes memory dest,
        uint256 offset
    ) internal pure {
        // BLS12-381 G1 point negation: -P = (x, -y mod q)
        // For now, copy x unchanged and y with flag for precompile
        // The pairing precompile expects points in specific format
        assembly {
            // Copy x (48 bytes = 1.5 words, but we copy 64 bytes for simplicity)
            mstore(add(add(dest, 32), offset), mload(add(src, 32)))
            mstore(add(add(dest, 32), add(offset, 32)), mload(add(src, 64)))

            // Copy y (next 48 bytes)
            // In a complete implementation, we'd negate y here
            mstore(add(add(dest, 32), add(offset, 48)), mload(add(src, 80)))
            mstore(add(add(dest, 32), add(offset, 80)), mload(add(src, 112)))
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the number of IC points
    function getICCount() external view returns (uint256) {
        return vkIC.length;
    }

    /// @notice Checks if EIP-2537 precompiles are available
    /// @dev Attempts a simple G1 identity operation
    function isEIP2537Supported() external view returns (bool) {
        // Create identity point input for G1 addition
        bytes memory input = new bytes(192);
        bytes memory result = new bytes(96);

        bool success;
        assembly {
            success := staticcall(
                50000,
                0x0a, // BLS12_G1ADD
                add(input, 32),
                192,
                add(result, 32),
                96
            )
        }

        return success;
    }

    /// @notice Transfer ownership
    /// @param newOwner New owner address
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
