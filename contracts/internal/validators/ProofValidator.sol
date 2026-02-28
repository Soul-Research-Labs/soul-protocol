// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ProofValidator
 * @author ZASEON
 * @notice Extracted proof validation logic for stack depth optimization
 * @dev Separates proof validation from main contract logic to enable
 *      better coverage instrumentation and reduce stack pressure.
 *
 * VALIDATION PIPELINE:
 * 1. Format validation (length, structure)
 * 2. Public input extraction
 * 3. Commitment binding check
 * 4. Nullifier uniqueness check
 * 5. Verifier dispatch
 */
library ProofValidator {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProofLength(uint256 expected, uint256 actual);
    error InvalidPublicInputs();
    error CommitmentMismatch(bytes32 expected, bytes32 actual);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error UnsupportedProofType(bytes32 proofType);
    error VerifierNotFound(bytes32 verifierKey);

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validated proof data after parsing
     */
    struct ValidatedProof {
        bytes32 proofHash;
        bytes32[] publicInputs;
        bytes32 nullifier;
        bytes32 newCommitment;
        bytes32 verifierKey;
        bool isValid;
    }

    /**
     * @notice Proof format specifications
     */
    struct ProofFormat {
        uint256 minLength;
        uint256 maxLength;
        uint256 publicInputCount;
        uint256 proofElementCount;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Groth16 BN254 proof format
    uint256 public constant GROTH16_BN254_MIN_LENGTH = 256;
    uint256 public constant GROTH16_BN254_MAX_LENGTH = 512;
    uint256 public constant GROTH16_BN254_PUBLIC_INPUTS = 1;

    /// @notice Groth16 BLS12-381 proof format
    uint256 public constant GROTH16_BLS_MIN_LENGTH = 384;
    uint256 public constant GROTH16_BLS_MAX_LENGTH = 768;
    uint256 public constant GROTH16_BLS_PUBLIC_INPUTS = 1;

    /// @notice PLONK proof format
    uint256 public constant PLONK_MIN_LENGTH = 512;
    uint256 public constant PLONK_MAX_LENGTH = 2048;

    /*//////////////////////////////////////////////////////////////
                          VALIDATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates proof format for Groth16 BN254
     * @param proof Raw proof bytes
     * @return isValid True if format is valid
     * @return proofHash Hash of the proof for caching
     */
    function validateGroth16BN254Format(
        bytes calldata proof
    ) internal pure returns (bool isValid, bytes32 proofHash) {
        uint256 len = proof.length;
        isValid =
            len >= GROTH16_BN254_MIN_LENGTH &&
            len <= GROTH16_BN254_MAX_LENGTH;
        if (isValid) {
            proofHash = keccak256(proof);
        }
    }

    /**
     * @notice Validates proof format for Groth16 BLS12-381
     * @param proof Raw proof bytes
     * @return isValid True if format is valid
     * @return proofHash Hash of the proof for caching
     */
    function validateGroth16BLSFormat(
        bytes calldata proof
    ) internal pure returns (bool isValid, bytes32 proofHash) {
        uint256 len = proof.length;
        isValid =
            len >= GROTH16_BLS_MIN_LENGTH &&
            len <= GROTH16_BLS_MAX_LENGTH;
        if (isValid) {
            proofHash = keccak256(proof);
        }
    }

    /**
     * @notice Extracts public inputs from proof data
     * @dev Assumes standard layout: [proof_elements][public_inputs]
     * @param proofData Full proof data
     * @param inputCount Number of public inputs to extract
     * @param proofSize Size of proof elements
     * @return inputs Array of extracted public inputs
     */
    function extractPublicInputs(
        bytes calldata proofData,
        uint256 inputCount,
        uint256 proofSize
    ) internal pure returns (bytes32[] memory inputs) {
        if (proofData.length < proofSize + (inputCount * 32)) {
            revert InvalidPublicInputs();
        }

        inputs = new bytes32[](inputCount);
        uint256 offset = proofSize;

        for (uint256 i = 0; i < inputCount; ) {
            inputs[i] = bytes32(proofData[offset:offset + 32]);
            offset += 32;
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Validates commitment binding
     * @dev Ensures proof commits to the expected state
     * @param publicInputs Extracted public inputs
     * @param expectedCommitment Expected state commitment
     * @param commitmentIndex Index of commitment in public inputs
     * @return isValid True if commitment matches
     */
    function validateCommitmentBinding(
        bytes32[] memory publicInputs,
        bytes32 expectedCommitment,
        uint256 commitmentIndex
    ) internal pure returns (bool isValid) {
        if (commitmentIndex >= publicInputs.length) {
            return false;
        }
        return publicInputs[commitmentIndex] == expectedCommitment;
    }

    /**
     * @notice Extracts nullifier from public inputs
     * @param publicInputs Extracted public inputs
     * @param nullifierIndex Index of nullifier in public inputs
     * @return nullifier The extracted nullifier
     */
    function extractNullifier(
        bytes32[] memory publicInputs,
        uint256 nullifierIndex
    ) internal pure returns (bytes32 nullifier) {
        if (nullifierIndex >= publicInputs.length) {
            revert InvalidPublicInputs();
        }
        return publicInputs[nullifierIndex];
    }

    /**
     * @notice Full proof validation pipeline
     * @param proofData Raw proof bytes
     * @param expectedCommitment Expected state commitment
     * @param format Proof format specification
     * @return validated Validated proof structure
     */
    function validateFull(
        bytes calldata proofData,
        bytes32 expectedCommitment,
        ProofFormat memory format
    ) internal pure returns (ValidatedProof memory validated) {
        // Step 1: Format validation
        uint256 len = proofData.length;
        if (len < format.minLength || len > format.maxLength) {
            validated.isValid = false;
            return validated;
        }

        // Step 2: Compute proof hash
        validated.proofHash = keccak256(proofData);

        // Step 3: Extract public inputs
        uint256 proofElementsSize = len - (format.publicInputCount * 32);
        validated.publicInputs = extractPublicInputs(
            proofData,
            format.publicInputCount,
            proofElementsSize
        );

        // Step 4: Validate commitment (assume index 0)
        if (
            !validateCommitmentBinding(
                validated.publicInputs,
                expectedCommitment,
                0
            )
        ) {
            validated.isValid = false;
            return validated;
        }

        // Step 5: Extract nullifier (assume index 1 if exists)
        if (format.publicInputCount > 1) {
            validated.nullifier = validated.publicInputs[1];
        }

        // Step 6: Extract new commitment (assume index 2 if exists)
        if (format.publicInputCount > 2) {
            validated.newCommitment = validated.publicInputs[2];
        }

        validated.isValid = true;
    }
}
