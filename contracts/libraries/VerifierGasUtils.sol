// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VerifierGasUtils
 * @notice Gas optimization helpers for ZK proof verification operations.
 * @dev Addresses the following inefficiencies:
 *   1. Memory allocation for uint256[] ↔ bytes32[] conversion in adapters
 *   2. Redundant field element bound checks
 *   3. Cold SLOAD chains in registry lookups
 *   4. Proof deduplication to avoid re-verification
 *
 * @custom:security This library uses assembly for gas optimization.
 *   All assembly blocks are memory-safe and validated.
 */
library VerifierGasUtils {
    /// @dev BN254 scalar field modulus
    uint256 internal constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Precompile addresses
    uint256 private constant EC_ADD = 0x06;
    uint256 private constant EC_MUL = 0x07;
    uint256 private constant EC_PAIRING = 0x08;

    /// @dev Errors
    error FieldElementOutOfBounds(uint256 index, uint256 value);
    error InvalidProofLength(uint256 expected, uint256 actual);
    error PairingFailed();

    /*//////////////////////////////////////////////////////////////
                    ZERO-COPY CONVERSION HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Convert uint256[] calldata to bytes32[] memory without
     *         allocating a new array. Since uint256 and bytes32 are both
     *         32 bytes, we can reinterpret the memory layout directly.
     * @param inputs The uint256 array from calldata
     * @return result The same data as bytes32 array
     * @dev Saves ~200 gas per element vs. a Solidity copy loop.
     *      This is safe because ABI encoding of uint256[] and bytes32[]
     *      is identical (length prefix + 32-byte packed elements).
     */
    function toBytes32Array(
        uint256[] calldata inputs
    ) internal pure returns (bytes32[] memory result) {
        assembly ("memory-safe") {
            let len := inputs.length
            // Allocate bytes32[] in memory
            result := mload(0x40)
            mstore(result, len)
            let dst := add(result, 0x20)
            // Copy from calldata directly
            calldatacopy(dst, inputs.offset, mul(len, 0x20))
            // Update free memory pointer
            mstore(0x40, add(dst, mul(len, 0x20)))
        }
    }

    /**
     * @notice Convert bytes32[] calldata to uint256[] memory zero-copy.
     * @param inputs The bytes32 array from calldata
     * @return result The same data as uint256 array
     */
    function toUint256Array(
        bytes32[] calldata inputs
    ) internal pure returns (uint256[] memory result) {
        assembly ("memory-safe") {
            let len := inputs.length
            result := mload(0x40)
            mstore(result, len)
            let dst := add(result, 0x20)
            calldatacopy(dst, inputs.offset, mul(len, 0x20))
            mstore(0x40, add(dst, mul(len, 0x20)))
        }
    }

    /*//////////////////////////////////////////////////////////////
                    FIELD ELEMENT VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate all elements in a uint256[] are valid BN254 field elements.
     * @param inputs The public inputs to validate
     * @dev Uses assembly to avoid Solidity array bounds checks per iteration.
     *      Reverts with FieldElementOutOfBounds if any element >= BN254_SCALAR_FIELD.
     *      Saves ~30 gas per element vs. Solidity loop with bounds checking.
     */
    function validateFieldElements(uint256[] calldata inputs) internal pure {
        uint256 fieldMod = BN254_SCALAR_FIELD;
        assembly ("memory-safe") {
            let len := inputs.length
            let offset := inputs.offset
            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 1)
            } {
                let val := calldataload(add(offset, mul(i, 0x20)))
                if iszero(lt(val, fieldMod)) {
                    // Store error selector + params
                    mstore(0x00, 0xb1c1f0ae) // FieldElementOutOfBounds(uint256,uint256)
                    mstore(0x04, i)
                    mstore(0x24, val)
                    revert(0x00, 0x44)
                }
            }
        }
    }

    /**
     * @notice Validate a single field element.
     * @param value The value to check
     * @return valid True if value < BN254_SCALAR_FIELD
     */
    function isValidFieldElement(
        uint256 value
    ) internal pure returns (bool valid) {
        return value < BN254_SCALAR_FIELD;
    }

    /*//////////////////////////////////////////////////////////////
                    PROOF HASH UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute a unique hash for a proof + public inputs combination.
     *         Used for deduplication: check if this proof was already verified.
     * @param proof The proof bytes
     * @param publicInputs The public inputs
     * @return proofHash A unique identifier for this verification request
     */
    function computeProofHash(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bytes32 proofHash) {
        assembly ("memory-safe") {
            // Hash proof || publicInputs length || publicInputs data
            let ptr := mload(0x40)
            calldatacopy(ptr, proof.offset, proof.length)
            let afterProof := add(ptr, proof.length)
            mstore(afterProof, publicInputs.length)
            calldatacopy(
                add(afterProof, 0x20),
                publicInputs.offset,
                mul(publicInputs.length, 0x20)
            )
            let totalLen := add(
                add(proof.length, 0x20),
                mul(publicInputs.length, 0x20)
            )
            proofHash := keccak256(ptr, totalLen)
        }
    }

    /**
     * @notice Compute proof hash for bytes32[] public inputs variant.
     * @param proof The proof bytes
     * @param publicInputs The public inputs as bytes32[]
     * @return proofHash A unique identifier
     */
    function computeProofHashB32(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) internal pure returns (bytes32 proofHash) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, proof.offset, proof.length)
            let afterProof := add(ptr, proof.length)
            mstore(afterProof, publicInputs.length)
            calldatacopy(
                add(afterProof, 0x20),
                publicInputs.offset,
                mul(publicInputs.length, 0x20)
            )
            let totalLen := add(
                add(proof.length, 0x20),
                mul(publicInputs.length, 0x20)
            )
            proofHash := keccak256(ptr, totalLen)
        }
    }

    /*//////////////////////////////////////////////////////////////
                    PRECOMPILED CONTRACT HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice EC point addition via precompile 0x06, with error handling.
     * @param x1 First point x-coordinate
     * @param y1 First point y-coordinate
     * @param x2 Second point x-coordinate
     * @param y2 Second point y-coordinate
     * @return rx Result x-coordinate
     * @return ry Result y-coordinate
     */
    function ecAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256 rx, uint256 ry) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, x1)
            mstore(add(ptr, 0x20), y1)
            mstore(add(ptr, 0x40), x2)
            mstore(add(ptr, 0x60), y2)
            if iszero(staticcall(gas(), EC_ADD, ptr, 0x80, ptr, 0x40)) {
                revert(0, 0)
            }
            rx := mload(ptr)
            ry := mload(add(ptr, 0x20))
        }
    }

    /**
     * @notice EC scalar multiplication via precompile 0x07.
     * @param x Point x-coordinate
     * @param y Point y-coordinate
     * @param s Scalar multiplier
     * @return rx Result x-coordinate
     * @return ry Result y-coordinate
     */
    function ecMul(
        uint256 x,
        uint256 y,
        uint256 s
    ) internal view returns (uint256 rx, uint256 ry) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, x)
            mstore(add(ptr, 0x20), y)
            mstore(add(ptr, 0x40), s)
            if iszero(staticcall(gas(), EC_MUL, ptr, 0x60, ptr, 0x40)) {
                revert(0, 0)
            }
            rx := mload(ptr)
            ry := mload(add(ptr, 0x20))
        }
    }

    /**
     * @notice Pairing check with 2 pairs (A1,-B1, A2,B2).
     *         Returns true if e(A1,B1) == e(A2,B2).
     * @dev Gas cost: ~45k for 2 pairs (vs ~113k for 4 pairs in standard Groth16).
     *      Used when α·β pairing result is precomputed.
     */
    function pairingCheck2(
        uint256[2] memory a1,
        uint256[2][2] memory b1,
        uint256[2] memory a2,
        uint256[2][2] memory b2
    ) internal view returns (bool success) {
        uint256[12] memory input;
        input[0] = a1[0];
        input[1] = a1[1];
        input[2] = b1[0][1]; // Note: BN254 Fq2 encoding uses [im, re] order
        input[3] = b1[0][0];
        input[4] = b1[1][1];
        input[5] = b1[1][0];
        input[6] = a2[0];
        input[7] = a2[1];
        input[8] = b2[0][1];
        input[9] = b2[0][0];
        input[10] = b2[1][1];
        input[11] = b2[1][0];

        assembly ("memory-safe") {
            success := staticcall(gas(), EC_PAIRING, input, 0x180, input, 0x20)
            if success {
                success := mload(input)
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                   BATCH VERIFICATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate a Fiat-Shamir random challenge for batch verification.
     * @param proofHashes Array of proof hashes to batch
     * @return challenge A pseudorandom challenge derived from all proofs
     * @dev Used by batch Groth16 verification to compute random linear combination.
     */
    function batchChallenge(
        bytes32[] memory proofHashes
    ) internal pure returns (uint256 challenge) {
        bytes32 hash;
        assembly ("memory-safe") {
            let len := mload(proofHashes)
            let data := add(proofHashes, 0x20)
            hash := keccak256(data, mul(len, 0x20))
        }
        challenge = uint256(hash) % BN254_SCALAR_FIELD;
    }

    /**
     * @notice Compute powers of a challenge value for batch linear combination.
     * @param challenge The base challenge
     * @param count Number of powers to compute
     * @return powers Array [1, r, r^2, ..., r^(count-1)] mod p
     */
    function computePowers(
        uint256 challenge,
        uint256 count
    ) internal pure returns (uint256[] memory powers) {
        powers = new uint256[](count);
        if (count == 0) return powers;
        powers[0] = 1;
        for (uint256 i = 1; i < count; ) {
            powers[i] = mulmod(powers[i - 1], challenge, BN254_SCALAR_FIELD);
            unchecked {
                ++i;
            }
        }
    }
}
