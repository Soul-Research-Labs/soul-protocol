// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title INoirVerifier
 * @notice Minimal interface for auto-generated Noir verifiers
 */
interface INoirVerifier {
    /**
     * @notice Verify a proof
     * @param _proof The proof bytes
     * @param _publicInputs The public inputs array
     * @return Whether the proof is valid
     */
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}

/**
 * @title NoirVerifierAdapter
 * @notice Base adapter to bridge SoulUniversalVerifier to auto-generated Noir verifiers
 * @dev Handles decoding of generic bytes public inputs into Noir's expected bytes32[]
 */
abstract contract NoirVerifierAdapter {
    /// @notice The auto-generated Noir verifier contract
    address public immutable noirVerifier;

    error VerificationFailed();

    constructor(address _noirVerifier) {
        noirVerifier = _noirVerifier;
    }

    /**
     * @notice Verify a proof
     * @param circuitHash Hash/ID of the circuit
     * @param proof The proof bytes
     * @param publicInputs Generic encoded public inputs
     * @return Whether the proof is valid
     */
    function verify(
        bytes32 circuitHash,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view virtual returns (bool);

    /**
     * @inheritdoc IProofVerifier
     */
    function getPublicInputCount() external view virtual override returns (uint256);

    /**
     * @inheritdoc IProofVerifier
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        // High-performance path: uses bytes32[] mapping directly
        return this.verify(bytes32(0), proof, publicInputs);
    }

    /**
     * @inheritdoc IProofVerifier
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory signals;
        assembly {
            let len := publicInputs.length
            // Allocate memory for the bytes32[] array (length word + data)
            signals := mload(0x40)
            mstore(signals, len) // Store length
            let signalsData := add(signals, 32) // Pointer to the start of data
            
            // Pointer to the start of publicInputs data in calldata
            let inputsData := add(publicInputs, 32)
            let size := mul(len, 32) // Total size of data in bytes
            
            // Batch copy uint256[] from calldata to bytes32[] in memory
            // Since uint256 and bytes32 have the same size and alignment,
            // a direct copy is efficient.
            calldatacopy(signalsData, inputsData, size)
            
            // Update Free Memory Pointer
            mstore(0x40, add(signalsData, size))
        }
        
        // Internal verification call
        return _verifyNoir(proof, signals);
    }

    /**
     * @inheritdoc IProofVerifier
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool) {
        bytes32[] memory signals = new bytes32[](1);
        signals[0] = bytes32(publicInput);
        return _verifyNoir(proof, signals);
    }

    /**
     * @inheritdoc IProofVerifier
     */
    function isReady() external view override returns (bool) {
        return noirVerifier != address(0);
    }

    /**
     * @notice Internal helper to call the Noir verifier
     * @param proof The proof bytes
     * @param signals The public inputs as bytes32[]
     * @return Whether the proof is valid
     */
    function _verifyNoir(bytes calldata proof, bytes32[] memory signals) internal view returns (bool) {
        return INoirVerifier(noirVerifier).verify(proof, signals);
    }

    /**
     * @notice Map generic bytes to Noir bytes32[] in-memory
     * @dev Highly optimized to minimize MSTORE calls and memory expansion costs
     */
    function _prepareSignals(bytes calldata publicInputs) internal pure returns (bytes32[] memory signals) {
        assembly {
            // Read length from calldata (first 32 bytes of publicInputs bytes payload)
            let len := calldataload(publicInputs.offset)
            
            // Allocate memory (signals pointer + length word + data)
            signals := mload(0x40)
            mstore(signals, len) // Store length in memory array
            let signalsData := add(signals, 32) // Pointer to the start of data
            
            // Batch copy all signals from calldata to memory
            calldatacopy(signalsData, add(publicInputs.offset, 32), mul(len, 32))
            
            // Range check: verify signals are in field r
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let val := mload(add(signalsData, mul(i, 32)))
                if iszero(lt(val, r)) {
                    // REVERT: FIELD_OVERFLOW
                    mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000) // Error selector for Error(string)
                    mstore(4, 32) // Offset to string data
                    mstore(36, 14) // Length of "FIELD_OVERFLOW"
                    mstore(68, "FIELD_OVERFLOW") // String data
                    revert(0, 100) // Revert with error data
                }
            }
            
            // Update Free Memory Pointer
            mstore(0x40, add(signalsData, mul(len, 32)))
        }
    }
}
