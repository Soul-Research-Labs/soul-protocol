// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "../../interfaces/IProofVerifier.sol";

/**
 * @title IUltraHonkVerifier
 * @notice Interface for bb-generated UltraHonk Solidity verifiers
 * @dev bb write_solidity_verifier generates contracts with this signature
 */
interface IUltraHonkVerifier {
        /**
     * @notice Verifys the operation
     * @param _proof The _proof
     * @param _publicInputs The _public inputs
     * @return The result value
     */
function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool);
}

/**
 * @title UltraHonkAdapter
 * @author ZASEON
 * @notice Adapter that wraps a bb-generated UltraHonk Solidity verifier
 *         behind the IProofVerifier interface used by ZASEON contracts.
 * @dev The bb-generated verifier expects:
 *      - proof: raw proof bytes
 *      - publicInputs: bytes32[] array
 *
 *      But IProofVerifier expects:
 *      - proof: raw proof bytes
 *      - publicInputs: uint256[] array (or various other formats)
 *
 *      This adapter bridges the gap and provides the standard IProofVerifier
 *      interface that ZKBoundStateLocks, ConfidentialStateContainerV3, and
 *      other core contracts expect.
 */
contract UltraHonkAdapter is IProofVerifier {
    /// @notice The bb-generated UltraHonk verifier contract
    IUltraHonkVerifier public immutable honkVerifier;

    /// @notice Expected number of public inputs for this circuit
    uint256 public immutable publicInputCount;

    /// @notice Circuit identifier for logging
    bytes32 public immutable circuitId;

    /// @notice Whether this adapter has been properly configured
    bool private _initialized;

    event ProofVerified(bytes32 indexed circuitId, bool success);

    error VerifierNotSet();
    error InvalidPublicInputCount(uint256 expected, uint256 actual);

    /**
     * @param _verifier Address of the bb-generated UltraHonk verifier
     * @param _publicInputCount Expected number of public inputs
     * @param _circuitId Human-readable circuit identifier (e.g., "nullifier")
     */
    constructor(
        address _verifier,
        uint256 _publicInputCount,
        bytes32 _circuitId
    ) {
        require(_verifier != address(0), "Zero verifier address");
        honkVerifier = IUltraHonkVerifier(_verifier);
        publicInputCount = _publicInputCount;
        circuitId = _circuitId;
        _initialized = true;
    }

    /// @inheritdoc IProofVerifier
        /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return success The success
     */
function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool success) {
        if (publicInputs.length != publicInputCount) {
            revert InvalidPublicInputCount(
                publicInputCount,
                publicInputs.length
            );
        }

        // Convert uint256[] to bytes32[] for UltraHonk verifier
        bytes32[] memory honkInputs = new bytes32[](publicInputs.length);
        for (uint256 i = 0; i < publicInputs.length; ) {
            honkInputs[i] = bytes32(publicInputs[i]);
            unchecked {
                ++i;
            }
        }

        return honkVerifier.verify(proof, honkInputs);
    }

    /// @inheritdoc IProofVerifier
        /**
     * @notice Verifys proof
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return success The success
     */
function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool success) {
        // Decode raw bytes as uint256[]
        uint256[] memory inputs = abi.decode(publicInputs, (uint256[]));
        if (inputs.length != publicInputCount) {
            revert InvalidPublicInputCount(publicInputCount, inputs.length);
        }

        bytes32[] memory honkInputs = new bytes32[](inputs.length);
        for (uint256 i = 0; i < inputs.length; ) {
            honkInputs[i] = bytes32(inputs[i]);
            unchecked {
                ++i;
            }
        }

        return honkVerifier.verify(proof, honkInputs);
    }

    /// @inheritdoc IProofVerifier
        /**
     * @notice Verifys single
     * @param proof The ZK proof data
     * @param publicInput The public input
     * @return success The success
     */
function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool success) {
        require(publicInputCount == 1, "Circuit expects multiple inputs");
        bytes32[] memory honkInputs = new bytes32[](1);
        honkInputs[0] = bytes32(publicInput);
        return honkVerifier.verify(proof, honkInputs);
    }

    /// @inheritdoc IProofVerifier
        /**
     * @notice Returns the public input count
     * @return The result value
     */
function getPublicInputCount() external view override returns (uint256) {
        return publicInputCount;
    }

    /// @inheritdoc IProofVerifier
        /**
     * @notice Checks if ready
     * @return The result value
     */
function isReady() external view override returns (bool) {
        return _initialized && address(honkVerifier) != address(0);
    }
}
