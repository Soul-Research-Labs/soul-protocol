// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../libraries/VerifierGasUtils.sol";

/**
 * @title ZaseonUniversalVerifier
 * @notice Universal verifier supporting multiple ZK proving systems
 * @dev Aggregates all Zaseon verifiers into a single interface
 */
contract ZaseonUniversalVerifier is Ownable, ReentrancyGuard {
    // ============================================
    // Types
    // ============================================

    enum ProofSystem {
        Groth16,
        Plonk,
        Noir,
        SP1,
        Plonky3,
        Jolt,
        Binius,
        Recursive
    }

    struct UniversalProof {
        ProofSystem system;
        bytes32 vkeyOrCircuitHash;
        bytes32 publicInputsHash;
        bytes proof;
    }

    struct VerifierConfig {
        address verifier;
        bool active;
        uint256 gasLimit;
        uint256 totalVerified;
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice Verifier contracts by proof system
    mapping(ProofSystem => VerifierConfig) public verifiers;

    /// @notice Registry for circuit-specific verifiers (used by Noir/Generic)
    address public verifierRegistry;

    /// @notice All verified proofs
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice Total proofs verified across all systems
    uint256 public totalVerified;

    /// @notice Default gas limit for verification
    uint256 public defaultGasLimit = 500000;

    // ============================================
    // Errors
    // ============================================

    error InvalidVerifier();
    error InvalidGasLimit();
    error VerifierNotActive();
    error VerifierNotRegistered();
    error AlreadyVerified();
    error LengthMismatch();
    error PublicInputsMismatch();

    // ============================================
    // Events
    // ============================================

    event VerifierRegistered(ProofSystem indexed system, address verifier);
    event ProofVerified(
        bytes32 indexed proofHash,
        ProofSystem indexed system,
        uint256 gasUsed
    );
    event VerifierDeactivated(ProofSystem indexed system);

    // ============================================
    // Constructor
    // ============================================

    constructor() Ownable(msg.sender) {}

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Register a verifier for a proof system
     * @param system The proof system
     * @param verifier The verifier contract address
     * @param gasLimit Gas limit for verification calls
     */
    function registerVerifier(
        ProofSystem system,
        address verifier,
        uint256 gasLimit
    ) external onlyOwner {
        if (verifier == address(0)) revert InvalidVerifier();

        verifiers[system] = VerifierConfig({
            verifier: verifier,
            active: true,
            gasLimit: gasLimit > 0 ? gasLimit : defaultGasLimit,
            totalVerified: 0
        });

        emit VerifierRegistered(system, verifier);
    }

    /**
     * @notice Deactivate a verifier
     * @param system The proof system to deactivate
     */
    function deactivateVerifier(ProofSystem system) external onlyOwner {
        verifiers[system].active = false;
        emit VerifierDeactivated(system);
    }

    /**
     * @notice Update gas limit for a verifier
     * @param system The proof system
     * @param newGasLimit New gas limit
     */
    function updateGasLimit(
        ProofSystem system,
        uint256 newGasLimit
    ) external onlyOwner {
        if (newGasLimit == 0) revert InvalidGasLimit();
        verifiers[system].gasLimit = newGasLimit;
    }

    /**
     * @notice Set the verifier registry for specialized verifier lookups
     * @param _registry The VerifierRegistry address
     */
    function setVerifierRegistry(address _registry) external onlyOwner {
        if (_registry == address(0)) revert InvalidVerifier();
        verifierRegistry = _registry;
    }

    // ============================================
    // Verification Functions
    // ============================================

    /**
     * @notice Verify a proof using the appropriate verifier
     * @param proof The universal proof structure
     * @param publicInputs The public inputs
     * @return valid Whether the proof is valid
     * @return gasUsed Gas used for verification
     */
    // slither-disable-start reentrancy-no-eth
    /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return valid The valid
     * @return gasUsed The gas used
     */
    function verify(
        UniversalProof calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant returns (bool valid, uint256 gasUsed) {
        uint256 gasStart = gasleft();

        VerifierConfig storage config = verifiers[proof.system];
        if (!config.active) revert VerifierNotActive();
        if (config.verifier == address(0)) revert VerifierNotRegistered();

        // Compute proof hash for deduplication
        bytes32 proofHash = keccak256(
            abi.encode(
                proof.system,
                proof.vkeyOrCircuitHash,
                proof.publicInputsHash,
                keccak256(proof.proof)
            )
        );

        if (verifiedProofs[proofHash]) revert AlreadyVerified();

        // Verify public inputs hash
        if (keccak256(publicInputs) != proof.publicInputsHash)
            revert PublicInputsMismatch();

        // Call the appropriate verifier
        valid = _callVerifier(
            proof.system,
            config.verifier,
            config.gasLimit,
            proof,
            publicInputs
        );

        if (valid) {
            verifiedProofs[proofHash] = true;
            config.totalVerified++;
            totalVerified++;
        }

        gasUsed = gasStart - gasleft();

        emit ProofVerified(proofHash, proof.system, gasUsed);

        return (valid, gasUsed);
    }

    // slither-disable-end reentrancy-no-eth

    /**
     * @notice Batch verify multiple proofs
     * @dev Skips already-verified proofs instead of reverting, making batch
     *      calls resilient to duplicates.
     * @param proofs Array of proofs
     * @param publicInputsArray Array of public inputs
     * @return results Array of verification results
     */
    function batchVerify(
        UniversalProof[] calldata proofs,
        bytes[] calldata publicInputsArray
    ) external returns (bool[] memory results) {
        if (proofs.length != publicInputsArray.length) revert LengthMismatch();

        results = new bool[](proofs.length);

        for (uint256 i = 0; i < proofs.length; ) {
            // Compute proof hash to check if already verified (skip instead of revert)
            bytes32 proofHash = keccak256(
                abi.encode(
                    proofs[i].system,
                    proofs[i].vkeyOrCircuitHash,
                    proofs[i].publicInputsHash,
                    keccak256(proofs[i].proof)
                )
            );

            if (verifiedProofs[proofHash]) {
                // Already verified — mark as valid, skip costly re-verification
                results[i] = true;
            } else {
                (bool valid, ) = this.verify(proofs[i], publicInputsArray[i]);
                results[i] = valid;
            }
            unchecked {
                ++i;
            }
        }

        return results;
    }

    /**
     * @notice Check if a proof has been verified
     * @param proofHash Hash of the proof
     * @return Whether the proof was verified
     */
    function isVerified(bytes32 proofHash) external view returns (bool) {
        return verifiedProofs[proofHash];
    }

    /**
     * @notice Get verifier info for a system
     * @param system The proof system
     * @return config The verifier configuration
     */
    function getVerifier(
        ProofSystem system
    ) external view returns (VerifierConfig memory) {
        return verifiers[system];
    }

    /**
     * @notice Get statistics across all systems
     * @return systems Array of proof systems
     * @return verified Array of verification counts
     * @return active Array of active status
     */
    function getStats()
        external
        view
        returns (
            ProofSystem[] memory systems,
            uint256[] memory verified,
            bool[] memory active
        )
    {
        systems = new ProofSystem[](8);
        verified = new uint256[](8);
        active = new bool[](8);

        for (uint256 i = 0; i < 8; ) {
            ProofSystem sys = ProofSystem(i);
            systems[i] = sys;
            verified[i] = verifiers[sys].totalVerified;
            active[i] = verifiers[sys].active;
            unchecked {
                ++i;
            }
        }

        return (systems, verified, active);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Call the appropriate verifier contract
     */
    function _callVerifier(
        ProofSystem system,
        address verifier,
        uint256 gasLimit,
        UniversalProof calldata proof,
        bytes calldata publicInputs
    ) internal returns (bool) {
        bytes memory callData;

        if (system == ProofSystem.Groth16) {
            uint256[] memory inputs = abi.decode(publicInputs, (uint256[]));
            // Validate all public inputs are valid BN254 field elements
            // Reverts early if any input >= BN254_SCALAR_FIELD, saving ~200k gas
            // vs a failed pairing check
            for (uint256 idx = 0; idx < inputs.length; ) {
                if (!VerifierGasUtils.isValidFieldElement(inputs[idx])) {
                    revert VerifierGasUtils.FieldElementOutOfBounds(
                        idx,
                        inputs[idx]
                    );
                }
                unchecked {
                    ++idx;
                }
            }
            callData = abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
                _extractG1Point(proof.proof, 0),
                _extractG2Point(proof.proof, 64),
                _extractG1Point(proof.proof, 192),
                inputs
            );
        } else if (system == ProofSystem.SP1) {
            // For SP1, pass proof directly without decoding
            callData = abi.encodeWithSignature(
                "verify(bytes32,bytes,bytes)",
                proof.vkeyOrCircuitHash,
                proof.proof,
                publicInputs
            );
        } else if (system == ProofSystem.Noir) {
            // For Noir, if a registry is set, resolve the specific adapter based on circuitHash
            address targetVerifier = verifier;
            if (verifierRegistry != address(0)) {
                // Try to resolve circuit-specific adapter from registry
                (bool regSuccess, bytes memory regData) = verifierRegistry
                    .staticcall(
                        abi.encodeWithSignature(
                            "getVerifier(bytes32)",
                            proof.vkeyOrCircuitHash
                        )
                    );
                if (regSuccess && regData.length == 32) {
                    address resolved = abi.decode(regData, (address));
                    if (resolved != address(0)) {
                        targetVerifier = resolved;
                    }
                }
            }

            callData = abi.encodeWithSignature(
                "verify(bytes32,bytes,bytes)",
                proof.vkeyOrCircuitHash,
                proof.proof,
                publicInputs
            );

            // Override the verifier address if we found a better one in the registry
            verifier = targetVerifier;
        } else {
            // Generic verification call for other systems
            callData = abi.encodeWithSignature(
                "verify(bytes32,bytes,bytes)",
                proof.vkeyOrCircuitHash,
                proof.proof,
                publicInputs
            );
        }

        (bool success, bytes memory result) = verifier.call{gas: gasLimit}(
            callData
        );

        if (!success) return false;
        if (result.length == 0) return false;

        return abi.decode(result, (bool));
    }

    /**
     * @notice Extract G1 point from proof bytes
     */
    function _extractG1Point(
        bytes calldata proof,
        uint256 offset
    ) internal pure returns (uint256[2] memory) {
        return [
            uint256(bytes32(proof[offset:offset + 32])),
            uint256(bytes32(proof[offset + 32:offset + 64]))
        ];
    }

    /**
     * @notice Extract G2 point from proof bytes
     */
    function _extractG2Point(
        bytes calldata proof,
        uint256 offset
    ) internal pure returns (uint256[2][2] memory) {
        return [
            [
                uint256(bytes32(proof[offset:offset + 32])),
                uint256(bytes32(proof[offset + 32:offset + 64]))
            ],
            [
                uint256(bytes32(proof[offset + 64:offset + 96])),
                uint256(bytes32(proof[offset + 96:offset + 128]))
            ]
        ];
    }
}
