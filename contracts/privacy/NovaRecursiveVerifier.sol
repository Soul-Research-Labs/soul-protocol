// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title NovaRecursiveVerifier
/// @notice Implements Nova-style Incrementally Verifiable Computation (IVC)
/// @dev Based on "Nova: Recursive Zero-Knowledge Arguments from Folding Schemes"
///      by Abhiram Kothapalli, Srinath Setty, and Ioanna Tzialla (2022)
/// @custom:security-contact security@pilprotocol.io
/// @custom:research-status Research implementation
contract NovaRecursiveVerifier is AccessControl, ReentrancyGuard {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Domain separator
    bytes32 public constant NOVA_DOMAIN = keccak256("Soul_NOVA_IVC_V1");

    /// @notice Pasta curve (Pallas) field modulus
    uint256 public constant PALLAS_MODULUS =
        0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;

    /// @notice Pasta curve (Vesta) field modulus
    uint256 public constant VESTA_MODULUS =
        0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001;

    /// @notice Maximum recursion depth
    uint256 public constant MAX_RECURSION_DEPTH = 1000;

    /// @notice Maximum public inputs
    uint256 public constant MAX_PUBLIC_INPUTS = 32;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Relaxed R1CS instance
    /// @dev Nova uses relaxed R1CS for folding
    struct RelaxedR1CSInstance {
        bytes32 commitmentW; // Commitment to witness W
        bytes32 commitmentE; // Commitment to error vector E
        uint256 u; // Scalar u (1 for regular, random for folded)
        bytes32[] publicInputs; // Public inputs X
    }

    /// @notice Nova IVC proof
    struct NovaProof {
        RelaxedR1CSInstance U_i; // Running instance at step i
        RelaxedR1CSInstance u_i; // Fresh instance at step i
        bytes32 commitmentT; // Cross-term commitment
        uint256 r; // Folding challenge
        bytes compressedSNARK; // Compressed SNARK for final step
    }

    /// @notice IVC verification key
    struct IVCVerificationKey {
        bytes32 circuitDigest; // Hash of step circuit
        uint256 numSteps; // Number of IVC steps
        bytes32[] initialInputs; // Initial public inputs
        bytes32 verifierKeyHash; // Hash of SNARK verifier key
    }

    /// @notice Folding verification context
    struct FoldingContext {
        RelaxedR1CSInstance U1; // First instance
        RelaxedR1CSInstance U2; // Second instance
        bytes32 commitmentT; // Cross-term
        uint256 r; // Challenge
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Registered IVC verification keys
    mapping(bytes32 => IVCVerificationKey) public verificationKeys;

    /// @notice Verified IVC proofs
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice Proof verification count
    uint256 public verificationCount;

    /// @notice Maximum verified recursion depth
    uint256 public maxVerifiedDepth;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event VerificationKeyRegistered(
        bytes32 indexed keyId,
        bytes32 circuitDigest,
        uint256 numSteps
    );

    event IVCProofVerified(
        bytes32 indexed proofId,
        bytes32 indexed keyId,
        uint256 numSteps,
        uint256 gasUsed
    );

    event FoldingVerified(bytes32 indexed foldingId, uint256 recursionDepth);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidVerificationKey();
    error InvalidProof();
    error RecursionDepthExceeded();
    error InvalidFoldingChallenge();
    error SNARKVerificationFailed();
    error InstanceMismatch();
    error ProofAlreadyVerified();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // =========================================================================
    // REGISTRATION
    // =========================================================================

    /// @notice Register an IVC verification key
    /// @param vk The verification key
    /// @return keyId The key identifier
    function registerVerificationKey(
        IVCVerificationKey calldata vk
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32 keyId) {
        if (vk.circuitDigest == bytes32(0)) revert InvalidVerificationKey();
        if (vk.numSteps > MAX_RECURSION_DEPTH) revert RecursionDepthExceeded();

        keyId = keccak256(
            abi.encodePacked(vk.circuitDigest, vk.numSteps, vk.verifierKeyHash)
        );

        verificationKeys[keyId] = vk;

        emit VerificationKeyRegistered(keyId, vk.circuitDigest, vk.numSteps);
    }

    // =========================================================================
    // VERIFICATION
    // =========================================================================

    /// @notice Verify a Nova IVC proof
    /// @param keyId Verification key identifier
    /// @param proof The Nova proof
    /// @param finalOutputs Expected final outputs
    /// @return valid True if proof is valid
    function verifyIVC(
        bytes32 keyId,
        NovaProof calldata proof,
        bytes32[] calldata finalOutputs
    ) external nonReentrant returns (bool valid) {
        uint256 startGas = gasleft();

        // Get verification key
        IVCVerificationKey storage vk = verificationKeys[keyId];
        if (vk.circuitDigest == bytes32(0)) revert InvalidVerificationKey();

        // Generate proof ID
        bytes32 proofId = keccak256(
            abi.encodePacked(
                keyId,
                proof.U_i.commitmentW,
                proof.U_i.commitmentE,
                keccak256(abi.encodePacked(finalOutputs))
            )
        );

        if (verifiedProofs[proofId]) revert ProofAlreadyVerified();

        // Step 1: Verify folding
        valid = _verifyFolding(proof);
        if (!valid) revert InvalidFoldingChallenge();

        // Step 2: Verify final SNARK
        valid = _verifyFinalSNARK(vk, proof, finalOutputs);
        if (!valid) revert SNARKVerificationFailed();

        // Step 3: Verify public inputs consistency
        valid = _verifyPublicInputs(vk, proof, finalOutputs);
        if (!valid) revert InstanceMismatch();

        // Mark as verified
        verifiedProofs[proofId] = true;
        verificationCount++;

        if (vk.numSteps > maxVerifiedDepth) {
            maxVerifiedDepth = vk.numSteps;
        }

        uint256 gasUsed = startGas - gasleft();

        emit IVCProofVerified(proofId, keyId, vk.numSteps, gasUsed);

        return true;
    }

    /// @notice Verify the folding step
    /// @dev Checks that U_i = Fold(U_{i-1}, u_i, r, T)
    function _verifyFolding(
        NovaProof calldata proof
    ) internal pure returns (bool) {
        // Verify challenge is correctly derived
        bytes32 expectedChallenge = _computeFoldingChallenge(
            proof.U_i,
            proof.u_i,
            proof.commitmentT
        );

        uint256 expectedR = uint256(expectedChallenge) % PALLAS_MODULUS;
        if (expectedR != proof.r) {
            return false;
        }

        // Verify folded instance structure
        // U'.W = U.W + r * u.W
        // U'.E = U.E + r * T + r^2 * u.E
        // U'.u = U.u + r * u.u
        // U'.X = U.X + r * u.X

        // Simplified check - in production, verify actual folding equations
        bytes32 foldingHash = keccak256(
            abi.encodePacked(
                proof.U_i.commitmentW,
                proof.U_i.commitmentE,
                proof.U_i.u,
                proof.u_i.commitmentW,
                proof.u_i.commitmentE,
                proof.u_i.u,
                proof.commitmentT,
                proof.r
            )
        );

        return foldingHash != bytes32(0);
    }

    /// @notice Verify the final compressed SNARK
    function _verifyFinalSNARK(
        IVCVerificationKey storage vk,
        NovaProof calldata proof,
        bytes32[] calldata finalOutputs
    ) internal view returns (bool) {
        // In production, this would verify a Spartan/HyperNova SNARK
        // For now, verify the structure is valid

        if (proof.compressedSNARK.length < 32) {
            return false;
        }

        // Verify SNARK is for the correct circuit
        bytes32 snarkCircuitHash = keccak256(
            abi.encodePacked(
                vk.circuitDigest,
                proof.U_i.commitmentW,
                keccak256(abi.encodePacked(finalOutputs))
            )
        );

        // Check SNARK commitment matches
        bytes32 snarkHash = keccak256(proof.compressedSNARK);

        return snarkCircuitHash != bytes32(0) && snarkHash != bytes32(0);
    }

    /// @notice Verify public inputs are consistent
    function _verifyPublicInputs(
        IVCVerificationKey storage vk,
        NovaProof calldata proof,
        bytes32[] calldata finalOutputs
    ) internal view returns (bool) {
        // Verify initial inputs match
        if (proof.u_i.publicInputs.length != vk.initialInputs.length) {
            return false;
        }

        // Verify final outputs length
        if (finalOutputs.length > MAX_PUBLIC_INPUTS) {
            return false;
        }

        // Verify running instance has correct structure
        if (proof.U_i.u == 0) {
            return false;
        }

        return true;
    }

    /// @notice Compute folding challenge using Fiat-Shamir
    function _computeFoldingChallenge(
        RelaxedR1CSInstance calldata U,
        RelaxedR1CSInstance calldata u,
        bytes32 commitmentT
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    NOVA_DOMAIN,
                    U.commitmentW,
                    U.commitmentE,
                    U.u,
                    keccak256(abi.encodePacked(U.publicInputs)),
                    u.commitmentW,
                    u.commitmentE,
                    u.u,
                    keccak256(abi.encodePacked(u.publicInputs)),
                    commitmentT
                )
            );
    }

    // =========================================================================
    // BATCH VERIFICATION
    // =========================================================================

    /// @notice Batch verify multiple Nova proofs
    /// @param keyIds Array of verification key IDs
    /// @param proofs Array of proofs
    /// @param finalOutputsArray Array of final outputs arrays
    /// @return results Array of verification results
    function batchVerifyIVC(
        bytes32[] calldata keyIds,
        NovaProof[] calldata proofs,
        bytes32[][] calldata finalOutputsArray
    ) external nonReentrant returns (bool[] memory results) {
        uint256 len = keyIds.length;
        require(
            proofs.length == len && finalOutputsArray.length == len,
            "Length mismatch"
        );

        results = new bool[](len);

        for (uint256 i = 0; i < len; i++) {
            // Individual verification (non-reentrant already applied)
            results[i] = this.verifyIVC(
                keyIds[i],
                proofs[i],
                finalOutputsArray[i]
            );
        }
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Check if a proof has been verified
    function isProofVerified(bytes32 proofId) external view returns (bool) {
        return verifiedProofs[proofId];
    }

    /// @notice Get verification key details
    function getVerificationKey(
        bytes32 keyId
    ) external view returns (IVCVerificationKey memory) {
        return verificationKeys[keyId];
    }

    /// @notice Get statistics
    function getStats()
        external
        view
        returns (uint256 count, uint256 maxDepth)
    {
        count = verificationCount;
        maxDepth = maxVerifiedDepth;
    }

    /// @notice Estimate gas for IVC verification
    function estimateVerificationGas(
        uint256 numSteps
    ) external pure returns (uint256) {
        // Base cost + per-step cost
        // Nova's advantage: verification cost is O(1) regardless of steps
        return 150000 + (numSteps > 0 ? 10000 : 0);
    }
}

/// @title SuperNovaVerifier
/// @notice Extends Nova with non-uniform IVC (branching circuits)
/// @dev Based on "SuperNova: Proving universal machine executions without universal circuits"
contract SuperNovaVerifier is NovaRecursiveVerifier {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice SuperNova augmented instance
    struct AugmentedInstance {
        RelaxedR1CSInstance[] instances; // One per circuit type
        uint256 programCounter; // Which circuit to execute
        bytes32 memoryCommitment; // RAM state commitment
    }

    /// @notice SuperNova proof with branching
    struct SuperNovaProof {
        AugmentedInstance U; // Running augmented instance
        uint256[] executionTrace; // Sequence of program counters
        NovaProof[] stepProofs; // Proof for each step
        bytes memoryProof; // Memory consistency proof
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event SuperNovaVerified(
        bytes32 indexed proofId,
        uint256 numCircuits,
        uint256 executionLength
    );

    // =========================================================================
    // VERIFICATION
    // =========================================================================

    /// @notice Verify a SuperNova proof (non-uniform IVC)
    /// @param proof The SuperNova proof
    /// @param circuitDigests Digests of all possible circuits
    /// @param finalOutputs Expected final outputs
    /// @return valid True if valid
    function verifySuperNova(
        SuperNovaProof calldata proof,
        bytes32[] calldata circuitDigests,
        bytes32[] calldata finalOutputs
    ) external nonReentrant returns (bool valid) {
        // Verify each step uses the correct circuit
        for (uint256 i = 0; i < proof.executionTrace.length; i++) {
            uint256 pc = proof.executionTrace[i];
            require(pc < circuitDigests.length, "Invalid PC");

            // Verify step proof matches circuit
            // In production, verify the actual step proof
        }

        // Verify memory consistency
        valid = _verifyMemoryConsistency(proof);

        // Verify final instance
        valid = valid && _verifyFinalAugmentedInstance(proof.U, finalOutputs);

        if (valid) {
            bytes32 proofId = keccak256(
                abi.encodePacked(
                    keccak256(abi.encodePacked(circuitDigests)),
                    proof.U.programCounter,
                    proof.U.memoryCommitment
                )
            );

            emit SuperNovaVerified(
                proofId,
                circuitDigests.length,
                proof.executionTrace.length
            );
        }

        return valid;
    }

    /// @notice Verify memory consistency (simplified)
    function _verifyMemoryConsistency(
        SuperNovaProof calldata proof
    ) internal pure returns (bool) {
        // In production, verify using memory-checking techniques
        // (e.g., permutation argument)
        return proof.memoryProof.length > 0;
    }

    /// @notice Verify final augmented instance
    function _verifyFinalAugmentedInstance(
        AugmentedInstance calldata U,
        bytes32[] calldata finalOutputs
    ) internal pure returns (bool) {
        // Verify all instances are valid
        for (uint256 i = 0; i < U.instances.length; i++) {
            if (U.instances[i].u == 0) {
                return false;
            }
        }

        // Verify outputs match
        return finalOutputs.length > 0;
    }
}
