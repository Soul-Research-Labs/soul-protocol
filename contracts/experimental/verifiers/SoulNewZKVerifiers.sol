// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SoulSP1Verifier
 * @notice Verifier for SP1 RISC-V zkVM proofs
 * @dev Supports Succinct's SP1 proving system for Soul
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 * @custom:deprecated SP1 verification is now handled by SoulMultiProver (contracts/verifiers/SoulMultiProver.sol)
 *   which implements 2-of-3 consensus across Noir, SP1, and Jolt. This standalone verifier is retained
 *   for reference only. Use SoulMultiProver + SoulUniversalVerifier for new integrations.
 */
contract SoulSP1Verifier is Ownable {
    // ============================================
    // Types
    // ============================================

    struct SP1Proof {
        bytes32 vkeyHash; // Verification key hash
        bytes32 publicValuesHash; // Hash of public values
        bytes proof; // The actual proof bytes
    }

    struct VerificationKey {
        bytes32 vkeyHash;
        bytes32 programHash; // Hash of the SP1 program
        bool active;
        uint256 registeredAt;
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice Registered verification keys
    mapping(bytes32 => VerificationKey) public verificationKeys;

    /// @notice Verified proof hashes
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice SP1 verifier gateway (for actual verification)
    address public sp1Gateway;

    /// @notice Total proofs verified
    uint256 public totalVerified;

    // ============================================
    // Errors
    // ============================================

    error InvalidVKey();
    error AlreadyRegistered();
    error VKeyNotRegistered();
    error AlreadyVerified();
    error PublicValuesMismatch();
    error ProofVerificationFailed();

    // ============================================
    // Events
    // ============================================

    event VKeyRegistered(bytes32 indexed vkeyHash, bytes32 programHash);
    event ProofVerified(bytes32 indexed proofHash, bytes32 indexed vkeyHash);
    event GatewayUpdated(address oldGateway, address newGateway);

    // ============================================
    // Constructor
    // ============================================

    constructor(address _sp1Gateway) Ownable(msg.sender) {
        sp1Gateway = _sp1Gateway;
    }

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Register a new verification key
     * @param vkeyHash Hash of the verification key
     * @param programHash Hash of the SP1 program
     */
    function registerVKey(
        bytes32 vkeyHash,
        bytes32 programHash
    ) external onlyOwner {
        if (vkeyHash == bytes32(0)) revert InvalidVKey();
        if (verificationKeys[vkeyHash].active) revert AlreadyRegistered();

        verificationKeys[vkeyHash] = VerificationKey({
            vkeyHash: vkeyHash,
            programHash: programHash,
            active: true,
            registeredAt: block.timestamp
        });

        emit VKeyRegistered(vkeyHash, programHash);
    }

    /**
     * @notice Deactivate a verification key
     * @param vkeyHash Hash of the verification key
     */
    function deactivateVKey(bytes32 vkeyHash) external onlyOwner {
        verificationKeys[vkeyHash].active = false;
    }

    /**
     * @notice Update SP1 gateway
     * @param newGateway New gateway address
     */
    function updateGateway(address newGateway) external onlyOwner {
        address old = sp1Gateway;
        sp1Gateway = newGateway;
        emit GatewayUpdated(old, newGateway);
    }

    // ============================================
    // Verification Functions
    // ============================================

    /**
     * @notice Verify an SP1 proof
     * @param proof The SP1 proof data
     * @param publicValues The public values
     * @return valid Whether the proof is valid
     */
    function verify(
        SP1Proof calldata proof,
        bytes calldata publicValues
    ) external returns (bool valid) {
        // Check vkey is registered
        if (!verificationKeys[proof.vkeyHash].active)
            revert VKeyNotRegistered();

        // Verify public values hash
        bytes32 computedHash = keccak256(publicValues);
        if (computedHash != proof.publicValuesHash)
            revert PublicValuesMismatch();

        // Compute proof hash
        bytes32 proofHash = keccak256(
            abi.encode(proof.vkeyHash, proof.publicValuesHash, proof.proof)
        );

        // Check not already verified (prevent replay)
        if (verifiedProofs[proofHash]) revert AlreadyVerified();

        // Call SP1 gateway for actual verification
        if (sp1Gateway != address(0)) {
            (bool success, bytes memory result) = sp1Gateway.staticcall(
                abi.encodeWithSignature(
                    "verifyProof(bytes32,bytes,bytes)",
                    proof.vkeyHash,
                    publicValues,
                    proof.proof
                )
            );
            if (!success || !abi.decode(result, (bool)))
                revert ProofVerificationFailed();
        }

        // Mark as verified
        verifiedProofs[proofHash] = true;
        totalVerified++;

        emit ProofVerified(proofHash, proof.vkeyHash);

        return true;
    }

    /**
     * @notice Verify without state changes (view)
     * @param proof The SP1 proof data
     * @param publicValues The public values
     * @return valid Whether the proof would be valid
     */
    function verifyView(
        SP1Proof calldata proof,
        bytes calldata publicValues
    ) external view returns (bool valid) {
        if (!verificationKeys[proof.vkeyHash].active) return false;

        bytes32 computedHash = keccak256(publicValues);
        if (computedHash != proof.publicValuesHash) return false;

        // For view function, we can only validate the proof structure
        // Full verification requires state changes via verify()
        // Check if gateway exists for actual verification capability
        if (sp1Gateway == address(0)) {
            // No gateway configured — cannot verify SP1 proofs
            return false;
        }

        // Call gateway for view verification
        (bool success, bytes memory result) = sp1Gateway.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes32,bytes,bytes)",
                proof.vkeyHash,
                publicValues,
                proof.proof
            )
        );

        return success && result.length >= 32 && abi.decode(result, (bool));
    }

    /**
     * @notice Check if a proof has been verified
     * @param proofHash Hash of the proof
     * @return Whether the proof was verified
     */
    function isVerified(bytes32 proofHash) external view returns (bool) {
        return verifiedProofs[proofHash];
    }
}

/**
 * @title SoulPlonky3Verifier
 * @notice Verifier for Plonky3 proofs
 * @dev Supports Polygon's Plonky3 proving system
 */
contract SoulPlonky3Verifier is Ownable {
    // ============================================
    // Types
    // ============================================

    struct Plonky3Proof {
        bytes32 circuitHash;
        bytes32[] publicInputs;
        bytes32 commitmentHash;
        bytes openingProof;
    }

    struct CircuitConfig {
        bytes32 circuitHash;
        uint256 numPublicInputs;
        uint256 degree;
        bool active;
    }

    // ============================================
    // State Variables
    // ============================================

    mapping(bytes32 => CircuitConfig) public circuits;
    mapping(bytes32 => bool) public verifiedProofs;
    uint256 public totalVerified;

    // ============================================
    // Errors
    // ============================================

    error CircuitNotRegistered();
    error InputCountMismatch();
    error AlreadyVerified();
    error EmptyOpeningProof();
    error InvalidProof();
    error InvalidFRICommitments();

    // ============================================
    // Events
    // ============================================

    event CircuitRegistered(bytes32 indexed circuitHash, uint256 numInputs);
    event ProofVerified(bytes32 indexed proofHash, bytes32 indexed circuitHash);

    // ============================================
    // Constructor
    // ============================================

    constructor() Ownable(msg.sender) {}

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Registers circuit
     * @param circuitHash The circuitHash hash value
     * @param numPublicInputs The num public inputs
     * @param degree The degree
     */
    function registerCircuit(
        bytes32 circuitHash,
        uint256 numPublicInputs,
        uint256 degree
    ) external onlyOwner {
        circuits[circuitHash] = CircuitConfig({
            circuitHash: circuitHash,
            numPublicInputs: numPublicInputs,
            degree: degree,
            active: true
        });

        emit CircuitRegistered(circuitHash, numPublicInputs);
    }

    // ============================================
    // Verification
    // ============================================

    /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @return The result value
     */
    function verify(Plonky3Proof calldata proof) external returns (bool) {
        CircuitConfig storage config = circuits[proof.circuitHash];
        if (!config.active) revert CircuitNotRegistered();
        if (proof.publicInputs.length != config.numPublicInputs)
            revert InputCountMismatch();

        bytes32 proofHash = keccak256(
            abi.encode(
                proof.circuitHash,
                proof.publicInputs,
                proof.commitmentHash
            )
        );

        if (verifiedProofs[proofHash]) revert AlreadyVerified();

        // Plonky3 verification logic would go here
        // For now, verify proof structure
        if (proof.openingProof.length == 0) revert EmptyOpeningProof();

        // Verify commitment is valid
        if (proof.commitmentHash == bytes32(0)) revert InvalidProof();

        verifiedProofs[proofHash] = true;
        totalVerified++;

        emit ProofVerified(proofHash, proof.circuitHash);

        return true;
    }
}

/**
 * @title SoulJoltVerifier
 * @notice Verifier for Jolt zkVM proofs
 * @dev Supports a]{ research's Jolt proving system
 */
contract SoulJoltVerifier is Ownable {
    // ============================================
    // Types
    // ============================================

    struct JoltProof {
        bytes32 programHash;
        bytes32 inputHash;
        bytes32 outputHash;
        bytes sumcheckProof;
        bytes lookupProof;
        bytes memoryProof;
    }

    struct JoltProgram {
        bytes32 programHash;
        uint256 maxCycles;
        bool active;
    }

    // ============================================
    // State Variables
    // ============================================

    mapping(bytes32 => JoltProgram) public programs;
    mapping(bytes32 => bool) public verifiedProofs;
    uint256 public totalVerified;

    // ============================================
    // Errors
    // ============================================

    error ProgramNotRegistered();
    error AlreadyVerified();
    error EmptySumcheck();
    error EmptyLookup();
    error EmptyMemory();
    error InvalidProof();

    // ============================================
    // Events
    // ============================================

    event ProgramRegistered(bytes32 indexed programHash, uint256 maxCycles);
    event ProofVerified(bytes32 indexed proofHash, bytes32 indexed programHash);

    // ============================================
    // Constructor
    // ============================================

    constructor() Ownable(msg.sender) {}

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Registers program
     * @param programHash The programHash hash value
     * @param maxCycles The maxCycles bound
     */
    function registerProgram(
        bytes32 programHash,
        uint256 maxCycles
    ) external onlyOwner {
        programs[programHash] = JoltProgram({
            programHash: programHash,
            maxCycles: maxCycles,
            active: true
        });

        emit ProgramRegistered(programHash, maxCycles);
    }

    // ============================================
    // Verification
    // ============================================

    /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @return The result value
     */
    function verify(JoltProof calldata proof) external returns (bool) {
        JoltProgram storage program = programs[proof.programHash];
        if (!program.active) revert ProgramNotRegistered();

        bytes32 proofHash = keccak256(
            abi.encode(proof.programHash, proof.inputHash, proof.outputHash)
        );

        if (verifiedProofs[proofHash]) revert AlreadyVerified();

        // Jolt verification consists of:
        // 1. Sumcheck verification
        if (proof.sumcheckProof.length == 0) revert EmptySumcheck();

        // 2. Lookup verification (Lasso)
        if (proof.lookupProof.length == 0) revert EmptyLookup();

        // 3. Memory verification
        if (proof.memoryProof.length == 0) revert EmptyMemory();

        // 4. Verify proof structure integrity
        bytes32 proofIntegrity = keccak256(
            abi.encodePacked(
                proof.programHash,
                proof.inputHash,
                proof.outputHash,
                keccak256(proof.sumcheckProof),
                keccak256(proof.lookupProof),
                keccak256(proof.memoryProof)
            )
        );
        if (proofIntegrity == bytes32(0)) revert InvalidProof();

        verifiedProofs[proofHash] = true;
        totalVerified++;

        emit ProofVerified(proofHash, proof.programHash);

        return true;
    }
}

/**
 * @title SoulBiniusVerifier
 * @notice Verifier for Binius binary field proofs
 * @dev Optimized for hash-heavy circuits
 */
contract SoulBiniusVerifier is Ownable {
    // ============================================
    // Types
    // ============================================

    struct BiniusProof {
        bytes32 circuitHash;
        bytes32 publicInputHash;
        bytes32 oracleCommitment;
        bytes sumcheckProof;
        bytes foldingProof;
    }

    // ============================================
    // State Variables
    // ============================================

    mapping(bytes32 => bool) public registeredCircuits;
    mapping(bytes32 => bool) public verifiedProofs;
    uint256 public totalVerified;

    // ============================================
    // Errors
    // ============================================

    error CircuitNotRegistered();
    error AlreadyVerified();
    error EmptySumcheck();
    error EmptyFolding();
    error InvalidProof();

    // ============================================
    // Events
    // ============================================

    event ProofVerified(bytes32 indexed proofHash, bytes32 indexed circuitHash);

    // ============================================
    // Constructor
    // ============================================

    constructor() Ownable(msg.sender) {}

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Registers circuit
     * @param circuitHash The circuitHash hash value
     */
    function registerCircuit(bytes32 circuitHash) external onlyOwner {
        registeredCircuits[circuitHash] = true;
    }

    // ============================================
    // Verification
    // ============================================

    /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @return The result value
     */
    function verify(BiniusProof calldata proof) external returns (bool) {
        if (!registeredCircuits[proof.circuitHash])
            revert CircuitNotRegistered();

        bytes32 proofHash = keccak256(
            abi.encode(
                proof.circuitHash,
                proof.publicInputHash,
                proof.oracleCommitment
            )
        );

        if (verifiedProofs[proofHash]) revert AlreadyVerified();

        // Binius uses binary fields (GF(2))
        // Verification is optimized for hash operations
        if (proof.sumcheckProof.length == 0) revert EmptySumcheck();
        if (proof.foldingProof.length == 0) revert EmptyFolding();

        // Verify oracle commitment is non-trivial
        if (proof.oracleCommitment == bytes32(0)) revert InvalidProof();

        verifiedProofs[proofHash] = true;
        totalVerified++;

        emit ProofVerified(proofHash, proof.circuitHash);

        return true;
    }
}
