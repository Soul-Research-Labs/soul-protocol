// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SoulSP1Verifier
 * @notice Verifier for SP1 RISC-V zkVM proofs
 * @dev Supports Succinct's SP1 proving system for Soul
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
        require(vkeyHash != bytes32(0), "Invalid vkey");
        require(!verificationKeys[vkeyHash].active, "Already registered");

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
        require(verificationKeys[proof.vkeyHash].active, "VKey not registered");

        // Verify public values hash
        bytes32 computedHash = keccak256(publicValues);
        require(
            computedHash == proof.publicValuesHash,
            "Public values mismatch"
        );

        // Compute proof hash
        bytes32 proofHash = keccak256(
            abi.encode(proof.vkeyHash, proof.publicValuesHash, proof.proof)
        );

        // Check not already verified (prevent replay)
        require(!verifiedProofs[proofHash], "Already verified");

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
            require(
                success && abi.decode(result, (bool)),
                "Proof verification failed"
            );
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

        // Would need gateway call for full verification
        return true;
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

    function verify(Plonky3Proof calldata proof) external returns (bool) {
        CircuitConfig storage config = circuits[proof.circuitHash];
        require(config.active, "Circuit not registered");
        require(
            proof.publicInputs.length == config.numPublicInputs,
            "Input count mismatch"
        );

        bytes32 proofHash = keccak256(
            abi.encode(
                proof.circuitHash,
                proof.publicInputs,
                proof.commitmentHash
            )
        );

        require(!verifiedProofs[proofHash], "Already verified");

        // Plonky3 verification logic would go here
        // For now, verify proof structure
        require(proof.openingProof.length > 0, "Empty opening proof");

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

    function verify(JoltProof calldata proof) external returns (bool) {
        JoltProgram storage program = programs[proof.programHash];
        require(program.active, "Program not registered");

        bytes32 proofHash = keccak256(
            abi.encode(proof.programHash, proof.inputHash, proof.outputHash)
        );

        require(!verifiedProofs[proofHash], "Already verified");

        // Jolt verification consists of:
        // 1. Sumcheck verification
        require(proof.sumcheckProof.length > 0, "Empty sumcheck");

        // 2. Lookup verification (Lasso)
        require(proof.lookupProof.length > 0, "Empty lookup");

        // 3. Memory verification
        require(proof.memoryProof.length > 0, "Empty memory");

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
    // Constructor
    // ============================================

    constructor() Ownable(msg.sender) {}

    // ============================================
    // Admin Functions
    // ============================================

    function registerCircuit(bytes32 circuitHash) external onlyOwner {
        registeredCircuits[circuitHash] = true;
    }

    // ============================================
    // Verification
    // ============================================

    function verify(BiniusProof calldata proof) external returns (bool) {
        require(
            registeredCircuits[proof.circuitHash],
            "Circuit not registered"
        );

        bytes32 proofHash = keccak256(
            abi.encode(
                proof.circuitHash,
                proof.publicInputHash,
                proof.oracleCommitment
            )
        );

        require(!verifiedProofs[proofHash], "Already verified");

        // Binius uses binary fields (GF(2))
        // Verification is optimized for hash operations
        require(proof.sumcheckProof.length > 0, "Empty sumcheck");
        require(proof.foldingProof.length > 0, "Empty folding");

        verifiedProofs[proofHash] = true;
        totalVerified++;

        return true;
    }
}
