// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MidnightProofVerifier
 * @author Soul Protocol
 * @notice Verifies ZK proofs from Midnight Network on Ethereum
 * @dev Translates Midnight's ZK-SNARK proofs to EVM-compatible Groth16 (BN254)
 *
 * PROOF TRANSLATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    MIDNIGHT → ETHEREUM PROOF FLOW                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  Midnight ZK-SNARK          Translation           EVM Groth16           │
 * │  ┌─────────────────┐       ┌───────────┐       ┌─────────────────┐      │
 * │  │ Kachina Proof   │──────►│ Relayer   │──────►│ BN254 Proof     │      │
 * │  │ (Recursive)     │       │ Network   │       │ (3 G1 + 1 G2)   │      │
 * │  └─────────────────┘       └───────────┘       └─────────────────┘      │
 * │                                                        │                 │
 * │                                                        ▼                 │
 * │                                              ┌─────────────────┐        │
 * │                                              │ EVM Precompiles │        │
 * │                                              │ 0x06, 0x07, 0x08│        │
 * │                                              └─────────────────┘        │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * CIRCUITS SUPPORTED:
 * 1. Bridge Transfer - Proves valid lock on Midnight
 * 2. State Transition - Proves valid state root update
 * 3. Nullifier Batch - Proves batch of nullifiers in tree
 * 4. Merkle Inclusion - Proves deposit in Merkle tree
 */
contract MidnightProofVerifier {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BN254 curve order
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Proof size in bytes (256 = 2*32 + 4*32 + 2*32)
    uint256 internal constant PROOF_SIZE = 256;

    /// @notice Public inputs count for bridge transfer proof
    uint256 internal constant BRIDGE_TRANSFER_INPUTS = 6;

    /// @notice Public inputs count for state transition proof
    uint256 internal constant STATE_TRANSITION_INPUTS = 3;

    /// @notice Public inputs count for nullifier batch proof
    uint256 internal constant NULLIFIER_BATCH_INPUTS = 2;

    /*//////////////////////////////////////////////////////////////
                             DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit type identifiers
    enum CircuitType {
        BridgeTransfer,
        StateTransition,
        NullifierBatch,
        MerkleInclusion
    }

    /// @notice G1 point structure
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// @notice G2 point structure
    struct G2Point {
        uint256[2] x; // [x_im, x_re]
        uint256[2] y; // [y_im, y_re]
    }

    /// @notice Verification key structure
    struct VerificationKey {
        G1Point alpha;
        G2Point beta;
        G2Point gamma;
        G2Point delta;
        G1Point[] ic;
        bytes32 circuitHash;
        bool initialized;
    }

    /// @notice Groth16 proof structure
    struct Proof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Owner address
    address public owner;

    /// @notice Verification keys per circuit type
    mapping(CircuitType => VerificationKey) public verificationKeys;

    /// @notice Circuit type to public input count
    mapping(CircuitType => uint256) public circuitInputCounts;

    /// @notice Verified proof hashes (for replay protection)
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice Proof verification count
    uint256 public totalVerifications;

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotOwner();
    error InvalidProofSize();
    error InvalidPublicInput();
    error CircuitNotInitialized();
    error PairingCheckFailed();
    error PrecompileFailed();
    error ProofAlreadyVerified();
    error InvalidInputCount();

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerificationKeySet(
        CircuitType indexed circuitType,
        bytes32 circuitHash
    );
    event ProofVerified(
        CircuitType indexed circuitType,
        bytes32 proofHash,
        bool valid
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

        // Set expected input counts
        circuitInputCounts[CircuitType.BridgeTransfer] = BRIDGE_TRANSFER_INPUTS;
        circuitInputCounts[
            CircuitType.StateTransition
        ] = STATE_TRANSITION_INPUTS;
        circuitInputCounts[CircuitType.NullifierBatch] = NULLIFIER_BATCH_INPUTS;
        circuitInputCounts[CircuitType.MerkleInclusion] = 3;
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFICATION KEY SETUP
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set verification key for a circuit type
     * @param circuitType Circuit type
     * @param alpha Alpha G1 point
     * @param beta Beta G2 point
     * @param gamma Gamma G2 point
     * @param delta Delta G2 point
     * @param ic Input commitment G1 points
     */
    function setVerificationKey(
        CircuitType circuitType,
        G1Point memory alpha,
        G2Point memory beta,
        G2Point memory gamma,
        G2Point memory delta,
        G1Point[] memory ic
    ) external onlyOwner {
        bytes32 circuitHash = keccak256(
            abi.encode(alpha, beta, gamma, delta, ic)
        );

        VerificationKey storage vk = verificationKeys[circuitType];
        vk.alpha = alpha;
        vk.beta = beta;
        vk.gamma = gamma;
        vk.delta = delta;
        delete vk.ic;
        for (uint256 i = 0; i < ic.length; i++) {
            vk.ic.push(ic[i]);
        }
        vk.circuitHash = circuitHash;
        vk.initialized = true;

        emit VerificationKeySet(circuitType, circuitHash);
    }

    /*//////////////////////////////////////////////////////////////
                    MIDNIGHT BRIDGE PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a Midnight bridge proof
     * @param commitment Pedersen commitment from Midnight
     * @param nullifier CDNA nullifier
     * @param merkleRoot Deposit Merkle root
     * @param token Token being claimed
     * @param amount Amount being claimed
     * @param recipient Ethereum recipient
     * @param proof Groth16 proof bytes
     * @return valid Whether the proof is valid
     */
    function verifyMidnightProof(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 merkleRoot,
        address token,
        uint256 amount,
        address recipient,
        bytes calldata proof
    ) external returns (bool valid) {
        VerificationKey storage vk = verificationKeys[
            CircuitType.BridgeTransfer
        ];
        if (!vk.initialized) revert CircuitNotInitialized();

        // Parse proof
        if (proof.length != PROOF_SIZE) revert InvalidProofSize();
        Proof memory p = _parseProof(proof);

        // Construct public inputs
        uint256[] memory publicInputs = new uint256[](BRIDGE_TRANSFER_INPUTS);
        publicInputs[0] = uint256(commitment);
        publicInputs[1] = uint256(nullifier);
        publicInputs[2] = uint256(merkleRoot);
        publicInputs[3] = uint256(uint160(token));
        publicInputs[4] = amount;
        publicInputs[5] = uint256(uint160(recipient));

        // Verify
        valid = _verifyProof(p, publicInputs, vk);

        // Mark proof as verified
        bytes32 proofHash = keccak256(proof);
        if (valid) {
            verifiedProofs[proofHash] = true;
            totalVerifications++;
        }

        emit ProofVerified(CircuitType.BridgeTransfer, proofHash, valid);
    }

    /**
     * @notice Verify a state transition proof
     * @param oldStateHash Previous state hash
     * @param newStateHash New state hash
     * @param proof Groth16 proof bytes
     * @return valid Whether the proof is valid
     */
    function verifyStateTransition(
        bytes32 oldStateHash,
        bytes32 newStateHash,
        bytes calldata proof
    ) external returns (bool valid) {
        VerificationKey storage vk = verificationKeys[
            CircuitType.StateTransition
        ];
        if (!vk.initialized) revert CircuitNotInitialized();

        if (proof.length != PROOF_SIZE) revert InvalidProofSize();
        Proof memory p = _parseProof(proof);

        uint256[] memory publicInputs = new uint256[](STATE_TRANSITION_INPUTS);
        publicInputs[0] = uint256(oldStateHash);
        publicInputs[1] = uint256(newStateHash);
        publicInputs[2] = block.chainid;

        valid = _verifyProof(p, publicInputs, vk);

        if (valid) {
            bytes32 proofHash = keccak256(proof);
            verifiedProofs[proofHash] = true;
            totalVerifications++;
            emit ProofVerified(CircuitType.StateTransition, proofHash, valid);
        }
    }

    /**
     * @notice Verify nullifier batch proof
     * @param nullifiers Array of nullifiers
     * @param nullifierRoot Current nullifier Merkle root
     * @param proof Groth16 proof bytes
     * @return valid Whether the proof is valid
     */
    function verifyNullifierBatch(
        bytes32[] calldata nullifiers,
        bytes32 nullifierRoot,
        bytes calldata proof
    ) external returns (bool valid) {
        VerificationKey storage vk = verificationKeys[
            CircuitType.NullifierBatch
        ];
        if (!vk.initialized) revert CircuitNotInitialized();

        if (proof.length != PROOF_SIZE) revert InvalidProofSize();
        Proof memory p = _parseProof(proof);

        // Hash all nullifiers
        bytes32 nullifiersHash = keccak256(abi.encodePacked(nullifiers));

        uint256[] memory publicInputs = new uint256[](NULLIFIER_BATCH_INPUTS);
        publicInputs[0] = uint256(nullifiersHash);
        publicInputs[1] = uint256(nullifierRoot);

        valid = _verifyProof(p, publicInputs, vk);

        if (valid) {
            bytes32 proofHash = keccak256(proof);
            verifiedProofs[proofHash] = true;
            totalVerifications++;
            emit ProofVerified(CircuitType.NullifierBatch, proofHash, valid);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GROTH16 VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Parse proof bytes into Proof struct
     * @param proofBytes Raw proof bytes
     * @return p Parsed proof
     */
    function _parseProof(
        bytes calldata proofBytes
    ) internal pure returns (Proof memory p) {
        // A: G1 point (64 bytes)
        p.a = G1Point({
            x: _bytesToUint(proofBytes[0:32]),
            y: _bytesToUint(proofBytes[32:64])
        });

        // B: G2 point (128 bytes)
        p.b = G2Point({
            x: [
                _bytesToUint(proofBytes[64:96]),
                _bytesToUint(proofBytes[96:128])
            ],
            y: [
                _bytesToUint(proofBytes[128:160]),
                _bytesToUint(proofBytes[160:192])
            ]
        });

        // C: G1 point (64 bytes)
        p.c = G1Point({
            x: _bytesToUint(proofBytes[192:224]),
            y: _bytesToUint(proofBytes[224:256])
        });
    }

    /**
     * @notice Verify Groth16 proof
     * @param p Proof
     * @param publicInputs Public inputs
     * @param vk Verification key
     * @return valid Whether proof is valid
     */
    function _verifyProof(
        Proof memory p,
        uint256[] memory publicInputs,
        VerificationKey storage vk
    ) internal view returns (bool valid) {
        // Check input count
        if (publicInputs.length + 1 != vk.ic.length) revert InvalidInputCount();

        // Compute vk_x = IC[0] + Σ publicInputs[i] * IC[i+1]
        G1Point memory vk_x = vk.ic[0];
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= FIELD_MODULUS) revert InvalidPublicInput();

            G1Point memory scaledIC = _scalarMul(vk.ic[i + 1], publicInputs[i]);
            vk_x = _pointAdd(vk_x, scaledIC);
        }

        // Verify pairing: e(A, B) == e(α, β) * e(vk_x, γ) * e(C, δ)
        // Rearranged: e(-A, B) * e(α, β) * e(vk_x, γ) * e(C, δ) == 1
        valid = _pairingCheck(
            _negate(p.a),
            p.b,
            vk.alpha,
            vk.beta,
            vk_x,
            vk.gamma,
            p.c,
            vk.delta
        );
    }

    /**
     * @notice G1 point addition using precompile 0x06
     */
    function _pointAdd(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {
        uint256[4] memory input = [p1.x, p1.y, p2.x, p2.y];

        assembly {
            let success := staticcall(gas(), 0x06, input, 128, r, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }
    }

    /**
     * @notice G1 scalar multiplication using precompile 0x07
     */
    function _scalarMul(
        G1Point memory p,
        uint256 s
    ) internal view returns (G1Point memory r) {
        uint256[3] memory input = [p.x, p.y, s];

        assembly {
            let success := staticcall(gas(), 0x07, input, 96, r, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }
    }

    /**
     * @notice Negate G1 point
     */
    function _negate(G1Point memory p) internal pure returns (G1Point memory) {
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.x == 0 && p.y == 0) return p;
        return G1Point(p.x, q - (p.y % q));
    }

    /**
     * @notice Pairing check using precompile 0x08
     */
    function _pairingCheck(
        G1Point memory a1,
        G2Point memory b1,
        G1Point memory a2,
        G2Point memory b2,
        G1Point memory a3,
        G2Point memory b3,
        G1Point memory a4,
        G2Point memory b4
    ) internal view returns (bool) {
        uint256[24] memory input = [
            a1.x,
            a1.y,
            b1.x[0],
            b1.x[1],
            b1.y[0],
            b1.y[1],
            a2.x,
            a2.y,
            b2.x[0],
            b2.x[1],
            b2.y[0],
            b2.y[1],
            a3.x,
            a3.y,
            b3.x[0],
            b3.x[1],
            b3.y[0],
            b3.y[1],
            a4.x,
            a4.y,
            b4.x[0],
            b4.x[1],
            b4.y[0],
            b4.y[1]
        ];

        uint256 result;
        assembly {
            let success := staticcall(gas(), 0x08, input, 768, result, 32)
            if iszero(success) {
                revert(0, 0)
            }
            result := mload(result)
        }

        return result == 1;
    }

    /**
     * @notice Convert bytes to uint256
     */
    function _bytesToUint(bytes calldata b) internal pure returns (uint256) {
        return uint256(bytes32(b));
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Transfer ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }
}
