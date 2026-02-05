// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title BitVMVerifier
 * @author Soul Protocol
 * @notice On-chain verification for BitVM fraud proofs
 * @dev Verifies gate computations, bit commitments, and Merkle proofs for circuits
 *
 * VERIFICATION FLOW:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                   BitVM Fraud Proof Verification                 │
 * ├─────────────────────────────────────────────────────────────────┤
 * │                                                                  │
 * │  1. BIT COMMITMENT                                               │
 * │     H0 = hash(preimage || 0)                                     │
 * │     H1 = hash(preimage || 1)                                     │
 * │     Reveal: provide preimage + bit value                         │
 * │                                                                  │
 * │  2. GATE COMMITMENT                                              │
 * │     NAND(a, b) = NOT(a AND b)                                    │
 * │     All gates reducible to NAND                                  │
 * │                                                                  │
 * │  3. CIRCUIT VERIFICATION                                         │
 * │     Merkle tree of all gates                                     │
 * │     Binary search to find faulty gate                            │
 * │     Fraud proof = gate input/output mismatch                     │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract BitVMVerifier is AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bit commitment with hash pair
    struct BitCommitment {
        bytes32 hash0;
        bytes32 hash1;
        bool revealed;
        uint8 revealedValue;
        bytes32 preimage;
    }

    /// @notice Gate verification result
    struct GateVerification {
        bytes32 gateId;
        uint8 inputA;
        uint8 inputB;
        uint8 claimedOutput;
        uint8 expectedOutput;
        bool isValid;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bit commitments
    mapping(bytes32 => BitCommitment) public bitCommitments;

    /// @notice Verified circuits
    mapping(bytes32 => bool) public verifiedCircuits;

    /// @notice Total verifications
    uint256 public totalVerifications;

    /// @notice Total fraud proofs
    uint256 public totalFraudProofs;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BitCommitmentCreated(
        bytes32 indexed commitmentId,
        bytes32 hash0,
        bytes32 hash1
    );
    event BitCommitmentRevealed(bytes32 indexed commitmentId, uint8 value);
    event GateVerified(bytes32 indexed gateId, bool isValid);
    event FraudProofVerified(bytes32 indexed circuitId, bytes32 faultyGateId);
    event CircuitVerified(bytes32 indexed circuitId, bool isValid);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidCommitment();
    error CommitmentAlreadyRevealed();
    error InvalidPreimage();
    error InvalidMerkleProof();
    error GateComputationMismatch();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(VERIFIER_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                       BIT COMMITMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a bit commitment
     * @param commitmentId Unique identifier
     * @param hash0 Hash of (preimage || 0)
     * @param hash1 Hash of (preimage || 1)
     */
    function createBitCommitment(
        bytes32 commitmentId,
        bytes32 hash0,
        bytes32 hash1
    ) external {
        if (hash0 == bytes32(0) || hash1 == bytes32(0)) {
            revert InvalidCommitment();
        }

        bitCommitments[commitmentId] = BitCommitment({
            hash0: hash0,
            hash1: hash1,
            revealed: false,
            revealedValue: 0,
            preimage: bytes32(0)
        });

        emit BitCommitmentCreated(commitmentId, hash0, hash1);
    }

    /**
     * @notice Reveal a bit commitment
     * @param commitmentId Commitment to reveal
     * @param value Bit value (0 or 1)
     * @param preimage Preimage used in hash
     */
    function revealBitCommitment(
        bytes32 commitmentId,
        uint8 value,
        bytes32 preimage
    ) external returns (bool) {
        BitCommitment storage commitment = bitCommitments[commitmentId];

        if (commitment.hash0 == bytes32(0)) revert InvalidCommitment();
        if (commitment.revealed) revert CommitmentAlreadyRevealed();

        // Verify preimage
        bytes32 computedHash = keccak256(abi.encodePacked(preimage, value));
        bytes32 expectedHash = value == 0 ? commitment.hash0 : commitment.hash1;

        if (computedHash != expectedHash) revert InvalidPreimage();

        commitment.revealed = true;
        commitment.revealedValue = value;
        commitment.preimage = preimage;

        emit BitCommitmentRevealed(commitmentId, value);

        return true;
    }

    /**
     * @notice Verify a bit commitment reveal
     * @param commitmentId Commitment to verify
     * @param value Claimed value
     * @param preimage Preimage
     * @return isValid Whether reveal is valid
     */
    function verifyBitReveal(
        bytes32 commitmentId,
        uint8 value,
        bytes32 preimage
    ) external view returns (bool isValid) {
        BitCommitment storage commitment = bitCommitments[commitmentId];

        if (commitment.hash0 == bytes32(0)) return false;

        bytes32 computedHash = keccak256(abi.encodePacked(preimage, value));
        bytes32 expectedHash = value == 0 ? commitment.hash0 : commitment.hash1;

        return computedHash == expectedHash;
    }

    /*//////////////////////////////////////////////////////////////
                       GATE VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a NAND gate computation
     * @param inputA First input (0 or 1)
     * @param inputB Second input (0 or 1)
     * @param claimedOutput Claimed output
     * @return isValid Whether gate computation is correct
     */
    function verifyNANDGate(
        uint8 inputA,
        uint8 inputB,
        uint8 claimedOutput
    ) public pure returns (bool isValid) {
        // NAND: output is 0 only if both inputs are 1
        uint8 expectedOutput = (inputA & inputB) == 1 ? 0 : 1;
        return claimedOutput == expectedOutput;
    }

    /**
     * @notice Verify a complete gate with bit commitments
     * @param gateId Gate identifier
     * @param inputACommitment Input A commitment ID
     * @param inputBCommitment Input B commitment ID
     * @param outputCommitment Output commitment ID
     * @param inputA Input A value
     * @param inputB Input B value
     * @param claimedOutput Claimed output
     * @param preimageA Preimage for input A
     * @param preimageB Preimage for input B
     * @param preimageOut Preimage for output
     * @return result Gate verification result
     */
    function verifyGateWithCommitments(
        bytes32 gateId,
        bytes32 inputACommitment,
        bytes32 inputBCommitment,
        bytes32 outputCommitment,
        uint8 inputA,
        uint8 inputB,
        uint8 claimedOutput,
        bytes32 preimageA,
        bytes32 preimageB,
        bytes32 preimageOut
    ) external returns (GateVerification memory result) {
        // Verify input A commitment
        BitCommitment storage commitA = bitCommitments[inputACommitment];
        bytes32 hashA = keccak256(abi.encodePacked(preimageA, inputA));
        bool validA = (inputA == 0 && hashA == commitA.hash0) ||
            (inputA == 1 && hashA == commitA.hash1);

        // Verify input B commitment
        BitCommitment storage commitB = bitCommitments[inputBCommitment];
        bytes32 hashB = keccak256(abi.encodePacked(preimageB, inputB));
        bool validB = (inputB == 0 && hashB == commitB.hash0) ||
            (inputB == 1 && hashB == commitB.hash1);

        // Verify output commitment
        BitCommitment storage commitOut = bitCommitments[outputCommitment];
        bytes32 hashOut = keccak256(
            abi.encodePacked(preimageOut, claimedOutput)
        );
        bool validOut = (claimedOutput == 0 && hashOut == commitOut.hash0) ||
            (claimedOutput == 1 && hashOut == commitOut.hash1);

        // Compute expected output
        uint8 expectedOutput = (inputA & inputB) == 1 ? 0 : 1; // NAND

        result = GateVerification({
            gateId: gateId,
            inputA: inputA,
            inputB: inputB,
            claimedOutput: claimedOutput,
            expectedOutput: expectedOutput,
            isValid: validA &&
                validB &&
                validOut &&
                (claimedOutput == expectedOutput)
        });

        totalVerifications++;

        if (!result.isValid) {
            totalFraudProofs++;
        }

        emit GateVerified(gateId, result.isValid);
    }

    /*//////////////////////////////////////////////////////////////
                     CIRCUIT VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set circuit verification status
     * @param circuitId Circuit identifier
     * @param isValid Whether the circuit is verified
     */
    function setCircuitVerified(
        bytes32 circuitId,
        bool isValid
    ) external onlyRole(VERIFIER_ROLE) {
        verifiedCircuits[circuitId] = isValid;
        emit CircuitVerified(circuitId, isValid);
    }

    /**
     * @notice Verify gate inclusion in circuit via Merkle proof
     * @param circuitRoot Circuit Merkle root
     * @param gateId Gate to verify
     * @param gateData Encoded gate data
     * @param proof Merkle proof siblings
     * @param index Gate index in tree
     * @return isValid Whether gate is in circuit
     */
    function verifyGateInCircuit(
        bytes32 circuitRoot,
        bytes32 gateId,
        bytes calldata gateData,
        bytes32[] calldata proof,
        uint256 index
    ) external pure returns (bool isValid) {
        bytes32 leaf = keccak256(abi.encodePacked(gateId, gateData));
        bytes32 computedRoot = _computeMerkleRoot(leaf, proof, index);

        return computedRoot == circuitRoot;
    }

    /**
     * @notice Verify a fraud proof
     * @param circuitRoot Circuit commitment
     * @param gateId Faulty gate
     * @param inputA Input A value
     * @param inputB Input B value
     * @param claimedOutput Prover's claimed output
     * @param proof Merkle proof for gate
     * @param index Gate index
     * @return isFraud Whether fraud is proven
     */
    function verifyFraudProof(
        bytes32 circuitRoot,
        bytes32 gateId,
        uint8 inputA,
        uint8 inputB,
        uint8 claimedOutput,
        bytes32[] calldata proof,
        uint256 index
    ) external returns (bool isFraud) {
        // Verify gate is in circuit
        bytes32 gateData = keccak256(
            abi.encodePacked(inputA, inputB, claimedOutput)
        );
        bytes32 leaf = keccak256(abi.encodePacked(gateId, gateData));
        bytes32 computedRoot = _computeMerkleRoot(leaf, proof, index);

        if (computedRoot != circuitRoot) {
            revert InvalidMerkleProof();
        }

        // Verify gate computation is wrong
        uint8 expectedOutput = (inputA & inputB) == 1 ? 0 : 1; // NAND
        isFraud = claimedOutput != expectedOutput;

        if (isFraud) {
            totalFraudProofs++;
            emit FraudProofVerified(circuitRoot, gateId);
        }

        totalVerifications++;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getBitCommitment(
        bytes32 commitmentId
    ) external view returns (BitCommitment memory) {
        return bitCommitments[commitmentId];
    }

    function isCircuitVerified(bytes32 circuitId) external view returns (bool) {
        return verifiedCircuits[circuitId];
    }

    function getStats()
        external
        view
        returns (uint256 verifications, uint256 fraudProofs)
    {
        return (totalVerifications, totalFraudProofs);
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Compute Merkle root from leaf and proof
     */
    function _computeMerkleRoot(
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }

            index = index / 2;
        }

        return computedHash;
    }
}
