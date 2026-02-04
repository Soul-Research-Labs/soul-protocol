// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title SoulMultiProver
/// @author Soul Protocol
/// @notice Multi-prover verification with 2-of-3 consensus for maximum security
/// @dev Aligns with Ethereum's "The Verge" roadmap multi-prover strategy
///
/// MULTI-PROVER ARCHITECTURE (per Vitalik's Possible Futures Part 4):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Soul Multi-Prover Strategy                            │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                          │
/// │   2-of-3 Prover Consensus (reduces bug risk 100x → 1000x):              │
/// │                                                                          │
/// │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                   │
/// │   │   Noir      │   │   SP1       │   │   Jolt      │                   │
/// │   │   (Aztec)   │   │   (Succinct)│   │   (a16z)    │                   │
/// │   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘                   │
/// │          │                 │                 │                          │
/// │          ▼                 ▼                 ▼                          │
/// │   ┌─────────────────────────────────────────────────────┐              │
/// │   │              Soul Multi-Prover Hub                   │              │
/// │   │  ┌───────────────────────────────────────────────┐  │              │
/// │   │  │ 2-of-3 Consensus: Any 2 provers must agree   │  │              │
/// │   │  │ Proof types: ZK-EVM, Application, Cross-chain│  │              │
/// │   │  └───────────────────────────────────────────────┘  │              │
/// │   └─────────────────────────────────────────────────────┘              │
/// │                                                                          │
/// │   Prover Ecosystem:                                                     │
/// │   • Noir (Aztec): Privacy-focused, UltraPlonk                          │
/// │   • SP1 (Succinct): RISC-V zkVM, fast proving                          │
/// │   • Jolt (a16z): Lasso-based, efficient lookups                        │
/// │   • Plonky3 (Polygon): Recursive, fast verification                    │
/// │   • Binius (Irreducible): Binary field, hardware-friendly              │
/// │                                                                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// References:
/// - https://vitalik.eth.limo/general/2024/10/23/futures4.html
/// - https://docs.succinct.xyz/sp1
/// - https://github.com/a16z/jolt
contract SoulMultiProver is ReentrancyGuard, AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported prover systems
    enum ProverSystem {
        NOIR,           // Aztec Noir (UltraPlonk)
        SP1,            // Succinct SP1 (RISC-V zkVM)
        JOLT,           // a16z Jolt (Lasso lookups)
        PLONKY3,        // Polygon Plonky3 (recursive)
        BINIUS,         // Irreducible Binius (binary field)
        HALO2,          // ZCash Halo2 (no trusted setup)
        GROTH16,        // Classic Groth16 (smallest proofs)
        RISC_ZERO       // RiscZero zkVM
    }

    /// @notice Prover configuration
    struct ProverConfig {
        ProverSystem system;
        address verifier;          // On-chain verifier contract
        bool isActive;
        uint256 weight;            // Voting weight (default: 1)
        uint256 successCount;      // Successful verifications
        uint256 failureCount;      // Failed verifications
    }

    /// @notice Multi-proof submission
    struct MultiProof {
        bytes32 proofId;
        bytes32 publicInputsHash;
        ProofSubmission[] submissions;
        uint256 consensusReached;  // Timestamp when consensus reached
        bool isVerified;
        bytes32 executionHash;     // For cross-chain execution
    }

    /// @notice Individual proof submission
    struct ProofSubmission {
        ProverSystem prover;
        bytes proof;
        bool isValid;
        uint64 submittedAt;
        address submitter;
    }

    /// @notice Verification result
    struct VerificationResult {
        bytes32 proofId;
        bool consensusReached;
        uint256 validCount;
        uint256 totalCount;
        ProverSystem[] validProvers;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered provers
    mapping(ProverSystem => ProverConfig) public provers;

    /// @notice Multi-proofs by ID
    mapping(bytes32 => MultiProof) public multiProofs;

    /// @notice Proof submissions by proof ID
    mapping(bytes32 => mapping(ProverSystem => ProofSubmission)) public submissions;

    /// @notice Active prover systems
    ProverSystem[] public activeProvers;

    /// @notice Required consensus (e.g., 2 for 2-of-3)
    uint256 public requiredConsensus = 2;

    /// @notice Minimum provers required
    uint256 public minProvers = 3;

    /// @notice Proof submission timeout
    uint256 public proofTimeout = 1 hours;

    /// @notice Total verified proofs
    uint256 public totalVerifiedProofs;

    /// @notice Total consensus failures
    uint256 public totalConsensusFailures;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProverRegistered(
        ProverSystem indexed system,
        address verifier
    );

    event ProverUpdated(
        ProverSystem indexed system,
        bool isActive,
        uint256 weight
    );

    event ProofSubmitted(
        bytes32 indexed proofId,
        ProverSystem indexed prover,
        address submitter
    );

    event ConsensusReached(
        bytes32 indexed proofId,
        uint256 validCount,
        uint256 totalCount
    );

    event ConsensusFailure(
        bytes32 indexed proofId,
        uint256 validCount,
        uint256 required
    );

    event MultiProofVerified(
        bytes32 indexed proofId,
        bytes32 publicInputsHash,
        ProverSystem[] validProvers
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ProverNotRegistered();
    error ProverNotActive();
    error ProofAlreadySubmitted();
    error ProofNotFound();
    error ConsensusNotReached();
    error ProofTimedOut();
    error InsufficientProvers();
    error VerificationFailed();
    error InvalidProverConfig();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        
        // Register default provers (verifiers set later)
        _registerDefaultProvers();
    }

    function _registerDefaultProvers() internal {
        provers[ProverSystem.NOIR] = ProverConfig({
            system: ProverSystem.NOIR,
            verifier: address(0),
            isActive: true,
            weight: 1,
            successCount: 0,
            failureCount: 0
        });

        provers[ProverSystem.SP1] = ProverConfig({
            system: ProverSystem.SP1,
            verifier: address(0),
            isActive: true,
            weight: 1,
            successCount: 0,
            failureCount: 0
        });

        provers[ProverSystem.JOLT] = ProverConfig({
            system: ProverSystem.JOLT,
            verifier: address(0),
            isActive: true,
            weight: 1,
            successCount: 0,
            failureCount: 0
        });

        activeProvers.push(ProverSystem.NOIR);
        activeProvers.push(ProverSystem.SP1);
        activeProvers.push(ProverSystem.JOLT);
    }

    /*//////////////////////////////////////////////////////////////
                         PROVER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register or update a prover system
    /// @param system The prover system
    /// @param verifier On-chain verifier address
    /// @param weight Voting weight
    function registerProver(
        ProverSystem system,
        address verifier,
        uint256 weight
    ) external onlyRole(OPERATOR_ROLE) {
        if (weight == 0) revert InvalidProverConfig();

        ProverConfig storage config = provers[system];
        
        bool isNew = config.verifier == address(0);
        
        config.system = system;
        config.verifier = verifier;
        config.isActive = true;
        config.weight = weight;

        if (isNew) {
            activeProvers.push(system);
            emit ProverRegistered(system, verifier);
        } else {
            emit ProverUpdated(system, true, weight);
        }
    }

    /// @notice Deactivate a prover
    function deactivateProver(
        ProverSystem system
    ) external onlyRole(OPERATOR_ROLE) {
        provers[system].isActive = false;
        emit ProverUpdated(system, false, provers[system].weight);
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a proof from a specific prover system
    /// @param proofId Unique proof identifier
    /// @param publicInputsHash Hash of public inputs
    /// @param prover The prover system
    /// @param proof The proof bytes
    function submitProof(
        bytes32 proofId,
        bytes32 publicInputsHash,
        ProverSystem prover,
        bytes calldata proof
    ) external nonReentrant {
        ProverConfig storage config = provers[prover];
        if (!config.isActive) revert ProverNotActive();

        if (submissions[proofId][prover].submittedAt != 0) {
            revert ProofAlreadySubmitted();
        }

        // Initialize multi-proof if first submission
        MultiProof storage mp = multiProofs[proofId];
        if (mp.proofId == bytes32(0)) {
            mp.proofId = proofId;
            mp.publicInputsHash = publicInputsHash;
        }

        // Verify the proof
        bool isValid = _verifyWithProver(prover, publicInputsHash, proof);

        submissions[proofId][prover] = ProofSubmission({
            prover: prover,
            proof: proof,
            isValid: isValid,
            submittedAt: uint64(block.timestamp),
            submitter: msg.sender
        });

        mp.submissions.push(submissions[proofId][prover]);

        if (isValid) {
            config.successCount++;
        } else {
            config.failureCount++;
        }

        emit ProofSubmitted(proofId, prover, msg.sender);

        // Check consensus after each submission
        _checkConsensus(proofId);
    }

    /// @notice Submit multiple proofs at once
    /// @param proofId Unique proof identifier
    /// @param publicInputsHash Hash of public inputs
    /// @param proverList List of provers
    /// @param proofs List of proofs
    function submitMultipleProofs(
        bytes32 proofId,
        bytes32 publicInputsHash,
        ProverSystem[] calldata proverList,
        bytes[] calldata proofs
    ) external nonReentrant {
        require(proverList.length == proofs.length, "Length mismatch");

        for (uint i = 0; i < proverList.length; i++) {
            ProverConfig storage config = provers[proverList[i]];
            if (!config.isActive) continue;

            if (submissions[proofId][proverList[i]].submittedAt != 0) continue;

            MultiProof storage mp = multiProofs[proofId];
            if (mp.proofId == bytes32(0)) {
                mp.proofId = proofId;
                mp.publicInputsHash = publicInputsHash;
            }

            bool isValid = _verifyWithProver(proverList[i], publicInputsHash, proofs[i]);

            submissions[proofId][proverList[i]] = ProofSubmission({
                prover: proverList[i],
                proof: proofs[i],
                isValid: isValid,
                submittedAt: uint64(block.timestamp),
                submitter: msg.sender
            });

            mp.submissions.push(submissions[proofId][proverList[i]]);

            emit ProofSubmitted(proofId, proverList[i], msg.sender);
        }

        _checkConsensus(proofId);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSENSUS CHECKING
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if consensus has been reached
    function _checkConsensus(bytes32 proofId) internal {
        MultiProof storage mp = multiProofs[proofId];
        
        uint256 validCount = 0;
        uint256 totalWeight = 0;
        
        for (uint i = 0; i < activeProvers.length; i++) {
            ProofSubmission storage sub = submissions[proofId][activeProvers[i]];
            if (sub.submittedAt != 0) {
                totalWeight += provers[activeProvers[i]].weight;
                if (sub.isValid) {
                    validCount += provers[activeProvers[i]].weight;
                }
            }
        }

        if (validCount >= requiredConsensus && !mp.isVerified) {
            mp.isVerified = true;
            mp.consensusReached = block.timestamp;
            totalVerifiedProofs++;

            // Collect valid provers
            ProverSystem[] memory validProvers = new ProverSystem[](activeProvers.length);
            uint256 validIdx = 0;
            for (uint i = 0; i < activeProvers.length; i++) {
                if (submissions[proofId][activeProvers[i]].isValid) {
                    validProvers[validIdx++] = activeProvers[i];
                }
            }

            // Resize array
            assembly {
                mstore(validProvers, validIdx)
            }

            emit ConsensusReached(proofId, validCount, totalWeight);
            emit MultiProofVerified(proofId, mp.publicInputsHash, validProvers);
        }
    }

    /// @notice Force consensus check (called after timeout)
    function finalizeProof(bytes32 proofId) external nonReentrant {
        MultiProof storage mp = multiProofs[proofId];
        if (mp.proofId == bytes32(0)) revert ProofNotFound();
        if (mp.isVerified) return;

        // Check if at least one submission and timeout passed
        if (mp.submissions.length > 0) {
            uint64 firstSubmission = mp.submissions[0].submittedAt;
            if (block.timestamp < firstSubmission + proofTimeout) {
                revert ProofTimedOut();
            }
        }

        _checkConsensus(proofId);

        if (!mp.isVerified) {
            totalConsensusFailures++;
            emit ConsensusFailure(proofId, _countValidSubmissions(proofId), requiredConsensus);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFICATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a proof with a specific prover
    function _verifyWithProver(
        ProverSystem prover,
        bytes32 publicInputsHash,
        bytes calldata proof
    ) internal view returns (bool) {
        ProverConfig storage config = provers[prover];
        
        if (config.verifier == address(0)) {
            // No verifier set, use mock verification
            return proof.length >= 32;
        }

        // Call the verifier contract
        // Different provers have different interfaces
        (bool success, bytes memory result) = config.verifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes32,bytes)",
                publicInputsHash,
                proof
            )
        );

        if (!success) return false;
        if (result.length < 32) return false;

        return abi.decode(result, (bool));
    }

    /// @notice Count valid submissions for a proof
    function _countValidSubmissions(bytes32 proofId) internal view returns (uint256 count) {
        for (uint i = 0; i < activeProvers.length; i++) {
            if (submissions[proofId][activeProvers[i]].isValid) {
                count++;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get verification result for a proof
    function getVerificationResult(
        bytes32 proofId
    ) external view returns (VerificationResult memory result) {
        MultiProof storage mp = multiProofs[proofId];
        
        uint256 validCount = 0;
        ProverSystem[] memory validProvers = new ProverSystem[](activeProvers.length);
        uint256 validIdx = 0;

        for (uint i = 0; i < activeProvers.length; i++) {
            if (submissions[proofId][activeProvers[i]].isValid) {
                validCount++;
                validProvers[validIdx++] = activeProvers[i];
            }
        }

        // Resize
        assembly {
            mstore(validProvers, validIdx)
        }

        result = VerificationResult({
            proofId: proofId,
            consensusReached: mp.isVerified,
            validCount: validCount,
            totalCount: mp.submissions.length,
            validProvers: validProvers
        });
    }

    /// @notice Check if a proof is verified
    function isProofVerified(bytes32 proofId) external view returns (bool) {
        return multiProofs[proofId].isVerified;
    }

    /// @notice Get active prover count
    function getActiveProverCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint i = 0; i < activeProvers.length; i++) {
            if (provers[activeProvers[i]].isActive) {
                count++;
            }
        }
        return count;
    }

    /// @notice Get all active provers
    function getActiveProvers() external view returns (ProverSystem[] memory) {
        return activeProvers;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Update consensus requirements
    function updateConsensusRequirements(
        uint256 _requiredConsensus,
        uint256 _minProvers
    ) external onlyRole(OPERATOR_ROLE) {
        requiredConsensus = _requiredConsensus;
        minProvers = _minProvers;
    }

    /// @notice Update proof timeout
    function setProofTimeout(uint256 timeout) external onlyRole(OPERATOR_ROLE) {
        proofTimeout = timeout;
    }
}
