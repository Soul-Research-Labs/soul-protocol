// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IZaseonMultiProver} from "../interfaces/IZaseonMultiProver.sol";

/// @title ZaseonMultiProver
/// @author ZASEON
/// @notice Multi-prover verification with 2-of-3 consensus for maximum security
/// @dev Aligns with Ethereum's "The Verge" roadmap multi-prover strategy
///
/// MULTI-PROVER ARCHITECTURE (per Vitalik's Possible Futures Part 4):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Zaseon Multi-Prover Strategy                            │
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
/// │   │              Zaseon Multi-Prover Hub                   │              │
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
/**
 * @title ZaseonMultiProver
 * @author ZASEON Team
 * @notice Zaseon Multi Prover contract
 */
contract ZaseonMultiProver is ReentrancyGuard, AccessControl, IZaseonMultiProver {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Multi-proof submission
    struct MultiProof {
        bytes32 proofId;
        bytes32 publicInputsHash;
        ProofSubmission[] submissions;
        uint256 consensusReached; // Timestamp when consensus reached
        bool isVerified;
        bytes32 executionHash; // For cross-chain execution
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered provers
    mapping(ProverSystem => ProverConfig) public provers;

    /// @notice Multi-proofs by ID
    mapping(bytes32 => MultiProof) public multiProofs;

    /// @notice Proof submissions by proof ID
    mapping(bytes32 => mapping(ProverSystem => ProofSubmission))
        public submissions;

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

    event ProverUpdated(
        ProverSystem indexed system,
        bool isActive,
        uint256 weight
    );

    event ConsensusFailure(
        bytes32 indexed proofId,
        uint256 validCount,
        uint256 required
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

        // Register Binius prover (binary field, ~5x faster than Mersenne31)
        // Reference: https://vitalik.eth.limo/general/2024/04/29/binius.html
        provers[ProverSystem.BINIUS] = ProverConfig({
            system: ProverSystem.BINIUS,
            verifier: address(0), // Set via registerProver()
            isActive: true,
            weight: 1,
            successCount: 0,
            failureCount: 0
        });
        activeProvers.push(ProverSystem.BINIUS);
    }

    /*//////////////////////////////////////////////////////////////
                         PROVER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register or update a prover system
    /// @param system The prover system
    /// @param verifier On-chain verifier address
    /// @param weight Voting weight
        /**
     * @notice Registers prover
     * @param system The system
     * @param verifier The verifier contract address
     * @param weight The weight value
     */
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
        /**
     * @notice Deactivate prover
     * @param system The system
     */
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
        /**
     * @notice Submits proof
     * @param proofId The proofId identifier
     * @param publicInputsHash The publicInputsHash hash value
     * @param prover The prover
     * @param proof The ZK proof data
     */
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
        /**
     * @notice Submits multiple proofs
     * @param proofId The proofId identifier
     * @param publicInputsHash The publicInputsHash hash value
     * @param proverList The prover list
     * @param proofs The proofs
     */
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

            bool isValid = _verifyWithProver(
                proverList[i],
                publicInputsHash,
                proofs[i]
            );

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

        for (uint i = 0; i < activeProvers.length; ) {
            ProofSubmission storage sub = submissions[proofId][
                activeProvers[i]
            ];
            if (sub.submittedAt != 0) {
                totalWeight += provers[activeProvers[i]].weight;
                if (sub.isValid) {
                    validCount += provers[activeProvers[i]].weight;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (validCount >= requiredConsensus && !mp.isVerified) {
            mp.isVerified = true;
            mp.consensusReached = block.timestamp;
            totalVerifiedProofs++;

            // Collect valid provers
            ProverSystem[] memory validProvers = new ProverSystem[](
                activeProvers.length
            );
            uint256 validIdx = 0;
            for (uint i = 0; i < activeProvers.length; ) {
                if (submissions[proofId][activeProvers[i]].isValid) {
                    validProvers[validIdx++] = activeProvers[i];
                }
                unchecked {
                    ++i;
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
        /**
     * @notice Finalizes proof
     * @param proofId The proofId identifier
     */
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
            emit ConsensusFailure(
                proofId,
                _countValidSubmissions(proofId),
                requiredConsensus
            );
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
            // No verifier configured — reject proof
            return false;
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
    function _countValidSubmissions(
        bytes32 proofId
    ) internal view returns (uint256 count) {
        for (uint i = 0; i < activeProvers.length; ) {
            if (submissions[proofId][activeProvers[i]].isValid) {
                count++;
            }
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get verification result for a proof
        /**
     * @notice Returns the verification result
     * @param proofId The proofId identifier
     * @return result The result
     */
function getVerificationResult(
        bytes32 proofId
    ) external view returns (VerificationResult memory result) {
        MultiProof storage mp = multiProofs[proofId];

        uint256 validCount = 0;
        ProverSystem[] memory validProvers = new ProverSystem[](
            activeProvers.length
        );
        uint256 validIdx = 0;

        for (uint i = 0; i < activeProvers.length; ) {
            if (submissions[proofId][activeProvers[i]].isValid) {
                validCount++;
                validProvers[validIdx++] = activeProvers[i];
            }
            unchecked {
                ++i;
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
        /**
     * @notice Checks if proof verified
     * @param proofId The proofId identifier
     * @return The result value
     */
function isProofVerified(bytes32 proofId) external view returns (bool) {
        return multiProofs[proofId].isVerified;
    }

    /// @notice Get active prover count
        /**
     * @notice Returns the active prover count
     * @return The result value
     */
function getActiveProverCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint i = 0; i < activeProvers.length; ) {
            if (provers[activeProvers[i]].isActive) {
                count++;
            }
            unchecked {
                ++i;
            }
        }
        return count;
    }

    /// @notice Get all active provers
        /**
     * @notice Returns the active provers
     * @return The result value
     */
function getActiveProvers() external view returns (ProverSystem[] memory) {
        return activeProvers;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Update consensus requirements
        /**
     * @notice Updates consensus requirements
     * @param _requiredConsensus The _required consensus
     * @param _minProvers The _minProvers bound
     */
function updateConsensusRequirements(
        uint256 _requiredConsensus,
        uint256 _minProvers
    ) external onlyRole(OPERATOR_ROLE) {
        requiredConsensus = _requiredConsensus;
        minProvers = _minProvers;
    }

    /// @notice Update proof timeout
        /**
     * @notice Sets the proof timeout
     * @param timeout The timeout duration
     */
function setProofTimeout(uint256 timeout) external onlyRole(OPERATOR_ROLE) {
        proofTimeout = timeout;
    }
}
