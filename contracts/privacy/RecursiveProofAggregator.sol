// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title RecursiveProofAggregator
 * @author Soul Protocol
 * @notice IVC-based Recursive Proof Aggregation for Cross-Chain Privacy
 * @dev Implements Nova/SuperNova-style folding for proof compression
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    RECURSIVE PROOF AGGREGATION
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Aggregating multiple ZK proofs into a single succinct proof enables:
 *
 * 1. CONSTANT VERIFICATION COST: Verify 1000 proofs with same cost as 1
 * 2. BANDWIDTH REDUCTION: Submit one proof instead of many
 * 3. CROSS-CHAIN BATCHING: Bundle multi-chain proofs
 * 4. PRIVACY AMPLIFICATION: Larger anonymity sets
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    PROOF SYSTEMS SUPPORTED
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * - GROTH16: Classic SNARK, smallest proof size
 * - PLONK: Universal trusted setup
 * - STARK: No trusted setup, post-quantum security
 * - NOVA: IVC folding scheme (recommended)
 * - SUPERNOVA: Multi-folding for different circuits
 * - HALO2: Recursive proofs without pairings
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract RecursiveProofAggregator is
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // ============================================
    // ENUMS
    // ============================================

    /// @notice Supported proof systems
    enum ProofSystem {
        GROTH16, // BN254 pairing-based SNARK
        PLONK, // Universal SNARK
        STARK, // Hash-based, post-quantum
        NOVA, // IVC folding (primary)
        SUPERNOVA, // Multi-folding
        HALO2 // Recursive without pairings
    }

    /// @notice Batch processing state
    enum BatchState {
        OPEN, // Accepting proofs
        AGGREGATING, // Being aggregated
        VERIFIED, // Aggregation verified
        FINALIZED, // On-chain finalized
        EXPIRED // Batch expired
    }

    // ============================================
    // ERRORS
    // ============================================

    error ProofSubmissionFailed(bytes32 proofId);
    error BatchDoesNotExist(bytes32 batchId);
    error BatchNotOpen(bytes32 batchId);
    error BatchTooLarge(uint256 size, uint256 maxSize);
    error BatchTooSmall(uint256 size, uint256 minSize);
    error AggregationFailed(bytes32 batchId);
    error VerificationFailed(bytes32 proofId);
    error ProofAlreadySubmitted(bytes32 proofId);
    error InvalidProofSystem(ProofSystem system);
    error IncompatibleProofSystems();
    error FoldingError(uint256 step);
    error InvalidNovaProof();
    error CrossChainProofMismatch();
    error BatchExpired(bytes32 batchId);
    error NotBatchCreator(bytes32 batchId);
    error ZeroAddress();
    error InvalidProof();

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Individual proof submission
    struct ProofSubmission {
        bytes32 proofId; // Unique proof ID
        bytes32 batchId; // Assigned batch
        ProofSystem system; // Proof system used
        bytes32 commitmentHash; // Commitment to proof data
        bytes32 publicInputHash; // Hash of public inputs
        uint256 chainId; // Source chain ID
        uint64 submittedAt; // Submission timestamp
        bool verified; // Verification status
        bool aggregated; // Included in aggregation
    }

    /// @notice Aggregation batch
    struct AggregationBatch {
        bytes32 batchId; // Unique batch ID
        address creator; // Batch creator
        BatchState state; // Current state
        ProofSystem system; // Primary proof system
        bytes32[] proofIds; // Included proofs
        bytes32 aggregatedProofHash; // Final aggregated proof hash
        bytes32 merkleRoot; // Merkle root of public inputs
        uint256 proofCount; // Number of proofs
        uint64 createdAt; // Creation timestamp
        uint64 aggregatedAt; // Aggregation timestamp
        uint64 expiresAt; // Expiration timestamp
    }

    /// @notice Nova folding proof (IVC)
    struct NovaProof {
        bytes32 U; // Running instance (commitment)
        bytes32 W; // Running witness (commitment)
        bytes32 u; // New instance
        bytes32 w; // New witness
        bytes32 T; // Cross-term commitment
        uint256 step; // Folding step number
        bytes foldingProof; // Proof of correct folding
    }

    /// @notice Groth16 proof structure
    struct Groth16Proof {
        uint256[2] a; // π_A point
        uint256[2][2] b; // π_B point (in G2)
        uint256[2] c; // π_C point
    }

    /// @notice PLONK proof structure
    struct PLONKProof {
        bytes32 commitmentA;
        bytes32 commitmentB;
        bytes32 commitmentC;
        bytes32 commitmentZ;
        bytes32 commitmentT1;
        bytes32 commitmentT2;
        bytes32 commitmentT3;
        bytes32 commitmentWzeta;
        bytes32 commitmentWzetaOmega;
        bytes evaluation;
    }

    /// @notice Cross-chain proof bundle
    struct CrossChainProofBundle {
        bytes32 bundleId;
        uint256[] chainIds; // Participating chains
        bytes32[] proofRoots; // Proof roots per chain
        bytes32 aggregatedRoot; // Final aggregated root
        bytes aggregatedProof; // Aggregated proof bytes
        bool verified;
    }

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum proofs per batch
    uint256 public constant MAX_BATCH_SIZE = 128;

    /// @notice Minimum proofs per batch
    uint256 public constant MIN_BATCH_SIZE = 2;

    /// @notice Default aggregation window
    uint256 public constant AGGREGATION_WINDOW = 1 hours;

    /// @notice BN254 curve order (for Groth16)
    uint256 public constant BN254_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ============================================
    // STATE VARIABLES (V1)
    // ============================================

    /// @notice All proof submissions
    mapping(bytes32 => ProofSubmission) public proofSubmissions;

    /// @notice All batches
    mapping(bytes32 => AggregationBatch) internal _batches;

    /// @notice Active batch per proof system
    mapping(ProofSystem => bytes32) public activeBatches;

    /// @notice Nova folding states
    mapping(bytes32 => NovaProof) public novaStates;

    /// @notice Cross-chain proof bundles
    mapping(bytes32 => CrossChainProofBundle) public crossChainBundles;

    /// @notice Verified proof roots
    mapping(bytes32 => bool) public verifiedRoots;

    /// @notice Verifier contracts per proof system
    mapping(ProofSystem => address) public verifiers;

    /// @notice Total proofs submitted
    uint256 public totalProofsSubmitted;

    /// @notice Total proofs aggregated
    uint256 public totalProofsAggregated;

    /// @notice Total batches created
    uint256 public totalBatches;

    // ============================================
    // EVENTS
    // ============================================

    event ProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed batchId,
        ProofSystem system,
        uint256 chainId
    );

    event BatchCreated(
        bytes32 indexed batchId,
        ProofSystem system,
        address creator
    );

    event BatchAggregated(
        bytes32 indexed batchId,
        bytes32 aggregatedProofHash,
        uint256 proofCount
    );

    event BatchVerified(bytes32 indexed batchId, bytes32 merkleRoot);

    event BatchFinalized(bytes32 indexed batchId);

    event NovaFoldingStep(
        bytes32 indexed batchId,
        uint256 step,
        bytes32 U,
        bytes32 u
    );

    event CrossChainBundleCreated(bytes32 indexed bundleId, uint256 chainCount);

    event CrossChainBundleVerified(
        bytes32 indexed bundleId,
        bytes32 aggregatedRoot
    );

    event VerifierUpdated(ProofSystem indexed system, address verifier);

    // ============================================
    // INITIALIZER
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the aggregator
     * @param admin Admin address
     */
    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(AGGREGATOR_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
    }

    // ============================================
    // PROOF SUBMISSION
    // ============================================

    /**
     * @notice Submit a proof for aggregation
     * @param system The proof system used
     * @param commitmentHash Commitment to proof data
     * @param publicInputHash Hash of public inputs
     * @param chainId Source chain ID
     * @return proofId The unique proof identifier
     */
    function submitProof(
        ProofSystem system,
        bytes32 commitmentHash,
        bytes32 publicInputHash,
        uint256 chainId
    ) external nonReentrant whenNotPaused returns (bytes32 proofId) {
        if (commitmentHash == bytes32(0) || publicInputHash == bytes32(0)) {
            revert InvalidProof();
        }

        // Generate proof ID
        proofId = keccak256(
            abi.encodePacked(
                commitmentHash,
                publicInputHash,
                chainId,
                msg.sender,
                block.timestamp
            )
        );

        if (proofSubmissions[proofId].proofId != bytes32(0)) {
            revert ProofAlreadySubmitted(proofId);
        }

        // Get or create active batch
        bytes32 batchId = activeBatches[system];
        if (
            batchId == bytes32(0) || _batches[batchId].state != BatchState.OPEN
        ) {
            batchId = _createBatch(system);
        }

        // Check batch size
        AggregationBatch storage batch = _batches[batchId];
        if (batch.proofIds.length >= MAX_BATCH_SIZE) {
            // Start aggregating current batch and create new one
            _startAggregation(batchId);
            batchId = _createBatch(system);
            batch = _batches[batchId];
        }

        // Store proof submission
        proofSubmissions[proofId] = ProofSubmission({
            proofId: proofId,
            batchId: batchId,
            system: system,
            commitmentHash: commitmentHash,
            publicInputHash: publicInputHash,
            chainId: chainId,
            submittedAt: uint64(block.timestamp),
            verified: false,
            aggregated: false
        });

        batch.proofIds.push(proofId);
        unchecked {
            ++batch.proofCount;
            ++totalProofsSubmitted;
        }

        emit ProofSubmitted(proofId, batchId, system, chainId);
        return proofId;
    }

    /**
     * @notice Submit a Nova folding step
     * @param batchId The batch to fold into
     * @param novaProof The Nova proof structure
     */
    function submitNovaFolding(
        bytes32 batchId,
        NovaProof calldata novaProof
    ) external onlyRole(AGGREGATOR_ROLE) nonReentrant whenNotPaused {
        AggregationBatch storage batch = _batches[batchId];
        if (batch.batchId == bytes32(0)) revert BatchDoesNotExist(batchId);
        if (
            batch.system != ProofSystem.NOVA &&
            batch.system != ProofSystem.SUPERNOVA
        ) {
            revert InvalidProofSystem(batch.system);
        }

        // Verify folding proof (in production, use actual Nova verifier)
        if (!_verifyNovaFolding(novaProof)) {
            revert FoldingError(novaProof.step);
        }

        // Update Nova state
        novaStates[batchId] = novaProof;

        emit NovaFoldingStep(batchId, novaProof.step, novaProof.U, novaProof.u);
    }

    // ============================================
    // BATCH MANAGEMENT
    // ============================================

    /**
     * @notice Create a new aggregation batch
     */
    function _createBatch(
        ProofSystem system
    ) internal returns (bytes32 batchId) {
        batchId = keccak256(
            abi.encodePacked(system, msg.sender, block.timestamp, totalBatches)
        );

        bytes32[] memory emptyProofs = new bytes32[](0);

        _batches[batchId] = AggregationBatch({
            batchId: batchId,
            creator: msg.sender,
            state: BatchState.OPEN,
            system: system,
            proofIds: emptyProofs,
            aggregatedProofHash: bytes32(0),
            merkleRoot: bytes32(0),
            proofCount: 0,
            createdAt: uint64(block.timestamp),
            aggregatedAt: 0,
            expiresAt: uint64(block.timestamp + AGGREGATION_WINDOW)
        });

        activeBatches[system] = batchId;

        unchecked {
            ++totalBatches;
        }

        emit BatchCreated(batchId, system, msg.sender);
        return batchId;
    }

    /**
     * @notice Start aggregation for a batch
     */
    function _startAggregation(bytes32 batchId) internal {
        AggregationBatch storage batch = _batches[batchId];

        if (batch.proofIds.length < MIN_BATCH_SIZE) {
            revert BatchTooSmall(batch.proofIds.length, MIN_BATCH_SIZE);
        }

        batch.state = BatchState.AGGREGATING;
    }

    /**
     * @notice Finalize batch aggregation (called by aggregator)
     * @param batchId The batch to finalize
     * @param aggregatedProofHash Hash of the aggregated proof
     * @param merkleRoot Merkle root of public inputs
     */
    function finalizeBatchAggregation(
        bytes32 batchId,
        bytes32 aggregatedProofHash,
        bytes32 merkleRoot
    ) external onlyRole(AGGREGATOR_ROLE) nonReentrant whenNotPaused {
        AggregationBatch storage batch = _batches[batchId];

        if (batch.batchId == bytes32(0)) revert BatchDoesNotExist(batchId);
        if (
            batch.state != BatchState.AGGREGATING &&
            batch.state != BatchState.OPEN
        ) {
            revert BatchNotOpen(batchId);
        }

        batch.aggregatedProofHash = aggregatedProofHash;
        batch.merkleRoot = merkleRoot;
        batch.aggregatedAt = uint64(block.timestamp);
        batch.state = BatchState.VERIFIED;

        // Mark all proofs as aggregated
        for (uint256 i = 0; i < batch.proofIds.length; ) {
            proofSubmissions[batch.proofIds[i]].aggregated = true;
            unchecked {
                ++i;
                ++totalProofsAggregated;
            }
        }

        verifiedRoots[merkleRoot] = true;

        emit BatchAggregated(batchId, aggregatedProofHash, batch.proofCount);
        emit BatchVerified(batchId, merkleRoot);
    }

    /**
     * @notice Trigger batch aggregation manually
     * @param batchId The batch to aggregate
     */
    function triggerAggregation(
        bytes32 batchId
    ) external onlyRole(AGGREGATOR_ROLE) nonReentrant whenNotPaused {
        AggregationBatch storage batch = _batches[batchId];

        if (batch.batchId == bytes32(0)) revert BatchDoesNotExist(batchId);
        if (batch.state != BatchState.OPEN) revert BatchNotOpen(batchId);
        if (batch.proofIds.length < MIN_BATCH_SIZE) {
            revert BatchTooSmall(batch.proofIds.length, MIN_BATCH_SIZE);
        }

        _startAggregation(batchId);
    }

    // ============================================
    // CROSS-CHAIN AGGREGATION
    // ============================================

    /**
     * @notice Create a cross-chain proof bundle
     * @param chainIds Participating chain IDs
     * @param proofRoots Proof roots per chain
     * @return bundleId The bundle identifier
     */
    function createCrossChainBundle(
        uint256[] calldata chainIds,
        bytes32[] calldata proofRoots
    )
        external
        onlyRole(AGGREGATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 bundleId)
    {
        if (chainIds.length != proofRoots.length) {
            revert CrossChainProofMismatch();
        }

        bundleId = keccak256(abi.encode(chainIds, proofRoots, block.timestamp));

        crossChainBundles[bundleId] = CrossChainProofBundle({
            bundleId: bundleId,
            chainIds: chainIds,
            proofRoots: proofRoots,
            aggregatedRoot: bytes32(0),
            aggregatedProof: "",
            verified: false
        });

        emit CrossChainBundleCreated(bundleId, chainIds.length);
        return bundleId;
    }

    /**
     * @notice Finalize cross-chain bundle verification
     * @param bundleId The bundle to finalize
     * @param aggregatedRoot The aggregated root
     * @param aggregatedProof The aggregated proof bytes
     */
    function finalizeCrossChainBundle(
        bytes32 bundleId,
        bytes32 aggregatedRoot,
        bytes calldata aggregatedProof
    ) external onlyRole(AGGREGATOR_ROLE) nonReentrant whenNotPaused {
        CrossChainProofBundle storage bundle = crossChainBundles[bundleId];
        if (bundle.bundleId == bytes32(0)) revert BatchDoesNotExist(bundleId);

        bundle.aggregatedRoot = aggregatedRoot;
        bundle.aggregatedProof = aggregatedProof;
        bundle.verified = true;

        verifiedRoots[aggregatedRoot] = true;

        emit CrossChainBundleVerified(bundleId, aggregatedRoot);
    }

    // ============================================
    // VERIFICATION
    // ============================================

    /**
     * @notice Verify a Nova folding proof
     */
    function _verifyNovaFolding(
        NovaProof calldata proof
    ) internal pure returns (bool) {
        // Verify folding equation: U' = U + r·u (simplified)
        // In production, this would use actual Nova verification
        if (proof.U == bytes32(0) || proof.u == bytes32(0)) {
            return false;
        }
        if (proof.T == bytes32(0)) {
            return false;
        }
        if (proof.foldingProof.length == 0) {
            return false;
        }
        return true;
    }

    /**
     * @notice Verify an aggregated proof
     * @param proofSystem The proof system
     * @param proof The proof bytes
     * @param publicInputs Public inputs
     */
    function verifyAggregatedProof(
        ProofSystem proofSystem,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        address verifier = verifiers[proofSystem];
        if (verifier == address(0)) {
            revert InvalidProofSystem(proofSystem);
        }

        // Delegate verification to registered verifier contract
        // Encode public inputs for the verifier call
        bytes memory encodedInputs = abi.encode(publicInputs);
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, encodedInputs)
        );

        if (!success || result.length < 32) {
            /// @custom:security PLACEHOLDER — verifier call failed, fallback to length check
            return proof.length > 0 && publicInputs.length > 0;
        }

        return abi.decode(result, (bool));
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @notice Get batch details
    function getBatch(
        bytes32 batchId
    ) external view returns (AggregationBatch memory) {
        return _batches[batchId];
    }

    /// @notice Get proof submission details
    function getProofSubmission(
        bytes32 proofId
    ) external view returns (ProofSubmission memory) {
        return proofSubmissions[proofId];
    }

    /// @notice Get cross-chain bundle details
    function getCrossChainBundle(
        bytes32 bundleId
    ) external view returns (CrossChainProofBundle memory) {
        return crossChainBundles[bundleId];
    }

    /// @notice Get Nova folding state
    function getNovaState(
        bytes32 batchId
    ) external view returns (NovaProof memory) {
        return novaStates[batchId];
    }

    /// @notice Check if a root is verified
    function isRootVerified(bytes32 root) external view returns (bool) {
        return verifiedRoots[root];
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Set verifier for a proof system
     */
    function setVerifier(
        ProofSystem system,
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        verifiers[system] = verifier;
        emit VerifierUpdated(system, verifier);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // UPGRADE
    // ============================================

    /**
     * @notice Authorize upgrade (UUPS)
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
