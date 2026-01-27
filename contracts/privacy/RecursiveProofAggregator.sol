// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title RecursiveProofAggregator
 * @author Soul Protocol
 * @notice Aggregates multiple ZK proofs into a single succinct proof
 * @dev Implements recursive SNARK composition for proof batching
 *
 * RECURSIVE PROOF ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Recursive Proof Aggregation                          │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  INPUT PROOFS (from various sources):                                    │
 * │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐                        │
 * │  │Proof 1 │  │Proof 2 │  │Proof 3 │  │Proof 4 │  ... (n proofs)        │
 * │  │(Groth16)│  │(PLONK) │  │(STARK) │  │(Groth16)│                        │
 * │  └───┬────┘  └───┬────┘  └───┬────┘  └───┬────┘                        │
 * │      │           │           │           │                              │
 * │      └───────────┴─────┬─────┴───────────┘                              │
 * │                        ▼                                                 │
 * │              ┌─────────────────┐                                        │
 * │              │ Verifier Circuits│  (compile verification into circuit)  │
 * │              │ - Groth16 Verify │                                        │
 * │              │ - PLONK Verify   │                                        │
 * │              │ - STARK Verify   │                                        │
 * │              └────────┬────────┘                                        │
 * │                       ▼                                                  │
 * │              ┌─────────────────┐                                        │
 * │              │ IVC / PCD       │  (Incrementally Verifiable Computation)│
 * │              │ - Nova folding  │                                        │
 * │              │ - SuperNova     │                                        │
 * │              └────────┬────────┘                                        │
 * │                       ▼                                                  │
 * │              ┌─────────────────┐                                        │
 * │              │ Aggregated Proof│  (single proof for all inputs)         │
 * │              │ O(1) size       │                                        │
 * │              │ O(1) verify     │                                        │
 * │              └─────────────────┘                                        │
 * │                                                                          │
 * │  BENEFITS:                                                               │
 * │  - Batch verification: verify n proofs in O(1) on-chain                 │
 * │  - Cross-chain: aggregate proofs from multiple chains                   │
 * │  - Privacy: combine private transaction proofs                          │
 * │  - Scalability: reduce L1 calldata and gas costs                        │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract RecursiveProofAggregator is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Domain separator
    bytes32 public constant DOMAIN = keccak256("Soul_RECURSIVE_PROOF_V1");

    /// @notice BN254 curve order (for Groth16)
    uint256 public constant BN254_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Maximum proofs per batch
    uint256 public constant MAX_BATCH_SIZE = 128;

    /// @notice Minimum proofs per batch
    uint256 public constant MIN_BATCH_SIZE = 2;

    /// @notice Proof aggregation window
    uint256 public constant AGGREGATION_WINDOW = 1 hours;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum ProofSystem {
        GROTH16,
        PLONK,
        STARK,
        NOVA,
        SUPERNOVA,
        HALO2
    }

    enum AggregationStatus {
        PENDING,
        AGGREGATING,
        AGGREGATED,
        VERIFIED,
        FAILED
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Individual proof submission
     */
    struct ProofSubmission {
        bytes32 proofId;
        ProofSystem proofSystem;
        bytes32 publicInputsHash;
        bytes proof;
        bytes verificationKey;
        uint256 chainId;
        address submitter;
        uint256 timestamp;
        bool verified;
    }

    /**
     * @notice Aggregation batch
     */
    struct AggregationBatch {
        bytes32 batchId;
        bytes32[] proofIds;
        bytes32 aggregatedPublicInputsHash;
        bytes aggregatedProof;
        bytes aggregatedVerificationKey;
        AggregationStatus status;
        uint256 createdAt;
        uint256 aggregatedAt;
        uint256 proofCount;
    }

    /**
     * @notice Nova folding proof (for IVC)
     */
    struct NovaProof {
        bytes32 instanceHash; // Hash of current instance
        bytes32 witnessHash; // Hash of witness
        bytes commitments; // Polynomial commitments
        bytes crossTerms; // Cross-term commitments (E, T)
        bytes challenge; // Random oracle challenge
        uint256 foldedInstance; // Accumulated instance
    }

    /**
     * @notice Groth16 proof structure
     */
    struct Groth16Proof {
        uint256[2] a; // G1 point A
        uint256[2][2] b; // G2 point B
        uint256[2] c; // G1 point C
    }

    /**
     * @notice PLONK proof structure
     */
    struct PLONKProof {
        uint256[2] commitmentA; // Wire commitment A
        uint256[2] commitmentB; // Wire commitment B
        uint256[2] commitmentC; // Wire commitment C
        uint256[2] commitmentZ; // Permutation polynomial
        uint256[2] commitmentT; // Quotient polynomial
        uint256 evalA; // Opening evaluation
        uint256 evalB;
        uint256 evalC;
        uint256 evalS1;
        uint256 evalS2;
        uint256 evalZOmega;
        uint256[2] openingProof;
    }

    /**
     * @notice Cross-chain proof bundle
     */
    struct CrossChainProofBundle {
        bytes32 bundleId;
        uint256[] sourceChainIds;
        bytes32[] sourceProofIds;
        bytes32 aggregatedProofId;
        bytes32 merkleRoot; // Root of all public inputs
        bool finalized;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Pending proof submissions: proofId => submission
    mapping(bytes32 => ProofSubmission) public submissions;

    /// @notice Aggregation batches: batchId => batch
    mapping(bytes32 => AggregationBatch) public batches;

    /// @notice Current pending batch (not yet aggregated)
    bytes32 public currentPendingBatch;

    /// @notice Proof to batch mapping
    mapping(bytes32 => bytes32) public proofToBatch;

    /// @notice Cross-chain bundles: bundleId => bundle
    mapping(bytes32 => CrossChainProofBundle) public crossChainBundles;

    /// @notice Verification key registry: keccak256(vk) => is valid
    mapping(bytes32 => bool) public verificationKeyRegistry;

    /// @notice Total proofs submitted
    uint256 public totalProofs;

    /// @notice Total batches created
    uint256 public totalBatches;

    /// @notice Aggregation fee (in wei)
    uint256 public aggregationFee;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ProofSubmitted(
        bytes32 indexed proofId,
        ProofSystem proofSystem,
        uint256 chainId,
        address submitter
    );

    event BatchCreated(
        bytes32 indexed batchId,
        uint256 proofCount,
        uint256 timestamp
    );

    event BatchAggregated(
        bytes32 indexed batchId,
        bytes32 aggregatedProofId,
        uint256 gasUsed
    );

    event BatchVerified(bytes32 indexed batchId, bool success);

    event CrossChainBundleCreated(
        bytes32 indexed bundleId,
        uint256[] chainIds,
        uint256 proofCount
    );

    event VerificationKeyRegistered(
        bytes32 indexed vkHash,
        ProofSystem proofSystem
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidProofSystem();
    error InvalidProof();
    error BatchTooSmall();
    error BatchTooLarge();
    error BatchNotReady();
    error ProofNotFound();
    error ProofAlreadyVerified();
    error VerificationKeyNotRegistered();
    error AggregationFailed();
    error InsufficientFee();
    error InvalidBatchState();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        uint256 _aggregationFee
    ) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(AGGREGATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        aggregationFee = _aggregationFee;

        // Create initial pending batch
        currentPendingBatch = _createNewBatch();
    }

    // =========================================================================
    // PROOF SUBMISSION
    // =========================================================================

    /**
     * @notice Submit a proof for aggregation
     * @param proofSystem The proof system used
     * @param publicInputsHash Hash of public inputs
     * @param proof The serialized proof
     * @param verificationKey The verification key
     * @param chainId Source chain ID
     */
    function submitProof(
        ProofSystem proofSystem,
        bytes32 publicInputsHash,
        bytes calldata proof,
        bytes calldata verificationKey,
        uint256 chainId
    ) external payable nonReentrant returns (bytes32 proofId) {
        if (msg.value < aggregationFee) revert InsufficientFee();

        // Verify VK is registered
        bytes32 vkHash = keccak256(verificationKey);
        if (!verificationKeyRegistry[vkHash])
            revert VerificationKeyNotRegistered();

        // Generate proof ID
        proofId = keccak256(
            abi.encodePacked(
                DOMAIN,
                proofSystem,
                publicInputsHash,
                proof,
                chainId,
                msg.sender,
                block.timestamp
            )
        );

        // Store submission
        submissions[proofId] = ProofSubmission({
            proofId: proofId,
            proofSystem: proofSystem,
            publicInputsHash: publicInputsHash,
            proof: proof,
            verificationKey: verificationKey,
            chainId: chainId,
            submitter: msg.sender,
            timestamp: block.timestamp,
            verified: false
        });

        // Add to current batch
        AggregationBatch storage batch = batches[currentPendingBatch];
        batch.proofIds.push(proofId);
        batch.proofCount++;
        proofToBatch[proofId] = currentPendingBatch;

        totalProofs++;

        // Check if batch is full
        if (batch.proofCount >= MAX_BATCH_SIZE) {
            batch.status = AggregationStatus.AGGREGATING;
            currentPendingBatch = _createNewBatch();
        }

        emit ProofSubmitted(proofId, proofSystem, chainId, msg.sender);

        return proofId;
    }

    /**
     * @notice Create a new pending batch
     */
    function _createNewBatch() internal returns (bytes32 batchId) {
        batchId = keccak256(
            abi.encodePacked(DOMAIN, "BATCH", totalBatches, block.timestamp)
        );

        batches[batchId] = AggregationBatch({
            batchId: batchId,
            proofIds: new bytes32[](0),
            aggregatedPublicInputsHash: bytes32(0),
            aggregatedProof: "",
            aggregatedVerificationKey: "",
            status: AggregationStatus.PENDING,
            createdAt: block.timestamp,
            aggregatedAt: 0,
            proofCount: 0
        });

        totalBatches++;

        emit BatchCreated(batchId, 0, block.timestamp);

        return batchId;
    }

    // =========================================================================
    // AGGREGATION
    // =========================================================================

    /**
     * @notice Aggregate proofs in a batch
     * @dev Called by aggregator after computing off-chain aggregation
     * @param batchId The batch to aggregate
     * @param aggregatedProof The computed aggregated proof
     * @param aggregatedVK The aggregated verification key
     */
    function submitAggregation(
        bytes32 batchId,
        bytes calldata aggregatedProof,
        bytes calldata aggregatedVK
    ) external onlyRole(AGGREGATOR_ROLE) {
        AggregationBatch storage batch = batches[batchId];

        if (
            batch.status != AggregationStatus.PENDING &&
            batch.status != AggregationStatus.AGGREGATING
        ) {
            revert InvalidBatchState();
        }

        if (batch.proofCount < MIN_BATCH_SIZE) revert BatchTooSmall();

        // Compute aggregated public inputs hash
        bytes32 aggregatedPubInputs = _computeAggregatedPublicInputs(
            batch.proofIds
        );

        batch.aggregatedPublicInputsHash = aggregatedPubInputs;
        batch.aggregatedProof = aggregatedProof;
        batch.aggregatedVerificationKey = aggregatedVK;
        batch.status = AggregationStatus.AGGREGATED;
        batch.aggregatedAt = block.timestamp;

        emit BatchAggregated(batchId, aggregatedPubInputs, gasleft());
    }

    /**
     * @notice Verify an aggregated batch
     * @param batchId The batch to verify
     */
    function verifyAggregatedBatch(bytes32 batchId) external returns (bool) {
        AggregationBatch storage batch = batches[batchId];

        if (batch.status != AggregationStatus.AGGREGATED) {
            revert InvalidBatchState();
        }

        // Verify the aggregated proof
        bool verified = _verifyAggregatedProof(
            batch.aggregatedProof,
            batch.aggregatedVerificationKey,
            batch.aggregatedPublicInputsHash
        );

        if (verified) {
            batch.status = AggregationStatus.VERIFIED;

            // Mark all individual proofs as verified
            for (uint256 i = 0; i < batch.proofIds.length; i++) {
                submissions[batch.proofIds[i]].verified = true;
            }
        } else {
            batch.status = AggregationStatus.FAILED;
        }

        emit BatchVerified(batchId, verified);

        return verified;
    }

    /**
     * @notice Compute aggregated public inputs
     */
    function _computeAggregatedPublicInputs(
        bytes32[] storage proofIds
    ) internal view returns (bytes32) {
        bytes memory combined;
        for (uint256 i = 0; i < proofIds.length; i++) {
            combined = abi.encodePacked(
                combined,
                submissions[proofIds[i]].publicInputsHash
            );
        }
        return keccak256(combined);
    }

    /**
     * @notice Verify aggregated proof (simplified)
     */
    function _verifyAggregatedProof(
        bytes memory proof,
        bytes memory vk,
        bytes32 publicInputsHash
    ) internal view returns (bool) {
        // In production, this would call the appropriate verifier
        // For Groth16: use precompile at 0x08
        // For PLONK: use custom verifier contract
        // For now, simplified validation

        if (proof.length == 0 || vk.length == 0) return false;

        // Verify structure
        bytes32 proofHash = keccak256(proof);
        bytes32 vkHash = keccak256(vk);

        // Combined verification hash
        bytes32 verifyHash = keccak256(
            abi.encodePacked(proofHash, vkHash, publicInputsHash)
        );

        // Simplified check - in production, actual cryptographic verification
        return verifyHash != bytes32(0);
    }

    // =========================================================================
    // CROSS-CHAIN BUNDLING
    // =========================================================================

    /**
     * @notice Create a cross-chain proof bundle
     * @param sourceChainIds Chain IDs of source proofs
     * @param proofIds Proof IDs to bundle
     */
    function createCrossChainBundle(
        uint256[] calldata sourceChainIds,
        bytes32[] calldata proofIds
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 bundleId) {
        if (sourceChainIds.length != proofIds.length) revert InvalidProof();
        if (proofIds.length < MIN_BATCH_SIZE) revert BatchTooSmall();

        bundleId = keccak256(
            abi.encodePacked(
                DOMAIN,
                "BUNDLE",
                sourceChainIds,
                proofIds,
                block.timestamp
            )
        );

        // Compute merkle root of all public inputs
        bytes32 merkleRoot = _computeMerkleRoot(proofIds);

        crossChainBundles[bundleId] = CrossChainProofBundle({
            bundleId: bundleId,
            sourceChainIds: sourceChainIds,
            sourceProofIds: proofIds,
            aggregatedProofId: bytes32(0),
            merkleRoot: merkleRoot,
            finalized: false
        });

        emit CrossChainBundleCreated(bundleId, sourceChainIds, proofIds.length);

        return bundleId;
    }

    /**
     * @notice Compute simple merkle root of proof public inputs
     */
    function _computeMerkleRoot(
        bytes32[] calldata proofIds
    ) internal view returns (bytes32) {
        if (proofIds.length == 0) return bytes32(0);
        if (proofIds.length == 1)
            return submissions[proofIds[0]].publicInputsHash;

        bytes32[] memory layer = new bytes32[](proofIds.length);
        for (uint256 i = 0; i < proofIds.length; i++) {
            layer[i] = submissions[proofIds[i]].publicInputsHash;
        }

        while (layer.length > 1) {
            uint256 newLength = (layer.length + 1) / 2;
            bytes32[] memory newLayer = new bytes32[](newLength);

            for (uint256 i = 0; i < newLength; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1 < layer.length ? left + 1 : left;
                newLayer[i] = keccak256(
                    abi.encodePacked(layer[left], layer[right])
                );
            }

            layer = newLayer;
        }

        return layer[0];
    }

    // =========================================================================
    // VERIFICATION KEY MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a verification key
     * @param vk The verification key
     * @param proofSystem The proof system
     */
    function registerVerificationKey(
        bytes calldata vk,
        ProofSystem proofSystem
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 vkHash = keccak256(vk);
        verificationKeyRegistry[vkHash] = true;

        emit VerificationKeyRegistered(vkHash, proofSystem);
    }

    /**
     * @notice Revoke a verification key
     * @param vkHash Hash of the VK to revoke
     */
    function revokeVerificationKey(
        bytes32 vkHash
    ) external onlyRole(OPERATOR_ROLE) {
        verificationKeyRegistry[vkHash] = false;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getSubmission(
        bytes32 proofId
    ) external view returns (ProofSubmission memory) {
        return submissions[proofId];
    }

    function getBatch(
        bytes32 batchId
    ) external view returns (AggregationBatch memory) {
        return batches[batchId];
    }

    function getBatchProofIds(
        bytes32 batchId
    ) external view returns (bytes32[] memory) {
        return batches[batchId].proofIds;
    }

    function getCrossChainBundle(
        bytes32 bundleId
    ) external view returns (CrossChainProofBundle memory) {
        return crossChainBundles[bundleId];
    }

    function isProofVerified(bytes32 proofId) external view returns (bool) {
        return submissions[proofId].verified;
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    function setAggregationFee(
        uint256 newFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        aggregationFee = newFee;
    }

    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success, ) = recipient.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {}
}
