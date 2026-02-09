// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title UnifiedNullifierManager
 * @author Soul Protocol
 * @notice Unified nullifier registry for cross-domain double-spend prevention
 * @dev Implements Cross-Domain Nullifier Algebra (CDNA) for multi-chain privacy
 *
 * CROSS-DOMAIN NULLIFIER ALGEBRA:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Nullifier Domain Separation                           │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  Chain-Specific Nullifier:                                              │
 * │  nf_chain = H(secret || commitment || chainId || "CHAIN_NULLIFIER")     │
 * │                                                                          │
 * │  Cross-Domain Nullifier (for bridging):                                 │
 * │  nf_cross = H(nf_source || sourceChain || destChain || "CROSS_DOMAIN")  │
 * │                                                                          │
 * │  Soul Binding:                                                           │
 * │  nf_soul = H(nf_source || domain || "Soul_BINDING")                      │
 * │                                                                          │
 * │  Properties:                                                            │
 * │  1. Uniqueness: Same note → same nullifier (per domain)                 │
 * │  2. Binding: Nullifier commits to specific note                         │
 * │  3. Unlinkability: Different domains → unlinkable nullifiers            │
 * │  4. Soundness: Cannot create valid nullifier without secret             │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED CHAINS:
 * - Privacy: Zcash, Monero, Secret, Oasis, Railgun, Tornado
 * - L2: Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM
 * - L1: Ethereum, Solana, Aptos, Sui, Celestia
 * - Enterprise: Canton, Provenance, Hyperledger
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract UnifiedNullifierManager is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES - Pre-computed hashes save ~200 gas per access
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant BRIDGE_ROLE =
        0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;
    bytes32 public constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;

    // =========================================================================
    // CONSTANTS - Pre-computed hashes for gas efficiency
    // =========================================================================

    /// @notice Domain separator for nullifier derivation
    /// @dev keccak256("Soul_UNIFIED_NULLIFIER_V1")
    bytes32 public constant NULLIFIER_DOMAIN =
        0x4e34b80f71d0c7dd46ffae77756be54f9e303fc51e2f7be5fff8e7a2bf349f32;

    /// @notice Cross-domain separator
    /// @dev keccak256("CROSS_DOMAIN")
    bytes32 public constant CROSS_DOMAIN_TAG =
        0xf6f08d2d647836449ce6c7faec104604bd003520989d06a862b6d31058c3d5ed;

    /// @notice Soul binding tag
    /// @dev keccak256("Soul_BINDING")
    bytes32 public constant SOUL_BINDING_TAG =
        0x656e8f2a48d70e58b878efa25a14fb177d2f624851d2d47f5979db5e4953df92;

    /// @notice Chain-specific tags
    bytes32 public constant ZCASH_TAG = keccak256("ZCASH");
    bytes32 public constant MONERO_TAG = keccak256("MONERO");
    bytes32 public constant SECRET_TAG = keccak256("SECRET");
    bytes32 public constant OASIS_TAG = keccak256("OASIS");
    bytes32 public constant RAILGUN_TAG = keccak256("RAILGUN");
    bytes32 public constant TORNADO_TAG = keccak256("TORNADO");
    bytes32 public constant MIDNIGHT_TAG = keccak256("MIDNIGHT");

    /// @notice Nullifier expiry (optional, for light clients)
    uint256 public constant NULLIFIER_EXPIRY = 365 days;

    /// @notice Maximum nullifiers per batch
    uint256 public constant MAX_BATCH_SIZE = 100;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum NullifierType {
        STANDARD, // Single-domain nullifier
        CROSS_DOMAIN, // Cross-chain nullifier
        TIME_BOUND, // Expiring nullifier
        BATCH, // Batch commitment
        RECURSIVE // Recursive proof nullifier
    }

    enum ChainType {
        EVM, // Ethereum, Polygon, etc.
        UTXO, // Bitcoin, Zcash
        ACCOUNT, // Solana, Aptos
        PRIVACY, // Monero, Secret
        COSMOS, // IBC chains
        ENTERPRISE // Canton, Hyperledger
    }

    enum NullifierStatus {
        UNKNOWN,
        REGISTERED,
        SPENT,
        REVOKED,
        EXPIRED
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Unified nullifier record
     */
    struct NullifierRecord {
        bytes32 nullifier; // The nullifier hash
        bytes32 commitment; // Associated commitment
        NullifierType nullifierType;
        NullifierStatus status;
        uint256 chainId; // Source chain
        ChainType chainType;
        bytes32 domainTag; // Chain-specific tag
        uint256 timestamp;
        uint256 expiresAt; // 0 = never expires
    }

    /**
     * @notice Cross-domain nullifier binding
     */
    struct CrossDomainBinding {
        bytes32 sourceNullifier;
        bytes32 destNullifier;
        bytes32 soulBinding; // Unified Soul binding
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 sourceDomain;
        bytes32 destDomain;
        bytes derivationProof;
        uint256 timestamp;
        bool verified;
    }

    /**
     * @notice Chain domain configuration
     */
    struct ChainDomain {
        uint256 chainId;
        ChainType chainType;
        bytes32 domainTag;
        bytes32 nullifierPrefix;
        address bridgeAdapter;
        bool isActive;
        uint256 registeredAt;
    }

    /**
     * @notice Batch nullifier submission
     */
    struct NullifierBatch {
        bytes32 batchId;
        bytes32[] nullifiers;
        bytes32 merkleRoot;
        uint256 chainId;
        uint256 timestamp;
        bool processed;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice All nullifier records: nullifier => record
    mapping(bytes32 => NullifierRecord) public nullifierRecords;

    /// @notice Cross-domain bindings: binding ID => binding
    mapping(bytes32 => CrossDomainBinding) public crossDomainBindings;

    /// @notice Chain domains: chainId => domain
    mapping(uint256 => ChainDomain) public chainDomains;

    /// @notice Cross-chain verifier adapter
    address public crossChainVerifier;

    /// @notice Soul unified bindings: source nullifier => Soul binding
    mapping(bytes32 => bytes32) public soulBindings;

    /// @notice Reverse lookup: Soul binding => source nullifiers
    mapping(bytes32 => bytes32[]) public reverseSoulLookup;

    /// @notice Nullifier batches: batchId => batch
    mapping(bytes32 => NullifierBatch) public nullifierBatches;

    /// @notice Merkle roots for batch verification
    mapping(bytes32 => bool) public validMerkleRoots;

    /// @notice Registered chain IDs
    uint256[] public registeredChains;

    /// @notice Total nullifiers registered
    uint256 public totalNullifiers;

    /// @notice Total cross-domain bindings
    uint256 public totalBindings;

    /// @notice Total batches processed
    uint256 public totalBatches;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed commitment,
        uint256 chainId,
        NullifierType nullifierType
    );

    event NullifierSpent(
        bytes32 indexed nullifier,
        uint256 chainId,
        uint256 timestamp
    );

    event CrossDomainBindingCreated(
        bytes32 indexed sourceNullifier,
        bytes32 indexed destNullifier,
        bytes32 indexed soulBinding,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event ChainDomainRegistered(
        uint256 indexed chainId,
        ChainType chainType,
        bytes32 domainTag
    );

    event BatchProcessed(
        bytes32 indexed batchId,
        uint256 nullifierCount,
        bytes32 merkleRoot
    );

    event SoulNullifierDerived(
        bytes32 indexed sourceNullifier,
        bytes32 indexed soulBinding,
        bytes32 domain
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error NullifierAlreadyExists();
    error NullifierNotFound();
    error NullifierAlreadySpent();
    error NullifierExpired();
    error InvalidChainDomain();
    error ChainDomainNotRegistered();
    error InvalidBatchSize();
    error BatchAlreadyProcessed();
    error InvalidProof();
    error UnauthorizedBridge();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(BRIDGE_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Register default chains
        _registerDefaultChains();
    }

    // =========================================================================
    // CHAIN DOMAIN MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new chain domain in the Cross-Domain Nullifier Algebra (CDNA) system
     * @dev Creates a domain-separated nullifier prefix using keccak256(NULLIFIER_DOMAIN, chainId, domainTag).
     *      Each chain needs a unique domain tag to prevent nullifier collisions across chains.
     * @param chainId The EVM chain ID or custom ID for non-EVM chains (e.g., 900001 for Monero)
     * @param chainType The chain classification (EVM, UTXO, PRIVACY, etc.)
     * @param domainTag A unique identifier tag for this chain's nullifier domain
     * @param bridgeAdapter The bridge adapter contract address for this chain (address(0) if none)
     */
    function registerChainDomain(
        uint256 chainId,
        ChainType chainType,
        bytes32 domainTag,
        address bridgeAdapter
    ) external onlyRole(OPERATOR_ROLE) {
        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        bytes32 nullifierPrefix = keccak256(
            abi.encode(NULLIFIER_DOMAIN, chainId, domainTag)
        );

        chainDomains[chainId] = ChainDomain({
            chainId: chainId,
            chainType: chainType,
            domainTag: domainTag,
            nullifierPrefix: nullifierPrefix,
            bridgeAdapter: bridgeAdapter,
            isActive: true,
            registeredAt: block.timestamp
        });

        registeredChains.push(chainId);

        emit ChainDomainRegistered(chainId, chainType, domainTag);
    }

    /**
     * @notice Set the cross-chain proof verifier adapter used for derivation proof validation
     * @dev Only callable by DEFAULT_ADMIN_ROLE. Reverts on zero address.
     * @param _verifier The address of the cross-chain verifier contract
     */
    function setCrossChainVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        crossChainVerifier = _verifier;
    }

    /**
     * @notice Register default supported chains
     */
    function _registerDefaultChains() internal {
        // Privacy chains
        _quickRegister(1, ChainType.EVM, RAILGUN_TAG); // Ethereum (Railgun)
        _quickRegister(56, ChainType.EVM, TORNADO_TAG); // BSC (Tornado)
        _quickRegister(137, ChainType.EVM, RAILGUN_TAG); // Polygon (Railgun)

        // L2s
        _quickRegister(42161, ChainType.EVM, keccak256("ARBITRUM"));
        _quickRegister(10, ChainType.EVM, keccak256("OPTIMISM"));
        _quickRegister(8453, ChainType.EVM, keccak256("BASE"));
        _quickRegister(324, ChainType.EVM, keccak256("ZKSYNC"));
        _quickRegister(534352, ChainType.EVM, keccak256("SCROLL"));
        _quickRegister(59144, ChainType.EVM, keccak256("LINEA"));

        // Alt L1s
        _quickRegister(900001, ChainType.PRIVACY, MONERO_TAG); // Monero (custom ID)
        _quickRegister(900002, ChainType.UTXO, ZCASH_TAG); // Zcash
        _quickRegister(900003, ChainType.PRIVACY, SECRET_TAG); // Secret Network
        _quickRegister(23294, ChainType.PRIVACY, OASIS_TAG); // Oasis Sapphire
    }

    function _quickRegister(
        uint256 chainId,
        ChainType chainType,
        bytes32 domainTag
    ) internal {
        chainDomains[chainId] = ChainDomain({
            chainId: chainId,
            chainType: chainType,
            domainTag: domainTag,
            // SECURITY FIX: Changed from abi.encodePacked to abi.encode
            nullifierPrefix: keccak256(
                abi.encode(NULLIFIER_DOMAIN, chainId, domainTag)
            ),
            bridgeAdapter: address(0),
            isActive: true,
            registeredAt: block.timestamp
        });
        registeredChains.push(chainId);
    }

    // =========================================================================
    // NULLIFIER REGISTRATION
    // =========================================================================

    /**
     * @notice Register a new nullifier with its commitment and derive a soul binding
     * @dev Creates a NullifierRecord, derives a unified soul binding via CDNA,
     *      and stores the reverse lookup. Only callable by BRIDGE_ROLE.
     *      The soul binding links nullifiers across chains to the same identity.
     * @param nullifier The unique nullifier hash (must not already exist)
     * @param commitment The Pedersen commitment associated with this nullifier
     * @param chainId The chain where this nullifier originates (must be registered)
     * @param nullifierType The classification of this nullifier (UTXO, NOTE, ACCOUNT, etc.)
     * @param expiresAt Unix timestamp when this nullifier expires (0 for no expiry)
     * @return soulBinding The derived cross-chain soul binding hash
     */
    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 chainId,
        NullifierType nullifierType,
        uint256 expiresAt
    ) external onlyRole(BRIDGE_ROLE) returns (bytes32 soulBinding) {
        if (nullifierRecords[nullifier].status != NullifierStatus.UNKNOWN) {
            revert NullifierAlreadyExists();
        }

        ChainDomain storage domain = chainDomains[chainId];
        if (!domain.isActive) revert ChainDomainNotRegistered();

        nullifierRecords[nullifier] = NullifierRecord({
            nullifier: nullifier,
            commitment: commitment,
            nullifierType: nullifierType,
            status: NullifierStatus.REGISTERED,
            chainId: chainId,
            chainType: domain.chainType,
            domainTag: domain.domainTag,
            timestamp: block.timestamp,
            expiresAt: expiresAt
        });

        // Derive Soul unified nullifier
        soulBinding = deriveSoulBinding(nullifier, domain.domainTag);
        soulBindings[nullifier] = soulBinding;
        reverseSoulLookup[soulBinding].push(nullifier);

        unchecked {
            ++totalNullifiers;
        }

        emit NullifierRegistered(nullifier, commitment, chainId, nullifierType);
        emit SoulNullifierDerived(nullifier, soulBinding, domain.domainTag);

        return soulBinding;
    }

    /**
     * @notice Mark nullifier as spent
     */
    function spendNullifier(bytes32 nullifier) external onlyRole(BRIDGE_ROLE) {
        NullifierRecord storage record = nullifierRecords[nullifier];

        if (record.status == NullifierStatus.UNKNOWN)
            revert NullifierNotFound();
        if (record.status == NullifierStatus.SPENT)
            revert NullifierAlreadySpent();
        if (record.expiresAt > 0 && block.timestamp > record.expiresAt) {
            revert NullifierExpired();
        }

        record.status = NullifierStatus.SPENT;

        emit NullifierSpent(nullifier, record.chainId, block.timestamp);
    }

    /**
     * @notice Check if nullifier is spent
     */
    function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        return nullifierRecords[nullifier].status == NullifierStatus.SPENT;
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER BINDING
    // =========================================================================

    /**
     * @notice Create a cross-domain nullifier binding between two chains
     * @dev Verifies a derivation proof, derives a destination nullifier using abi.encode
     *      (not abi.encodePacked to prevent hash collision attacks), and creates a
     *      CrossDomainBinding record linking source and destination nullifiers.
     * @param sourceNullifier The nullifier on the source chain (must be registered)
     * @param sourceChainId The chain ID where the source nullifier exists
     * @param destChainId The target chain ID for the binding
     * @param derivationProof ZK proof validating the cross-domain derivation
     * @return destNullifier The derived nullifier on the destination chain
     * @return soulBinding The unified soul binding hash linking both nullifiers
     */
    function createCrossDomainBinding(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId,
        bytes calldata derivationProof
    )
        external
        onlyRole(BRIDGE_ROLE)
        returns (bytes32 destNullifier, bytes32 soulBinding)
    {
        NullifierRecord storage sourceRecord = nullifierRecords[
            sourceNullifier
        ];
        if (sourceRecord.status == NullifierStatus.UNKNOWN)
            revert NullifierNotFound();

        ChainDomain storage sourceDomain = chainDomains[sourceChainId];
        ChainDomain storage destDomain = chainDomains[destChainId];
        if (!sourceDomain.isActive || !destDomain.isActive) {
            revert ChainDomainNotRegistered();
        }

        // Verify derivation proof
        if (
            !_verifyDerivationProof(
                sourceNullifier,
                destChainId,
                derivationProof
            )
        ) {
            revert InvalidProof();
        }

        // SECURITY FIX: Changed from abi.encodePacked to abi.encode to prevent hash collision
        destNullifier = keccak256(
            abi.encode(
                sourceNullifier,
                sourceChainId,
                destChainId,
                CROSS_DOMAIN_TAG
            )
        );

        // Derive unified Soul nullifier
        soulBinding = deriveSoulBinding(
            sourceNullifier,
            sourceDomain.domainTag
        );

        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        bytes32 bindingId = keccak256(
            abi.encode(sourceNullifier, destNullifier)
        );

        crossDomainBindings[bindingId] = CrossDomainBinding({
            sourceNullifier: sourceNullifier,
            destNullifier: destNullifier,
            soulBinding: soulBinding,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            sourceDomain: sourceDomain.domainTag,
            destDomain: destDomain.domainTag,
            derivationProof: derivationProof,
            timestamp: block.timestamp,
            verified: true
        });

        // Update lookups
        soulBindings[sourceNullifier] = soulBinding;
        soulBindings[destNullifier] = soulBinding;
        reverseSoulLookup[soulBinding].push(sourceNullifier);
        reverseSoulLookup[soulBinding].push(destNullifier);

        unchecked {
            ++totalBindings;
        }

        emit CrossDomainBindingCreated(
            sourceNullifier,
            destNullifier,
            soulBinding,
            sourceChainId,
            destChainId
        );

        return (destNullifier, soulBinding);
    }

    /**
     * @notice Verify cross-domain binding exists
     */
    function verifyCrossDomainBinding(
        bytes32 sourceNullifier,
        bytes32 destNullifier
    ) external view returns (bool valid, bytes32 soulBinding) {
        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        bytes32 bindingId = keccak256(
            abi.encode(sourceNullifier, destNullifier)
        );

        CrossDomainBinding storage binding = crossDomainBindings[bindingId];

        return (binding.verified, binding.soulBinding);
    }

    // =========================================================================
    // BATCH OPERATIONS
    // =========================================================================

    /**
     * @notice Process batch of nullifiers
     */
    function processBatch(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        uint256 chainId,
        bytes32 merkleRoot
    ) external onlyRole(BRIDGE_ROLE) returns (bytes32 batchId) {
        if (nullifiers.length == 0 || nullifiers.length > MAX_BATCH_SIZE) {
            revert InvalidBatchSize();
        }
        if (nullifiers.length != commitments.length) revert InvalidBatchSize();

        // SECURITY FIX: Changed from abi.encodePacked to abi.encode to prevent hash collision
        batchId = keccak256(
            abi.encode(merkleRoot, chainId, block.timestamp, totalBatches)
        );

        ChainDomain storage domain = chainDomains[chainId];
        if (!domain.isActive) revert ChainDomainNotRegistered();

        // Register all nullifiers
        for (uint256 i = 0; i < nullifiers.length; ) {
            if (
                nullifierRecords[nullifiers[i]].status ==
                NullifierStatus.UNKNOWN
            ) {
                nullifierRecords[nullifiers[i]] = NullifierRecord({
                    nullifier: nullifiers[i],
                    commitment: commitments[i],
                    nullifierType: NullifierType.BATCH,
                    status: NullifierStatus.REGISTERED,
                    chainId: chainId,
                    chainType: domain.chainType,
                    domainTag: domain.domainTag,
                    timestamp: block.timestamp,
                    expiresAt: 0
                });

                bytes32 soulBinding = deriveSoulBinding(
                    nullifiers[i],
                    domain.domainTag
                );
                soulBindings[nullifiers[i]] = soulBinding;

                unchecked {
                    ++totalNullifiers;
                }
            }
            unchecked {
                ++i;
            }
        }

        nullifierBatches[batchId] = NullifierBatch({
            batchId: batchId,
            nullifiers: nullifiers,
            merkleRoot: merkleRoot,
            chainId: chainId,
            timestamp: block.timestamp,
            processed: true
        });

        validMerkleRoots[merkleRoot] = true;
        unchecked {
            ++totalBatches;
        }

        emit BatchProcessed(batchId, nullifiers.length, merkleRoot);

        return batchId;
    }

    // =========================================================================
    // DERIVATION FUNCTIONS
    // =========================================================================

    /**
     * @notice Derive Soul unified nullifier
     * @dev HIGH FIX: Changed from abi.encodePacked to abi.encode to prevent hash collision
     *      abi.encodePacked with multiple bytes32 can have collisions if bits align
     */
    function deriveSoulBinding(
        bytes32 sourceNullifier,
        bytes32 domainTag
    ) public pure returns (bytes32) {
        return
            keccak256(abi.encode(sourceNullifier, domainTag, SOUL_BINDING_TAG));
    }

    /**
     * @notice Derive chain-specific nullifier from commitment
     */
    function deriveChainNullifier(
        bytes32 commitment,
        bytes32 secret,
        uint256 chainId
    ) external view returns (bytes32) {
        ChainDomain storage domain = chainDomains[chainId];
        if (!domain.isActive) revert ChainDomainNotRegistered();

        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        return
            keccak256(
                abi.encode(
                    secret,
                    commitment,
                    chainId,
                    domain.domainTag,
                    "CHAIN_NULLIFIER"
                )
            );
    }

    /**
     * @notice Derive cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    ) external pure returns (bytes32) {
        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        return
            keccak256(
                abi.encode(
                    sourceNullifier,
                    sourceChainId,
                    destChainId,
                    CROSS_DOMAIN_TAG
                )
            );
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _verifyDerivationProof(
        bytes32 sourceNullifier,
        uint256 destChainId,
        bytes calldata proof
    ) internal view returns (bool) {
        // CRITICAL FIX: Previously accepted any non-empty proof when verifier not set
        // This allowed attackers to create arbitrary cross-domain bindings
        if (crossChainVerifier == address(0)) {
            // In production, verifier MUST be set - revert if not
            // For testing only: can be bypassed by setting a mock verifier
            revert("CrossChainVerifier not configured");
        }

        // Verify ZK proof using the configured verifier
        // Proof must demonstrate valid derivation from source to dest chain
        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(sourceNullifier);
        publicInputs[1] = destChainId;
        publicInputs[2] = uint256(
            keccak256(abi.encode(sourceNullifier, destChainId))
        );

        return IProofVerifier(crossChainVerifier).verify(proof, publicInputs);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getNullifierRecord(
        bytes32 nullifier
    ) external view returns (NullifierRecord memory) {
        return nullifierRecords[nullifier];
    }

    function getCrossDomainBinding(
        bytes32 sourceNullifier,
        bytes32 destNullifier
    ) external view returns (CrossDomainBinding memory) {
        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        bytes32 bindingId = keccak256(
            abi.encode(sourceNullifier, destNullifier)
        );
        return crossDomainBindings[bindingId];
    }

    function getChainDomain(
        uint256 chainId
    ) external view returns (ChainDomain memory) {
        return chainDomains[chainId];
    }

    function getSoulBinding(
        bytes32 sourceNullifier
    ) external view returns (bytes32) {
        return soulBindings[sourceNullifier];
    }

    /// @notice Gets all source nullifiers for a soul binding
    /// @dev WARNING: May run out of gas for bindings with many nullifiers. Use paginated version for large sets.
    function getSourceNullifiers(
        bytes32 soulBinding
    ) external view returns (bytes32[] memory) {
        return reverseSoulLookup[soulBinding];
    }

    /// @notice Gets source nullifiers with pagination
    /// @param soulBinding The soul binding to query
    /// @param offset Starting index
    /// @param limit Maximum number of nullifiers to return
    /// @return nullifiers Array of source nullifiers
    /// @return total Total number of nullifiers for this binding
    /// @dev M-12: Added pagination to prevent out-of-gas for large arrays
    function getSourceNullifiersPaginated(
        bytes32 soulBinding,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory nullifiers, uint256 total) {
        bytes32[] storage allNullifiers = reverseSoulLookup[soulBinding];
        total = allNullifiers.length;

        if (offset >= total) {
            return (new bytes32[](0), total);
        }

        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        nullifiers = new bytes32[](count);

        for (uint256 i = 0; i < count; ) {
            nullifiers[i] = allNullifiers[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    function getBatch(
        bytes32 batchId
    ) external view returns (NullifierBatch memory) {
        return nullifierBatches[batchId];
    }

    function getRegisteredChainCount() external view returns (uint256) {
        return registeredChains.length;
    }

    function getStats()
        external
        view
        returns (
            uint256 _totalNullifiers,
            uint256 _totalBindings,
            uint256 _totalBatches,
            uint256 _registeredChains
        )
    {
        return (
            totalNullifiers,
            totalBindings,
            totalBatches,
            registeredChains.length
        );
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
