// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IUnifiedNullifierManager
 * @notice Interface for the unified nullifier registry implementing Cross-Domain Nullifier Algebra (CDNA)
 */
interface IUnifiedNullifierManager {
    // =========================================================================
    // ENUMS
    // =========================================================================

    enum NullifierType {
        STANDARD,
        CROSS_DOMAIN,
        TIME_BOUND,
        BATCH,
        RECURSIVE
    }

    enum ChainType {
        EVM,
        UTXO,
        ACCOUNT,
        PRIVACY,
        COSMOS,
        ENTERPRISE
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

    struct NullifierRecord {
        bytes32 nullifier;
        bytes32 commitment;
        NullifierType nullifierType;
        NullifierStatus status;
        uint256 chainId;
        ChainType chainType;
        bytes32 domainTag;
        uint256 timestamp;
        uint256 expiresAt;
    }

    struct CrossDomainBinding {
        bytes32 sourceNullifier;
        bytes32 destNullifier;
        bytes32 soulBinding;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 sourceDomain;
        bytes32 destDomain;
        bytes derivationProof;
        uint256 timestamp;
        bool verified;
    }

    struct ChainDomain {
        uint256 chainId;
        ChainType chainType;
        bytes32 domainTag;
        bytes32 nullifierPrefix;
        address bridgeAdapter;
        bool isActive;
        uint256 registeredAt;
    }

    struct NullifierBatch {
        bytes32 batchId;
        bytes32[] nullifiers;
        bytes32 merkleRoot;
        uint256 chainId;
        uint256 timestamp;
        bool processed;
    }

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
    // CHAIN DOMAIN MANAGEMENT
    // =========================================================================

    function registerChainDomain(
        uint256 chainId,
        ChainType chainType,
        bytes32 domainTag,
        address bridgeAdapter
    ) external;

    function setCrossChainVerifier(address _verifier) external;

    // =========================================================================
    // NULLIFIER REGISTRATION
    // =========================================================================

    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 chainId,
        NullifierType nullifierType,
        uint256 expiresAt
    ) external returns (bytes32 soulBinding);

    function spendNullifier(bytes32 nullifier) external;

    function isNullifierSpent(bytes32 nullifier) external view returns (bool);

    // =========================================================================
    // CROSS-DOMAIN BINDING
    // =========================================================================

    function createCrossDomainBinding(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external returns (bytes32 destNullifier, bytes32 soulBinding);

    function verifyCrossDomainBinding(
        bytes32 sourceNullifier,
        bytes32 destNullifier
    ) external view returns (bool valid, bytes32 soulBinding);

    // =========================================================================
    // BATCH OPERATIONS
    // =========================================================================

    function processBatch(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        uint256 chainId,
        bytes32 merkleRoot
    ) external returns (bytes32 batchId);

    // =========================================================================
    // DERIVATION FUNCTIONS
    // =========================================================================

    function deriveSoulBinding(
        bytes32 sourceNullifier,
        bytes32 domainTag
    ) external pure returns (bytes32);

    function deriveChainNullifier(
        bytes32 commitment,
        bytes32 secret,
        uint256 chainId
    ) external view returns (bytes32);

    function deriveCrossDomainNullifier(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    ) external pure returns (bytes32);

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function crossChainVerifier() external view returns (address);

    function totalNullifiers() external view returns (uint256);

    function totalBindings() external view returns (uint256);

    function totalBatches() external view returns (uint256);

    function getNullifierRecord(
        bytes32 nullifier
    ) external view returns (NullifierRecord memory);

    function getCrossDomainBinding(
        bytes32 sourceNullifier,
        bytes32 destNullifier
    ) external view returns (CrossDomainBinding memory);

    function getChainDomain(
        uint256 chainId
    ) external view returns (ChainDomain memory);

    function getSoulBinding(
        bytes32 sourceNullifier
    ) external view returns (bytes32);

    function getSourceNullifiers(
        bytes32 soulBinding
    ) external view returns (bytes32[] memory);

    function getSourceNullifiersPaginated(
        bytes32 soulBinding,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory nullifiers, uint256 total);

    function getBatch(
        bytes32 batchId
    ) external view returns (NullifierBatch memory);

    function getRegisteredChainCount() external view returns (uint256);

    function getStats()
        external
        view
        returns (
            uint256 _totalNullifiers,
            uint256 _totalBindings,
            uint256 _totalBatches,
            uint256 _registeredChains
        );
}
