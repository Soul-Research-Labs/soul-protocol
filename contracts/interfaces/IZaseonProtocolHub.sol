// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZaseonProtocolHub
 * @notice Interface for the ZaseonProtocolHub central registry and integration hub
 * @dev Inherits: AccessControl, Pausable, ReentrancyGuard
 */
interface IZaseonProtocolHub {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Component categories
    enum ComponentCategory {
        CORE,
        VERIFIER,
        RELAY,
        PRIVACY,
        SECURITY,
        PRIMITIVE,
        GOVERNANCE,
        INFRASTRUCTURE
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Component registration info
    struct ComponentInfo {
        address contractAddress;
        ComponentCategory category;
        uint256 version;
        bool isActive;
        uint256 registeredAt;
        bytes32 configHash;
    }

    /// @notice Relay adapter info
    struct RelayInfo {
        address adapter;
        uint256 chainId;
        bool supportsPrivacy;
        bool isActive;
        uint256 minConfirmations;
    }

    /// @notice Verifier info
    struct VerifierInfo {
        address verifier;
        bytes32 proofType;
        uint256 gasLimit;
        bool isActive;
    }

    /// @notice Parameters for wireAll batch wiring
    struct WireAllParams {
        address _verifierRegistry;
        address _universalVerifier;
        address _crossChainMessageRelay;
        address _crossChainPrivacyHub;
        address _stealthAddressRegistry;
        address _privateRelayerNetwork;
        address _viewKeyRegistry;
        address _shieldedPool;
        address _nullifierManager;
        address _complianceOracle;
        address _proofTranslator;
        address _privacyRouter;
        address _relayProofValidator;
        address _zkBoundStateLocks;
        address _proofCarryingContainer;
        address _crossDomainNullifierAlgebra;
        address _policyBoundProofs;
        address _multiProver;
        address _relayWatchtower;
        address _intentCompletionLayer;
        address _instantCompletionGuarantee;
        address _dynamicRoutingOrchestrator;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ComponentRegistered(
        bytes32 indexed componentId,
        ComponentCategory indexed category,
        address contractAddress,
        uint256 version
    );

    event ComponentUpdated(
        bytes32 indexed componentId,
        address oldAddress,
        address newAddress,
        uint256 newVersion
    );

    event ComponentDeactivated(bytes32 indexed componentId);

    event VerifierRegistered(
        bytes32 indexed verifierType,
        address verifier,
        uint256 gasLimit
    );

    event RelayAdapterRegistered(
        uint256 indexed chainId,
        address adapter,
        bool supportsPrivacy
    );

    event PrivacyModuleRegistered(string indexed moduleName, address module);

    event SecurityModuleRegistered(string indexed moduleName, address module);

    event ProtocolWired(address indexed caller, uint256 componentsUpdated);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ComponentNotFound(bytes32 componentId);
    error ComponentAlreadyRegistered(bytes32 componentId);
    error ChainNotSupported(uint256 chainId);
    error InvalidConfiguration();
    error UnauthorizedCaller();
    error BatchTooLarge(uint256 provided, uint256 max);

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function OPERATOR_ROLE() external view returns (bytes32);

    function GUARDIAN_ROLE() external view returns (bytes32);

    function UPGRADER_ROLE() external view returns (bytes32);

    function MAX_BATCH_SIZE() external view returns (uint256);

    function GROTH16_VERIFIER() external view returns (bytes32);

    function NOIR_VERIFIER() external view returns (bytes32);

    function ULTRAHONK_VERIFIER() external view returns (bytes32);

    /*//////////////////////////////////////////////////////////////
                       PUBLIC STATE GETTERS
    //////////////////////////////////////////////////////////////*/

    // Verifiers
    function verifierRegistry() external view returns (address);

    function universalVerifier() external view returns (address);

    function multiProver() external view returns (address);

    function verifiers(
        bytes32 verifierType
    )
        external
        view
        returns (
            address verifier,
            bytes32 proofType,
            uint256 gasLimit,
            bool isActive
        );

    // Bridges
    function crossChainMessageRelay() external view returns (address);

    function crossChainPrivacyHub() external view returns (address);

    function relayAdapters(
        uint256 chainId
    )
        external
        view
        returns (
            address adapter,
            uint256 chainId_,
            bool supportsPrivacy,
            bool isActive,
            uint256 minConfirmations
        );

    function supportedChainIds(uint256 index) external view returns (uint256);

    // Privacy
    function stealthAddressRegistry() external view returns (address);

    function privateRelayerNetwork() external view returns (address);

    function viewKeyRegistry() external view returns (address);

    function shieldedPool() external view returns (address);

    function nullifierManager() external view returns (address);

    function complianceOracle() external view returns (address);

    function proofTranslator() external view returns (address);

    function privacyRouter() external view returns (address);

    // Security
    function relayProofValidator() external view returns (address);

    function relayWatchtower() external view returns (address);

    function relayCircuitBreaker() external view returns (address);

    // Primitives
    function zkBoundStateLocks() external view returns (address);

    function proofCarryingContainer() external view returns (address);

    function crossDomainNullifierAlgebra() external view returns (address);

    function policyBoundProofs() external view returns (address);

    // Intent & Completion
    function intentCompletionLayer() external view returns (address);

    function instantCompletionGuarantee() external view returns (address);

    function dynamicRoutingOrchestrator() external view returns (address);

    // Governance
    function timelock() external view returns (address);

    function upgradeTimelock() external view returns (address);

    /*//////////////////////////////////////////////////////////////
                      VERIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function setVerifierRegistry(address _registry) external;

    function setUniversalVerifier(address _verifier) external;

    function setMultiProver(address _multiProver) external;

    function registerVerifier(
        bytes32 verifierType,
        address _verifier,
        uint256 gasLimit
    ) external;

    function batchRegisterVerifiers(
        bytes32[] calldata verifierTypes,
        address[] calldata verifierAddresses,
        uint256[] calldata gasLimits
    ) external;

    /*//////////////////////////////////////////////////////////////
                       RELAY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function setCrossChainMessageRelay(address _relay) external;

    function setCrossChainPrivacyHub(address _hub) external;

    function registerRelayAdapter(
        uint256 chainId,
        address adapter,
        bool supportsPrivacy,
        uint256 minConfirmations
    ) external;

    function batchRegisterRelayAdapters(
        uint256[] calldata chainIds,
        address[] calldata adapters,
        bool[] calldata supportsPrivacy,
        uint256[] calldata minConfirmations
    ) external;

    /*//////////////////////////////////////////////////////////////
                      PRIVACY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function setStealthAddressRegistry(address _module) external;

    function setPrivateRelayerNetwork(address _module) external;

    function setViewKeyRegistry(address _module) external;

    function setShieldedPool(address _module) external;

    function setNullifierManager(address _module) external;

    function setComplianceOracle(address _module) external;

    function setProofTranslator(address _module) external;

    function setPrivacyRouter(address _module) external;

    /*//////////////////////////////////////////////////////////////
                      SECURITY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function setRelayProofValidator(address _module) external;

    function setRelayWatchtower(address _module) external;

    function setRelayCircuitBreaker(address _module) external;

    /*//////////////////////////////////////////////////////////////
                     PRIMITIVE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function setZKBoundStateLocks(address _module) external;

    function setProofCarryingContainer(address _module) external;

    function setCrossDomainNullifierAlgebra(address _module) external;

    function setPolicyBoundProofs(address _module) external;

    /*//////////////////////////////////////////////////////////////
                     GOVERNANCE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function setTimelock(address _module) external;

    function setUpgradeTimelock(address _module) external;

    /*//////////////////////////////////////////////////////////////
                        BATCH WIRING
    //////////////////////////////////////////////////////////////*/

    function wireAll(WireAllParams calldata p) external;

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getVerifier(bytes32 verifierType) external view returns (address);

    function getRelayAdapter(uint256 chainId) external view returns (address);

    function isChainSupported(uint256 chainId) external view returns (bool);

    function getSupportedChainIds() external view returns (uint256[] memory);

    function getVerifierInfo(
        bytes32 verifierType
    ) external view returns (VerifierInfo memory);

    function getRelayInfo(
        uint256 chainId
    ) external view returns (RelayInfo memory);

    function isFullyConfigured() external view returns (bool configured);

    function getComponentStatus()
        external
        view
        returns (string[] memory names, address[] memory addresses);

    /*//////////////////////////////////////////////////////////////
                       EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external;

    function unpause() external;

    function deactivateVerifier(bytes32 verifierType) external;

    function deactivateRelay(uint256 chainId) external;
}
