// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SoulProtocolHub
 * @author Soul Protocol
 * @notice Central registry and integration hub for all Soul Protocol components
 * @dev Routes requests to appropriate modules and maintains component registrations
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                         SOUL PROTOCOL HUB                                    │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────────┐ │
 * │  │   VERIFIERS    │  │    BRIDGES     │  │         PRIVACY                │ │
 * │  ├────────────────┤  ├────────────────┤  ├────────────────────────────────┤ │
 * │  │ • Groth16      │  │ • Arbitrum     │  │ • Stealth Addresses            │ │
 * │  │ • UltraHonk    │  │ • Optimism     │  │ • Private Relayer              │ │
 * │  │ • Noir         │  │ • Base         │  │ • View Key Registry            │ │
 * │  │ • Multi-Prover │  │ • LayerZero    │  └────────────────────────────────┘ │
 * │  └────────────────┘  └────────────────┘                                      │
 * │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────────┐ │
 * │  │   SECURITY     │  │  GOVERNANCE    │  │      PRIMITIVES                │ │
 * │  ├────────────────┤  ├────────────────┤  ├────────────────────────────────┤ │
 * │  │ • Proof Valid. │  │ • Timelock     │  │ • ZK-Bound State Locks         │ │
 * │  │ • Watchtower   │  │ • Upgrade TL   │  │ • Proof-Carrying Containers    │ │
 * │  │ • Ckt Breaker  │  │                │  │ • Cross-Domain Nullifiers      │ │
 * │  └────────────────┘  └────────────────┘  │ • Policy Bound Proofs          │ │
 * │                                           └────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Integration Pattern:
 * 1. Register components by category using setter functions
 * 2. Components can query the hub for addresses of other components
 * 3. Supports versioning for upgradeable components
 * 4. Emits events for all registrations for off-chain indexing
 */
contract SoulProtocolHub is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    /// @dev Pre-computed: keccak256("GUARDIAN_ROLE")
    bytes32 public constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;
    /// @dev Pre-computed: keccak256("UPGRADER_ROLE")
    bytes32 public constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Component categories
    enum ComponentCategory {
        VERIFIER,
        BRIDGE,
        PRIVACY,
        SECURITY,
        PRIMITIVE,
        GOVERNANCE,
        INFRASTRUCTURE
    }

    /// @notice Component registration info
    struct ComponentInfo {
        address contractAddress;
        ComponentCategory category;
        uint256 version;
        bool isActive;
        uint256 registeredAt;
        bytes32 configHash;
    }

    /// @notice Bridge adapter info
    struct BridgeInfo {
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

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // ============ Component Registry ============

    /// @dev NOTE: components/componentsByCategory/latestVersion mappings removed (dead code — never written to)
    /// Storage slots preserved for upgrade safety if needed in future.

    // ============ Verifiers ============

    /// @notice Verifier registry address
    address public verifierRegistry;

    /// @notice Universal verifier address
    address public universalVerifier;

    /// @notice Multi-prover hub
    address public multiProver;

    /// @notice Individual verifiers by type
    mapping(bytes32 => VerifierInfo) public verifiers;

    /// @notice Verifier type constants
    bytes32 public constant GROTH16_VERIFIER = keccak256("GROTH16");
    bytes32 public constant NOIR_VERIFIER = keccak256("NOIR");
    bytes32 public constant ULTRAHONK_VERIFIER = keccak256("ULTRAHONK");

    // ============ Bridges ============

    /// @notice Cross-chain message relay
    address public crossChainMessageRelay;

    /// @notice Cross-chain privacy hub
    address public crossChainPrivacyHub;

    /// @notice Bridge adapters by chain ID
    mapping(uint256 => BridgeInfo) public bridgeAdapters;

    /// @notice Supported chain IDs
    uint256[] public supportedChainIds;

    // ============ Privacy ============

    /// @notice Privacy module addresses
    address public stealthAddressRegistry;
    address public privateRelayerNetwork;
    address public viewKeyRegistry;
    address public shieldedPool;
    address public nullifierManager;
    address public complianceOracle;
    address public proofTranslator;
    address public privacyRouter;

    // ============ Security ============

    /// @notice Security module addresses
    address public bridgeProofValidator;
    address public bridgeWatchtower;
    address public bridgeCircuitBreaker;

    // ============ Primitives ============

    /// @notice Core primitive addresses
    address public zkBoundStateLocks;
    address public proofCarryingContainer;
    address public crossDomainNullifierAlgebra;
    address public policyBoundProofs;

    // ============ Governance ============

    /// @notice Governance addresses
    address public timelock;
    address public upgradeTimelock;

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

    event BridgeAdapterRegistered(
        uint256 indexed chainId,
        address adapter,
        bool supportsPrivacy
    );

    event PrivacyModuleRegistered(string indexed moduleName, address module);

    event SecurityModuleRegistered(string indexed moduleName, address module);

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
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum batch size for DoS prevention
    uint256 public constant MAX_BATCH_SIZE = 50;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set the verifier registry
     * @param _registry Verifier registry address
     */
    function setVerifierRegistry(
        address _registry
    ) external onlyRole(OPERATOR_ROLE) {
        if (_registry == address(0)) revert ZeroAddress();
        verifierRegistry = _registry;
        emit ComponentRegistered(
            keccak256("VERIFIER_REGISTRY"),
            ComponentCategory.VERIFIER,
            _registry,
            1
        );
    }

    /**
     * @notice Set the universal verifier
     * @param _verifier Universal verifier address
     */
    function setUniversalVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        universalVerifier = _verifier;
        emit ComponentRegistered(
            keccak256("UNIVERSAL_VERIFIER"),
            ComponentCategory.VERIFIER,
            _verifier,
            1
        );
    }

    /**
     * @notice Set the multi-prover hub
     * @param _multiProver Multi-prover address
     */
    function setMultiProver(
        address _multiProver
    ) external onlyRole(OPERATOR_ROLE) {
        if (_multiProver == address(0)) revert ZeroAddress();
        multiProver = _multiProver;
        emit ComponentRegistered(
            keccak256("MULTI_PROVER"),
            ComponentCategory.VERIFIER,
            _multiProver,
            1
        );
    }

    /**
     * @notice Register a verifier by type
     * @param verifierType Type identifier (BINIUS, PLONK, etc.)
     * @param _verifier Verifier contract address
     * @param gasLimit Gas limit for verification
     */
    function registerVerifier(
        bytes32 verifierType,
        address _verifier,
        uint256 gasLimit
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();

        verifiers[verifierType] = VerifierInfo({
            verifier: _verifier,
            proofType: verifierType,
            gasLimit: gasLimit > 0 ? gasLimit : 500000,
            isActive: true
        });

        emit VerifierRegistered(verifierType, _verifier, gasLimit);
    }

    /**
     * @notice Batch register verifiers
     * @param verifierTypes Array of verifier type identifiers
     * @param verifierAddresses Array of verifier addresses
     * @param gasLimits Array of gas limits
     */
    function batchRegisterVerifiers(
        bytes32[] calldata verifierTypes,
        address[] calldata verifierAddresses,
        uint256[] calldata gasLimits
    ) external onlyRole(OPERATOR_ROLE) {
        // SECURITY FIX: Add batch size limit to prevent DoS
        if (verifierTypes.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge(verifierTypes.length, MAX_BATCH_SIZE);
        }
        require(
            verifierTypes.length == verifierAddresses.length &&
                verifierTypes.length == gasLimits.length,
            "Length mismatch"
        );

        for (uint256 i = 0; i < verifierTypes.length; ) {
            if (verifierAddresses[i] == address(0)) revert ZeroAddress();

            verifiers[verifierTypes[i]] = VerifierInfo({
                verifier: verifierAddresses[i],
                proofType: verifierTypes[i],
                gasLimit: gasLimits[i] > 0 ? gasLimits[i] : 500000,
                isActive: true
            });

            emit VerifierRegistered(
                verifierTypes[i],
                verifierAddresses[i],
                gasLimits[i]
            );
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         BRIDGE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set the cross-chain message relay
     * @param _relay Message relay address
     */
    function setCrossChainMessageRelay(
        address _relay
    ) external onlyRole(OPERATOR_ROLE) {
        if (_relay == address(0)) revert ZeroAddress();
        crossChainMessageRelay = _relay;
        emit ComponentRegistered(
            keccak256("CROSSCHAIN_MESSAGE_RELAY"),
            ComponentCategory.BRIDGE,
            _relay,
            1
        );
    }

    /**
     * @notice Set the cross-chain privacy hub
     * @param _hub Privacy hub address
     */
    function setCrossChainPrivacyHub(
        address _hub
    ) external onlyRole(OPERATOR_ROLE) {
        if (_hub == address(0)) revert ZeroAddress();
        crossChainPrivacyHub = _hub;
        emit ComponentRegistered(
            keccak256("CROSSCHAIN_PRIVACY_HUB"),
            ComponentCategory.BRIDGE,
            _hub,
            1
        );
    }

    /**
     * @notice Register a bridge adapter for a chain
     * @param chainId Target chain ID
     * @param adapter Bridge adapter address
     * @param supportsPrivacy Whether adapter supports private transfers
     * @param minConfirmations Minimum confirmations required
     */
    function registerBridgeAdapter(
        uint256 chainId,
        address adapter,
        bool supportsPrivacy,
        uint256 minConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapter == address(0)) revert ZeroAddress();

        // Track new chain
        if (bridgeAdapters[chainId].adapter == address(0)) {
            supportedChainIds.push(chainId);
        }

        bridgeAdapters[chainId] = BridgeInfo({
            adapter: adapter,
            chainId: chainId,
            supportsPrivacy: supportsPrivacy,
            isActive: true,
            minConfirmations: minConfirmations
        });

        emit BridgeAdapterRegistered(chainId, adapter, supportsPrivacy);
    }

    /**
     * @notice Batch register bridge adapters
     */
    function batchRegisterBridgeAdapters(
        uint256[] calldata chainIds,
        address[] calldata adapters,
        bool[] calldata supportsPrivacy,
        uint256[] calldata minConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        // SECURITY FIX: Add batch size limit to prevent DoS
        if (chainIds.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge(chainIds.length, MAX_BATCH_SIZE);
        }
        require(
            chainIds.length == adapters.length &&
                chainIds.length == supportsPrivacy.length &&
                chainIds.length == minConfirmations.length,
            "Length mismatch"
        );

        for (uint256 i = 0; i < chainIds.length; ) {
            if (adapters[i] == address(0)) revert ZeroAddress();

            if (bridgeAdapters[chainIds[i]].adapter == address(0)) {
                supportedChainIds.push(chainIds[i]);
            }

            bridgeAdapters[chainIds[i]] = BridgeInfo({
                adapter: adapters[i],
                chainId: chainIds[i],
                supportsPrivacy: supportsPrivacy[i],
                isActive: true,
                minConfirmations: minConfirmations[i]
            });

            emit BridgeAdapterRegistered(
                chainIds[i],
                adapters[i],
                supportsPrivacy[i]
            );
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Stealth Address Registry
     */
    function setStealthAddressRegistry(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        stealthAddressRegistry = _module;
        emit PrivacyModuleRegistered("STEALTH_REGISTRY", _module);
    }

    /**
     * @notice Set Private Relayer Network
     */
    function setPrivateRelayerNetwork(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        privateRelayerNetwork = _module;
        emit PrivacyModuleRegistered("PRIVATE_RELAYER", _module);
    }

    /**
     * @notice Set View Key Registry
     */
    function setViewKeyRegistry(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        viewKeyRegistry = _module;
        emit PrivacyModuleRegistered("VIEW_KEY_REGISTRY", _module);
    }

    /**
     * @notice Set Shielded Pool
     * @param _module Address of the shielded pool contract
     */
    function setShieldedPool(address _module) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        shieldedPool = _module;
        emit PrivacyModuleRegistered("SHIELDED_POOL", _module);
    }

    /**
     * @notice Set Nullifier Manager
     * @param _module Address of the nullifier manager contract
     */
    function setNullifierManager(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        nullifierManager = _module;
        emit PrivacyModuleRegistered("NULLIFIER_MANAGER", _module);
    }

    /**
     * @notice Set Compliance Oracle
     * @param _module Address of the compliance oracle contract
     */
    function setComplianceOracle(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        complianceOracle = _module;
        emit PrivacyModuleRegistered("COMPLIANCE_ORACLE", _module);
    }

    /**
     * @notice Set Proof Translator
     * @param _module Address of the proof translator contract
     */
    function setProofTranslator(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        proofTranslator = _module;
        emit PrivacyModuleRegistered("PROOF_TRANSLATOR", _module);
    }

    /**
     * @notice Set Privacy Router
     * @param _module Address of the privacy router contract
     */
    function setPrivacyRouter(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        privacyRouter = _module;
        emit PrivacyModuleRegistered("PRIVACY_ROUTER", _module);
    }

    /*//////////////////////////////////////////////////////////////
                         SECURITY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Bridge Proof Validator
     * @param _module Address of the bridge proof validator contract
     */
    function setBridgeProofValidator(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        bridgeProofValidator = _module;
        emit SecurityModuleRegistered("BRIDGE_PROOF_VALIDATOR", _module);
    }

    /**
     * @notice Set Bridge Watchtower
     * @param _module Address of the bridge watchtower contract
     */
    function setBridgeWatchtower(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        bridgeWatchtower = _module;
        emit SecurityModuleRegistered("BRIDGE_WATCHTOWER", _module);
    }

    /**
     * @notice Set Bridge Circuit Breaker
     * @param _module Address of the bridge circuit breaker contract
     */
    function setBridgeCircuitBreaker(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        bridgeCircuitBreaker = _module;
        emit SecurityModuleRegistered("BRIDGE_CIRCUIT_BREAKER", _module);
    }

    /*//////////////////////////////////////////////////////////////
                        PRIMITIVE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set ZK-Bound State Locks
     * @param _module Address of the ZK-bound state locks contract
     */
    function setZKBoundStateLocks(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        zkBoundStateLocks = _module;
        emit ComponentRegistered(
            keccak256("ZK_BOUND_STATE_LOCKS"),
            ComponentCategory.PRIMITIVE,
            _module,
            1
        );
    }

    /**
     * @notice Set Proof-Carrying Container
     * @param _module Address of the proof-carrying container contract
     */
    function setProofCarryingContainer(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        proofCarryingContainer = _module;
        emit ComponentRegistered(
            keccak256("PROOF_CARRYING_CONTAINER"),
            ComponentCategory.PRIMITIVE,
            _module,
            1
        );
    }

    /**
     * @notice Set Cross-Domain Nullifier Algebra
     * @param _module Address of the CDNA contract
     */
    function setCrossDomainNullifierAlgebra(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        crossDomainNullifierAlgebra = _module;
        emit ComponentRegistered(
            keccak256("CDNA"),
            ComponentCategory.PRIMITIVE,
            _module,
            1
        );
    }

    /**
     * @notice Set Policy Bound Proofs
     * @param _module Address of the policy bound proofs contract
     */
    function setPolicyBoundProofs(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        policyBoundProofs = _module;
        emit ComponentRegistered(
            keccak256("POLICY_BOUND_PROOFS"),
            ComponentCategory.PRIMITIVE,
            _module,
            1
        );
    }

    /*//////////////////////////////////////////////////////////////
                       GOVERNANCE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Timelock
     * @param _module Address of the timelock contract
     */
    function setTimelock(
        address _module
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        timelock = _module;
        emit ComponentRegistered(
            keccak256("TIMELOCK"),
            ComponentCategory.GOVERNANCE,
            _module,
            1
        );
    }

    /**
     * @notice Set Upgrade Timelock
     * @param _module Address of the upgrade timelock contract
     */
    function setUpgradeTimelock(
        address _module
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        upgradeTimelock = _module;
        emit ComponentRegistered(
            keccak256("UPGRADE_TIMELOCK"),
            ComponentCategory.GOVERNANCE,
            _module,
            1
        );
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get verifier address by type
     * @param verifierType The verifier type identifier
     * @return Verifier contract address
     */
    function getVerifier(bytes32 verifierType) external view returns (address) {
        return verifiers[verifierType].verifier;
    }

    /**
     * @notice Get bridge adapter for a chain
     * @param chainId The target chain ID
     * @return Bridge adapter address
     */
    function getBridgeAdapter(uint256 chainId) external view returns (address) {
        return bridgeAdapters[chainId].adapter;
    }

    /**
     * @notice Check if a chain is supported
     * @param chainId The chain ID to check
     * @return Whether the chain is supported
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return bridgeAdapters[chainId].isActive;
    }

    /**
     * @notice Get all supported chain IDs
     * @return Array of supported chain IDs
     */
    function getSupportedChainIds() external view returns (uint256[] memory) {
        return supportedChainIds;
    }

    /**
     * @notice Get verifier info
     * @param verifierType The verifier type
     * @return VerifierInfo struct
     */
    function getVerifierInfo(
        bytes32 verifierType
    ) external view returns (VerifierInfo memory) {
        return verifiers[verifierType];
    }

    /**
     * @notice Get bridge info
     * @param chainId The chain ID
     * @return BridgeInfo struct
     */
    function getBridgeInfo(
        uint256 chainId
    ) external view returns (BridgeInfo memory) {
        return bridgeAdapters[chainId];
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH WIRING
    //////////////////////////////////////////////////////////////*/

    /// @notice Wire all core protocol components in a single transaction
    /// @dev Reduces deployment setup from 20+ calls to 1. All addresses must be non-zero.
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
        address _bridgeProofValidator;
        address _zkBoundStateLocks;
        address _proofCarryingContainer;
        address _crossDomainNullifierAlgebra;
        address _policyBoundProofs;
    }

    /**
     * @notice Wire all core protocol components in a single transaction
     * @dev Reduces deployment setup from 20+ calls to 1. Zero-address fields are
     *      skipped (existing value preserved), allowing partial wiring updates.
     * @param p Struct containing all component addresses to wire
     */
    function wireAll(
        WireAllParams calldata p
    ) external onlyRole(OPERATOR_ROLE) {
        if (p._verifierRegistry != address(0))
            verifierRegistry = p._verifierRegistry;
        if (p._universalVerifier != address(0))
            universalVerifier = p._universalVerifier;
        if (p._crossChainMessageRelay != address(0))
            crossChainMessageRelay = p._crossChainMessageRelay;
        if (p._crossChainPrivacyHub != address(0))
            crossChainPrivacyHub = p._crossChainPrivacyHub;
        if (p._stealthAddressRegistry != address(0))
            stealthAddressRegistry = p._stealthAddressRegistry;
        if (p._privateRelayerNetwork != address(0))
            privateRelayerNetwork = p._privateRelayerNetwork;
        if (p._viewKeyRegistry != address(0))
            viewKeyRegistry = p._viewKeyRegistry;
        if (p._shieldedPool != address(0)) shieldedPool = p._shieldedPool;
        if (p._nullifierManager != address(0))
            nullifierManager = p._nullifierManager;
        if (p._complianceOracle != address(0))
            complianceOracle = p._complianceOracle;
        if (p._proofTranslator != address(0))
            proofTranslator = p._proofTranslator;
        if (p._privacyRouter != address(0)) privacyRouter = p._privacyRouter;
        if (p._bridgeProofValidator != address(0))
            bridgeProofValidator = p._bridgeProofValidator;
        if (p._zkBoundStateLocks != address(0))
            zkBoundStateLocks = p._zkBoundStateLocks;
        if (p._proofCarryingContainer != address(0))
            proofCarryingContainer = p._proofCarryingContainer;
        if (p._crossDomainNullifierAlgebra != address(0))
            crossDomainNullifierAlgebra = p._crossDomainNullifierAlgebra;
        if (p._policyBoundProofs != address(0))
            policyBoundProofs = p._policyBoundProofs;
    }

    /// @notice Check if all critical protocol components are configured
    /// @return configured True if all required components have non-zero addresses
    function isFullyConfigured() external view returns (bool configured) {
        return (verifierRegistry != address(0) &&
            nullifierManager != address(0) &&
            shieldedPool != address(0) &&
            privacyRouter != address(0) &&
            zkBoundStateLocks != address(0) &&
            crossDomainNullifierAlgebra != address(0));
    }

    /// @notice Get a summary of which components are configured
    /// @return names Array of component names
    /// @return addresses Array of component addresses
    function getComponentStatus()
        external
        view
        returns (string[] memory names, address[] memory addresses)
    {
        names = new string[](17);
        addresses = new address[](17);
        names[0] = "verifierRegistry";
        addresses[0] = verifierRegistry;
        names[1] = "universalVerifier";
        addresses[1] = universalVerifier;
        names[2] = "crossChainMessageRelay";
        addresses[2] = crossChainMessageRelay;
        names[3] = "crossChainPrivacyHub";
        addresses[3] = crossChainPrivacyHub;
        names[4] = "stealthAddressRegistry";
        addresses[4] = stealthAddressRegistry;
        names[5] = "privateRelayerNetwork";
        addresses[5] = privateRelayerNetwork;
        names[6] = "viewKeyRegistry";
        addresses[6] = viewKeyRegistry;
        names[7] = "shieldedPool";
        addresses[7] = shieldedPool;
        names[8] = "nullifierManager";
        addresses[8] = nullifierManager;
        names[9] = "complianceOracle";
        addresses[9] = complianceOracle;
        names[10] = "proofTranslator";
        addresses[10] = proofTranslator;
        names[11] = "privacyRouter";
        addresses[11] = privacyRouter;
        names[12] = "bridgeProofValidator";
        addresses[12] = bridgeProofValidator;
        names[13] = "zkBoundStateLocks";
        addresses[13] = zkBoundStateLocks;
        names[14] = "proofCarryingContainer";
        addresses[14] = proofCarryingContainer;
        names[15] = "crossDomainNullifierAlgebra";
        addresses[15] = crossDomainNullifierAlgebra;
        names[16] = "policyBoundProofs";
        addresses[16] = policyBoundProofs;
    }

    /*//////////////////////////////////////////////////////////////
                         EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emergency pause — halts all operations
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause — resumes normal operations
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Deactivate a verifier
     * @param verifierType The verifier type to deactivate
     */
    function deactivateVerifier(
        bytes32 verifierType
    ) external onlyRole(GUARDIAN_ROLE) {
        verifiers[verifierType].isActive = false;
        emit ComponentDeactivated(verifierType);
    }

    /**
     * @notice Deactivate a bridge adapter
     * @param chainId The chain ID to deactivate
     */
    function deactivateBridge(
        uint256 chainId
    ) external onlyRole(GUARDIAN_ROLE) {
        bridgeAdapters[chainId].isActive = false;
        emit ComponentDeactivated(bytes32(chainId));
    }
}
