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

    /// @notice All registered components by ID
    mapping(bytes32 => ComponentInfo) public components;

    /// @notice Component IDs by category
    mapping(ComponentCategory => bytes32[]) public componentsByCategory;

    /// @notice Latest version by component name
    mapping(bytes32 => uint256) public latestVersion;

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

        for (uint256 i = 0; i < verifierTypes.length; i++) {
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

        for (uint256 i = 0; i < chainIds.length; i++) {
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

    /*//////////////////////////////////////////////////////////////
                         SECURITY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Bridge Proof Validator
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
                         EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emergency pause
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause
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
    }

    /**
     * @notice Deactivate a bridge adapter
     * @param chainId The chain ID to deactivate
     */
    function deactivateBridge(
        uint256 chainId
    ) external onlyRole(GUARDIAN_ROLE) {
        bridgeAdapters[chainId].isActive = false;
    }
}
