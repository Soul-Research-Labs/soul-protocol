// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISoulProtocolHub} from "../interfaces/ISoulProtocolHub.sol";

/**
 * @title SoulProtocolHubUpgradeable
 * @author Soul Protocol
 * @notice UUPS-upgradeable central registry and integration hub for all Soul Protocol components
 * @dev Routes requests to appropriate modules and maintains component registrations.
 *      Upgradeable variant of SoulProtocolHub using the UUPS proxy pattern.
 * @custom:oz-upgrades-from SoulProtocolHub
 */
contract SoulProtocolHubUpgradeable is
    Initializable,
    ISoulProtocolHub,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
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
                                STORAGE
    //////////////////////////////////////////////////////////////*/

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

    // ============ Relay Adapters ============

    /// @notice Cross-chain message relay
    address public crossChainMessageRelay;

    /// @notice Cross-chain privacy hub
    address public crossChainPrivacyHub;

    /// @notice Bridge adapters by chain ID
    mapping(uint256 => RelayInfo) public relayAdapters;

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
    address public relayProofValidator;
    address public relayWatchtower;
    address public relayCircuitBreaker;

    // ============ Primitives ============

    /// @notice Core primitive addresses
    address public zkBoundStateLocks;
    address public proofCarryingContainer;
    address public crossDomainNullifierAlgebra;
    address public policyBoundProofs;

    // ============ Intent & Completion ============

    /// @notice Intent-based completion layer
    address public intentCompletionLayer;

    /// @notice Instant completion guarantee (solver bonds)
    address public instantCompletionGuarantee;

    /// @notice Dynamic routing orchestrator
    address public dynamicRoutingOrchestrator;

    // ============ Governance ============

    /// @notice Governance addresses
    address public timelock;
    address public upgradeTimelock;

    // ============ Upgrade Tracking ============

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum batch size for DoS prevention
    uint256 public constant MAX_BATCH_SIZE = 50;

    /*//////////////////////////////////////////////////////////////
                           INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the upgradeable hub
     * @param admin Address to receive all initial roles
     */
    function initialize(address admin) public initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the verifier registry
    /**
     * @notice Sets the verifier registry
     * @param _registry The _registry
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

    /// @notice Set the universal verifier
    /**
     * @notice Sets the universal verifier
     * @param _verifier The _verifier
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

    /// @notice Set the multi-prover hub
    /**
     * @notice Sets the multi prover
     * @param _multiProver The _multi prover
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

    /// @notice Register a verifier by type
    /**
     * @notice Registers verifier
     * @param verifierType The verifier type
     * @param _verifier The _verifier
     * @param gasLimit The gas limit
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

    /// @notice Batch register verifiers
    /**
     * @notice Batchs register verifiers
     * @param verifierTypes The verifier types
     * @param verifierAddresses The verifierAddresses address
     * @param gasLimits The gas limits
     */
    function batchRegisterVerifiers(
        bytes32[] calldata verifierTypes,
        address[] calldata verifierAddresses,
        uint256[] calldata gasLimits
    ) external onlyRole(OPERATOR_ROLE) {
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
                         RELAY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the cross-chain message relay
    /**
     * @notice Sets the cross chain message relay
     * @param _relay The _relay
     */
    function setCrossChainMessageRelay(
        address _relay
    ) external onlyRole(OPERATOR_ROLE) {
        if (_relay == address(0)) revert ZeroAddress();
        crossChainMessageRelay = _relay;
        emit ComponentRegistered(
            keccak256("CROSSCHAIN_MESSAGE_RELAY"),
            ComponentCategory.RELAY,
            _relay,
            1
        );
    }

    /// @notice Set the cross-chain privacy hub
    /**
     * @notice Sets the cross chain privacy hub
     * @param _hub The _hub
     */
    function setCrossChainPrivacyHub(
        address _hub
    ) external onlyRole(OPERATOR_ROLE) {
        if (_hub == address(0)) revert ZeroAddress();
        crossChainPrivacyHub = _hub;
        emit ComponentRegistered(
            keccak256("CROSSCHAIN_PRIVACY_HUB"),
            ComponentCategory.RELAY,
            _hub,
            1
        );
    }

    /// @notice Register a bridge adapter for a chain
    /**
     * @notice Registers relay adapter
     * @param chainId The chain identifier
     * @param adapter The bridge adapter address
     * @param supportsPrivacy The supports privacy
     * @param minConfirmations The minConfirmations bound
     */
    function registerRelayAdapter(
        uint256 chainId,
        address adapter,
        bool supportsPrivacy,
        uint256 minConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapter == address(0)) revert ZeroAddress();

        if (relayAdapters[chainId].adapter == address(0)) {
            supportedChainIds.push(chainId);
        }

        relayAdapters[chainId] = RelayInfo({
            adapter: adapter,
            chainId: chainId,
            supportsPrivacy: supportsPrivacy,
            isActive: true,
            minConfirmations: minConfirmations
        });

        emit RelayAdapterRegistered(chainId, adapter, supportsPrivacy);
    }

    /// @notice Batch register bridge adapters
    /**
     * @notice Batchs register relay adapters
     * @param chainIds The chainIds identifier
     * @param adapters The adapters
     * @param supportsPrivacy The supports privacy
     * @param minConfirmations The minConfirmations bound
     */
    function batchRegisterRelayAdapters(
        uint256[] calldata chainIds,
        address[] calldata adapters,
        bool[] calldata supportsPrivacy,
        uint256[] calldata minConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
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

            if (relayAdapters[chainIds[i]].adapter == address(0)) {
                supportedChainIds.push(chainIds[i]);
            }

            relayAdapters[chainIds[i]] = RelayInfo({
                adapter: adapters[i],
                chainId: chainIds[i],
                supportsPrivacy: supportsPrivacy[i],
                isActive: true,
                minConfirmations: minConfirmations[i]
            });

            emit RelayAdapterRegistered(
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

    /// @notice Set Stealth Address Registry
    /**
     * @notice Sets the stealth address registry
     * @param _module The _module
     */
    function setStealthAddressRegistry(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        stealthAddressRegistry = _module;
        emit PrivacyModuleRegistered("STEALTH_REGISTRY", _module);
    }

    /// @notice Set Private Relayer Network
    /**
     * @notice Sets the private relayer network
     * @param _module The _module
     */
    function setPrivateRelayerNetwork(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        privateRelayerNetwork = _module;
        emit PrivacyModuleRegistered("PRIVATE_RELAYER", _module);
    }

    /// @notice Set View Key Registry
    /**
     * @notice Sets the view key registry
     * @param _module The _module
     */
    function setViewKeyRegistry(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        viewKeyRegistry = _module;
        emit PrivacyModuleRegistered("VIEW_KEY_REGISTRY", _module);
    }

    /// @notice Set Shielded Pool
    /**
     * @notice Sets the shielded pool
     * @param _module The _module
     */
    function setShieldedPool(address _module) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        shieldedPool = _module;
        emit PrivacyModuleRegistered("SHIELDED_POOL", _module);
    }

    /// @notice Set Nullifier Manager
    /**
     * @notice Sets the nullifier manager
     * @param _module The _module
     */
    function setNullifierManager(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        nullifierManager = _module;
        emit PrivacyModuleRegistered("NULLIFIER_MANAGER", _module);
    }

    /// @notice Set Compliance Oracle
    /**
     * @notice Sets the compliance oracle
     * @param _module The _module
     */
    function setComplianceOracle(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        complianceOracle = _module;
        emit PrivacyModuleRegistered("COMPLIANCE_ORACLE", _module);
    }

    /// @notice Set Proof Translator
    /**
     * @notice Sets the proof translator
     * @param _module The _module
     */
    function setProofTranslator(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        proofTranslator = _module;
        emit PrivacyModuleRegistered("PROOF_TRANSLATOR", _module);
    }

    /// @notice Set Privacy Router
    /**
     * @notice Sets the privacy router
     * @param _module The _module
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

    /// @notice Set Relay Proof Validator
    /**
     * @notice Sets the relay proof validator
     * @param _module The _module
     */
    function setRelayProofValidator(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        relayProofValidator = _module;
        emit SecurityModuleRegistered("RELAY_PROOF_VALIDATOR", _module);
    }

    /// @notice Set Relay Watchtower
    /**
     * @notice Sets the relay watchtower
     * @param _module The _module
     */
    function setRelayWatchtower(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        relayWatchtower = _module;
        emit SecurityModuleRegistered("RELAY_WATCHTOWER", _module);
    }

    /// @notice Set Relay Circuit Breaker
    /**
     * @notice Sets the relay circuit breaker
     * @param _module The _module
     */
    function setRelayCircuitBreaker(
        address _module
    ) external onlyRole(OPERATOR_ROLE) {
        if (_module == address(0)) revert ZeroAddress();
        relayCircuitBreaker = _module;
        emit SecurityModuleRegistered("RELAY_CIRCUIT_BREAKER", _module);
    }

    /*//////////////////////////////////////////////////////////////
                        PRIMITIVE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Set ZK-Bound State Locks
    /**
     * @notice Sets the z k bound state locks
     * @param _module The _module
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

    /// @notice Set Proof-Carrying Container
    /**
     * @notice Sets the proof carrying container
     * @param _module The _module
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

    /// @notice Set Cross-Domain Nullifier Algebra
    /**
     * @notice Sets the cross domain nullifier algebra
     * @param _module The _module
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

    /// @notice Set Policy Bound Proofs
    /**
     * @notice Sets the policy bound proofs
     * @param _module The _module
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

    /// @notice Set Timelock
    /**
     * @notice Sets the timelock
     * @param _module The _module
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

    /// @notice Set Upgrade Timelock
    /**
     * @notice Sets the upgrade timelock
     * @param _module The _module
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

    /// @notice Get verifier address by type
    /**
     * @notice Returns the verifier
     * @param verifierType The verifier type
     * @return The verifier contract address for the given type
     */
    function getVerifier(bytes32 verifierType) external view returns (address) {
        return verifiers[verifierType].verifier;
    }

    /// @notice Get relay adapter for a chain
    /**
     * @notice Returns the relay adapter
     * @param chainId The chain identifier
     * @return The relay adapter address for the given chain ID
     */
    function getRelayAdapter(uint256 chainId) external view returns (address) {
        return relayAdapters[chainId].adapter;
    }

    /// @notice Check if a chain is supported
    /**
     * @notice Checks if chain supported
     * @param chainId The chain identifier
     * @return True if the given chain ID has an active relay adapter
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return relayAdapters[chainId].isActive;
    }

    /// @notice Get all supported chain IDs
    /**
     * @notice Returns the supported chain ids
     * @return Array of all supported chain IDs
     */
    function getSupportedChainIds() external view returns (uint256[] memory) {
        return supportedChainIds;
    }

    /// @notice Get verifier info
    /**
     * @notice Returns the verifier info
     * @param verifierType The verifier type
     * @return The VerifierInfo struct for the given verifier type
     */
    function getVerifierInfo(
        bytes32 verifierType
    ) external view returns (VerifierInfo memory) {
        return verifiers[verifierType];
    }

    /// @notice Get relay info
    /**
     * @notice Returns the relay info
     * @param chainId The chain identifier
     * @return The RelayInfo struct for the given chain ID
     */
    function getRelayInfo(
        uint256 chainId
    ) external view returns (RelayInfo memory) {
        return relayAdapters[chainId];
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH WIRING
    //////////////////////////////////////////////////////////////*/

    /// @notice Wire all core protocol components in a single transaction
    /**
     * @notice Wire all
     * @param p The p
     */
    function wireAll(
        WireAllParams calldata p
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        uint256 updated;
        if (p._verifierRegistry != address(0)) {
            verifierRegistry = p._verifierRegistry;
            emit ComponentRegistered(
                keccak256("verifierRegistry"),
                ComponentCategory.CORE,
                p._verifierRegistry,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._universalVerifier != address(0)) {
            universalVerifier = p._universalVerifier;
            emit ComponentRegistered(
                keccak256("universalVerifier"),
                ComponentCategory.VERIFIER,
                p._universalVerifier,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._crossChainMessageRelay != address(0)) {
            crossChainMessageRelay = p._crossChainMessageRelay;
            emit ComponentRegistered(
                keccak256("crossChainMessageRelay"),
                ComponentCategory.RELAY,
                p._crossChainMessageRelay,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._crossChainPrivacyHub != address(0)) {
            crossChainPrivacyHub = p._crossChainPrivacyHub;
            emit PrivacyModuleRegistered(
                "CROSS_CHAIN_PRIVACY_HUB",
                p._crossChainPrivacyHub
            );
            unchecked {
                ++updated;
            }
        }
        if (p._stealthAddressRegistry != address(0)) {
            stealthAddressRegistry = p._stealthAddressRegistry;
            emit PrivacyModuleRegistered(
                "STEALTH_REGISTRY",
                p._stealthAddressRegistry
            );
            unchecked {
                ++updated;
            }
        }
        if (p._privateRelayerNetwork != address(0)) {
            privateRelayerNetwork = p._privateRelayerNetwork;
            emit PrivacyModuleRegistered(
                "PRIVATE_RELAYER",
                p._privateRelayerNetwork
            );
            unchecked {
                ++updated;
            }
        }
        if (p._viewKeyRegistry != address(0)) {
            viewKeyRegistry = p._viewKeyRegistry;
            emit PrivacyModuleRegistered(
                "VIEW_KEY_REGISTRY",
                p._viewKeyRegistry
            );
            unchecked {
                ++updated;
            }
        }
        if (p._shieldedPool != address(0)) {
            shieldedPool = p._shieldedPool;
            emit PrivacyModuleRegistered("SHIELDED_POOL", p._shieldedPool);
            unchecked {
                ++updated;
            }
        }
        if (p._nullifierManager != address(0)) {
            nullifierManager = p._nullifierManager;
            emit PrivacyModuleRegistered(
                "NULLIFIER_MANAGER",
                p._nullifierManager
            );
            unchecked {
                ++updated;
            }
        }
        if (p._complianceOracle != address(0)) {
            complianceOracle = p._complianceOracle;
            emit SecurityModuleRegistered(
                "COMPLIANCE_ORACLE",
                p._complianceOracle
            );
            unchecked {
                ++updated;
            }
        }
        if (p._proofTranslator != address(0)) {
            proofTranslator = p._proofTranslator;
            emit ComponentRegistered(
                keccak256("proofTranslator"),
                ComponentCategory.VERIFIER,
                p._proofTranslator,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._privacyRouter != address(0)) {
            privacyRouter = p._privacyRouter;
            emit ComponentRegistered(
                keccak256("privacyRouter"),
                ComponentCategory.CORE,
                p._privacyRouter,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._relayProofValidator != address(0)) {
            relayProofValidator = p._relayProofValidator;
            emit SecurityModuleRegistered(
                "RELAY_PROOF_VALIDATOR",
                p._relayProofValidator
            );
            unchecked {
                ++updated;
            }
        }
        if (p._zkBoundStateLocks != address(0)) {
            zkBoundStateLocks = p._zkBoundStateLocks;
            emit ComponentRegistered(
                keccak256("zkBoundStateLocks"),
                ComponentCategory.CORE,
                p._zkBoundStateLocks,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._proofCarryingContainer != address(0)) {
            proofCarryingContainer = p._proofCarryingContainer;
            emit ComponentRegistered(
                keccak256("proofCarryingContainer"),
                ComponentCategory.CORE,
                p._proofCarryingContainer,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._crossDomainNullifierAlgebra != address(0)) {
            crossDomainNullifierAlgebra = p._crossDomainNullifierAlgebra;
            emit ComponentRegistered(
                keccak256("crossDomainNullifierAlgebra"),
                ComponentCategory.CORE,
                p._crossDomainNullifierAlgebra,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._policyBoundProofs != address(0)) {
            policyBoundProofs = p._policyBoundProofs;
            emit ComponentRegistered(
                keccak256("policyBoundProofs"),
                ComponentCategory.CORE,
                p._policyBoundProofs,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._multiProver != address(0)) {
            multiProver = p._multiProver;
            emit ComponentRegistered(
                keccak256("multiProver"),
                ComponentCategory.VERIFIER,
                p._multiProver,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._relayWatchtower != address(0)) {
            relayWatchtower = p._relayWatchtower;
            emit SecurityModuleRegistered(
                "RELAY_WATCHTOWER",
                p._relayWatchtower
            );
            unchecked {
                ++updated;
            }
        }
        if (p._intentCompletionLayer != address(0)) {
            intentCompletionLayer = p._intentCompletionLayer;
            emit ComponentRegistered(
                keccak256("intentCompletionLayer"),
                ComponentCategory.CORE,
                p._intentCompletionLayer,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._instantCompletionGuarantee != address(0)) {
            instantCompletionGuarantee = p._instantCompletionGuarantee;
            emit ComponentRegistered(
                keccak256("instantCompletionGuarantee"),
                ComponentCategory.CORE,
                p._instantCompletionGuarantee,
                1
            );
            unchecked {
                ++updated;
            }
        }
        if (p._dynamicRoutingOrchestrator != address(0)) {
            dynamicRoutingOrchestrator = p._dynamicRoutingOrchestrator;
            emit ComponentRegistered(
                keccak256("dynamicRoutingOrchestrator"),
                ComponentCategory.INFRASTRUCTURE,
                p._dynamicRoutingOrchestrator,
                1
            );
            unchecked {
                ++updated;
            }
        }

        emit ProtocolWired(msg.sender, updated);
    }

    /// @notice Check if all critical protocol components are configured
    /**
     * @notice Checks if fully configured
     * @return configured The configured
     */
    function isFullyConfigured() external view returns (bool configured) {
        return (verifierRegistry != address(0) &&
            universalVerifier != address(0) &&
            nullifierManager != address(0) &&
            shieldedPool != address(0) &&
            privacyRouter != address(0) &&
            zkBoundStateLocks != address(0) &&
            crossDomainNullifierAlgebra != address(0) &&
            crossChainMessageRelay != address(0) &&
            crossChainPrivacyHub != address(0) &&
            relayProofValidator != address(0) &&
            relayWatchtower != address(0) &&
            multiProver != address(0) &&
            proofCarryingContainer != address(0) &&
            stealthAddressRegistry != address(0) &&
            privateRelayerNetwork != address(0) &&
            complianceOracle != address(0));
    }

    /// @notice Get a summary of which components are configured
    /**
     * @notice Returns the component status
     * @return names The names
     * @return addresses The addresses
     */
    function getComponentStatus()
        external
        view
        returns (string[] memory names, address[] memory addresses)
    {
        names = new string[](25);
        addresses = new address[](25);
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
        names[12] = "relayProofValidator";
        addresses[12] = relayProofValidator;
        names[13] = "zkBoundStateLocks";
        addresses[13] = zkBoundStateLocks;
        names[14] = "proofCarryingContainer";
        addresses[14] = proofCarryingContainer;
        names[15] = "crossDomainNullifierAlgebra";
        addresses[15] = crossDomainNullifierAlgebra;
        names[16] = "policyBoundProofs";
        addresses[16] = policyBoundProofs;
        names[17] = "multiProver";
        addresses[17] = multiProver;
        names[18] = "relayWatchtower";
        addresses[18] = relayWatchtower;
        names[19] = "intentCompletionLayer";
        addresses[19] = intentCompletionLayer;
        names[20] = "instantCompletionGuarantee";
        addresses[20] = instantCompletionGuarantee;
        names[21] = "dynamicRoutingOrchestrator";
        addresses[21] = dynamicRoutingOrchestrator;
        names[22] = "relayCircuitBreaker";
        addresses[22] = relayCircuitBreaker;
        names[23] = "timelock";
        addresses[23] = timelock;
        names[24] = "upgradeTimelock";
        addresses[24] = upgradeTimelock;
    }

    /*//////////////////////////////////////////////////////////////
                         EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emergency pause
    /**
     * @notice Pauses the operation
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause
    /**
     * @notice Unpauses the operation
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /// @notice Deactivate a verifier
    /**
     * @notice Deactivate verifier
     * @param verifierType The verifier type
     */
    function deactivateVerifier(
        bytes32 verifierType
    ) external onlyRole(GUARDIAN_ROLE) {
        verifiers[verifierType].isActive = false;
        emit ComponentDeactivated(verifierType);
    }

    /// @notice Deactivate a bridge adapter
    /**
     * @notice Deactivate relay
     * @param chainId The chain identifier
     */
    function deactivateRelay(uint256 chainId) external onlyRole(GUARDIAN_ROLE) {
        relayAdapters[chainId].isActive = false;
        emit ComponentDeactivated(bytes32(chainId));
    }

    /*//////////////////////////////////////////////////////////////
                         UPGRADE AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /// @dev Only UPGRADER_ROLE can authorize upgrades
    function _authorizeUpgrade(
        address /* newImplementation */
    ) internal override onlyRole(UPGRADER_ROLE) {
        uint256 oldVersion = contractVersion;
        contractVersion++;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    /// @notice Event emitted on contract upgrade
    event ContractUpgraded(uint256 oldVersion, uint256 newVersion);

    /*//////////////////////////////////////////////////////////////
                           STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;
}
