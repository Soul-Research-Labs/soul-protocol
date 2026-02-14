// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/// @notice Minimal interface for SoulProtocolHub address resolution
interface ISoulProtocolHubUpgradeable {
    function shieldedPool() external view returns (address);

    function crossChainPrivacyHub() external view returns (address);

    function stealthAddressRegistry() external view returns (address);

    function nullifierManager() external view returns (address);

    function complianceOracle() external view returns (address);

    function proofTranslator() external view returns (address);
}

/**
 * @title PrivacyRouterUpgradeable
 * @author Soul Protocol
 * @notice UUPS-upgradeable unified entry point for all Soul Protocol privacy operations
 * @dev Upgradeable version of PrivacyRouter using UUPS proxy pattern.
 *      Improvements over the non-upgradeable version:
 *      - UUPS upgradeability with UPGRADER_ROLE
 *      - Uses `Address.functionCallWithValue` to bubble up revert reasons
 *      - ERC20 deposits: router pulls tokens then approves pool (user approves router)
 *
 * @custom:security-contact security@soul.network
 * @custom:oz-upgrades-from PrivacyRouter
 */
contract PrivacyRouterUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;
    using Address for address;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                      PRE-COMPUTED NAME HASHES
    //////////////////////////////////////////////////////////////*/

    bytes32 private constant _SHIELDED_POOL_HASH = keccak256("shieldedPool");
    bytes32 private constant _CROSS_CHAIN_HUB_HASH = keccak256("crossChainHub");
    bytes32 private constant _STEALTH_REGISTRY_HASH =
        keccak256("stealthRegistry");
    bytes32 private constant _NULLIFIER_MANAGER_HASH =
        keccak256("nullifierManager");
    bytes32 private constant _COMPLIANCE_HASH = keccak256("compliance");
    bytes32 private constant _PROOF_TRANSLATOR_HASH =
        keccak256("proofTranslator");

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    struct DepositParams {
        bytes32 commitment;
        bytes32 assetId;
        uint256 amount;
    }

    struct WithdrawParams {
        bytes proof;
        bytes32 merkleRoot;
        bytes32 nullifier;
        address recipient;
        address relayerAddress;
        uint256 amount;
        uint256 relayerFee;
        bytes32 assetId;
        bytes32 destChainId;
    }

    struct CrossChainTransferParams {
        uint256 destChainId;
        bytes32 recipientStealth;
        uint256 amount;
        uint8 privacyLevel;
        uint8 proofSystem;
        bytes proof;
        bytes32[] publicInputs;
        bytes32 proofHash;
    }

    struct OperationReceipt {
        bytes32 operationId;
        OperationType opType;
        uint256 timestamp;
        bytes32 commitmentOrNullifier;
        bool success;
    }

    enum OperationType {
        DEPOSIT,
        WITHDRAW,
        CROSS_CHAIN_TRANSFER,
        STEALTH_PAYMENT,
        PROOF_TRANSLATION
    }

    /*//////////////////////////////////////////////////////////////
                            COMPONENT ADDRESSES
    //////////////////////////////////////////////////////////////*/

    address public shieldedPool;
    address public crossChainHub;
    address public stealthRegistry;
    address public nullifierManager;
    address public compliance;
    address public proofTranslator;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    bool public complianceEnabled;
    uint8 public minimumKYCTier;
    uint256 public operationNonce;
    mapping(OperationType => uint256) public operationCounts;
    mapping(bytes32 => OperationReceipt) public receipts;
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrivateDeposit(
        bytes32 indexed operationId,
        bytes32 indexed commitment,
        bytes32 assetId,
        uint256 amount
    );

    event PrivateWithdrawal(
        bytes32 indexed operationId,
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount
    );

    event CrossChainTransferInitiated(
        bytes32 indexed operationId,
        uint256 indexed destChainId,
        bytes32 recipientStealth,
        uint256 amount
    );

    event StealthPaymentSent(
        bytes32 indexed operationId,
        address indexed stealthAddress,
        uint256 amount
    );

    event ComponentUpdated(string name, address newAddress);
    event ComplianceToggled(bool enabled);
    event MinimumKYCTierUpdated(uint8 oldTier, uint8 newTier);
    event ETHWithdrawn(address indexed to, uint256 amount);
    event SyncedFromHub(address indexed hub);
    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ComponentNotSet(string name);
    error ComplianceCheckFailed(address user);
    error SanctionedAddress(address user);
    error InsufficientKYCTier(address user, uint8 required, uint8 actual);
    error ZeroAddress();
    error ZeroAmount();
    error OperationFailed(string reason);
    error InvalidParams();

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the upgradeable privacy router
    function initialize(
        address _admin,
        address _shieldedPool,
        address _crossChainHub,
        address _stealthRegistry,
        address _nullifierManager,
        address _compliance,
        address _proofTranslator
    ) external initializer {
        if (_admin == address(0)) revert ZeroAddress();
        if (_shieldedPool == address(0)) revert ZeroAddress();
        if (_crossChainHub == address(0)) revert ZeroAddress();
        if (_stealthRegistry == address(0)) revert ZeroAddress();
        if (_nullifierManager == address(0)) revert ZeroAddress();
        if (_compliance == address(0)) revert ZeroAddress();
        if (_proofTranslator == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        shieldedPool = _shieldedPool;
        crossChainHub = _crossChainHub;
        stealthRegistry = _stealthRegistry;
        nullifierManager = _nullifierManager;
        compliance = _compliance;
        proofTranslator = _proofTranslator;

        complianceEnabled = true;
        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit native ETH into the shielded pool
    function depositETH(
        bytes32 commitment
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 operationId)
    {
        _requireComponent(shieldedPool, "shieldedPool");
        _checkCompliance(msg.sender);
        if (msg.value == 0) revert ZeroAmount();

        operationId = _nextOperationId();

        // Use Address.functionCallWithValue to bubble up revert reasons
        shieldedPool.functionCallWithValue(
            abi.encodeWithSignature("depositETH(bytes32)", commitment),
            msg.value
        );

        _recordReceipt(operationId, OperationType.DEPOSIT, commitment);
        emit PrivateDeposit(operationId, commitment, bytes32(0), msg.value);
    }

    /// @notice Deposit ERC20 tokens — user approves THIS router, router handles pool approval
    function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external nonReentrant whenNotPaused returns (bytes32 operationId) {
        _requireComponent(shieldedPool, "shieldedPool");
        _checkCompliance(msg.sender);
        if (amount == 0) revert ZeroAmount();

        operationId = _nextOperationId();

        // Look up token address from the pool
        // Use a try/catch-style approach: read the asset config from pool
        (bool readSuccess, bytes memory assetData) = shieldedPool.staticcall(
            abi.encodeWithSignature("assets(bytes32)", assetId)
        );
        require(
            readSuccess && assetData.length >= 160,
            "PrivacyRouter: asset lookup failed"
        );

        // AssetConfig: (address tokenAddress, bytes32 assetId, uint256 totalDeposited, uint256 totalWithdrawn, bool active)
        (address tokenAddress, , , , ) = abi.decode(
            assetData,
            (address, bytes32, uint256, uint256, bool)
        );
        require(tokenAddress != address(0), "PrivacyRouter: invalid token");

        // Pull tokens from user to router
        IERC20(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );

        // Approve pool to spend
        IERC20(tokenAddress).forceApprove(shieldedPool, amount);

        // Forward to pool  (tokens are now in router, pool pulls from router via transferFrom)
        shieldedPool.functionCall(
            abi.encodeWithSignature(
                "depositERC20(bytes32,uint256,bytes32)",
                assetId,
                amount,
                commitment
            )
        );

        _recordReceipt(operationId, OperationType.DEPOSIT, commitment);
        emit PrivateDeposit(operationId, commitment, assetId, amount);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw from the shielded pool with a ZK proof
    function withdraw(
        WithdrawParams calldata params
    ) external nonReentrant whenNotPaused returns (bytes32 operationId) {
        _requireComponent(shieldedPool, "shieldedPool");
        _checkCompliance(params.recipient);

        operationId = _nextOperationId();

        shieldedPool.functionCall(
            abi.encodeWithSignature(
                "withdraw((bytes,bytes32,bytes32,address,address,uint256,uint256,bytes32,bytes32))",
                params.proof,
                params.merkleRoot,
                params.nullifier,
                params.recipient,
                params.relayerAddress,
                params.amount,
                params.relayerFee,
                params.assetId,
                params.destChainId
            )
        );

        _recordReceipt(operationId, OperationType.WITHDRAW, params.nullifier);
        emit PrivateWithdrawal(
            operationId,
            params.nullifier,
            params.recipient,
            params.amount
        );
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN PRIVATE TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initiate a private cross-chain transfer via the Privacy Hub
    function initiatePrivateTransfer(
        CrossChainTransferParams calldata params
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 operationId)
    {
        _requireComponent(crossChainHub, "crossChainHub");
        _checkCompliance(msg.sender);
        if (params.amount == 0) revert ZeroAmount();

        operationId = _nextOperationId();

        crossChainHub.functionCallWithValue(
            abi.encodeWithSignature(
                "initiatePrivateTransfer(uint256,bytes32,uint256,uint8,(uint8,bytes,bytes32[],bytes32))",
                params.destChainId,
                params.recipientStealth,
                params.amount,
                params.privacyLevel,
                params.proofSystem,
                params.proof,
                params.publicInputs,
                params.proofHash
            ),
            msg.value
        );

        _recordReceipt(
            operationId,
            OperationType.CROSS_CHAIN_TRANSFER,
            params.recipientStealth
        );
        emit CrossChainTransferInitiated(
            operationId,
            params.destChainId,
            params.recipientStealth,
            params.amount
        );
    }

    /*//////////////////////////////////////////////////////////////
                       STEALTH ADDRESS OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function registerStealthMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        uint8 curveType,
        uint256 schemeId
    ) external nonReentrant whenNotPaused {
        _requireComponent(stealthRegistry, "stealthRegistry");
        _checkCompliance(msg.sender);

        stealthRegistry.functionCall(
            abi.encodeWithSignature(
                "registerMetaAddress(bytes,bytes,uint8,uint256)",
                spendingPubKey,
                viewingPubKey,
                curveType,
                schemeId
            )
        );
    }

    function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag) {
        _requireComponent(stealthRegistry, "stealthRegistry");

        bytes memory result = stealthRegistry.functionStaticCall(
            abi.encodeWithSignature(
                "deriveStealthAddress(address,bytes,bytes32)",
                recipient,
                ephemeralPubKey,
                sharedSecretHash
            )
        );
        (stealthAddress, viewTag) = abi.decode(result, (address, bytes1));
    }

    /*//////////////////////////////////////////////////////////////
                         QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        if (nullifierManager == address(0)) return false;
        (bool success, bytes memory result) = nullifierManager.staticcall(
            abi.encodeWithSignature("isNullifierSpent(bytes32)", nullifier)
        );
        if (!success) return false;
        return abi.decode(result, (bool));
    }

    function checkCompliance(address user) external view returns (bool passes) {
        if (!complianceEnabled || compliance == address(0)) return true;
        (bool success, bytes memory result) = compliance.staticcall(
            abi.encodeWithSignature("isKYCValid(address)", user)
        );
        if (!success) return false;
        passes = abi.decode(result, (bool));
    }

    function getOperationCount(
        OperationType opType
    ) external view returns (uint256) {
        return operationCounts[opType];
    }

    function getReceipt(
        bytes32 operationId
    ) external view returns (OperationReceipt memory) {
        return receipts[operationId];
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setComponent(
        string calldata name,
        address addr
    ) external onlyRole(OPERATOR_ROLE) {
        if (addr == address(0)) revert ZeroAddress();

        bytes32 nameHash = keccak256(bytes(name));
        if (nameHash == _SHIELDED_POOL_HASH) shieldedPool = addr;
        else if (nameHash == _CROSS_CHAIN_HUB_HASH) crossChainHub = addr;
        else if (nameHash == _STEALTH_REGISTRY_HASH) stealthRegistry = addr;
        else if (nameHash == _NULLIFIER_MANAGER_HASH) nullifierManager = addr;
        else if (nameHash == _COMPLIANCE_HASH) compliance = addr;
        else if (nameHash == _PROOF_TRANSLATOR_HASH) proofTranslator = addr;
        else revert InvalidParams();

        emit ComponentUpdated(name, addr);
    }

    /// @notice Sync all component addresses from SoulProtocolHub
    function syncFromHub(address hub) external onlyRole(OPERATOR_ROLE) {
        if (hub == address(0)) revert ZeroAddress();
        ISoulProtocolHubUpgradeable h = ISoulProtocolHubUpgradeable(hub);

        address _shieldedPool = h.shieldedPool();
        address _crossChainHub = h.crossChainPrivacyHub();
        address _stealthRegistry = h.stealthAddressRegistry();
        address _nullifierManager = h.nullifierManager();
        address _compliance = h.complianceOracle();
        address _proofTranslator = h.proofTranslator();

        if (_shieldedPool != address(0)) shieldedPool = _shieldedPool;
        if (_crossChainHub != address(0)) crossChainHub = _crossChainHub;
        if (_stealthRegistry != address(0)) stealthRegistry = _stealthRegistry;
        if (_nullifierManager != address(0))
            nullifierManager = _nullifierManager;
        if (_compliance != address(0)) compliance = _compliance;
        if (_proofTranslator != address(0)) proofTranslator = _proofTranslator;

        emit SyncedFromHub(hub);
    }

    function setComplianceEnabled(
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        complianceEnabled = enabled;
        emit ComplianceToggled(enabled);
    }

    function setMinimumKYCTier(uint8 tier) external onlyRole(OPERATOR_ROLE) {
        uint8 oldTier = minimumKYCTier;
        minimumKYCTier = tier;
        emit MinimumKYCTierUpdated(oldTier, tier);
    }

    /// @notice Withdraw ETH accidentally sent to this contract
    function withdrawETH(
        address payable to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 balance = address(this).balance;
        if (balance == 0) revert ZeroAmount();
        (bool success, ) = to.call{value: balance}("");
        if (!success) revert OperationFailed("ETH withdrawal failed");
        emit ETHWithdrawn(to, balance);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _nextOperationId() internal returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(msg.sender, block.chainid, operationNonce++)
            );
    }

    function _recordReceipt(
        bytes32 operationId,
        OperationType opType,
        bytes32 commitmentOrNullifier
    ) internal {
        receipts[operationId] = OperationReceipt({
            operationId: operationId,
            opType: opType,
            timestamp: block.timestamp,
            commitmentOrNullifier: commitmentOrNullifier,
            success: true
        });
        operationCounts[opType]++;
    }

    function _requireComponent(
        address component,
        string memory name
    ) internal pure {
        if (component == address(0)) revert ComponentNotSet(name);
    }

    function _checkCompliance(address user) internal view {
        if (!complianceEnabled || compliance == address(0)) return;

        (bool sSuccess, bytes memory sResult) = compliance.staticcall(
            abi.encodeWithSignature("sanctionedAddresses(address)", user)
        );
        if (sSuccess && sResult.length >= 32) {
            if (abi.decode(sResult, (bool))) revert SanctionedAddress(user);
        }

        (bool kSuccess, bytes memory kResult) = compliance.staticcall(
            abi.encodeWithSignature("isKYCValid(address)", user)
        );
        if (kSuccess && kResult.length >= 32) {
            if (!abi.decode(kResult, (bool)))
                revert ComplianceCheckFailed(user);
        }

        if (minimumKYCTier > 0) {
            (bool tSuccess, bytes memory tResult) = compliance.staticcall(
                abi.encodeWithSignature(
                    "meetsKYCTier(address,uint8)",
                    user,
                    minimumKYCTier
                )
            );
            if (tSuccess && tResult.length >= 32) {
                if (!abi.decode(tResult, (bool)))
                    revert InsufficientKYCTier(user, minimumKYCTier, 0);
            }
        }
    }

    /// @notice Authorize UUPS upgrade — restricted to UPGRADER_ROLE
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        require(
            newImplementation != address(0),
            "PrivacyRouter: zero implementation"
        );
        require(
            newImplementation.code.length > 0,
            "PrivacyRouter: implementation not a contract"
        );
        uint256 oldVersion = contractVersion;
        contractVersion = oldVersion + 1;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    receive() external payable {}
}
