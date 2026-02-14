// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Minimal interface for SoulProtocolHub address resolution
interface ISoulProtocolHub {
    function shieldedPool() external view returns (address);

    function crossChainPrivacyHub() external view returns (address);

    function stealthAddressRegistry() external view returns (address);

    function nullifierManager() external view returns (address);

    function complianceOracle() external view returns (address);

    function proofTranslator() external view returns (address);
}

/**
 * @title PrivacyRouter
 * @author Soul Protocol
 * @notice Unified entry point for all Soul Protocol privacy operations
 * @dev Composes UniversalShieldedPool, CrossChainPrivacyHub, StealthAddressRegistry,
 *      UnifiedNullifierManager, SoulComplianceV2, and UniversalProofTranslator into
 *      a single developer-facing API. This is the "privacy middleware" that dApps integrate.
 *
 * DESIGN PHILOSOPHY:
 * 1. One contract to import — applications call PrivacyRouter for everything
 * 2. Each call is compliance-gated (KYC + sanctions) before executing privacy ops
 * 3. Cross-chain transfers are composed: generate stealth address → deposit to pool →
 *    relay proof → withdraw on destination
 * 4. All proof systems accepted transparently (translation handled internally)
 *
 * WORKFLOW: Private Cross-Chain Transfer
 * ┌─────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────────┐
 * │  User   │───>│ PrivacyRouter │───>│ ShieldedPool │───>│ CrossChain   │
 * │  dApp   │    │ (this)        │    │ (deposit)    │    │ PrivacyHub   │
 * └─────────┘    └───────────────┘    └──────────────┘    └──────────────┘
 *                       │                                        │
 *                       ▼                                        ▼
 *                ┌──────────────┐                        ┌──────────────┐
 *                │ Compliance   │                        │ Stealth Addr │
 *                │ (KYC check)  │                        │ (recipient)  │
 *                └──────────────┘                        └──────────────┘
 *
 * @custom:security-contact security@soul.network
 */
contract PrivacyRouter is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

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

    /// @notice Parameters for a private deposit
    struct DepositParams {
        bytes32 commitment; // Pedersen/Poseidon commitment: H(secret, nullifier, amount)
        bytes32 assetId; // Asset identifier (bytes32(0) for native ETH)
        uint256 amount; // Amount to deposit (0 for ETH — uses msg.value)
    }

    /// @notice Parameters for a private withdrawal
    struct WithdrawParams {
        bytes proof; // ZK proof of knowledge
        bytes32 merkleRoot; // Merkle root the proof is against
        bytes32 nullifier; // Nullifier to prevent double-spend
        address recipient; // Withdrawal recipient
        address relayerAddress; // Relayer for gas abstraction (address(0) if self-relay)
        uint256 amount; // Amount to withdraw
        uint256 relayerFee; // Fee for relayer
        bytes32 assetId; // Asset being withdrawn
        bytes32 destChainId; // Destination chain (bytes32(0) for same-chain)
    }

    /// @notice Parameters for a cross-chain private transfer
    struct CrossChainTransferParams {
        uint256 destChainId; // EVM chain ID of destination
        bytes32 recipientStealth; // Stealth address hash of recipient
        uint256 amount; // Transfer amount
        uint8 privacyLevel; // 0=NONE, 1=BASIC, 2=MEDIUM, 3=HIGH, 4=MAXIMUM
        uint8 proofSystem; // Proof system enum value
        bytes proof; // ZK proof bytes
        bytes32[] publicInputs; // Public inputs to the proof
        bytes32 proofHash; // Hash of the proof for dedup
    }

    /// @notice Privacy operation receipt
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

    /// @notice Core protocol components
    address public shieldedPool;
    address public crossChainHub;
    address public stealthRegistry;
    address public nullifierManager;
    address public compliance;
    address public proofTranslator;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Whether compliance checks are enforced
    bool public complianceEnabled = true;

    /// @notice Minimum KYC tier required (0 = no minimum)
    uint8 public minimumKYCTier;

    /// @notice Operation nonce
    uint256 public operationNonce;

    /// @notice Total operations by type
    mapping(OperationType => uint256) public operationCounts;

    /// @notice Operation receipts
    mapping(bytes32 => OperationReceipt) public receipts;

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
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        address _shieldedPool,
        address _crossChainHub,
        address _stealthRegistry,
        address _nullifierManager,
        address _compliance,
        address _proofTranslator
    ) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_shieldedPool == address(0)) revert ZeroAddress();
        if (_crossChainHub == address(0)) revert ZeroAddress();
        if (_stealthRegistry == address(0)) revert ZeroAddress();
        if (_nullifierManager == address(0)) revert ZeroAddress();
        if (_compliance == address(0)) revert ZeroAddress();
        if (_proofTranslator == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);

        shieldedPool = _shieldedPool;
        crossChainHub = _crossChainHub;
        stealthRegistry = _stealthRegistry;
        nullifierManager = _nullifierManager;
        compliance = _compliance;
        proofTranslator = _proofTranslator;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit native ETH into the shielded pool
    /// @param commitment The Pedersen commitment: H(secret, nullifier, amount)
    /// @return operationId Unique operation identifier
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

        // Forward to shielded pool
        (bool success, ) = shieldedPool.call{value: msg.value}(
            abi.encodeWithSignature("depositETH(bytes32)", commitment)
        );
        if (!success) revert OperationFailed("ETH deposit failed");

        _recordReceipt(operationId, OperationType.DEPOSIT, commitment);

        emit PrivateDeposit(operationId, commitment, bytes32(0), msg.value);
    }

    /// @notice Deposit ERC20 tokens into the shielded pool
    /// @param assetId The registered asset identifier
    /// @param amount Token amount to deposit
    /// @param commitment The Pedersen commitment
    /// @return operationId Unique operation identifier
    function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external nonReentrant whenNotPaused returns (bytes32 operationId) {
        _requireComponent(shieldedPool, "shieldedPool");
        _checkCompliance(msg.sender);

        if (amount == 0) revert ZeroAmount();

        operationId = _nextOperationId();

        // The user must have approved the shielded pool directly,
        // or we transfer to this contract first then forward.
        // For gas efficiency, require direct approval to shieldedPool.
        (bool success, ) = shieldedPool.call(
            abi.encodeWithSignature(
                "depositERC20(bytes32,uint256,bytes32)",
                assetId,
                amount,
                commitment
            )
        );
        if (!success) revert OperationFailed("ERC20 deposit failed");

        _recordReceipt(operationId, OperationType.DEPOSIT, commitment);

        emit PrivateDeposit(operationId, commitment, assetId, amount);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw from the shielded pool with a ZK proof
    /// @param params Withdrawal parameters including proof and nullifier
    /// @return operationId Unique operation identifier
    function withdraw(
        WithdrawParams calldata params
    ) external nonReentrant whenNotPaused returns (bytes32 operationId) {
        _requireComponent(shieldedPool, "shieldedPool");

        // Compliance check on recipient (not msg.sender — may be relayer)
        _checkCompliance(params.recipient);

        operationId = _nextOperationId();

        // Encode the WithdrawalProof struct for the shielded pool
        (bool success, ) = shieldedPool.call(
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
        if (!success) revert OperationFailed("Withdrawal failed");

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
    /// @param params Transfer parameters
    /// @return operationId Operation identifier
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

        // Compose the PrivacyProof struct for CrossChainPrivacyHub
        (bool success, ) = crossChainHub.call{value: msg.value}(
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
            )
        );
        if (!success) revert OperationFailed("Cross-chain transfer failed");

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

    /// @notice Register a stealth meta-address for receiving private payments
    /// @param spendingPubKey The spending public key
    /// @param viewingPubKey The viewing public key
    /// @param curveType Elliptic curve type (0=SECP256K1, 1=ED25519, etc.)
    /// @param schemeId Stealth address scheme identifier
    function registerStealthMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        uint8 curveType,
        uint256 schemeId
    ) external nonReentrant whenNotPaused {
        _requireComponent(stealthRegistry, "stealthRegistry");
        _checkCompliance(msg.sender);

        (bool success, ) = stealthRegistry.call(
            abi.encodeWithSignature(
                "registerMetaAddress(bytes,bytes,uint8,uint256)",
                spendingPubKey,
                viewingPubKey,
                curveType,
                schemeId
            )
        );
        if (!success) revert OperationFailed("Stealth registration failed");
    }

    /// @notice Derive a one-time stealth address for a recipient
    /// @param recipient The intended recipient address
    /// @param ephemeralPubKey Ephemeral public key for DKSAP
    /// @param sharedSecretHash Hash of the DH shared secret
    /// @return stealthAddress The derived stealth address
    /// @return viewTag Single-byte view tag for scanning
    function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag) {
        _requireComponent(stealthRegistry, "stealthRegistry");

        (bool success, bytes memory result) = stealthRegistry.staticcall(
            abi.encodeWithSignature(
                "deriveStealthAddress(address,bytes,bytes32)",
                recipient,
                ephemeralPubKey,
                sharedSecretHash
            )
        );
        require(success, "Stealth derivation failed");
        (stealthAddress, viewTag) = abi.decode(result, (address, bytes1));
    }

    /*//////////////////////////////////////////////////////////////
                         QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a nullifier has been spent
    function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        if (nullifierManager == address(0)) return false;

        (bool success, bytes memory result) = nullifierManager.staticcall(
            abi.encodeWithSignature("isNullifierSpent(bytes32)", nullifier)
        );
        if (!success) return false;
        return abi.decode(result, (bool));
    }

    /// @notice Check if a user passes compliance requirements
    function checkCompliance(address user) external view returns (bool passes) {
        if (!complianceEnabled || compliance == address(0)) return true;

        (bool success, bytes memory result) = compliance.staticcall(
            abi.encodeWithSignature("isKYCValid(address)", user)
        );
        if (!success) return false;
        passes = abi.decode(result, (bool));
    }

    /// @notice Get total operations by type
    function getOperationCount(
        OperationType opType
    ) external view returns (uint256) {
        return operationCounts[opType];
    }

    /// @notice Get operation receipt
    function getReceipt(
        bytes32 operationId
    ) external view returns (OperationReceipt memory) {
        return receipts[operationId];
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update a protocol component address
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
    /// @param hub The SoulProtocolHub contract address
    function syncFromHub(address hub) external onlyRole(OPERATOR_ROLE) {
        if (hub == address(0)) revert ZeroAddress();
        ISoulProtocolHub h = ISoulProtocolHub(hub);

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

    /// @notice Toggle compliance enforcement
    function setComplianceEnabled(
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        complianceEnabled = enabled;
        emit ComplianceToggled(enabled);
    }

    /// @notice Set minimum KYC tier required
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

    /// @notice Emergency pause
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpause
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Generate next unique operation ID
    function _nextOperationId() internal returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(msg.sender, block.chainid, operationNonce++)
            );
    }

    /// @notice Record an operation receipt
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

    /// @notice Require a component to be configured
    function _requireComponent(
        address component,
        string memory name
    ) internal pure {
        if (component == address(0)) revert ComponentNotSet(name);
    }

    /// @notice Check compliance for a user (KYC + sanctions)
    /// @dev Fail-closed: reverts if compliance oracle is unreachable
    function _checkCompliance(address user) internal view {
        if (!complianceEnabled || compliance == address(0)) return;

        // Check sanctions — fail-closed on oracle failure
        (bool sSuccess, bytes memory sResult) = compliance.staticcall(
            abi.encodeWithSignature("sanctionedAddresses(address)", user)
        );
        if (!sSuccess || sResult.length < 32)
            revert ComplianceCheckFailed(user);
        {
            bool sanctioned = abi.decode(sResult, (bool));
            if (sanctioned) revert SanctionedAddress(user);
        }

        // Check KYC validity — fail-closed on oracle failure
        (bool kSuccess, bytes memory kResult) = compliance.staticcall(
            abi.encodeWithSignature("isKYCValid(address)", user)
        );
        if (!kSuccess || kResult.length < 32)
            revert ComplianceCheckFailed(user);
        {
            bool valid = abi.decode(kResult, (bool));
            if (!valid) revert ComplianceCheckFailed(user);
        }

        // Check minimum KYC tier if required — fail-closed
        if (minimumKYCTier > 0) {
            (bool tSuccess, bytes memory tResult) = compliance.staticcall(
                abi.encodeWithSignature(
                    "meetsKYCTier(address,uint8)",
                    user,
                    minimumKYCTier
                )
            );
            if (!tSuccess || tResult.length < 32)
                revert ComplianceCheckFailed(user);
            {
                bool meets = abi.decode(tResult, (bool));
                if (!meets) revert InsufficientKYCTier(user, minimumKYCTier, 0);
            }
        }
    }

    /// @notice Accept ETH for deposits
    receive() external payable {}
}
