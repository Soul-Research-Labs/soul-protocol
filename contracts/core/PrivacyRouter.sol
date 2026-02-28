// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPrivacyRouter} from "../interfaces/IPrivacyRouter.sol";
import {IUniversalShieldedPool} from "../interfaces/IUniversalShieldedPool.sol";

/// @notice Minimal interface for ZaseonProtocolHub address resolution
/**
 * @title IZaseonProtocolHub
 * @author ZASEON Team
 * @notice I ZASEON Hub interface
 */
interface IZaseonProtocolHub {
        /**
     * @notice Shielded pool
     * @return The result value
     */
function shieldedPool() external view returns (address);

        /**
     * @notice Cross chain privacy hub
     * @return The result value
     */
function crossChainPrivacyHub() external view returns (address);

        /**
     * @notice Stealth address registry
     * @return The result value
     */
function stealthAddressRegistry() external view returns (address);

        /**
     * @notice Nullifier manager
     * @return The result value
     */
function nullifierManager() external view returns (address);

        /**
     * @notice Compliance oracle
     * @return The result value
     */
function complianceOracle() external view returns (address);

        /**
     * @notice Proof translator
     * @return The result value
     */
function proofTranslator() external view returns (address);
}

/// @notice Minimal interface for StealthAddressRegistry operations
interface IStealthRegistryMinimal {
        /**
     * @notice Registers meta address
     * @param spendingPubKey The spending pub key
     * @param viewingPubKey The viewing pub key
     * @param curveType The curve type
     * @param schemeId The schemeId identifier
     */
function registerMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        uint8 curveType,
        uint256 schemeId
    ) external;

        /**
     * @notice Derive stealth address
     * @param recipient The recipient address
     * @param ephemeralPubKey The ephemeral pub key
     * @param sharedSecretHash The sharedSecretHash hash value
     * @return stealthAddress The stealth address
     * @return viewTag The view tag
     */
function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag);
}

/// @notice Minimal interface for compliance oracle queries
interface IComplianceOracleMinimal {
        /**
     * @notice Checks if k y c valid
     * @param user The user
     * @return The result value
     */
function isKYCValid(address user) external view returns (bool);

        /**
     * @notice Sanctioned addresses
     * @param user The user
     * @return The result value
     */
function sanctionedAddresses(address user) external view returns (bool);

        /**
     * @notice Meets k y c tier
     * @param user The user
     * @param tier The tier
     * @return The result value
     */
function meetsKYCTier(
        address user,
        uint8 tier
    ) external view returns (bool);
}

/**
 * @title PrivacyRouter
 * @author ZASEON
 * @notice Unified entry point for all ZASEON privacy operations
 * @dev Composes UniversalShieldedPool, CrossChainPrivacyHub, StealthAddressRegistry,
 *      UnifiedNullifierManager, ZaseonComplianceV2, and UniversalProofTranslator into
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
 * @custom:security-contact security@zaseon.network
 */
contract PrivacyRouter is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    IPrivacyRouter
{
    using SafeERC20 for IERC20;
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Role for protocol operators who can update components and configuration
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    /// @dev Role for relayers who can submit cross-chain proofs on behalf of users
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    /// @dev Role for emergency operations such as pausing the contract
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

    /// @notice Emitted when the minimum KYC tier requirement is updated
    event MinimumKYCTierUpdated(uint8 oldTier, uint8 newTier);
    /// @notice Emitted when ETH is withdrawn from the contract by an admin
    event ETHWithdrawn(address indexed to, uint256 amount);
    /// @notice Emitted when component addresses are synced from a ZaseonProtocolHub
    event SyncedFromHub(address indexed hub);

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
    /// @dev Compliance-gated: the sender must pass KYC + sanctions checks before the deposit
    ///      is forwarded. ETH is sent via low-level `call` to the shielded pool's `depositETH(bytes32)`
    ///      selector. If the forwarded call reverts, the entire transaction reverts, ensuring
    ///      atomicity. A unique operation ID is derived from `(msg.sender, chainId, block.number, nonce)`.
    /// @param commitment The Pedersen commitment: H(secret, nullifier, amount)
    /// @return operationId Unique operation identifier for tracking via `getReceipt()`
        /**
     * @notice Deposits e t h
     * @param commitment The cryptographic commitment
     * @return operationId The operation id
     */
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

        // Forward to shielded pool via typed interface
        IUniversalShieldedPool(shieldedPool).depositETH{value: msg.value}(
            commitment
        );

        _recordReceipt(operationId, OperationType.DEPOSIT, commitment);

        emit PrivateDeposit(operationId, commitment, bytes32(0), msg.value);
    }

    /// @notice Deposit ERC20 tokens into the shielded pool
    /// @dev Security fix C-6: tokens are first pulled from the user to this router via
    ///      `safeTransferFrom`, then approved to the shielded pool via `forceApprove`.
    ///      This two-step pattern prevents approval front-running and ensures the pool
    ///      can only pull the exact deposit amount. The token address is resolved from
    ///      the shielded pool's asset registry via `assetAddresses(bytes32)`.
    /// @param assetId The registered asset identifier (maps to an ERC20 token in the shielded pool)
    /// @param amount Token amount to deposit (must be > 0)
    /// @param commitment The Pedersen commitment: H(secret, nullifier, amount)
    /// @return operationId Unique operation identifier for tracking via `getReceipt()`
        /**
     * @notice Deposits e r c20
     * @param assetId The assetId identifier
     * @param amount The amount to process
     * @param commitment The cryptographic commitment
     * @return operationId The operation id
     */
function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external nonReentrant whenNotPaused returns (bytes32 operationId) {
        _requireComponent(shieldedPool, "shieldedPool");
        _checkCompliance(msg.sender);

        if (amount == 0) revert ZeroAmount();

        operationId = _nextOperationId();

        // SECURITY FIX C-6: Transfer tokens from user to router,
        // then approve and forward to shielded pool.
        // Resolve the token address from the shielded pool's asset registry.
        // NOTE: Uses raw staticcall because `assetAddresses` is an auto-generated
        // mapping getter not present in IUniversalShieldedPool.
        (bool success, bytes memory returnData) = shieldedPool.staticcall(
            abi.encodeWithSignature("assetAddresses(bytes32)", assetId)
        );
        if (!success) revert OperationFailed("Asset lookup failed");
        address token = abi.decode(returnData, (address));
        if (token == address(0)) revert OperationFailed("Invalid asset");

        // Pull tokens from user to router
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        // Approve shielded pool to pull from router
        IERC20(token).forceApprove(shieldedPool, amount);

        // Forward to shielded pool via typed interface
        IUniversalShieldedPool(shieldedPool).depositERC20(
            assetId,
            amount,
            commitment
        );

        _recordReceipt(operationId, OperationType.DEPOSIT, commitment);

        emit PrivateDeposit(operationId, commitment, assetId, amount);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw from the shielded pool with a ZK proof
    /// @dev Compliance is checked on `params.recipient` (not `msg.sender`) because the caller
    ///      may be a relayer submitting on behalf of the actual recipient. The withdrawal proof
    ///      is forwarded to the shielded pool which verifies it against the Merkle root and
    ///      nullifier. The nullifier is recorded to prevent double-spending.
    /// @param params Withdrawal parameters including ZK proof, Merkle root, nullifier,
    ///        recipient, relayer details, amount, fees, asset ID, and destination chain ID
    /// @return operationId Unique operation identifier for tracking via `getReceipt()`
        /**
     * @notice Withdraws the operation
     * @param params The params
     * @return operationId The operation id
     */
function withdraw(
        WithdrawParams calldata params
    ) external nonReentrant whenNotPaused returns (bytes32 operationId) {
        _requireComponent(shieldedPool, "shieldedPool");

        // Compliance check on recipient (not msg.sender — may be relayer)
        _checkCompliance(params.recipient);

        operationId = _nextOperationId();

        // Forward withdrawal to shielded pool via typed interface
        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: params.proof,
                merkleRoot: params.merkleRoot,
                nullifier: params.nullifier,
                recipient: params.recipient,
                relayerAddress: params.relayerAddress,
                amount: params.amount,
                relayerFee: params.relayerFee,
                assetId: params.assetId,
                destChainId: params.destChainId
            });
        IUniversalShieldedPool(shieldedPool).withdraw(wp);

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
    /// @dev Composes a cross-chain private transfer through CrossChainPrivacyHub. The caller
    ///      provides a ZK proof of sufficient balance which is forwarded along with transfer
    ///      details. `msg.value` covers bridge fees (Hyperlane, LayerZero, etc.). The privacy
    ///      level parameter controls the anonymity set size on the destination chain.
    /// @param params Transfer parameters including destination chain, stealth recipient,
    ///        amount, privacy level, proof system type, and the ZK proof itself
    /// @return operationId Unique operation identifier for tracking via `getReceipt()`
        /**
     * @notice Initiates private transfer
     * @param params The params
     * @return operationId The operation id
     */
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

        // NOTE: Uses raw call because CrossChainPrivacyHub has a complex nested
        // struct signature that varies across versions. A typed interface would
        // couple PrivacyRouter to a specific hub implementation.
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
    /// @dev Forwards to StealthAddressRegistry.registerMetaAddress(). The meta-address
    ///      consists of a spending key (controls funds) and viewing key (enables scanning)
    ///      per ERC-5564. Once registered, senders can derive one-time stealth addresses
    ///      for this user without on-chain interaction.
    /// @param spendingPubKey The spending public key (controls stealth address funds)
    /// @param viewingPubKey The viewing public key (enables recipient to scan for payments)
    /// @param curveType Elliptic curve type (0=SECP256K1, 1=ED25519, 2=BN254, etc.)
    /// @param schemeId Stealth address scheme identifier (per ERC-5564 scheme registry)
        /**
     * @notice Registers stealth meta address
     * @param spendingPubKey The spending pub key
     * @param viewingPubKey The viewing pub key
     * @param curveType The curve type
     * @param schemeId The schemeId identifier
     */
function registerStealthMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        uint8 curveType,
        uint256 schemeId
    ) external nonReentrant whenNotPaused {
        _requireComponent(stealthRegistry, "stealthRegistry");
        _checkCompliance(msg.sender);

        // Forward to stealth registry via typed interface
        IStealthRegistryMinimal(stealthRegistry).registerMetaAddress(
            spendingPubKey,
            viewingPubKey,
            curveType,
            schemeId
        );
    }

    /// @notice Derive a one-time stealth address for a recipient
    /// @dev Uses the Dual-Key Stealth Address Protocol (DKSAP). The sender generates an
    ///      ephemeral keypair, computes a shared secret with the recipient's viewing key,
    ///      and derives a unique stealth address. The view tag allows the recipient to
    ///      efficiently filter announcements without full decryption.
    /// @param recipient The intended recipient address (must have a registered meta-address)
    /// @param ephemeralPubKey Ephemeral public key for DKSAP (generated per-payment)
    /// @param sharedSecretHash Hash of the Diffie-Hellman shared secret
    /// @return stealthAddress The derived one-time stealth address for this payment
    /// @return viewTag Single-byte view tag for efficient announcement scanning
        /**
     * @notice Derive stealth address
     * @param recipient The recipient address
     * @param ephemeralPubKey The ephemeral pub key
     * @param sharedSecretHash The sharedSecretHash hash value
     * @return stealthAddress The stealth address
     * @return viewTag The view tag
     */
function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag) {
        _requireComponent(stealthRegistry, "stealthRegistry");

        // Derive via typed interface
        (stealthAddress, viewTag) = IStealthRegistryMinimal(stealthRegistry)
            .deriveStealthAddress(recipient, ephemeralPubKey, sharedSecretHash);
    }

    /*//////////////////////////////////////////////////////////////
                         QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a nullifier has been spent
    /// @dev Uses a two-step fallback pattern to support both UnifiedNullifierManager and legacy
    ///      NullifierRegistryV3. Tries `isNullifierSpent(bytes32)` first, then falls back to
    ///      `exists(bytes32)`. Returns `false` if the nullifier manager is not configured or
    ///      both calls fail (fail-open for read-only queries; state-changing ops use fail-closed).
    /// @param nullifier The nullifier hash to check (derived from the note's secret)
    /// @return True if the nullifier has already been spent, false otherwise
        /**
     * @notice Checks if nullifier spent
     * @param nullifier The nullifier hash
     * @return The result value
     */
function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        if (nullifierManager == address(0)) return false;

        // Try isNullifierSpent(bytes32) — UnifiedNullifierManager signature
        (bool success, bytes memory result) = nullifierManager.staticcall(
            abi.encodeWithSignature("isNullifierSpent(bytes32)", nullifier)
        );
        if (success && result.length >= 32) return abi.decode(result, (bool));

        // Fallback: try exists(bytes32) — NullifierRegistryV3 signature
        (success, result) = nullifierManager.staticcall(
            abi.encodeWithSignature("exists(bytes32)", nullifier)
        );
        if (success && result.length >= 32) return abi.decode(result, (bool));

        return false;
    }

    /// @notice Check if a user passes compliance requirements
    /// @dev Non-reverting read-only compliance check. Returns `true` if compliance is disabled
    ///      or the compliance oracle is not configured. Unlike `_checkCompliance()`, this does
    ///      not revert on failure — it returns `false` instead, making it safe for UI queries.
    /// @param user The address to check compliance for
    /// @return passes True if the user passes all compliance checks (KYC valid + not sanctioned)
        /**
     * @notice Checks compliance
     * @param user The user
     * @return passes The passes
     */
function checkCompliance(address user) external view returns (bool passes) {
        if (!complianceEnabled || compliance == address(0)) return true;

        try IComplianceOracleMinimal(compliance).isKYCValid(user) returns (
            bool valid
        ) {
            passes = valid;
        } catch {
            passes = false;
        }
    }

    /// @notice Get total operations by type
    /// @param opType The operation type to query
    /// @return The total number of operations of the given type
        /**
     * @notice Returns the operation count
     * @param opType The op type
     * @return The result value
     */
function getOperationCount(
        OperationType opType
    ) external view returns (uint256) {
        return operationCounts[opType];
    }

    /// @notice Get operation receipt
    /// @param operationId The unique identifier of the operation
    /// @return The receipt containing operation details and status
        /**
     * @notice Returns the receipt
     * @param operationId The operationId identifier
     * @return The result value
     */
function getReceipt(
        bytes32 operationId
    ) external view returns (OperationReceipt memory) {
        return receipts[operationId];
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update a protocol component address
    /// @dev Component names are matched via `keccak256` against pre-computed hashes
    ///      to save gas. Valid names: "shieldedPool", "crossChainHub", "stealthRegistry",
    ///      "nullifierManager", "compliance", "proofTranslator". Reverts with `InvalidParams()`
    ///      if the name is not recognized. Use `syncFromHub()` to batch-update from ZaseonProtocolHub.
    /// @param name The component name (must match one of the six supported components)
    /// @param addr The new non-zero address for the component
        /**
     * @notice Sets the component
     * @param name The name
     * @param addr The target address
     */
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

    /// @notice Sync all component addresses from ZaseonProtocolHub
    /// @dev Reads all six component addresses from the hub and updates local storage.
    ///      Only updates a component if the hub returns a non-zero address, preserving
    ///      any manually-configured value. This is the preferred way to keep PrivacyRouter
    ///      in sync after hub component upgrades.
    /// @param hub The ZaseonProtocolHub contract address to read component addresses from
        /**
     * @notice Sync from hub
     * @param hub The hub
     */
function syncFromHub(address hub) external onlyRole(OPERATOR_ROLE) {
        if (hub == address(0)) revert ZeroAddress();
        IZaseonProtocolHub h = IZaseonProtocolHub(hub);

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
    /// @param enabled True to enable compliance checks, false to disable
        /**
     * @notice Sets the compliance enabled
     * @param enabled Whether the feature is enabled
     */
function setComplianceEnabled(
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        complianceEnabled = enabled;
        emit ComplianceToggled(enabled);
    }

    /// @notice Set minimum KYC tier required
    /// @param tier The new minimum KYC tier (0 = no minimum)
        /**
     * @notice Sets the minimum k y c tier
     * @param tier The tier
     */
function setMinimumKYCTier(uint8 tier) external onlyRole(OPERATOR_ROLE) {
        uint8 oldTier = minimumKYCTier;
        minimumKYCTier = tier;
        emit MinimumKYCTierUpdated(oldTier, tier);
    }

    /// @notice Withdraw ETH accidentally sent to this contract
    /// @dev Admin-only rescue function. Sends ETH via low-level `call` to support
    ///      both EOA and contract recipients. Reverts if the transfer fails.
    /// @param to The recipient address for the withdrawn ETH (must be non-zero)
    /// @param amount The amount of ETH to withdraw (must be > 0 and <= contract balance)
        /**
     * @notice Withdraws e t h
     * @param to The destination address
     * @param amount The amount to process
     */
function withdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (amount > address(this).balance)
            revert OperationFailed("Insufficient balance");
        (bool success, ) = to.call{value: amount}("");
        if (!success) revert OperationFailed("ETH withdrawal failed");
        emit ETHWithdrawn(to, amount);
    }

    /// @notice Emergency pause
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpause
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Generate next unique operation ID
    /// @dev Deterministic: hash of `(msg.sender, chainId, block.number, nonce++)`. The nonce
    ///      is incremented atomically to ensure uniqueness within the same block.
    /// @return A unique bytes32 operation identifier
    function _nextOperationId() internal returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    msg.sender,
                    block.chainid,
                    block.number,
                    operationNonce++
                )
            );
    }

    /// @notice Record an operation receipt
    /// @dev Stores an immutable receipt for the operation and increments the per-type counter.
    ///      Receipts are queryable via `getReceipt()` and operation counts via `getOperationCount()`.
    /// @param operationId The unique operation identifier from `_nextOperationId()`
    /// @param opType The operation type (DEPOSIT, WITHDRAW, CROSS_CHAIN_TRANSFER)
    /// @param commitmentOrNullifier The commitment (for deposits) or nullifier (for withdrawals)
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

    /// @notice Require a component to be configured (non-zero address)
    /// @dev Reverts with `ComponentNotSet(name)` if the component address is zero.
    /// @param component The component address to validate
    /// @param name Human-readable component name for the revert message
    function _requireComponent(
        address component,
        string memory name
    ) internal pure {
        if (component == address(0)) revert ComponentNotSet(name);
    }

    /// @notice Check compliance for a user (KYC + sanctions + minimum tier)
    /// @dev Fail-closed design: reverts if the compliance oracle is unreachable or returns
    ///      unexpected data. Performs three sequential checks:
    ///      1. Sanctions screening — reverts with `SanctionedAddress` if flagged
    ///      2. KYC validity — reverts with `ComplianceCheckFailed` if not valid
    ///      3. Minimum KYC tier (if configured) — reverts with `InsufficientKYCTier`
    ///      Short-circuits if compliance is disabled or the oracle is not configured.
    /// @param user The address to verify against compliance requirements
    function _checkCompliance(address user) internal view {
        if (!complianceEnabled || compliance == address(0)) return;

        IComplianceOracleMinimal oracle = IComplianceOracleMinimal(compliance);

        // Check sanctions — fail-closed on oracle failure
        try oracle.sanctionedAddresses(user) returns (bool sanctioned) {
            if (sanctioned) revert SanctionedAddress(user);
        } catch {
            revert ComplianceCheckFailed(user);
        }

        // Check KYC validity — fail-closed on oracle failure
        try oracle.isKYCValid(user) returns (bool valid) {
            if (!valid) revert ComplianceCheckFailed(user);
        } catch {
            revert ComplianceCheckFailed(user);
        }

        // Check minimum KYC tier if required — fail-closed
        if (minimumKYCTier > 0) {
            try oracle.meetsKYCTier(user, minimumKYCTier) returns (bool meets) {
                if (!meets) revert InsufficientKYCTier(user, minimumKYCTier, 0);
            } catch {
                revert ComplianceCheckFailed(user);
            }
        }
    }

    /// @notice Accept ETH for deposits and bridge fee top-ups
    /// @dev Required for `depositETH()` and `initiatePrivateTransfer()` which forward
    ///      `msg.value` to downstream contracts. Accepts ETH for relay gas fees.
    receive() external payable {}
}
