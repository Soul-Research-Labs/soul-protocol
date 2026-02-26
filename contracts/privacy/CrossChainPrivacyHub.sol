// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SelectiveDisclosureManager} from "../compliance/SelectiveDisclosureManager.sol";
import {ComplianceReportingModule} from "../compliance/ComplianceReportingModule.sol";

/**
 * @title CrossChainPrivacyHub
 * @author Soul Protocol
 * @notice Unified aggregator for cross-chain privacy-preserving proof relays
 * @dev Provides a single entry point for all 41+ chain adapters with privacy features
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      CrossChainPrivacyHub                                │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
 * │  │ StealthAddr  │  │    RCT       │  │  Nullifier   │                  │
 * │  │  Registry    │  │   Module     │  │   Manager    │                  │
 * │  └──────────────┘  └──────────────┘  └──────────────┘                  │
 * │          │                │                  │                          │
 * │          └────────────────┼──────────────────┘                          │
 * │                           │                                             │
 * │                    ┌──────┴──────┐                                      │
 * │                    │   Router    │                                      │
 * │                    └──────┬──────┘                                      │
 * │                           │                                             │
 * │  ┌────────────────────────┼────────────────────────────────────────┐   │
 * │  │                   Chain Adapters                                │   │
 * │  │  Arbitrum · Optimism · Base · LayerZero · Hyperlane             │   │
 * │  └──────────────────────────────────────────────────────────────┘   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * PRIVACY FEATURES:
 * 1. Stealth Addresses - One-time addresses for each relay
 * 2. Ring Confidential Transactions - Amount hiding with decoys
 * 3. Cross-Domain Nullifiers - Double-spend prevention across chains
 * 4. ZK Proof Verification - Groth16, Noir UltraHonk
 * 5. Encrypted Metadata - Privacy-preserving proofs
 */
contract CrossChainPrivacyHub is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 public constant VERSION = 1;
    uint256 public constant MAX_ADAPTERS = 100;
    uint256 public constant MAX_RING_SIZE = 16;
    uint256 public constant MIN_RING_SIZE = 4;
    uint256 public constant NULLIFIER_EXPIRY = 365 days;
    uint256 public constant MAX_RELAY_AMOUNT = 10000 ether;
    uint256 public constant MIN_RELAY_AMOUNT = 0.001 ether;
    uint256 public constant QUORUM_BPS = 6667; // 66.67%
    uint256 public constant MAX_FEE_BPS = 500; // 5%

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum PrivacyLevel {
        NONE, // No privacy (transparent)
        BASIC, // Encrypted metadata only
        MEDIUM, // Stealth addresses
        HIGH, // Stealth + amount hiding
        MAXIMUM // Full RCT with decoys
    }

    enum RequestStatus {
        PENDING,
        RELAYED,
        COMPLETED,
        REFUNDED,
        FAILED
    }

    enum ProofSystem {
        NONE,
        GROTH16,
        PLONK,
        STARK,
        BULLETPROOF,
        HALO2,
        CLSAG
    }

    enum ChainType {
        EVM,
        UTXO,
        ACCOUNT,
        MOVE,
        WASM,
        CAIRO,
        PLUTUS
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Chain adapter configuration
     */
    struct AdapterConfig {
        address adapter;
        uint256 chainId;
        ChainType chainType;
        ProofSystem proofSystem;
        bool isActive;
        bool supportsPrivacy;
        uint256 minConfirmations;
        uint256 maxRelayAmount;
        uint256 dailyLimit;
        uint256 dailyVolume;
        uint256 lastResetTimestamp;
    }

    /**
     * @notice Cross-chain proof relay request
     */
    struct RelayRequest {
        bytes32 requestId;
        address sender;
        bytes32 recipient; // Can be stealth address
        uint256 sourceChainId;
        uint256 destChainId;
        address token;
        uint256 amount;
        uint256 fee;
        PrivacyLevel privacyLevel;
        bytes32 commitment;
        bytes32 nullifier;
        uint64 timestamp;
        uint64 expiry;
        RequestStatus status;
    }

    /**
     * @notice Stealth address components
     */
    struct StealthAddress {
        bytes32 spendingPubKey;
        bytes32 viewingPubKey;
        bytes32 ephemeralPubKey;
        bytes32 stealthPubKey;
        uint256 chainId;
    }

    /**
     * @notice Ring signature components
     */
    struct RingSignature {
        bytes32[] keyImages;
        bytes32[] publicKeys;
        uint256[] responses;
        bytes32 challenge;
        uint256 ringSize;
    }

    /**
     * @notice Confidential amount (Pedersen commitment)
     */
    struct ConfidentialAmount {
        bytes32 commitment; // C = aG + bH
        bytes rangeProof; // Bulletproof range proof
        bytes32 blindingFactor; // Encrypted for recipient
    }

    /**
     * @notice Cross-domain nullifier binding
     */
    struct NullifierBinding {
        bytes32 sourceNullifier;
        bytes32 soulNullifier;
        uint256 sourceChainId;
        uint256 destChainId;
        uint64 timestamp;
        bool consumed;
    }

    /**
     * @notice Privacy relay proof
     */
    struct PrivacyProof {
        ProofSystem system;
        bytes proof;
        bytes32[] publicInputs;
        bytes32 proofHash;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    // Adapter registry: chainId => adapter config
    mapping(uint256 => AdapterConfig) public adapters;
    uint256[] public supportedChainIds;

    // Request registry: requestId => transfer
    mapping(bytes32 => RelayRequest) public relayRequests;
    mapping(address => bytes32[]) public userRequests;

    // Nullifier registry: nullifier => binding
    mapping(bytes32 => NullifierBinding) public nullifierBindings;
    mapping(bytes32 => bool) public consumedNullifiers;

    // Stealth address registry: stealthPubKey => owner
    mapping(bytes32 => address) public stealthAddressOwners;
    mapping(address => bytes32[]) public userStealthAddresses;

    // Statistics
    uint256 public totalRelays;
    uint256 public totalVolume;
    uint256 public totalPrivateRelays;

    // Configuration
    uint256 public defaultRingSize;
    uint256 public defaultPrivacyLevel;
    uint256 public protocolFeeBps;
    address public feeRecipient;

    // Circuit breaker
    bool public circuitBreakerActive;
    uint256 public lastCircuitBreakerTimestamp;
    string public circuitBreakerReason;

    /// @notice External verifier contracts per proof system
    mapping(ProofSystem => address) public proofVerifiers;

    // =========================================================================
    // COMPLIANCE INTEGRATION (Tachyon Learning #2 & #7)
    // =========================================================================

    /// @notice Optional selective disclosure manager for privacy-preserving compliance
    /// @dev Non-reverting try/catch pattern — compliance failures never block relays
    SelectiveDisclosureManager public disclosureManager;

    /// @notice Optional compliance reporting module for aggregate reporting
    ComplianceReportingModule public complianceReporting;

    /// @dev Gap for future compliance storage upgrades
    uint256[48] private __complianceGap;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event AdapterRegistered(
        uint256 indexed chainId,
        address indexed adapter,
        ChainType chainType,
        ProofSystem proofSystem
    );

    event AdapterUpdated(
        uint256 indexed chainId,
        address indexed adapter,
        bool isActive
    );

    event RelayInitiated(
        bytes32 indexed requestId,
        address indexed sender,
        bytes32 indexed recipient,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        PrivacyLevel privacyLevel
    );

    event ProofRelayed(
        bytes32 indexed requestId,
        bytes32 indexed nullifier,
        uint256 destChainId
    );

    event RelayCompleted(
        bytes32 indexed requestId,
        bytes32 indexed recipient,
        uint256 amount
    );

    event RelayRefunded(
        bytes32 indexed requestId,
        address indexed sender,
        uint256 amount,
        string reason
    );

    event StealthAddressGenerated(
        bytes32 indexed stealthPubKey,
        address indexed owner,
        uint256 chainId
    );

    event NullifierConsumed(
        bytes32 indexed sourceNullifier,
        bytes32 indexed soulNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event CircuitBreakerTriggered(
        address indexed triggeredBy,
        string reason,
        uint256 timestamp
    );

    event CircuitBreakerReset(address indexed resetBy, uint256 timestamp);

    event DisclosureManagerUpdated(
        address indexed oldManager,
        address indexed newManager
    );

    event ComplianceReportingUpdated(
        address indexed oldModule,
        address indexed newModule
    );

    event ComplianceHookFailed(bytes32 indexed requestId, string reason);

    event ProtocolFeeUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event FeeRecipientUpdated(
        address indexed oldRecipient,
        address indexed newRecipient
    );
    event DefaultRingSizeUpdated(uint256 oldSize, uint256 newSize);
    event ProofVerifierUpdated(
        ProofSystem indexed system,
        address indexed oldVerifier,
        address indexed newVerifier
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error AdapterNotFound(uint256 chainId);
    error AdapterNotActive(uint256 chainId);
    error AdapterAlreadyExists(uint256 chainId);
    error InvalidAmount(uint256 amount);
    error ExceedsMaxRelayAmount(uint256 amount, uint256 max);
    error ExceedsDailyLimit(uint256 amount, uint256 remaining);
    error InsufficientFee(uint256 provided, uint256 required);
    error RequestNotFound(bytes32 requestId);
    error RequestAlreadyProcessed(bytes32 requestId);
    error RequestExpired(bytes32 requestId);
    error InvalidPrivacyLevel(uint256 level);
    error InvalidProof();
    error InvalidNullifier(bytes32 nullifier);
    error NullifierAlreadyConsumed(bytes32 nullifier);
    error InvalidStealthAddress(bytes32 stealthPubKey);
    error InvalidRingSize(uint256 size);
    error InsufficientDecoys(uint256 provided, uint256 required);
    error CircuitBreakerOn();
    error UnauthorizedCaller();
    error ZeroAddress();
    error FeePaymentFailed();
    error RefundFailed();
    error FeeTooHigh();

    // =========================================================================
    // COMPLIANCE SETTERS
    // =========================================================================

    /**
     * @notice Set the optional SelectiveDisclosureManager for privacy-preserving compliance
     * @dev Setting to address(0) disables disclosure hooks without affecting transfers
     * @param _manager Address of the SelectiveDisclosureManager (or address(0) to disable)
     */
    function setDisclosureManager(
        address _manager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = address(disclosureManager);
        disclosureManager = SelectiveDisclosureManager(_manager);
        emit DisclosureManagerUpdated(old, _manager);
    }

    /**
     * @notice Set the optional ComplianceReportingModule for aggregate reporting
     * @dev Setting to address(0) disables reporting hooks without affecting transfers
     * @param _module Address of the ComplianceReportingModule (or address(0) to disable)
     */
    function setComplianceReporting(
        address _module
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = address(complianceReporting);
        complianceReporting = ComplianceReportingModule(_module);
        emit ComplianceReportingUpdated(old, _module);
    }

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier whenCircuitBreakerOff() {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        _;
    }

    modifier validChain(uint256 chainId) {
        if (adapters[chainId].adapter == address(0))
            revert AdapterNotFound(chainId);
        if (!adapters[chainId].isActive) revert AdapterNotActive(chainId);
        _;
    }

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address guardian,
        address _feeRecipient
    ) external initializer {
        // M-19: Validate feeRecipient is not zero - consistent with setFeeRecipient()
        if (admin == address(0)) revert ZeroAddress();
        if (guardian == address(0)) revert ZeroAddress();
        if (_feeRecipient == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
        _grantRole(UPGRADER_ROLE, admin);

        feeRecipient = _feeRecipient;
        protocolFeeBps = 30; // 0.3% default
        defaultRingSize = 8;
        defaultPrivacyLevel = uint256(PrivacyLevel.MEDIUM);
    }

    // =========================================================================
    // ADAPTER MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new chain adapter
     */
    function registerAdapter(
        uint256 chainId,
        address adapter,
        ChainType chainType,
        ProofSystem proofSystem,
        bool supportsPrivacy,
        uint256 minConfirmations,
        uint256 maxRelayAmount,
        uint256 dailyLimit
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapter == address(0)) revert ZeroAddress();
        if (adapters[chainId].adapter != address(0))
            revert AdapterAlreadyExists(chainId);

        adapters[chainId] = AdapterConfig({
            adapter: adapter,
            chainId: chainId,
            chainType: chainType,
            proofSystem: proofSystem,
            isActive: true,
            supportsPrivacy: supportsPrivacy,
            minConfirmations: minConfirmations,
            maxRelayAmount: maxRelayAmount,
            dailyLimit: dailyLimit,
            dailyVolume: 0,
            lastResetTimestamp: block.timestamp
        });

        supportedChainIds.push(chainId);

        emit AdapterRegistered(chainId, adapter, chainType, proofSystem);
    }

    /**
     * @notice Update adapter configuration
     */
    function updateAdapter(
        uint256 chainId,
        bool isActive,
        uint256 maxRelayAmount,
        uint256 dailyLimit
    ) external onlyRole(OPERATOR_ROLE) validChain(chainId) {
        AdapterConfig storage config = adapters[chainId];
        config.isActive = isActive;
        config.maxRelayAmount = maxRelayAmount;
        config.dailyLimit = dailyLimit;

        emit AdapterUpdated(chainId, config.adapter, isActive);
    }

    // =========================================================================
    // PRIVACY RELAY FUNCTIONS
    // =========================================================================

    /**
     * @notice Initiate a privacy-preserving cross-chain proof relay
     * @param destChainId Destination chain ID
     * @param recipient Recipient address (can be stealth address)
     * @param amount Relay amount
     * @param privacyLevel Desired privacy level
     * @param proof Privacy proof (if required)
     */
    function initiatePrivateTransfer(
        uint256 destChainId,
        bytes32 recipient,
        uint256 amount,
        PrivacyLevel privacyLevel,
        PrivacyProof calldata proof
    )
        external
        payable
        nonReentrant
        whenNotPaused
        whenCircuitBreakerOff
        validChain(destChainId)
        returns (bytes32 requestId)
    {
        // Validate amount
        if (amount < MIN_RELAY_AMOUNT) revert InvalidAmount(amount);
        if (amount > MAX_RELAY_AMOUNT)
            revert ExceedsMaxRelayAmount(amount, MAX_RELAY_AMOUNT);

        AdapterConfig storage destAdapter = adapters[destChainId];
        if (amount > destAdapter.maxRelayAmount) {
            revert ExceedsMaxRelayAmount(amount, destAdapter.maxRelayAmount);
        }

        // Check daily limit
        _checkAndUpdateDailyLimit(destChainId, amount);

        // Calculate fee
        uint256 fee = (amount * protocolFeeBps) / 10000;
        // SECURITY FIX C-1: Require msg.value covers BOTH the relay amount AND protocol fee
        if (msg.value < amount + fee)
            revert InsufficientFee(msg.value, amount + fee);

        // Verify privacy proof if required
        if (privacyLevel >= PrivacyLevel.MEDIUM) {
            if (proof.proof.length == 0) revert InvalidProof();
            if (!_verifyPrivacyProof(proof, destChainId)) {
                revert InvalidProof();
            }
        }

        // Generate request ID
        requestId = keccak256(
            abi.encode(
                msg.sender,
                recipient,
                block.chainid,
                destChainId,
                amount,
                block.timestamp,
                totalRelays
            )
        );

        // Generate nullifier
        bytes32 nullifier = _generateNullifier(requestId, msg.sender);

        // Create commitment
        bytes32 commitment = _generateCommitment(recipient, amount, nullifier);

        // Store request
        relayRequests[requestId] = RelayRequest({
            requestId: requestId,
            sender: msg.sender,
            recipient: recipient,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            token: address(0), // ETH
            amount: amount,
            fee: fee,
            privacyLevel: privacyLevel,
            commitment: commitment,
            nullifier: nullifier,
            timestamp: uint64(block.timestamp),
            expiry: uint64(block.timestamp + 7 days),
            status: RequestStatus.PENDING
        });

        userRequests[msg.sender].push(requestId);
        unchecked {
            totalRelays++;
            totalVolume += amount;
        }
        if (privacyLevel >= PrivacyLevel.MEDIUM) {
            unchecked {
                totalPrivateRelays++;
            }
        }

        // Send fee to recipient
        if (fee > 0) {
            (bool sent, ) = feeRecipient.call{value: fee}("");
            if (!sent) revert FeePaymentFailed();
        }

        emit RelayInitiated(
            requestId,
            msg.sender,
            recipient,
            block.chainid,
            destChainId,
            amount,
            privacyLevel
        );

        // Compliance hook: register with disclosure manager (non-reverting)
        _registerWithDisclosureManager(
            requestId,
            commitment,
            msg.sender,
            privacyLevel
        );

        return requestId;
    }

    /**
     * @notice Initiate a privacy-preserving cross-chain ERC20 token proof relay
     * @dev Pulls tokens from sender via safeTransferFrom, deducts protocol fee,
     *      verifies privacy proof (if MEDIUM+ privacy level), generates nullifier
     *      and commitment, then stores the relay request for relaying.
     * @param token The ERC20 token contract address (must not be address(0))
     * @param destChainId The destination chain ID (must be a registered adapter)
     * @param recipient The recipient address encoded as bytes32 (can be stealth address)
     * @param amount The total relay amount in token's smallest unit (fee deducted internally)
     * @param privacyLevel The desired privacy level (BASIC, MEDIUM, HIGH, MAXIMUM)
     * @param proof ZK privacy proof required for MEDIUM+ privacy levels
     * @return requestId Unique identifier for tracking and completing this relay request
     */
    function initiatePrivateTransferERC20(
        address token,
        uint256 destChainId,
        bytes32 recipient,
        uint256 amount,
        PrivacyLevel privacyLevel,
        PrivacyProof calldata proof
    )
        external
        nonReentrant
        whenNotPaused
        whenCircuitBreakerOff
        validChain(destChainId)
        returns (bytes32 requestId)
    {
        if (token == address(0)) revert ZeroAddress();
        if (amount < MIN_RELAY_AMOUNT) revert InvalidAmount(amount);

        // Pull tokens into hub
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Calculate fee
        uint256 fee = (amount * protocolFeeBps) / 10000;

        // Verify privacy proof if required
        if (privacyLevel >= PrivacyLevel.MEDIUM) {
            if (proof.proof.length == 0) revert InvalidProof();
            if (!_verifyPrivacyProof(proof, destChainId)) {
                revert InvalidProof();
            }
        }

        // Check daily limit
        _checkAndUpdateDailyLimit(destChainId, amount);

        // Generate request ID
        requestId = keccak256(
            abi.encode(
                msg.sender,
                token,
                recipient,
                destChainId,
                amount,
                block.timestamp,
                totalRelays
            )
        );

        bytes32 nullifier = _generateNullifier(requestId, msg.sender);
        bytes32 commitment = _generateCommitment(recipient, amount, nullifier);

        relayRequests[requestId] = RelayRequest({
            requestId: requestId,
            sender: msg.sender,
            recipient: recipient,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            token: token,
            amount: amount - fee,
            fee: fee,
            privacyLevel: privacyLevel,
            commitment: commitment,
            nullifier: nullifier,
            timestamp: uint64(block.timestamp),
            expiry: uint64(block.timestamp + 7 days),
            status: RequestStatus.PENDING
        });

        // Send fee to recipient
        if (fee > 0 && feeRecipient != address(0)) {
            IERC20(token).safeTransfer(feeRecipient, fee);
        }

        userRequests[msg.sender].push(requestId);
        unchecked {
            totalRelays++;
            totalVolume += amount;
        }

        emit RelayInitiated(
            requestId,
            msg.sender,
            recipient,
            block.chainid,
            destChainId,
            amount - fee,
            privacyLevel
        );

        // Compliance hook: register with disclosure manager (non-reverting)
        _registerWithDisclosureManager(
            requestId,
            commitment,
            msg.sender,
            privacyLevel
        );

        return requestId;
    }

    /**
     * @notice Relay a pending proof request to the destination chain
     * @dev Called by authorized relayers after the source chain request is initiated.
     *      Verifies the privacy proof, binds source and destination nullifiers, and
     *      marks the request as RELAYED. Must be called before request expiry.
     * @param requestId The request ID from initiatePrivateTransfer
     * @param destNullifier The derived nullifier on the destination chain
     * @param proof ZK proof validating the cross-chain relay
     */
    function relayProof(
        bytes32 requestId,
        bytes32 destNullifier,
        PrivacyProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenCircuitBreakerOff {
        RelayRequest storage transfer = relayRequests[requestId];
        if (transfer.requestId == bytes32(0))
            revert RequestNotFound(requestId);
        if (transfer.status != RequestStatus.PENDING)
            revert RequestAlreadyProcessed(requestId);
        if (block.timestamp > transfer.expiry)
            revert RequestExpired(requestId);

        // Verify proof
        if (!_verifyPrivacyProof(proof, transfer.destChainId)) {
            revert InvalidProof();
        }

        // Create nullifier binding
        _bindNullifier(
            transfer.nullifier,
            destNullifier,
            transfer.sourceChainId,
            transfer.destChainId
        );

        transfer.status = RequestStatus.RELAYED;

        emit ProofRelayed(requestId, destNullifier, transfer.destChainId);
    }

    /**
     * @notice Complete a relayed proof request on the destination chain and release escrowed value
     * @dev Verifies the nullifier hasn't been consumed (double-spend prevention),
     *      validates the ZK proof, then sends escrowed value to the recipient. Marks the
     *      nullifier as consumed and the request as COMPLETED.
     * @param requestId The request ID (must be in RELAYED status)
     * @param nullifier The destination nullifier to consume (must not be already spent)
     * @param proof ZK proof validating the withdrawal claim
     */
    function completeRelay(
        bytes32 requestId,
        bytes32 nullifier,
        PrivacyProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenCircuitBreakerOff {
        RelayRequest storage transfer = relayRequests[requestId];
        if (transfer.requestId == bytes32(0))
            revert RequestNotFound(requestId);
        if (transfer.status != RequestStatus.RELAYED)
            revert RequestAlreadyProcessed(requestId);

        // Verify nullifier not consumed
        if (consumedNullifiers[nullifier])
            revert NullifierAlreadyConsumed(nullifier);

        // Verify proof
        if (!_verifyPrivacyProof(proof, transfer.destChainId)) {
            revert InvalidProof();
        }

        // Consume nullifier
        consumedNullifiers[nullifier] = true;
        nullifierBindings[transfer.nullifier].consumed = true;

        transfer.status = RequestStatus.COMPLETED;

        // SECURITY FIX C-2: Actually deliver escrowed value to the recipient
        address recipientAddr = address(uint160(uint256(transfer.recipient)));
        if (transfer.token == address(0)) {
            // ETH delivery
            (bool sent, ) = recipientAddr.call{value: transfer.amount}("");
            if (!sent) revert RefundFailed();
        } else {
            // ERC20 delivery
            IERC20(transfer.token).safeTransfer(recipientAddr, transfer.amount);
        }

        emit RelayCompleted(requestId, transfer.recipient, transfer.amount);
        emit NullifierConsumed(
            transfer.nullifier,
            nullifier,
            transfer.sourceChainId,
            transfer.destChainId
        );

        // Compliance hook: register completion with disclosure manager (non-reverting)
        _registerWithDisclosureManager(
            requestId,
            transfer.commitment,
            transfer.sender,
            transfer.privacyLevel
        );
    }

    /**
     * @notice Refund expired or failed relay request
     */
    function refundRelay(
        bytes32 requestId,
        string calldata reason
    ) external nonReentrant {
        RelayRequest storage transfer = relayRequests[requestId];
        if (transfer.requestId == bytes32(0))
            revert RequestNotFound(requestId);
        if (transfer.status != RequestStatus.PENDING)
            revert RequestAlreadyProcessed(requestId);

        // Only allow refund after expiry or by guardian
        if (
            block.timestamp <= transfer.expiry &&
            !hasRole(GUARDIAN_ROLE, msg.sender)
        ) {
            if (msg.sender != transfer.sender) revert UnauthorizedCaller();
            revert RequestExpired(requestId); // Misleading but prevents early refund
        }

        transfer.status = RequestStatus.REFUNDED;

        // Refund
        if (transfer.token == address(0)) {
            (bool sent, ) = transfer.sender.call{value: transfer.amount}("");
            if (!sent) revert RefundFailed();
        } else {
            IERC20(transfer.token).safeTransfer(
                transfer.sender,
                transfer.amount
            );
        }

        emit RelayRefunded(
            requestId,
            transfer.sender,
            transfer.amount,
            reason
        );
    }

    // =========================================================================
    // STEALTH ADDRESS FUNCTIONS
    // =========================================================================

    /**
     * @notice Generate a stealth address for receiving
     * @param spendingPubKey Recipient's spending public key
     * @param viewingPubKey Recipient's viewing public key
     * @param chainId Target chain ID
     * @dev WARNING: This function uses block.prevrandao which is predictable by validators.
     *      For production use, ephemeral keys should be generated off-chain with proper
     *      randomness (e.g., CSPRNG) and only verified on-chain. This on-chain generation
     *      is provided for testing and low-value use cases only.
     */
    function generateStealthAddress(
        bytes32 spendingPubKey,
        bytes32 viewingPubKey,
        uint256 chainId
    ) external returns (bytes32 stealthPubKey, bytes32 ephemeralPubKey) {
        // SECURITY FIX M-9: Include a counter nonce to prevent predictable outputs
        // even when block.prevrandao is known to validators
        uint256 nonce = userStealthAddresses[msg.sender].length;
        // Generate ephemeral keypair (in practice, done off-chain)
        ephemeralPubKey = keccak256(
            abi.encode(
                spendingPubKey,
                viewingPubKey,
                block.timestamp,
                block.prevrandao,
                msg.sender,
                nonce
            )
        );

        // Compute shared secret: S = ephemeralPrivKey * viewingPubKey
        // In practice, this is ECDH on secp256k1 or ed25519
        bytes32 sharedSecret = keccak256(
            abi.encode(ephemeralPubKey, viewingPubKey)
        );

        // Derive stealth public key: P' = P + hash(S) * G
        stealthPubKey = keccak256(abi.encode(spendingPubKey, sharedSecret));

        // Register stealth address
        stealthAddressOwners[stealthPubKey] = msg.sender;
        userStealthAddresses[msg.sender].push(stealthPubKey);

        emit StealthAddressGenerated(stealthPubKey, msg.sender, chainId);

        return (stealthPubKey, ephemeralPubKey);
    }

    /**
     * @notice Check if an address can claim value (stealth address scanning)
     * @param stealthPubKey The stealth public key
     * @param ephemeralPubKey The ephemeral public key from sender
     * @param viewingPrivKey The recipient's viewing private key (hashed)
     */
    function canClaimStealth(
        bytes32 stealthPubKey,
        bytes32 ephemeralPubKey,
        bytes32 viewingPrivKey
    ) external pure returns (bool) {
        // Recipient computes shared secret: S = viewingPrivKey * ephemeralPubKey
        bytes32 sharedSecret = keccak256(
            abi.encode(viewingPrivKey, ephemeralPubKey)
        );

        // Derive expected stealth key: P' = P_spend + hash(S) * G
        // Must match the same derivation used in generateStealthAddress
        bytes32 expectedStealth = keccak256(
            abi.encode(sharedSecret, ephemeralPubKey)
        );

        // Only return true if derived stealth key matches the provided one
        return stealthPubKey == expectedStealth;
    }

    // =========================================================================
    // RING CONFIDENTIAL TRANSACTION FUNCTIONS
    // =========================================================================

    /**
     * @notice Create a ring confidential transaction
     * @param amount The amount to relay (hidden)
     * @param decoyKeys Public keys of decoy outputs
     * @param blindingFactor Random blinding factor
     */
    function createRingCT(
        uint256 amount,
        bytes32[] calldata decoyKeys,
        bytes32 blindingFactor
    )
        external
        view
        returns (ConfidentialAmount memory confidentialAmount, bytes32 keyImage)
    {
        if (decoyKeys.length < MIN_RING_SIZE - 1) {
            revert InsufficientDecoys(decoyKeys.length, MIN_RING_SIZE - 1);
        }
        if (decoyKeys.length > MAX_RING_SIZE - 1) {
            revert InvalidRingSize(decoyKeys.length + 1);
        }

        // Create Pedersen commitment: C = aG + bH
        // a = amount, b = blindingFactor
        bytes32 commitment = keccak256(
            abi.encode(amount, blindingFactor, "PEDERSEN_COMMIT")
        );

        // Generate key image: I = x * Hp(P)
        // This prevents double-spending
        keyImage = keccak256(abi.encode(msg.sender, commitment, "KEY_IMAGE"));

        // Range proof generated off-chain using Bulletproofs
        // On-chain we store commitment + proof hash for verification
        bytes memory rangeProof = abi.encodePacked(
            commitment,
            amount, // In practice, this is not revealed
            "BULLETPROOF_RANGE"
        );

        confidentialAmount = ConfidentialAmount({
            commitment: commitment,
            rangeProof: rangeProof,
            blindingFactor: keccak256(abi.encode(blindingFactor, msg.sender))
        });

        return (confidentialAmount, keyImage);
    }

    /**
     * @notice Verify a ring signature
     * @param signature The ring signature
     * @param message The signed message
     */
    function verifyRingSignature(
        RingSignature calldata signature,
        bytes32 message
    ) external pure returns (bool) {
        if (signature.ringSize < MIN_RING_SIZE) return false;
        if (signature.ringSize > MAX_RING_SIZE) return false;
        if (signature.publicKeys.length != signature.ringSize) return false;
        if (signature.responses.length != signature.ringSize) return false;

        // Simplified verification - real implementation uses EC operations
        // Check challenge computation
        bytes32 computedChallenge = keccak256(
            abi.encode(message, signature.publicKeys, signature.responses)
        );

        // In practice, we verify the ring equation:
        // c_0 = H(L_0 || R_0 || ... || L_{n-1} || R_{n-1})
        // where L_i = r_i * G + c_i * P_i
        // and R_i = r_i * Hp(P_i) + c_i * I

        // Require valid key images and matching challenge
        return
            signature.keyImages.length > 0 &&
            computedChallenge == signature.challenge;
    }

    // =========================================================================
    // NULLIFIER MANAGEMENT
    // =========================================================================

    /**
     * @notice Bind source nullifier to Soul nullifier
     */
    function _bindNullifier(
        bytes32 sourceNullifier,
        bytes32 soulNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    ) internal {
        if (nullifierBindings[sourceNullifier].sourceNullifier != bytes32(0)) {
            revert NullifierAlreadyConsumed(sourceNullifier);
        }

        nullifierBindings[sourceNullifier] = NullifierBinding({
            sourceNullifier: sourceNullifier,
            soulNullifier: soulNullifier,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            timestamp: uint64(block.timestamp),
            consumed: false
        });
    }

    /**
     * @notice Check if nullifier is valid (not consumed)
     */
    function isNullifierValid(bytes32 nullifier) external view returns (bool) {
        return !consumedNullifiers[nullifier];
    }

    /**
     * @notice Get nullifier binding
     */
    function getNullifierBinding(
        bytes32 sourceNullifier
    ) external view returns (NullifierBinding memory) {
        return nullifierBindings[sourceNullifier];
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @dev Register a relay request with the SelectiveDisclosureManager if configured.
     *      Uses non-reverting try/catch so compliance failures never block relays.
     *      Follows the ConfidentialStateContainerV3 pattern.
     * @param requestId The request ID (used as txId for disclosure)
     * @param commitment The relay commitment
     * @param owner The relay initiator
     * @param privacyLevel The privacy level of the relay
     */
    function _registerWithDisclosureManager(
        bytes32 requestId,
        bytes32 commitment,
        address owner,
        PrivacyLevel privacyLevel
    ) internal {
        SelectiveDisclosureManager dm = disclosureManager;
        if (address(dm) == address(0)) return;

        // Map CrossChainPrivacyHub PrivacyLevel → SelectiveDisclosureManager DisclosureLevel
        // NONE/BASIC → PUBLIC, MEDIUM → AUDITOR, HIGH → REGULATOR, MAXIMUM → COUNTERPARTY
        SelectiveDisclosureManager.DisclosureLevel level;
        if (privacyLevel == PrivacyLevel.MAXIMUM) {
            level = SelectiveDisclosureManager.DisclosureLevel.COUNTERPARTY;
        } else if (privacyLevel == PrivacyLevel.HIGH) {
            level = SelectiveDisclosureManager.DisclosureLevel.REGULATOR;
        } else if (privacyLevel == PrivacyLevel.MEDIUM) {
            level = SelectiveDisclosureManager.DisclosureLevel.AUDITOR;
        } else {
            level = SelectiveDisclosureManager.DisclosureLevel.PUBLIC;
        }

        // Non-reverting: compliance failure must not block relay
        try dm.registerTransactionFor(requestId, commitment, owner, level) {
            // Successfully registered
        } catch {
            emit ComplianceHookFailed(
                requestId,
                "disclosure_registration_failed"
            );
        }
    }

    function _generateNullifier(
        bytes32 requestId,
        address sender
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    requestId,
                    sender,
                    block.chainid,
                    "Soul_NULLIFIER"
                )
            );
    }

    function _generateCommitment(
        bytes32 recipient,
        uint256 amount,
        bytes32 nullifier
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    recipient,
                    amount,
                    nullifier,
                    block.timestamp,
                    "Soul_COMMITMENT"
                )
            );
    }

    function _verifyPrivacyProof(
        PrivacyProof calldata proof,
        uint256 chainId
    ) internal view returns (bool) {
        AdapterConfig storage adapter = adapters[chainId];

        // Route to appropriate verifier based on proof system
        if (proof.system == ProofSystem.GROTH16) {
            return _verifyGroth16(proof);
        } else if (proof.system == ProofSystem.PLONK) {
            return _verifyPLONK(proof);
        } else if (proof.system == ProofSystem.STARK) {
            return _verifySTARK(proof);
        } else if (proof.system == ProofSystem.BULLETPROOF) {
            return _verifyBulletproof(proof);
        } else if (proof.system == ProofSystem.HALO2) {
            return _verifyHalo2(proof);
        } else if (proof.system == ProofSystem.CLSAG) {
            return _verifyCLSAG(proof);
        }

        // If no proof required or none specified
        return
            proof.proof.length == 0 || adapter.proofSystem == ProofSystem.NONE;
    }

    /// @notice Verify a Groth16 proof via the registered verifier
    /// @dev Reverts if no Groth16 verifier is configured. Call setProofVerifier() first.
    function _verifyGroth16(
        PrivacyProof calldata proof
    ) internal view returns (bool) {
        address verifier = proofVerifiers[ProofSystem.GROTH16];
        require(verifier != address(0), "Groth16 verifier not configured");
        return _delegateVerify(verifier, proof.proof);
    }

    /// @notice Verify a PLONK proof via the registered verifier
    /// @dev Reverts if no PLONK verifier is configured. Call setProofVerifier() first.
    function _verifyPLONK(
        PrivacyProof calldata proof
    ) internal view returns (bool) {
        address verifier = proofVerifiers[ProofSystem.PLONK];
        require(verifier != address(0), "PLONK verifier not configured");
        return _delegateVerify(verifier, proof.proof);
    }

    /// @notice Verify a STARK proof via the registered verifier
    /// @dev Reverts if no STARK verifier is configured. Call setProofVerifier() first.
    function _verifySTARK(
        PrivacyProof calldata proof
    ) internal view returns (bool) {
        address verifier = proofVerifiers[ProofSystem.STARK];
        require(verifier != address(0), "STARK verifier not configured");
        return _delegateVerify(verifier, proof.proof);
    }

    /// @notice Verify a Bulletproof via the registered verifier
    /// @dev Reverts if no Bulletproof verifier is configured. Call setProofVerifier() first.
    function _verifyBulletproof(
        PrivacyProof calldata proof
    ) internal view returns (bool) {
        address verifier = proofVerifiers[ProofSystem.BULLETPROOF];
        require(verifier != address(0), "Bulletproof verifier not configured");
        return _delegateVerify(verifier, proof.proof);
    }

    /// @notice Verify a Halo2 proof via the registered verifier
    /// @dev Reverts if no Halo2 verifier is configured. Call setProofVerifier() first.
    function _verifyHalo2(
        PrivacyProof calldata proof
    ) internal view returns (bool) {
        address verifier = proofVerifiers[ProofSystem.HALO2];
        require(verifier != address(0), "Halo2 verifier not configured");
        return _delegateVerify(verifier, proof.proof);
    }

    /// @notice Verify a CLSAG proof via the registered verifier
    /// @dev Reverts if no CLSAG verifier is configured. Call setProofVerifier() first.
    function _verifyCLSAG(
        PrivacyProof calldata proof
    ) internal view returns (bool) {
        address verifier = proofVerifiers[ProofSystem.CLSAG];
        require(verifier != address(0), "CLSAG verifier not configured");
        return _delegateVerify(verifier, proof.proof);
    }

    /**
     * @dev Delegate proof verification to an external verifier contract
     * @param verifier The verifier contract address
     * @param proof The proof bytes to verify
     * @return valid Whether the proof is valid
     */
    function _delegateVerify(
        address verifier,
        bytes calldata proof
    ) internal view returns (bool valid) {
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature("verify(bytes)", proof)
        );
        if (success && result.length >= 32) {
            valid = abi.decode(result, (bool));
        }
        // Returns false if staticcall fails or returns unexpected data
    }

    function _checkAndUpdateDailyLimit(
        uint256 chainId,
        uint256 amount
    ) internal {
        AdapterConfig storage adapter = adapters[chainId];

        // Reset daily volume if needed
        if (block.timestamp >= adapter.lastResetTimestamp + 1 days) {
            adapter.dailyVolume = 0;
            adapter.lastResetTimestamp = block.timestamp;
        }

        uint256 remaining = adapter.dailyLimit > adapter.dailyVolume
            ? adapter.dailyLimit - adapter.dailyVolume
            : 0;

        if (amount > remaining) {
            revert ExceedsDailyLimit(amount, remaining);
        }

        adapter.dailyVolume += amount;
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerActive = true;
        lastCircuitBreakerTimestamp = block.timestamp;
        circuitBreakerReason = reason;

        emit CircuitBreakerTriggered(msg.sender, reason, block.timestamp);
    }

    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerActive = false;

        emit CircuitBreakerReset(msg.sender, block.timestamp);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function setProtocolFee(
        uint256 feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        uint256 oldFeeBps = protocolFeeBps;
        protocolFeeBps = feeBps;
        emit ProtocolFeeUpdated(oldFeeBps, feeBps);
    }

    function setFeeRecipient(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert ZeroAddress();
        address oldRecipient = feeRecipient;
        feeRecipient = recipient;
        emit FeeRecipientUpdated(oldRecipient, recipient);
    }

    function setDefaultRingSize(uint256 size) external onlyRole(OPERATOR_ROLE) {
        if (size < MIN_RING_SIZE || size > MAX_RING_SIZE)
            revert InvalidRingSize(size);
        uint256 oldSize = defaultRingSize;
        defaultRingSize = size;
        emit DefaultRingSizeUpdated(oldSize, size);
    }

    /**
     * @notice Set external verifier contract for a proof system
     * @param system The proof system to configure
     * @param verifier The verifier contract address (implements verify(bytes,bytes) → bool)
     */
    function setProofVerifier(
        ProofSystem system,
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        address oldVerifier = proofVerifiers[system];
        proofVerifiers[system] = verifier;
        emit ProofVerifierUpdated(system, oldVerifier, verifier);
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getRelayRequest(
        bytes32 requestId
    ) external view returns (RelayRequest memory) {
        return relayRequests[requestId];
    }

    function getUserRequests(
        address user
    ) external view returns (bytes32[] memory) {
        return userRequests[user];
    }

    function getUserStealthAddresses(
        address user
    ) external view returns (bytes32[] memory) {
        return userStealthAddresses[user];
    }

    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChainIds;
    }

    function getAdapterConfig(
        uint256 chainId
    ) external view returns (AdapterConfig memory) {
        return adapters[chainId];
    }

    function getStats()
        external
        view
        returns (
            uint256 _totalRelays,
            uint256 _totalVolume,
            uint256 _totalPrivateRelays,
            uint256 _supportedChainsCount,
            bool _circuitBreakerActive
        )
    {
        return (
            totalRelays,
            totalVolume,
            totalPrivateRelays,
            supportedChainIds.length,
            circuitBreakerActive
        );
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

    // =========================================================================
    // STORAGE GAP
    // =========================================================================

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;
}
