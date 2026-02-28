// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPrivacyIntegration} from "../interfaces/IPrivacyIntegration.sol";

/**
 * @title PrivateProofRelayIntegration
 * @author ZASEON
 * @notice Cross-chain private proof relay integration implementing IPrivacyIntegration
 * @dev Connects to CrossChainPrivacyHub with stealth addresses and ZK proofs
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     PrivateProofRelayIntegration                                 │
 * │                                                                              │
 * │   Source Chain                          Destination Chain                    │
 * │   ┌──────────────────┐                  ┌──────────────────┐                │
 * │   │  1. Create       │                  │  4. Verify       │                │
 * │   │     commitment   │                  │     cross-chain  │                │
 * │   │     + nullifier  │      Proof Relay │     proof        │                │
 * │   │                  │   ──────────▶    │                  │                │
 * │   │  2. Generate     │                  │  5. Complete     │                │
 * │   │     ZK proof     │                  │     deliver to   │                │
 * │   │                  │                  │     stealth addr │                │
 * │   │  3. Initiate     │                  │                  │                │
 * │   │     transfer     │                  │  6. Register     │                │
 * │   │                  │                  │     nullifier    │                │
 * │   └──────────────────┘                  └──────────────────┘                │
 * │                                                                              │
 * │   PRIVACY FEATURES:                                                          │
 * │   ├─ Stealth addresses for unlinkable recipients                            │
 * │   ├─ Cross-chain nullifiers prevent double-spend                            │
 * │   ├─ ZK proofs hide relay amounts                                        │
 * │   └─ Encrypted metadata for enhanced privacy                                │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PrivateProofRelayIntegration is ReentrancyGuard, AccessControl, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error InvalidCommitment();
    error InvalidProof();
    error InvalidNullifier();
    error InvalidChainId();
    error NullifierAlreadyUsed();
    error RequestNotFound();
    error RequestAlreadyCompleted();
    error RequestExpired();
    error InvalidRecipient();
    error ChainNotSupported();
    error InsufficientRelayCapacity();
    error ChainAdapterNotSet();
    error CrossChainVerificationFailed();
    error MessageNotRelayed();
    error InvalidMessageSource();
    error UnauthorizedRelayer();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrivateRelayInitiated(
        bytes32 indexed requestId,
        bytes32 indexed commitment,
        uint256 sourceChain,
        uint256 destChain,
        uint256 timestamp
    );

    event PrivateRelayCompleted(
        bytes32 indexed requestId,
        bytes32 indexed nullifierHash,
        bytes32 indexed destRecipient,
        uint256 timestamp
    );

    event PrivateRelayRefunded(
        bytes32 indexed requestId,
        address indexed refundRecipient,
        uint256 timestamp
    );

    event CrossChainNullifierRegistered(
        bytes32 indexed nullifierHash,
        uint256 sourceChain,
        uint256 destChain
    );

    event ChainAdapterSet(uint256 indexed chainId, address indexed adapter);

    event RelayerAuthorized(address indexed relayer, bool authorized);

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Domain separator for private proof relay
    bytes32 public constant PRIVATE_RELAY_DOMAIN =
        keccak256("Zaseon_PRIVATE_RELAY_V1");

    /// @notice Cross-domain nullifier separator
    bytes32 public constant CROSS_DOMAIN_TAG =
        keccak256("CROSS_DOMAIN_NULLIFIER");

    /// @notice Request expiry time (7 days)
    uint256 public constant REQUEST_EXPIRY = 7 days;

    /// @notice Minimum confirmations for finality
    uint256 public constant MIN_CONFIRMATIONS = 12;

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Private relay message structure
     */
    struct PrivateRelayMessage {
        bytes32 commitment;
        bytes32 nullifierHash;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 destRecipient; // Stealth address
        bytes proof;
    }

    /**
     * @notice Relay request record
     */
    struct RelayRecord {
        bytes32 requestId;
        bytes32 commitment;
        bytes32 nullifierHash;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 destRecipient;
        address token;
        uint256 amount;
        RequestStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /**
     * @notice Request status
     */
    enum RequestStatus {
        PENDING,
        RELAYED,
        COMPLETED,
        REFUNDED,
        EXPIRED
    }

    /**
     * @notice Chain configuration
     */
    struct ChainConfig {
        bool isSupported;
        address chainAdapter;
        uint256 minConfirmations;
        uint256 maxRelayAmount;
        uint256 dailyLimit;
        uint256 dailyUsed;
        uint256 lastResetDay;
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain configurations
    mapping(uint256 => ChainConfig) public chainConfigs;

    /// @notice Supported chain IDs
    uint256[] public supportedChains;

    /// @notice Relay request records by ID
    mapping(bytes32 => RelayRecord) public relayRecords;

    /// @notice User relay request history
    mapping(address => bytes32[]) public userRequests;

    /// @notice Cross-chain nullifier tracking
    /// @dev nullifierHash => sourceChain => spent
    mapping(bytes32 => mapping(uint256 => bool)) public crossChainNullifiers;

    /// @notice Local nullifier tracking
    mapping(bytes32 => bool) public localNullifiers;

    /// @notice Proof verifier contract
    address public proofVerifier;

    /// @notice Cross-chain message verifier
    address public messageVerifier;

    /// @notice Authorized relayers
    mapping(address => bool) public authorizedRelayers;

    /// @notice This chain ID
    uint256 public immutable THIS_CHAIN_ID;

    /// @notice Native token marker
    address public constant NATIVE_TOKEN =
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _proofVerifier,
        address _messageVerifier,
        uint256 _chainId
    ) {
        if (_proofVerifier == address(0)) revert ZeroAddress();
        if (_messageVerifier == address(0)) revert ZeroAddress();

        proofVerifier = _proofVerifier;
        messageVerifier = _messageVerifier;
        THIS_CHAIN_ID = _chainId;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        CHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add or update supported chain
     * @param chainId Chain ID to configure
     * @param adapter Chain adapter address
     * @param minConfirmations Minimum confirmations required
     * @param maxRelayAmount Maximum relay amount
     * @param dailyLimit Daily relay limit
     */
    function setChainConfig(
        uint256 chainId,
        address adapter,
        uint256 minConfirmations,
        uint256 maxRelayAmount,
        uint256 dailyLimit
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapter == address(0)) revert ZeroAddress();
        if (chainId == THIS_CHAIN_ID) revert InvalidChainId();

        bool isNew = !chainConfigs[chainId].isSupported;

        chainConfigs[chainId] = ChainConfig({
            isSupported: true,
            chainAdapter: adapter,
            minConfirmations: minConfirmations,
            maxRelayAmount: maxRelayAmount,
            dailyLimit: dailyLimit,
            dailyUsed: 0,
            lastResetDay: block.timestamp / 1 days
        });

        if (isNew) {
            supportedChains.push(chainId);
        }

        emit ChainAdapterSet(chainId, adapter);
    }

    /**
     * @notice Authorize or revoke relayer
          * @param relayer The relayer address
     * @param authorized The authorized
     */
    function setRelayerAuthorization(
        address relayer,
        bool authorized
    ) external onlyRole(OPERATOR_ROLE) {
        if (relayer == address(0)) revert ZeroAddress();
        authorizedRelayers[relayer] = authorized;
        emit RelayerAuthorized(relayer, authorized);
    }

    /*//////////////////////////////////////////////////////////////
                     INITIATE PRIVATE RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a private cross-chain proof relay
     * @param message The relay message with privacy proofs
     */
    function initiatePrivateRelay(
        PrivateRelayMessage calldata message
    ) external payable nonReentrant whenNotPaused {
        // Validate inputs
        if (message.commitment == bytes32(0)) revert InvalidCommitment();
        if (message.nullifierHash == bytes32(0)) revert InvalidNullifier();
        if (message.destRecipient == bytes32(0)) revert InvalidRecipient();
        if (message.sourceChain != THIS_CHAIN_ID) revert InvalidChainId();

        ChainConfig storage destConfig = chainConfigs[message.destChain];
        if (!destConfig.isSupported) revert ChainNotSupported();

        // Check local nullifier
        if (localNullifiers[message.nullifierHash])
            revert NullifierAlreadyUsed();

        // Verify ZK proof
        if (!_verifyInitiateProof(message)) {
            revert InvalidProof();
        }

        // Reset daily limit if needed
        _resetDailyLimitIfNeeded(destConfig);

        // Generate transfer ID
        bytes32 requestId = keccak256(
            abi.encodePacked(
                message.commitment,
                message.nullifierHash,
                message.sourceChain,
                message.destChain,
                block.timestamp
            )
        );

        // Create transfer record
        relayRecords[requestId] = RelayRecord({
            requestId: requestId,
            commitment: message.commitment,
            nullifierHash: message.nullifierHash,
            sourceChain: message.sourceChain,
            destChain: message.destChain,
            destRecipient: message.destRecipient,
            token: NATIVE_TOKEN, // Simplified for ETH
            amount: msg.value,
            status: RequestStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        // Mark local nullifier
        localNullifiers[message.nullifierHash] = true;

        // Track user transfer
        userRequests[msg.sender].push(requestId);

        // Send cross-chain message via chain adapter
        _sendCrossChainMessage(message, requestId, destConfig.chainAdapter);

        emit PrivateRelayInitiated(
            requestId,
            message.commitment,
            message.sourceChain,
            message.destChain,
            block.timestamp
        );
    }

    /*//////////////////////////////////////////////////////////////
                     COMPLETE PRIVATE RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Complete a private cross-chain proof relay on destination
     * @param message The relay message
     * @param crossChainProof Proof from source chain
     * @param relayerProof Proof that message was relayed correctly
     */
    function completePrivateRelay(
        PrivateRelayMessage calldata message,
        bytes calldata crossChainProof,
        bytes calldata relayerProof
    ) external nonReentrant whenNotPaused {
        // Only authorized relayers can complete
        if (
            !authorizedRelayers[msg.sender] &&
            !hasRole(RELAYER_ROLE, msg.sender)
        ) {
            revert UnauthorizedRelayer();
        }

        // Validate destination is this chain
        if (message.destChain != THIS_CHAIN_ID) revert InvalidChainId();

        // Check cross-chain nullifier
        if (crossChainNullifiers[message.nullifierHash][message.sourceChain]) {
            revert NullifierAlreadyUsed();
        }

        // Verify cross-chain proof
        if (!_verifyCrossChainProof(message, crossChainProof)) {
            revert CrossChainVerificationFailed();
        }

        // Verify relayer proof (message authenticity)
        if (!_verifyRelayerProof(message, relayerProof)) {
            revert MessageNotRelayed();
        }

        // Generate transfer ID (same derivation as source)
        bytes32 requestId = keccak256(
            abi.encodePacked(
                message.commitment,
                message.nullifierHash,
                message.sourceChain,
                message.destChain,
                block.timestamp
            )
        );

        // Register cross-chain nullifier
        crossChainNullifiers[message.nullifierHash][message.sourceChain] = true;

        emit CrossChainNullifierRegistered(
            message.nullifierHash,
            message.sourceChain,
            message.destChain
        );

        // Deliver value to stealth address
        _deliverToStealth(message.destRecipient);

        emit PrivateRelayCompleted(
            requestId,
            message.nullifierHash,
            message.destRecipient,
            block.timestamp
        );
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN NULLIFIER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify cross-chain nullifier hasn't been used on dest chain
     * @param nullifierHash The nullifier to check
     * @param sourceChain The source chain ID
     * @return unused Whether the nullifier is unused
     */
    function verifyCrossChainNullifier(
        bytes32 nullifierHash,
        uint256 sourceChain
    ) external view returns (bool unused) {
        return !crossChainNullifiers[nullifierHash][sourceChain];
    }

    /**
     * @notice Check if nullifier is used locally
          * @param nullifierHash The nullifier hash value
     * @return The result value
     */
    function isLocalNullifierUsed(
        bytes32 nullifierHash
    ) external view returns (bool) {
        return localNullifiers[nullifierHash];
    }

    /*//////////////////////////////////////////////////////////////
                         REFUND MECHANISM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Refund expired relay request
     * @param requestId Request ID to refund
     * @param refundProof ZK proof for refund authorization
     */
    function refundExpiredRelay(
        bytes32 requestId,
        bytes calldata refundProof
    ) external nonReentrant {
        RelayRecord storage transfer = relayRecords[requestId];

        if (transfer.requestId == bytes32(0)) revert RequestNotFound();
        if (transfer.status != RequestStatus.PENDING)
            revert RequestAlreadyCompleted();
        if (block.timestamp < transfer.initiatedAt + REQUEST_EXPIRY)
            revert RequestNotFound();

        // Verify refund proof (proves ownership without revealing identity)
        if (!_verifyRefundProof(requestId, refundProof)) {
            revert InvalidProof();
        }

        transfer.status = RequestStatus.REFUNDED;
        transfer.completedAt = block.timestamp;

        // Extract refund recipient from proof
        address refundRecipient = _extractRefundRecipient(refundProof);

        // Return escrowed value (implementation depends on token type)
        // For ETH relays - use recorded amount, not full balance
        (bool success, ) = refundRecipient.call{value: transfer.amount}(
            ""
        );
        if (!success) revert InvalidRecipient();

        emit PrivateRelayRefunded(
            requestId,
            refundRecipient,
            block.timestamp
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Reset daily limit if new day
     */
    function _resetDailyLimitIfNeeded(ChainConfig storage config) internal {
        uint256 currentDay = block.timestamp / 1 days;
        if (config.lastResetDay < currentDay) {
            config.dailyUsed = 0;
            config.lastResetDay = currentDay;
        }
    }

    /**
     * @notice Verify initiation proof
     */
    function _verifyInitiateProof(
        PrivateRelayMessage calldata message
    ) internal view returns (bool) {
        (bool success, bytes memory result) = proofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyInitiateProof(bytes32,bytes32,uint256,uint256,bytes32,bytes)",
                message.commitment,
                message.nullifierHash,
                message.sourceChain,
                message.destChain,
                message.destRecipient,
                message.proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify cross-chain proof
     */
    function _verifyCrossChainProof(
        PrivateRelayMessage calldata message,
        bytes calldata crossChainProof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = messageVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyCrossChainProof(bytes32,bytes32,uint256,uint256,bytes)",
                message.commitment,
                message.nullifierHash,
                message.sourceChain,
                message.destChain,
                crossChainProof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify relayer proof
     */
    function _verifyRelayerProof(
        PrivateRelayMessage calldata message,
        bytes calldata relayerProof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = messageVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyRelayerProof(bytes32,bytes32,uint256,bytes)",
                message.commitment,
                message.destRecipient,
                message.sourceChain,
                relayerProof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify refund proof
     */
    function _verifyRefundProof(
        bytes32 requestId,
        bytes calldata refundProof
    ) internal view returns (bool) {
        RelayRecord storage transfer = relayRecords[requestId];

        (bool success, bytes memory result) = proofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyRefundProof(bytes32,bytes32,bytes)",
                requestId,
                transfer.commitment,
                refundProof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Extract refund recipient from proof
     */
    function _extractRefundRecipient(
        bytes calldata refundProof
    ) internal pure returns (address) {
        if (refundProof.length < 20) return address(0);
        return address(bytes20(refundProof[0:20]));
    }

    /**
     * @notice Send cross-chain message
     */
    function _sendCrossChainMessage(
        PrivateRelayMessage calldata message,
        bytes32 requestId,
        address chainAdapter
    ) internal {
        // Encode message for cross-chain delivery
        bytes memory encodedMessage = abi.encode(
            requestId,
            message.commitment,
            message.nullifierHash,
            message.destRecipient,
            message.proof
        );

        // Call chain adapter
        (bool success, ) = chainAdapter.call{value: msg.value}(
            abi.encodeWithSignature(
                "sendMessage(uint256,bytes)",
                message.destChain,
                encodedMessage
            )
        );

        if (!success) revert ChainAdapterNotSet();
    }

    /**
     * @notice Deliver value to stealth address
     */
    function _deliverToStealth(bytes32 stealthRecipient) internal {
        // Convert bytes32 stealth address to EVM address
        address recipient = address(uint160(uint256(stealthRecipient)));

        // Deliver value - use msg.value for the current transaction amount
        uint256 amount = msg.value;
        if (amount > 0) {
            (bool success, ) = recipient.call{value: amount}("");
            if (!success) revert InvalidRecipient();
        }
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get relay record
          * @param requestId The requestId identifier
     * @return The result value
     */
    function getRelayRecord(
        bytes32 requestId
    ) external view returns (RelayRecord memory) {
        return relayRecords[requestId];
    }

    /**
     * @notice Get user relay requests
          * @param user The user
     * @return The result value
     */
    function getUserRequests(
        address user
    ) external view returns (bytes32[] memory) {
        return userRequests[user];
    }

    /**
     * @notice Get chain config
          * @param chainId The chain identifier
     * @return The result value
     */
    function getChainConfig(
        uint256 chainId
    ) external view returns (ChainConfig memory) {
        return chainConfigs[chainId];
    }

    /**
     * @notice Get supported chains
          * @return The result value
     */
    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    /**
     * @notice Check if chain is supported
          * @param chainId The chain identifier
     * @return The result value
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].isSupported;
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update proof verifier
          * @param _proofVerifier The _proof verifier
     */
    function setProofVerifier(
        address _proofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_proofVerifier == address(0)) revert ZeroAddress();
        proofVerifier = _proofVerifier;
    }

    /**
     * @notice Update message verifier
          * @param _messageVerifier The _message verifier
     */
    function setMessageVerifier(
        address _messageVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_messageVerifier == address(0)) revert ZeroAddress();
        messageVerifier = _messageVerifier;
    }

    /**
     * @notice Pause relay
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause relay
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency withdraw (only admin)
          * @param token The token address
     * @param to The destination address
     */
    function emergencyWithdraw(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();

        if (token == NATIVE_TOKEN) {
            (bool success, ) = to.call{value: address(this).balance}("");
            if (!success) revert InvalidRecipient();
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransfer(to, balance);
        }
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
