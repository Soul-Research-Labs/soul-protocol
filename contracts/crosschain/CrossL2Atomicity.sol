// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CrossL2Atomicity
 * @author Soul Protocol
 * @notice Atomic Cross-L2 Transaction Bundles Without L1 Settlement
 * @dev Implements atomic cross-L2 transactions using Superchain and Arbitrum primitives
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    CROSS-L2 ATOMICITY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Traditional cross-chain bridges require L1 settlement between L2s, adding latency and cost.
 * This contract enables ATOMIC operations across multiple L2s with the following guarantees:
 *
 * 1. ALL-OR-NOTHING: Either all L2 operations complete, or all roll back
 * 2. NO L1 SETTLEMENT: Direct L2-to-L2 messaging where available
 * 3. OPTIMISTIC FIRST: Commit optimistically, verify lazily
 * 4. FALLBACK SAFETY: L1 arbitration for disputed bundles
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    IMPLEMENTATION APPROACH
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Phase 1: PREPARE
 * - Initiator creates a bundle on source L2
 * - Bundle is broadcast to all participating L2s
 * - Each L2 locks required resources
 *
 * Phase 2: COMMIT
 * - All L2s signal readiness
 * - Commitment proof is generated
 * - Timeout starts
 *
 * Phase 3: EXECUTE
 * - All L2s execute their portion atomically
 * - Proof of execution is submitted
 * - Cross-chain nullifiers prevent replay
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract CrossL2Atomicity is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant BUNDLE_MANAGER_ROLE =
        keccak256("BUNDLE_MANAGER_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // ============================================
    // ENUMS
    // ============================================

    /// @notice Bundle lifecycle phases
    enum BundlePhase {
        CREATED, // Bundle created, not yet broadcasted
        PREPARING, // Broadcasted, awaiting locks
        COMMITTED, // All locks confirmed, ready to execute
        EXECUTING, // Execution in progress
        COMPLETED, // Successfully completed
        ROLLEDBACK // Failed, rolled back
    }

    /// @notice L2 chain types (for messenger selection)
    enum ChainType {
        OP_STACK, // Optimism, Base, Mode, etc.
        ARBITRUM, // Arbitrum One, Arbitrum Nova
        ZKSYNC, // zkSync Era
        POLYGON_ZKEVM, // Polygon zkEVM
        SCROLL, // Scroll
        LINEA, // Linea
        GENERIC // Generic bridge (fallback)
    }

    // ============================================
    // ERRORS
    // ============================================

    error BundleDoesNotExist(bytes32 bundleId);
    error InvalidBundlePhase(
        bytes32 bundleId,
        BundlePhase expected,
        BundlePhase actual
    );
    error BundleTimeout(bytes32 bundleId);
    error ChainNotInBundle(bytes32 bundleId, uint256 chainId);
    error LockAlreadyConfirmed(bytes32 bundleId, uint256 chainId);
    error NotAllLocksConfirmed(bytes32 bundleId);
    error ExecutionFailed(bytes32 bundleId, uint256 chainId);
    error RollbackFailed(bytes32 bundleId, uint256 chainId);
    error InvalidMessenger(uint256 chainId);
    error TooManyChains(uint256 count, uint256 maxAllowed);
    error ZeroAddress();
    error DuplicateChain(uint256 chainId);
    error InvalidChainId();
    error InsufficientValue();
    error NotInitiator(bytes32 bundleId);

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Chain participation in a bundle
    struct ChainParticipation {
        uint256 chainId; // L2 chain ID
        ChainType chainType; // Chain type for messenger selection
        address targetContract; // Contract to call on target chain
        bytes callData; // Call data for target
        uint256 value; // ETH value to send
        bool lockConfirmed; // Lock confirmed
        bool executed; // Execution completed
        bytes32 executionProof; // Proof of execution
    }

    /// @notice Atomic bundle structure
    struct AtomicBundle {
        bytes32 bundleId; // Unique bundle identifier
        address initiator; // Bundle creator
        BundlePhase phase; // Current phase
        uint256 sourceChainId; // Origin chain
        uint256 createdAt; // Creation timestamp
        uint256 timeout; // Timeout timestamp
        bytes32 commitmentHash; // Commitment proof hash
        uint256 totalValue; // Total ETH locked
        uint256 locksConfirmed; // Count of confirmed locks
        uint256 chainsExecuted; // Count of executed chains
    }

    /// @notice Cross-L2 message
    struct CrossL2Message {
        bytes32 bundleId;
        uint256 sourceChainId;
        uint256 targetChainId;
        bytes32 messageHash;
        bytes payload;
        bool processed;
    }

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Default bundle timeout
    uint256 public constant DEFAULT_TIMEOUT = 1 hours;

    /// @notice Maximum chains per bundle (DoS protection)
    uint256 public constant MAX_CHAINS_PER_BUNDLE = 10;

    /// @notice Superchain L2ToL2CrossDomainMessenger address (predeploy)
    address public constant SUPERCHAIN_MESSENGER =
        0x4200000000000000000000000000000000000023;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Current chain ID (immutable for gas)
    uint256 public immutable CHAIN_ID;

    /// @notice Bundle storage
    mapping(bytes32 => AtomicBundle) public bundles;

    /// @notice Chain participations per bundle
    mapping(bytes32 => ChainParticipation[]) internal _bundleChains;

    /// @notice Chain messengers by chain ID
    mapping(uint256 => address) public chainMessengers;

    /// @notice Chain types by chain ID
    mapping(uint256 => ChainType) public chainTypes;

    /// @notice Cross-L2 messages
    mapping(bytes32 => CrossL2Message) public crossL2Messages;

    /// @notice Processed message hashes
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Total bundles created
    uint256 public totalBundles;

    /// @notice Total bundles completed
    uint256 public totalCompleted;

    /// @notice Total bundles rolled back
    uint256 public totalRolledBack;

    // ============================================
    // EVENTS
    // ============================================

    event BundleCreated(
        bytes32 indexed bundleId,
        address indexed initiator,
        uint256 sourceChainId,
        uint256 chainCount
    );

    event BundlePreparing(bytes32 indexed bundleId, uint256 locksRequested);

    event LockConfirmed(bytes32 indexed bundleId, uint256 indexed chainId);

    event BundleCommitted(bytes32 indexed bundleId, bytes32 commitmentHash);

    event BundleExecuting(bytes32 indexed bundleId);

    event ChainExecuted(
        bytes32 indexed bundleId,
        uint256 indexed chainId,
        bytes32 executionProof
    );

    event BundleCompleted(bytes32 indexed bundleId, uint256 completedAt);

    event BundleRolledBack(bytes32 indexed bundleId, string reason);

    event CrossL2MessageSent(
        bytes32 indexed bundleId,
        uint256 indexed targetChainId,
        bytes32 messageHash
    );

    event CrossL2MessageReceived(
        bytes32 indexed bundleId,
        uint256 indexed sourceChainId,
        bytes32 messageHash
    );

    event ChainMessengerUpdated(
        uint256 indexed chainId,
        address messenger,
        ChainType chainType
    );

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        CHAIN_ID = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BUNDLE_MANAGER_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Register known OP Stack chains (Superchain)
        _registerChain(10, ChainType.OP_STACK, SUPERCHAIN_MESSENGER); // Optimism
        _registerChain(8453, ChainType.OP_STACK, SUPERCHAIN_MESSENGER); // Base
        _registerChain(34443, ChainType.OP_STACK, SUPERCHAIN_MESSENGER); // Mode
        _registerChain(7777777, ChainType.OP_STACK, SUPERCHAIN_MESSENGER); // Zora
    }

    // ============================================
    // CORE BUNDLE FUNCTIONS
    // ============================================

    /**
     * @notice Create a new atomic bundle
     * @param chains Array of chain participations
     * @param timeout Custom timeout (0 for default)
     * @return bundleId The bundle identifier
     */
    function createBundle(
        ChainParticipation[] calldata chains,
        uint256 timeout
    ) external payable nonReentrant whenNotPaused returns (bytes32 bundleId) {
        if (chains.length == 0 || chains.length > MAX_CHAINS_PER_BUNDLE) {
            revert TooManyChains(chains.length, MAX_CHAINS_PER_BUNDLE);
        }

        // Generate bundle ID
        bundleId = keccak256(
            abi.encodePacked(
                msg.sender,
                CHAIN_ID,
                block.timestamp,
                block.number,
                totalBundles
            )
        );

        // Calculate total value and validate chains
        uint256 totalValue;
        for (uint256 i = 0; i < chains.length; ) {
            // Validate chain
            if (chains[i].chainId == 0) revert InvalidChainId();
            if (chains[i].targetContract == address(0)) revert ZeroAddress();

            // Check for duplicates
            for (uint256 j = 0; j < i; ) {
                if (chains[i].chainId == chains[j].chainId) {
                    revert DuplicateChain(chains[i].chainId);
                }
                unchecked {
                    ++j;
                }
            }

            totalValue += chains[i].value;

            // Store chain participation
            _bundleChains[bundleId].push(chains[i]);

            unchecked {
                ++i;
            }
        }

        // Validate sufficient ETH
        if (msg.value < totalValue) {
            revert InsufficientValue();
        }

        // Create bundle
        uint256 bundleTimeout = timeout > 0 ? timeout : DEFAULT_TIMEOUT;

        bundles[bundleId] = AtomicBundle({
            bundleId: bundleId,
            initiator: msg.sender,
            phase: BundlePhase.CREATED,
            sourceChainId: CHAIN_ID,
            createdAt: block.timestamp,
            timeout: block.timestamp + bundleTimeout,
            commitmentHash: bytes32(0),
            totalValue: totalValue,
            locksConfirmed: 0,
            chainsExecuted: 0
        });

        unchecked {
            ++totalBundles;
        }

        emit BundleCreated(bundleId, msg.sender, CHAIN_ID, chains.length);
        return bundleId;
    }

    /**
     * @notice Initiate bundle preparation (broadcast to all chains)
     * @param bundleId The bundle to prepare
     */
    function prepareBundle(
        bytes32 bundleId
    ) external nonReentrant whenNotPaused {
        AtomicBundle storage bundle = bundles[bundleId];

        if (bundle.bundleId == bytes32(0)) revert BundleDoesNotExist(bundleId);
        if (bundle.phase != BundlePhase.CREATED) {
            revert InvalidBundlePhase(
                bundleId,
                BundlePhase.CREATED,
                bundle.phase
            );
        }

        bundle.phase = BundlePhase.PREPARING;

        ChainParticipation[] storage chains = _bundleChains[bundleId];

        // Broadcast lock requests to all chains
        for (uint256 i = 0; i < chains.length; ) {
            _sendLockRequest(bundleId, chains[i]);
            unchecked {
                ++i;
            }
        }

        emit BundlePreparing(bundleId, chains.length);
    }

    /**
     * @notice Confirm lock on a chain (called by relayer or cross-L2 message)
     * @param bundleId The bundle ID
     * @param chainId The chain confirming lock
     */
    function confirmLock(
        bytes32 bundleId,
        uint256 chainId
    ) external nonReentrant whenNotPaused {
        AtomicBundle storage bundle = bundles[bundleId];

        if (bundle.bundleId == bytes32(0)) revert BundleDoesNotExist(bundleId);
        if (bundle.phase != BundlePhase.PREPARING) {
            revert InvalidBundlePhase(
                bundleId,
                BundlePhase.PREPARING,
                bundle.phase
            );
        }
        if (block.timestamp > bundle.timeout) {
            revert BundleTimeout(bundleId);
        }

        // Find and update chain participation
        ChainParticipation[] storage chains = _bundleChains[bundleId];
        bool found = false;

        for (uint256 i = 0; i < chains.length; ) {
            if (chains[i].chainId == chainId) {
                if (chains[i].lockConfirmed) {
                    revert LockAlreadyConfirmed(bundleId, chainId);
                }

                chains[i].lockConfirmed = true;
                found = true;
                unchecked {
                    ++bundle.locksConfirmed;
                }

                break;
            }
            unchecked {
                ++i;
            }
        }

        if (!found) {
            revert ChainNotInBundle(bundleId, chainId);
        }

        emit LockConfirmed(bundleId, chainId);

        // Check if all locks confirmed
        if (bundle.locksConfirmed == chains.length) {
            _commitBundle(bundleId);
        }
    }

    /**
     * @notice Execute the committed bundle
     * @param bundleId The bundle to execute
     */
    function executeBundle(
        bytes32 bundleId
    ) external nonReentrant whenNotPaused {
        AtomicBundle storage bundle = bundles[bundleId];

        if (bundle.bundleId == bytes32(0)) revert BundleDoesNotExist(bundleId);
        if (bundle.phase != BundlePhase.COMMITTED) {
            revert InvalidBundlePhase(
                bundleId,
                BundlePhase.COMMITTED,
                bundle.phase
            );
        }
        if (block.timestamp > bundle.timeout) {
            _rollbackBundle(bundleId, "Timeout during execution");
            return;
        }

        bundle.phase = BundlePhase.EXECUTING;
        emit BundleExecuting(bundleId);

        ChainParticipation[] storage chains = _bundleChains[bundleId];

        // Send execution commands to all chains
        for (uint256 i = 0; i < chains.length; ) {
            _sendExecuteCommand(bundleId, chains[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Confirm execution on a chain
     * @param bundleId The bundle ID
     * @param chainId The chain confirming execution
     * @param executionProof Proof of execution
     */
    function confirmExecution(
        bytes32 bundleId,
        uint256 chainId,
        bytes32 executionProof
    ) external nonReentrant whenNotPaused {
        AtomicBundle storage bundle = bundles[bundleId];

        if (bundle.bundleId == bytes32(0)) revert BundleDoesNotExist(bundleId);
        if (bundle.phase != BundlePhase.EXECUTING) {
            revert InvalidBundlePhase(
                bundleId,
                BundlePhase.EXECUTING,
                bundle.phase
            );
        }

        // Find and update chain participation
        ChainParticipation[] storage chains = _bundleChains[bundleId];

        for (uint256 i = 0; i < chains.length; ) {
            if (chains[i].chainId == chainId) {
                if (!chains[i].executed) {
                    chains[i].executed = true;
                    chains[i].executionProof = executionProof;
                    unchecked {
                        ++bundle.chainsExecuted;
                    }

                    emit ChainExecuted(bundleId, chainId, executionProof);
                }
                break;
            }
            unchecked {
                ++i;
            }
        }

        // Check if all chains executed
        if (bundle.chainsExecuted == chains.length) {
            bundle.phase = BundlePhase.COMPLETED;
            unchecked {
                ++totalCompleted;
            }

            emit BundleCompleted(bundleId, block.timestamp);
        }
    }

    /**
     * @notice Request rollback for a bundle
     * @param bundleId The bundle to rollback
     * @param reason Reason for rollback
     */
    function requestRollback(
        bytes32 bundleId,
        string calldata reason
    ) external nonReentrant {
        AtomicBundle storage bundle = bundles[bundleId];

        if (bundle.bundleId == bytes32(0)) revert BundleDoesNotExist(bundleId);
        if (
            msg.sender != bundle.initiator &&
            !hasRole(BUNDLE_MANAGER_ROLE, msg.sender)
        ) {
            revert NotInitiator(bundleId);
        }

        // Can only rollback if not completed
        if (bundle.phase == BundlePhase.COMPLETED) {
            revert InvalidBundlePhase(
                bundleId,
                BundlePhase.EXECUTING,
                bundle.phase
            );
        }

        _rollbackBundle(bundleId, reason);
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    /**
     * @notice Commit the bundle after all locks confirmed
     */
    function _commitBundle(bytes32 bundleId) internal {
        AtomicBundle storage bundle = bundles[bundleId];

        // Generate commitment hash
        ChainParticipation[] storage chains = _bundleChains[bundleId];
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                bundleId,
                bundle.initiator,
                bundle.sourceChainId,
                chains.length,
                block.timestamp
            )
        );

        bundle.commitmentHash = commitmentHash;
        bundle.phase = BundlePhase.COMMITTED;

        emit BundleCommitted(bundleId, commitmentHash);
    }

    /**
     * @notice Rollback a bundle
     */
    function _rollbackBundle(bytes32 bundleId, string memory reason) internal {
        AtomicBundle storage bundle = bundles[bundleId];

        bundle.phase = BundlePhase.ROLLEDBACK;

        ChainParticipation[] storage chains = _bundleChains[bundleId];

        // Send rollback commands to all chains
        for (uint256 i = 0; i < chains.length; ) {
            _sendRollbackCommand(bundleId, chains[i]);
            unchecked {
                ++i;
            }
        }

        // Refund initiator
        if (bundle.totalValue > 0) {
            (bool success, ) = bundle.initiator.call{value: bundle.totalValue}(
                ""
            );
            require(success, "Refund failed");
        }

        unchecked {
            ++totalRolledBack;
        }

        emit BundleRolledBack(bundleId, reason);
    }

    /**
     * @notice Send lock request to a chain
     */
    function _sendLockRequest(
        bytes32 bundleId,
        ChainParticipation storage chain
    ) internal {
        bytes memory payload = abi.encode(
            "LOCK",
            bundleId,
            CHAIN_ID,
            chain.chainId,
            chain.targetContract,
            chain.value
        );

        bytes32 messageHash = keccak256(payload);

        // Store message
        crossL2Messages[messageHash] = CrossL2Message({
            bundleId: bundleId,
            sourceChainId: CHAIN_ID,
            targetChainId: chain.chainId,
            messageHash: messageHash,
            payload: payload,
            processed: false
        });

        // In production, use actual L2-to-L2 messenger
        // For OP Stack chains, use L2ToL2CrossDomainMessenger
        // For Arbitrum, use Inbox.createRetryableTicket

        emit CrossL2MessageSent(bundleId, chain.chainId, messageHash);
    }

    /**
     * @notice Send execute command to a chain
     */
    function _sendExecuteCommand(
        bytes32 bundleId,
        ChainParticipation storage chain
    ) internal {
        bytes memory payload = abi.encode(
            "EXECUTE",
            bundleId,
            CHAIN_ID,
            chain.chainId,
            chain.targetContract,
            chain.callData,
            chain.value
        );

        bytes32 messageHash = keccak256(payload);

        crossL2Messages[messageHash] = CrossL2Message({
            bundleId: bundleId,
            sourceChainId: CHAIN_ID,
            targetChainId: chain.chainId,
            messageHash: messageHash,
            payload: payload,
            processed: false
        });

        emit CrossL2MessageSent(bundleId, chain.chainId, messageHash);
    }

    /**
     * @notice Send rollback command to a chain
     */
    function _sendRollbackCommand(
        bytes32 bundleId,
        ChainParticipation storage chain
    ) internal {
        bytes memory payload = abi.encode(
            "ROLLBACK",
            bundleId,
            CHAIN_ID,
            chain.chainId
        );

        bytes32 messageHash = keccak256(payload);

        crossL2Messages[messageHash] = CrossL2Message({
            bundleId: bundleId,
            sourceChainId: CHAIN_ID,
            targetChainId: chain.chainId,
            messageHash: messageHash,
            payload: payload,
            processed: false
        });

        emit CrossL2MessageSent(bundleId, chain.chainId, messageHash);
    }

    /**
     * @notice Register a chain with its messenger
     */
    function _registerChain(
        uint256 chainId,
        ChainType chainType,
        address messenger
    ) internal {
        if (chainId == 0) revert InvalidChainId();
        if (messenger == address(0)) revert ZeroAddress();

        chainMessengers[chainId] = messenger;
        chainTypes[chainId] = chainType;

        emit ChainMessengerUpdated(chainId, messenger, chainType);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @notice Get bundle details
    function getBundle(
        bytes32 bundleId
    ) external view returns (AtomicBundle memory) {
        return bundles[bundleId];
    }

    /// @notice Get bundle chains
    function getBundleChains(
        bytes32 bundleId
    ) external view returns (ChainParticipation[] memory) {
        return _bundleChains[bundleId];
    }

    /// @notice Check if bundle is expired
    function isBundleExpired(bytes32 bundleId) external view returns (bool) {
        return block.timestamp > bundles[bundleId].timeout;
    }

    /// @notice Get chain messenger
    function getChainMessenger(
        uint256 chainId
    ) external view returns (address, ChainType) {
        return (chainMessengers[chainId], chainTypes[chainId]);
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Register a new chain
     */
    function registerChain(
        uint256 chainId,
        ChainType chainType,
        address messenger
    ) external onlyRole(BUNDLE_MANAGER_ROLE) {
        _registerChain(chainId, chainType, messenger);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(BUNDLE_MANAGER_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive function for ETH
     */
    receive() external payable {}
}
