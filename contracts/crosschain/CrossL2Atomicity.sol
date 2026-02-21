// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CrossL2Atomicity
 * @author Soul Protocol
 * @notice Cross-L2 atomic operations with Superchain interop and Arbitrum Nitro
 * @dev Implements atomic cross-L2 transactions without L1 settlement
 *
 * CROSS-L2 ATOMICITY ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                Cross-L2 Atomic Operations                       │
 * │                                                                  │
 * │   OP Stack L2s (Superchain)         Arbitrum L2s               │
 * │   ┌────────────┐  ┌────────────┐   ┌────────────┐              │
 * │   │ Optimism   │──│ Base       │   │ Arbitrum   │              │
 * │   │            │  │            │   │ One        │              │
 * │   └─────┬──────┘  └─────┬──────┘   └─────┬──────┘              │
 * │         │               │                │                      │
 * │   ┌─────▼───────────────▼────────────────▼─────┐               │
 * │   │          Atomic Coordinator                │               │
 * │   │                                            │               │
 * │   │  Phase 1: Prepare                          │               │
 * │   │  ├─ Lock assets on all chains             │               │
 * │   │  └─ Generate cross-chain proofs           │               │
 * │   │                                            │               │
 * │   │  Phase 2: Commit                           │               │
 * │   │  ├─ Verify all preparations               │               │
 * │   │  └─ Mark atomic bundle committed          │               │
 * │   │                                            │               │
 * │   │  Phase 3: Execute                          │               │
 * │   │  ├─ Execute on all chains                 │               │
 * │   │  └─ Release locks                         │               │
 * │   │                                            │               │
 * │   │  Rollback: If any phase fails             │               │
 * │   │  └─ Unlock all assets                     │               │
 * │   └────────────────────────────────────────────┘               │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED PROTOCOLS:
 * - OP Stack Superchain: Native interop via L2ToL2CrossDomainMessenger
 * - Arbitrum Nitro: Inbox/Outbox message passing
 * - General L2: Via LayerZero/Hyperlane bridging
 */
contract CrossL2Atomicity is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidChainCount();
    error InvalidOperationData();
    error BundleNotFound();
    error BundleAlreadyExists();
    error BundleNotReady();
    error BundleExpired();
    error ChainNotPrepared();
    error AllChainsMustPrepare();
    error UnauthorizedExecutor();
    error ExecutionFailed();
    error RollbackRequired();
    error AlreadyExecuted();
    error InvalidPhase();
    error TimeoutNotReached();
    error InsufficientValue();
    error SuperchainSendFailed();
    error DuplicateChainId(uint256 chainId);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event AtomicBundleCreated(
        bytes32 indexed bundleId,
        address indexed initiator,
        uint256[] chainIds,
        uint256 timeout
    );

    event ChainPrepared(
        bytes32 indexed bundleId,
        uint256 indexed chainId,
        bytes32 proofHash
    );

    event BundleCommitted(bytes32 indexed bundleId, uint256 timestamp);

    event ChainExecuted(
        bytes32 indexed bundleId,
        uint256 indexed chainId,
        bool success
    );

    event BundleCompleted(bytes32 indexed bundleId, bool success);

    event BundleRolledBack(bytes32 indexed bundleId, string reason);

    event SuperchainMessageSent(
        uint256 indexed destinationChainId,
        bytes32 indexed messageId,
        bytes payload
    );

    event ArbitrumRetryableCreated(
        uint256 indexed ticketId,
        address indexed destAddr,
        uint256 value
    );

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum BundlePhase {
        CREATED,
        PREPARING,
        COMMITTED,
        EXECUTING,
        COMPLETED,
        ROLLEDBACK
    }

    enum ChainType {
        OP_STACK, // Optimism, Base, etc.
        ARBITRUM, // Arbitrum One, Nova
        ZKSYNC, // zkSync Era
        POLYGON_ZKEVM, // Polygon zkEVM
        SCROLL, // Scroll
        LINEA, // Linea
        GENERIC // Via LayerZero/Hyperlane
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Atomic operation on a single chain
    struct ChainOperation {
        uint256 chainId;
        ChainType chainType;
        address target;
        bytes data;
        uint256 value;
        bytes32 proofHash;
        bool prepared;
        bool executed;
    }

    /// @notice Atomic bundle across multiple chains
    struct AtomicBundle {
        bytes32 bundleId;
        address initiator;
        BundlePhase phase;
        uint256 createdAt;
        uint256 timeout;
        uint256 chainCount;
        uint256 preparedCount;
        uint256 executedCount;
        mapping(uint256 => ChainOperation) operations;
        uint256[] chainIds;
    }

    /// @notice Superchain message format
    struct SuperchainMessage {
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        bytes32 bundleId;
        bytes payload;
        uint256 nonce;
    }

    /// @notice Arbitrum retryable ticket
    struct RetryableTicket {
        uint256 ticketId;
        address destAddr;
        uint256 l2CallValue;
        uint256 maxSubmissionCost;
        address excessFeeRefundAddress;
        address callValueRefundAddress;
        uint256 gasLimit;
        uint256 maxFeePerGas;
        bytes data;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Current chain ID
    uint256 public immutable currentChainId;

    /// @notice Default timeout (1 hour)
    uint256 public constant DEFAULT_TIMEOUT = 1 hours;

    /// @notice Maximum chains per bundle
    uint256 public constant MAX_CHAINS_PER_BUNDLE = 10;

    /// @notice Bundle storage
    mapping(bytes32 => AtomicBundle) internal _bundles;

    /// @notice Bundle IDs array for iteration
    bytes32[] public bundleIds;

    /// @notice Chain adapters
    mapping(uint256 => address) public chainAdapters;

    /// @notice Superchain messenger (for OP Stack)
    address public superchainMessenger;

    /// @notice Arbitrum inbox (for Arbitrum chains)
    address public arbitrumInbox;

    /// @notice Nonce per bundle
    mapping(bytes32 => uint256) public bundleNonces;

    /// @notice Global nonce
    uint256 public globalNonce;

    /// @notice Executed operations (for idempotency)
    mapping(bytes32 => bool) public executedOperations;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the atomic coordinator with the current chain ID and admin roles
    /// @param _admin Address to receive all administrative roles
    constructor(address _admin) {
        currentChainId = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EXECUTOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                     ATOMIC BUNDLE CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new atomic bundle across multiple L2s
     * @param chainIds Array of chain IDs involved
     * @param chainTypes Array of chain types
     * @param targets Array of target addresses per chain
     * @param datas Array of calldata per chain
     * @param values Array of values per chain
     * @param timeout Custom timeout (0 for default)
     * @return bundleId Unique bundle identifier
     */
    function createAtomicBundle(
        uint256[] calldata chainIds,
        ChainType[] calldata chainTypes,
        address[] calldata targets,
        bytes[] calldata datas,
        uint256[] calldata values,
        uint256 timeout
    ) external payable nonReentrant whenNotPaused returns (bytes32 bundleId) {
        uint256 chainCount = chainIds.length;

        if (chainCount == 0 || chainCount > MAX_CHAINS_PER_BUNDLE) {
            revert InvalidChainCount();
        }
        if (
            chainTypes.length != chainCount ||
            targets.length != chainCount ||
            datas.length != chainCount ||
            values.length != chainCount
        ) {
            revert InvalidOperationData();
        }

        // Calculate total required value
        {
            uint256 totalRequiredValue = 0;
            for (uint256 i = 0; i < chainCount; ) {
                totalRequiredValue += values[i];
                unchecked {
                    ++i;
                }
            }
            if (msg.value < totalRequiredValue) revert InsufficientValue();
        }

        bundleId = keccak256(
            abi.encodePacked(
                msg.sender,
                chainIds,
                ++globalNonce,
                block.timestamp
            )
        );

        if (_bundles[bundleId].createdAt != 0) revert BundleAlreadyExists();

        // Initialize bundle
        {
            AtomicBundle storage bundle = _bundles[bundleId];
            bundle.bundleId = bundleId;
            bundle.initiator = msg.sender;
            bundle.phase = BundlePhase.CREATED;
            bundle.createdAt = block.timestamp;
            bundle.timeout = timeout > 0 ? timeout : DEFAULT_TIMEOUT;
            bundle.chainCount = chainCount;
            bundle.chainIds = chainIds;
        }

        _populateBundleOperations(
            bundleId,
            chainIds,
            chainTypes,
            targets,
            datas,
            values
        );

        bundleIds.push(bundleId);

        emit AtomicBundleCreated(
            bundleId,
            msg.sender,
            chainIds,
            _bundles[bundleId].timeout
        );

        return bundleId;
    }

    function _populateBundleOperations(
        bytes32 bundleId,
        uint256[] calldata chainIds,
        ChainType[] calldata chainTypes,
        address[] calldata targets,
        bytes[] calldata datas,
        uint256[] calldata values
    ) private {
        AtomicBundle storage bundle = _bundles[bundleId];
        uint256 chainCount = chainIds.length;

        for (uint256 i = 0; i < chainCount; ) {
            // Check for duplicate chainIds
            for (uint256 j = 0; j < i; ) {
                if (chainIds[j] == chainIds[i])
                    revert DuplicateChainId(chainIds[i]);
                unchecked {
                    ++j;
                }
            }
            bundle.operations[chainIds[i]] = ChainOperation({
                chainId: chainIds[i],
                chainType: chainTypes[i],
                target: targets[i],
                data: datas[i],
                value: values[i],
                proofHash: bytes32(0),
                prepared: false,
                executed: false
            });
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         PHASE 1: PREPARE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Mark a chain as prepared for atomic execution
     * @param bundleId Bundle identifier
     * @param chainId Chain that is prepared
     * @param proofHash Proof of preparation (lock proof, etc.)
     */
    function markChainPrepared(
        bytes32 bundleId,
        uint256 chainId,
        bytes32 proofHash
    ) external onlyRole(EXECUTOR_ROLE) {
        AtomicBundle storage bundle = _bundles[bundleId];

        if (bundle.createdAt == 0) revert BundleNotFound();
        if (
            bundle.phase != BundlePhase.CREATED &&
            bundle.phase != BundlePhase.PREPARING
        ) {
            revert InvalidPhase();
        }
        if (block.timestamp > bundle.createdAt + bundle.timeout) {
            revert BundleExpired();
        }

        ChainOperation storage op = bundle.operations[chainId];
        if (op.chainId != chainId) revert ChainNotPrepared();
        if (op.prepared) return; // Already prepared

        op.prepared = true;
        op.proofHash = proofHash;
        bundle.preparedCount++;

        if (bundle.phase == BundlePhase.CREATED) {
            bundle.phase = BundlePhase.PREPARING;
        }

        emit ChainPrepared(bundleId, chainId, proofHash);

        // Auto-commit if all chains prepared
        if (bundle.preparedCount == bundle.chainCount) {
            _commitBundle(bundleId);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         PHASE 2: COMMIT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Manually commit a bundle (if auto-commit disabled)
     * @param bundleId Bundle identifier
     */
    function commitBundle(bytes32 bundleId) external onlyRole(EXECUTOR_ROLE) {
        AtomicBundle storage bundle = _bundles[bundleId];

        if (bundle.createdAt == 0) revert BundleNotFound();
        if (bundle.phase != BundlePhase.PREPARING) revert InvalidPhase();
        if (bundle.preparedCount != bundle.chainCount)
            revert AllChainsMustPrepare();

        _commitBundle(bundleId);
    }

    function _commitBundle(bytes32 bundleId) internal {
        AtomicBundle storage bundle = _bundles[bundleId];
        bundle.phase = BundlePhase.COMMITTED;

        emit BundleCommitted(bundleId, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                         PHASE 3: EXECUTE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute operations on the current chain
     * @param bundleId Bundle identifier
     */
    function executeOnCurrentChain(
        bytes32 bundleId
    ) external nonReentrant onlyRole(EXECUTOR_ROLE) {
        AtomicBundle storage bundle = _bundles[bundleId];

        if (bundle.createdAt == 0) revert BundleNotFound();
        if (
            bundle.phase != BundlePhase.COMMITTED &&
            bundle.phase != BundlePhase.EXECUTING
        ) {
            revert InvalidPhase();
        }

        ChainOperation storage op = bundle.operations[currentChainId];
        if (op.chainId != currentChainId) revert ChainNotPrepared();
        if (op.executed) revert AlreadyExecuted();

        bundle.phase = BundlePhase.EXECUTING;

        // Execute the operation first (CEI: check, then external call, then state update)
        (bool success, ) = op.target.call{value: op.value}(op.data);

        emit ChainExecuted(bundleId, currentChainId, success);

        if (!success) revert ExecutionFailed();

        // Update state only after successful execution
        op.executed = true;
        bundle.executedCount++;

        // Check if all chains executed
        if (bundle.executedCount == bundle.chainCount) {
            bundle.phase = BundlePhase.COMPLETED;
            emit BundleCompleted(bundleId, true);
        }
    }

    /**
     * @notice Send execution message to another L2 via Superchain
     * @param bundleId Bundle identifier
     * @param destChainId Destination chain ID
     */
    function sendSuperchainExecution(
        bytes32 bundleId,
        uint256 destChainId
    ) external payable onlyRole(EXECUTOR_ROLE) {
        AtomicBundle storage bundle = _bundles[bundleId];

        if (bundle.createdAt == 0) revert BundleNotFound();
        if (
            bundle.phase != BundlePhase.COMMITTED &&
            bundle.phase != BundlePhase.EXECUTING
        ) {
            revert InvalidPhase();
        }

        ChainOperation storage op = bundle.operations[destChainId];
        if (op.chainId != destChainId) revert ChainNotPrepared();

        // Encode execution message
        bytes memory payload = abi.encode(
            bundleId,
            op.target,
            op.data,
            op.value
        );

        bytes32 messageId = keccak256(
            abi.encodePacked(bundleId, destChainId, ++bundleNonces[bundleId])
        );

        // Send via Superchain messenger (OP Stack L2ToL2CrossDomainMessenger)
        if (superchainMessenger != address(0)) {
            (bool success, ) = superchainMessenger.call{value: msg.value}(
                abi.encodeWithSignature(
                    "sendMessage(uint256,address,bytes)",
                    destChainId,
                    chainAdapters[destChainId],
                    payload
                )
            );
            if (!success) revert SuperchainSendFailed();
        }

        emit SuperchainMessageSent(destChainId, messageId, payload);
    }

    /**
     * @notice Send execution via Arbitrum Nitro retryable ticket
     * @param bundleId Bundle identifier
     * @param ticket Retryable ticket parameters
     */
    function sendArbitrumExecution(
        bytes32 bundleId,
        uint256, // destChainId (unused)
        RetryableTicket calldata ticket
    ) external payable onlyRole(EXECUTOR_ROLE) {
        AtomicBundle storage bundle = _bundles[bundleId];

        if (bundle.createdAt == 0) revert BundleNotFound();
        if (
            bundle.phase != BundlePhase.COMMITTED &&
            bundle.phase != BundlePhase.EXECUTING
        ) {
            revert InvalidPhase();
        }

        // Create retryable ticket via Arbitrum Inbox
        if (arbitrumInbox != address(0)) {
            (bool success, bytes memory result) = arbitrumInbox.call{
                value: msg.value
            }(
                abi.encodeWithSignature(
                    "createRetryableTicket(address,uint256,uint256,address,address,uint256,uint256,bytes)",
                    ticket.destAddr,
                    ticket.l2CallValue,
                    ticket.maxSubmissionCost,
                    ticket.excessFeeRefundAddress,
                    ticket.callValueRefundAddress,
                    ticket.gasLimit,
                    ticket.maxFeePerGas,
                    ticket.data
                )
            );

            if (success) {
                uint256 ticketId = abi.decode(result, (uint256));
                emit ArbitrumRetryableCreated(
                    ticketId,
                    ticket.destAddr,
                    ticket.l2CallValue
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                            ROLLBACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate rollback after timeout
     * @param bundleId Bundle identifier
     */
    function rollbackAfterTimeout(bytes32 bundleId) external {
        AtomicBundle storage bundle = _bundles[bundleId];

        if (bundle.createdAt == 0) revert BundleNotFound();
        if (
            bundle.phase == BundlePhase.COMPLETED ||
            bundle.phase == BundlePhase.ROLLEDBACK
        ) {
            revert InvalidPhase();
        }
        if (block.timestamp <= bundle.createdAt + bundle.timeout) {
            revert TimeoutNotReached();
        }

        _initiateRollback(bundleId, "Timeout reached");
    }

    function _initiateRollback(
        bytes32 bundleId,
        string memory reason
    ) internal {
        AtomicBundle storage bundle = _bundles[bundleId];
        bundle.phase = BundlePhase.ROLLEDBACK;

        emit BundleRolledBack(bundleId, reason);
        emit BundleCompleted(bundleId, false);

        // In production: Send rollback messages to all chains
        // to unlock assets
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get bundle details
     * @param bundleId Bundle identifier
     * @return initiator Bundle initiator
     * @return phase Current phase
     * @return chainCount Number of chains
     * @return preparedCount Prepared chain count
     * @return executedCount Executed chain count
     * @return timeout Bundle timeout
     */
    function getBundle(
        bytes32 bundleId
    )
        external
        view
        returns (
            address initiator,
            BundlePhase phase,
            uint256 chainCount,
            uint256 preparedCount,
            uint256 executedCount,
            uint256 timeout
        )
    {
        AtomicBundle storage bundle = _bundles[bundleId];
        return (
            bundle.initiator,
            bundle.phase,
            bundle.chainCount,
            bundle.preparedCount,
            bundle.executedCount,
            bundle.timeout
        );
    }

    /**
     * @notice Get chain operation details
     * @param bundleId Bundle identifier
     * @param chainId Chain ID
     * @return operation Chain operation details
     */
    function getChainOperation(
        bytes32 bundleId,
        uint256 chainId
    ) external view returns (ChainOperation memory) {
        return _bundles[bundleId].operations[chainId];
    }

    /**
     * @notice Check if bundle is expired
     * @param bundleId Bundle identifier
     * @return expired True if expired
     */
    function isBundleExpired(bytes32 bundleId) external view returns (bool) {
        AtomicBundle storage bundle = _bundles[bundleId];
        return block.timestamp > bundle.createdAt + bundle.timeout;
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set chain adapter address
     * @param chainId Chain ID
     * @param adapter Adapter address
     */
    function setChainAdapter(
        uint256 chainId,
        address adapter
    ) external onlyRole(OPERATOR_ROLE) {
        chainAdapters[chainId] = adapter;
    }

    /**
     * @notice Set Superchain messenger
     * @param messenger Messenger address
     */
    function setSuperchainMessenger(
        address messenger
    ) external onlyRole(OPERATOR_ROLE) {
        superchainMessenger = messenger;
    }

    /**
     * @notice Set Arbitrum inbox
     * @param inbox Inbox address
     */
    function setArbitrumInbox(address inbox) external onlyRole(OPERATOR_ROLE) {
        arbitrumInbox = inbox;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive native tokens
     */
    receive() external payable {}
}
