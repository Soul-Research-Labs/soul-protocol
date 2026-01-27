// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IL2DirectMessenger
 * @author Soul Protocol
 * @notice Interface for direct L2-to-L2 messaging without L1 settlement
 */
interface IL2DirectMessenger {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Message delivery path
    enum MessagePath {
        SUPERCHAIN, // OP Stack native (Optimism, Base, Mode, Zora)
        SHARED_SEQUENCER, // Espresso, Astria, Radius
        FAST_RELAYER, // Bonded relayer network
        SLOW_L1 // Via L1 settlement
    }

    /// @notice Message status
    enum MessageStatus {
        NONE,
        SENT,
        RELAYED,
        CHALLENGED,
        EXECUTED,
        FAILED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cross-L2 message
    struct L2Message {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address recipient;
        bytes payload;
        uint256 value;
        uint256 nonce;
        uint256 timestamp;
        uint256 deadline;
        MessagePath path;
        MessageStatus status;
        bytes32 nullifierBinding;
    }

    /// @notice Relayer information
    struct Relayer {
        address addr;
        uint256 bond;
        uint256 successCount;
        uint256 failCount;
        uint256 slashedAmount;
        bool active;
        uint256 registeredAt;
    }

    /// @notice Route configuration
    struct RouteConfig {
        MessagePath preferredPath;
        address adapter;
        uint256 minConfirmations;
        uint256 challengeWindow;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        uint256 indexed destChainId,
        address sender,
        address recipient,
        bytes payload,
        uint256 nonce,
        MessagePath path
    );

    event MessageReceived(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        address sender,
        address recipient,
        bytes payload
    );

    event MessageExecuted(
        bytes32 indexed messageId,
        bool success,
        bytes returnData
    );

    event RelayerRegistered(address indexed relayer, uint256 bond);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        bytes32 reason
    );

    /*//////////////////////////////////////////////////////////////
                          MESSAGE SENDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a direct L2-to-L2 message
     * @param destChainId Destination chain ID
     * @param recipient Message recipient on destination
     * @param payload Message payload
     * @param path Preferred message path
     * @param nullifierBinding Optional Soul nullifier for privacy
     * @return messageId Unique message identifier
     */
    function sendMessage(
        uint256 destChainId,
        address recipient,
        bytes calldata payload,
        MessagePath path,
        bytes32 nullifierBinding
    ) external payable returns (bytes32 messageId);

    /**
     * @notice Receive a message from another L2 (via Superchain)
     * @param messageId Message identifier
     * @param sourceChainId Source chain ID
     * @param sender Original sender
     * @param recipient Target recipient
     * @param payload Message payload
     */
    function receiveMessage(
        bytes32 messageId,
        uint256 sourceChainId,
        address sender,
        address recipient,
        bytes calldata payload
    ) external;

    /**
     * @notice Receive message via fast relayer path
     * @param messageId Message identifier
     * @param sourceChainId Source chain ID
     * @param sender Original sender
     * @param recipient Target recipient
     * @param payload Message payload
     * @param signatures Relayer signatures
     */
    function receiveViaRelayer(
        bytes32 messageId,
        uint256 sourceChainId,
        address sender,
        address recipient,
        bytes calldata payload,
        bytes[] calldata signatures
    ) external;

    /**
     * @notice Execute a received message
     * @param messageId Message identifier
     */
    function executeMessage(bytes32 messageId) external;

    /*//////////////////////////////////////////////////////////////
                         RELAYER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a relayer
     */
    function registerRelayer() external payable;

    /**
     * @notice Withdraw relayer bond (after unbonding period)
     */
    function withdrawRelayerBond() external;

    /**
     * @notice Slash a relayer for fraudulent behavior
     * @param relayer Relayer address
     * @param amount Amount to slash
     * @param reason Reason for slashing
     */
    function slashRelayer(
        address relayer,
        uint256 amount,
        bytes32 reason
    ) external;

    /*//////////////////////////////////////////////////////////////
                        CHALLENGE MECHANISM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge a relayed message
     * @param messageId Message identifier
     * @param reason Challenge reason
     */
    function challengeMessage(
        bytes32 messageId,
        bytes32 reason
    ) external payable;

    /**
     * @notice Resolve a challenge
     * @param messageId Message identifier
     * @param fraudProven Whether fraud was proven
     */
    function resolveChallenge(bytes32 messageId, bool fraudProven) external;

    /*//////////////////////////////////////////////////////////////
                         ROUTE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a route between chains
     * @param sourceChainId Source chain ID
     * @param destChainId Destination chain ID
     * @param path Preferred message path
     * @param adapter Adapter address
     * @param minConfirmations Minimum confirmations
     * @param challengeWindow Challenge window duration
     */
    function configureRoute(
        uint256 sourceChainId,
        uint256 destChainId,
        MessagePath path,
        address adapter,
        uint256 minConfirmations,
        uint256 challengeWindow
    ) external;

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    function getMessage(
        bytes32 messageId
    ) external view returns (L2Message memory);

    function getRelayer(address addr) external view returns (Relayer memory);

    function getRoute(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (RouteConfig memory);

    function getConfirmationCount(
        bytes32 messageId
    ) external view returns (uint256);

    function isMessageProcessed(bytes32 messageId) external view returns (bool);

    function getRelayerCount() external view returns (uint256);

    function requiredConfirmations() external view returns (uint256);
}

/**
 * @title IL2ProofRouter
 * @author Soul Protocol
 * @notice Interface for optimized proof routing across L2 networks
 */
interface IL2ProofRouter {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported proof types
    enum ProofType {
        GROTH16,
        PLONK,
        STARK,
        BULLETPROOF,
        NOVA_IVC,
        RECURSIVE,
        STATE_PROOF,
        NULLIFIER_PROOF
    }

    /// @notice Routing paths
    enum RoutingPath {
        DIRECT,
        VIA_L1,
        SHARED_SEQUENCER,
        RELAY_NETWORK,
        HYBRID
    }

    /// @notice Batch status
    enum BatchStatus {
        OPEN,
        FULL,
        ROUTING,
        COMPLETED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Proof {
        bytes32 proofId;
        ProofType proofType;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes proofData;
        bytes publicInputs;
        address submitter;
        uint256 timestamp;
        uint256 gasEstimate;
        bool verified;
        bytes32 nullifierBinding;
    }

    struct ProofBatch {
        bytes32 batchId;
        uint256 destChainId;
        bytes32[] proofIds;
        uint256 totalGasEstimate;
        BatchStatus status;
        uint256 createdAt;
        uint256 routedAt;
        RoutingPath usedPath;
        bytes compressedData;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofSubmitted(
        bytes32 indexed proofId,
        uint256 indexed sourceChainId,
        uint256 indexed destChainId,
        ProofType proofType,
        address submitter
    );

    event BatchCreated(
        bytes32 indexed batchId,
        uint256 proofCount,
        uint256 totalGas
    );
    event BatchRouted(
        bytes32 indexed batchId,
        uint256 indexed destChainId,
        RoutingPath path,
        uint256 cost
    );

    /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a proof for routing
     */
    function submitProof(
        ProofType proofType,
        uint256 destChainId,
        bytes calldata proofData,
        bytes calldata publicInputs,
        bytes32 nullifierBinding
    ) external returns (bytes32 proofId);

    /**
     * @notice Route a batch to destination
     */
    function routeBatch(bytes32 batchId) external;

    /**
     * @notice Force route all pending batches for a destination
     */
    function flushBatches(uint256 destChainId) external;

    /**
     * @notice Clear expired cache entries
     */
    function clearExpiredCache() external;

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    function getProof(bytes32 proofId) external view returns (Proof memory);

    function getBatch(
        bytes32 batchId
    ) external view returns (ProofBatch memory);

    function getActiveBatch(
        uint256 destChainId
    ) external view returns (bytes32);

    function getCacheSize() external view returns (uint256);
}

/**
 * @title ISharedSequencerIntegration
 * @author Soul Protocol
 * @notice Interface for shared sequencer integration
 */
interface ISharedSequencerIntegration {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum SequencerType {
        ESPRESSO,
        ASTRIA,
        RADIUS,
        CUSTOM
    }

    enum BundleStatus {
        PENDING,
        COMMITTED,
        FINALIZED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct AtomicTransaction {
        bytes32 transactionHash;
        uint256 targetChainId;
        address target;
        bytes data;
        uint256 value;
        uint256 gasLimit;
        bytes32 nullifierBinding;
    }

    struct InclusionProof {
        bytes32 transactionHash;
        uint256 chainId;
        bytes32[] merkleProof;
        uint256 leafIndex;
        bytes32 blockHash;
        uint64 blockNumber;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event AtomicBundleSubmitted(
        bytes32 indexed bundleId,
        address indexed submitter,
        uint256[] chainIds,
        uint256 transactionCount
    );

    event AtomicBundleCommitted(
        bytes32 indexed bundleId,
        address indexed sequencer,
        bytes32 commitmentRoot
    );

    event AtomicBundleFinalized(
        bytes32 indexed bundleId,
        bytes32[] transactionHashes,
        uint256 timestamp
    );

    /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an atomic bundle for cross-chain execution
     */
    function submitAtomicBundle(
        AtomicTransaction[] calldata transactions,
        address preferredSequencer
    ) external returns (bytes32 bundleId);

    /**
     * @notice Finalize bundle with inclusion proofs
     */
    function finalizeBundle(
        bytes32 bundleId,
        InclusionProof[] calldata proofs
    ) external;

    /**
     * @notice Request ordered cross-chain message delivery
     */
    function requestOrderedMessage(
        uint256 destChainId,
        bytes32 messageId,
        address preferredSequencer
    ) external returns (uint256 sequenceNumber);

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    function getSequenceNumber(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (uint256);

    function isTransactionProcessed(
        bytes32 txHash
    ) external view returns (bool);

    function getActiveSequencers() external view returns (address[] memory);
}
